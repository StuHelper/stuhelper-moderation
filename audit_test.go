package moderation_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	m "github.com/StuHelper/stuhelper-moderation"
	"strings"
	"testing"
	"time"
)

func TestAuditFiltersScopesAndProjection(t *testing.T) {
	repo, db := database(t)
	at := time.Date(2026, 11, 9, 1, 0, 0, 0, time.UTC)
	add := func(id, actor, school, action, reason, result string) {
		t.Helper()
		err := repo.Transaction(context.Background(), func(tx m.Transaction) error {
			return tx.Event(m.Event{ID: id, Actor: actor, SchoolID: school, Type: action, Subject: "task/1", At: at, Reason: reason, Result: result})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	add("a", "admin", "school-a", "review", "", "unknown")
	add("b", "admin", "school-b", "review", "safe_code", "success")
	add("c", "another", "school-a", "configure", "", "failed")
	add("d", "admin", "", "review", "", "unknown")
	// Raw storage contains material-shaped canaries; projection must never select it.
	_, err := db.Exec(`UPDATE moderation.audit SET data=data || '{"body":"private-body","evidence":"private-evidence","document_number":"private-document","materials":"private-material"}'::jsonb`)
	if err != nil {
		t.Fatal(err)
	}
	q := m.AuditRequest{Principal: "viewer", Scopes: []m.AuditScope{{School: "*", Group: "*", Module: "moderation"}}, Until: at.Add(time.Second), Limit: 101}
	all, err := repo.ReadAudit(context.Background(), q)
	if err != nil || len(all.Records) != 4 {
		t.Fatalf("all: %+v %v", all, err)
	}
	raw, _ := json.Marshal(all)
	if strings.Contains(string(raw), "private-") {
		t.Fatal("raw audit leaked")
	}
	for _, r := range all.Records {
		if r.Source != "moderation" || r.Scope.Module != "moderation" || r.Scope.Group != "*" {
			t.Fatal(r)
		}
	}
	for _, test := range []struct {
		name   string
		change func(*m.AuditRequest)
		ids    string
	}{
		{"actor", func(q *m.AuditRequest) { q.Actor = "another" }, "c"},
		{"target", func(q *m.AuditRequest) { q.Target = "missing" }, ""},
		{"action", func(q *m.AuditRequest) { q.Action = "configure" }, "c"},
		{"time lower inclusive", func(q *m.AuditRequest) { q.From = at }, "dcba"},
		{"time upper exclusive", func(q *m.AuditRequest) { q.Until = at }, ""},
		{"school before limit", func(q *m.AuditRequest) {
			q.Scopes = []m.AuditScope{{School: "school-b", Group: "*", Module: "moderation"}}
			q.Limit = 1
		}, "b"},
		{"union", func(q *m.AuditRequest) {
			q.Scopes = []m.AuditScope{{School: "school-b", Group: "*", Module: "moderation"}, {School: "school-a", Group: "*", Module: "moderation"}}
		}, "cba"},
		{"group", func(q *m.AuditRequest) {
			q.Scopes = []m.AuditScope{{School: "*", Group: "group-1", Module: "moderation"}}
		}, ""},
		{"module", func(q *m.AuditRequest) { q.Scopes = []m.AuditScope{{School: "*", Group: "*", Module: "other"}} }, ""},
		{"empty scopes", func(q *m.AuditRequest) { q.Scopes = nil }, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			query := q
			test.change(&query)
			batch, err := repo.ReadAudit(context.Background(), query)
			ids := ""
			for _, r := range batch.Records {
				ids += r.ID
			}
			if err != nil || ids != test.ids {
				t.Fatal(ids, err)
			}
		})
	}
	q.Actor = "admin"
	q.Scopes = []m.AuditScope{{School: "school-a", Group: "*", Module: "moderation"}}
	batch, err := repo.ReadAudit(context.Background(), q)
	if err != nil || len(batch.Records) != 1 || batch.Records[0].Reason != "" || batch.Records[0].Result != "unknown" {
		t.Fatal(batch, err)
	}
	for _, limit := range []int{0, 102} {
		query := q
		query.Limit = limit
		if _, err := repo.ReadAudit(context.Background(), query); !errors.Is(err, m.ErrInput) {
			t.Fatal("limit", err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repo.ReadAudit(canceled, q); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation", err)
	}
}

func TestAuditSnapshotExcludesBackfillAndLateCommit(t *testing.T) {
	repo, db := database(t)
	at := time.Date(2026, 11, 9, 1, 0, 0, 0, time.UTC)
	write := func(tx m.Transaction, id string) error {
		return tx.Event(m.Event{ID: id, Actor: "admin", SchoolID: "school", Type: "review", Subject: "task", At: at})
	}
	for _, id := range []string{"a", "b", "c"} {
		if err := repo.Transaction(context.Background(), func(tx m.Transaction) error { return write(tx, id) }); err != nil {
			t.Fatal(err)
		}
	}
	pending, release := make(chan struct{}), make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- repo.Transaction(context.Background(), func(tx m.Transaction) error { err := write(tx, "late"); close(pending); <-release; return err })
	}()
	<-pending
	q := m.AuditRequest{Principal: "viewer", Scopes: []m.AuditScope{{School: "*", Group: "*", Module: "*"}}, Until: at.Add(time.Second), Limit: 1}
	first, err := repo.ReadAudit(context.Background(), q)
	close(release)
	if e := <-finished; e != nil {
		t.Fatal(e)
	}
	if err != nil || len(first.Records) != 1 || first.Records[0].ID != "c" || first.Snapshot == "" || len(first.Snapshot) > 256 {
		t.Fatal(first, err)
	}
	if err := repo.Transaction(context.Background(), func(tx m.Transaction) error { return write(tx, "backfill") }); err != nil {
		t.Fatal(err)
	}
	q.Snapshot = first.Snapshot
	q.Before = &m.AuditPosition{Time: at, Source: "moderation", ID: "c"}
	second, err := repo.ReadAudit(context.Background(), q)
	if err != nil || len(second.Records) != 1 || second.Records[0].ID != "b" || second.Snapshot != first.Snapshot {
		t.Fatal(second, err)
	}
	q.Before.ID = "b"
	third, err := repo.ReadAudit(context.Background(), q)
	if err != nil || len(third.Records) != 1 || third.Records[0].ID != "a" {
		t.Fatal(third, err)
	}
	q.Before.ID = "a"
	end, err := repo.ReadAudit(context.Background(), q)
	if err != nil || len(end.Records) != 0 {
		t.Fatal(end, err)
	}
	// A boundary from another provider compares Source before ID.
	q.Before = &m.AuditPosition{Time: at, Source: "zzz", ID: "0"}
	page, err := repo.ReadAudit(context.Background(), q)
	if err != nil || len(page.Records) != 1 || page.Records[0].ID != "c" {
		t.Fatal(page, err)
	}
	q.Before.Source = "aaa"
	page, err = repo.ReadAudit(context.Background(), q)
	if err != nil || len(page.Records) != 0 {
		t.Fatal(page, err)
	}
	q.Before = nil
	q.Snapshot = ""
	q.Limit = 101
	fresh, err := repo.ReadAudit(context.Background(), q)
	if err != nil || len(fresh.Records) != 5 {
		t.Fatal(fresh, err)
	}
	for _, token := range []string{"invalid", strings.Replace(first.Snapshot, strings.Split(first.Snapshot, "|")[1], "1", 1)} {
		q.Snapshot = token
		if _, err := repo.ReadAudit(context.Background(), q); err == nil {
			t.Fatal("invalid/expired snapshot accepted")
		}
	}
	q.Snapshot = first.Snapshot
	if _, err := db.Exec(`DELETE FROM moderation.audit WHERE id='b'`); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ReadAudit(context.Background(), q); !errors.Is(err, m.ErrUnavailable) {
		t.Fatal("retention did not invalidate", err)
	}
}

func TestAuditDefaultsAndTransactionRollback(t *testing.T) {
	repo, db := database(t)
	at := time.Date(2026, 11, 9, 1, 0, 0, 0, time.UTC)
	if err := repo.Transaction(context.Background(), func(tx m.Transaction) error {
		if err := tx.Event(m.Event{ID: "rollback", Actor: "admin", Type: "review", Subject: "task", At: at, Reason: "safe_code", Result: "success"}); err != nil {
			return err
		}
		return m.ErrConflict
	}); !errors.Is(err, m.ErrConflict) {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM moderation.audit`).Scan(&count); err != nil || count != 0 {
		t.Fatal(count, err)
	}
	if err := repo.Transaction(context.Background(), func(tx m.Transaction) error {
		return tx.Event(m.Event{ID: "unknown", Actor: "admin", Type: "review", Subject: "task", At: at})
	}); err != nil {
		t.Fatal(err)
	}
	q := m.AuditRequest{Principal: "viewer", Scopes: []m.AuditScope{{School: "*", Group: "*", Module: "*"}}, Until: at.Add(time.Second), Limit: 101}
	page, err := repo.ReadAudit(context.Background(), q)
	if err != nil || len(page.Records) != 1 || page.Records[0].Result != "unknown" || page.Records[0].Reason != "" {
		t.Fatal(page, err)
	}
}

func TestAuditBatchLimitAndRecordedOutcome(t *testing.T) {
	repo, _ := database(t)
	at := time.Now().UTC().Add(-time.Minute)
	err := repo.Transaction(context.Background(), func(tx m.Transaction) error {
		for i := 0; i < 102; i++ {
			if err := tx.Event(m.Event{ID: fmt.Sprintf("%03d", i), Actor: "admin", Type: "review", Subject: "task", At: at, Reason: "safe_code", Result: "denied"}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	q := m.AuditRequest{Principal: "viewer", Scopes: []m.AuditScope{{School: "*", Group: "*", Module: "*"}}, Until: time.Now().UTC(), Limit: 101}
	page, err := repo.ReadAudit(context.Background(), q)
	if err != nil || len(page.Records) != 101 {
		t.Fatal(len(page.Records), err)
	}
	for _, r := range page.Records {
		if r.Reason != "safe_code" || r.Result != "denied" {
			t.Fatal(r)
		}
	}
	last := page.Records[100]
	q.Before = &m.AuditPosition{Time: last.CreatedAt, Source: last.Source, ID: last.ID}
	q.Snapshot = page.Snapshot
	rest, err := repo.ReadAudit(context.Background(), q)
	if err != nil || len(rest.Records) != 1 || rest.Records[0].ID != "000" {
		t.Fatal(rest, err)
	}
}

func TestAuditDecisionSavedIsNotExecutionSuccess(t *testing.T) {
	s, _, _ := fixture(t)
	task, err := s.Submit(context.Background(), m.Principal{Subject: "reporter"}, "audit-submit", m.Submission{ObjectID: "review", Kind: "report", Reason: "private report evidence"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Decide(context.Background(), m.Principal{Subject: "admin"}, task.ID, "audit-decide", m.Decide{Revision: task.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "private decision reason"}})
	if err != nil {
		t.Fatal(err)
	}
	query := m.AuditRequest{Principal: "viewer", Scopes: []m.AuditScope{{School: "*", Group: "*", Module: "*"}}, Until: time.Now().Add(time.Minute), Action: "moderation.decided.v1", Limit: 101}
	page, err := s.Repo.(m.AuditReader).ReadAudit(context.Background(), query)
	if err != nil || len(page.Records) != 1 || page.Records[0].Result != "unknown" || page.Records[0].Reason != "" {
		t.Fatal(page, err)
	}
	if _, err = s.Work(context.Background(), 50); err != nil {
		t.Fatal(err)
	}
	query.Action = "moderation.result.v1"
	page, err = s.Repo.(m.AuditReader).ReadAudit(context.Background(), query)
	if err != nil || len(page.Records) != 1 || page.Records[0].Result != "success" || page.Records[0].Actor != "admin" {
		t.Fatal(page, err)
	}
}
