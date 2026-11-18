package moderation_test

import (
	"context"
	"database/sql"
	"fmt"
	m "github.com/StuHelper/stuhelper-moderation"
	f "github.com/StuHelper/stuhelper-moderation/feedback"
	pg "github.com/StuHelper/stuhelper-moderation/postgres"
	"testing"
	"time"
)

func TestEmptyFeedbackCleanupDoesNotInvalidateAuditSnapshot(t *testing.T) {
	repo, _ := database(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 18, 6, 0, 0, 0, time.UTC)

	for _, id := range []string{"a1", "a2"} {
		if err := repo.Transaction(ctx, func(tx m.Transaction) error {
			return tx.Event(m.Event{ID: id, Actor: "admin", SchoolID: "school", Type: "review", Subject: "task/1", At: at})
		}); err != nil {
			t.Fatal(err)
		}
	}

	q := m.AuditRequest{
		Principal: "viewer",
		Scopes:    []m.AuditScope{{School: "*", Group: "*", Module: "moderation"}},
		Until:     at.Add(time.Second),
		Limit:     1,
	}
	first, err := repo.ReadAudit(ctx, q)
	if err != nil || len(first.Records) != 1 || first.Records[0].ID != "a2" {
		t.Fatalf("first page failed: %+v %v", first, err)
	}

	// Run scheduled feedback Cleanup when 0 feedback audit rows are expired.
	fbSvc := &f.Service{
		Repo:   &pg.FeedbackRepository{DB: repo.DB},
		Access: &feedbackAccess{},
		Blobs:  &feedbackBlobs{values: map[string][]byte{}},
		Now:    func() time.Time { return at },
	}
	if err = fbSvc.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}

	q.Snapshot = first.Snapshot
	q.Before = &m.AuditPosition{Time: at, Source: "moderation", ID: "a2"}
	second, err := repo.ReadAudit(ctx, q)
	if err != nil || len(second.Records) != 1 || second.Records[0].ID != "a1" {
		t.Fatalf("empty feedback cleanup invalidated active ReadAudit snapshot: %+v %v", second, err)
	}
}

func TestReadAuditSnapshotStaysWithin256BytesUnderManyConcurrentWriters(t *testing.T) {
	repo, migration := database(t)
	migration.SetMaxOpenConns(80)
	ctx := context.Background()
	at := time.Date(2026, 11, 18, 6, 0, 0, 0, time.UTC)

	for _, id := range []string{"committed-1", "committed-2"} {
		if err := repo.Transaction(ctx, func(tx m.Transaction) error {
			return tx.Event(m.Event{ID: id, Actor: "admin", SchoolID: "school", Type: "review", Subject: "task/1", At: at})
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Open 65 uncommitted write transactions, then commit 1 transaction after them so latestCompletedXid+1 (xmax)
	// advances past all 65 active XIDs, expanding pg_current_snapshot()::text past 256 bytes.
	const writerCount = 65
	txs := make([]*sql.Tx, 0, writerCount)
	defer func() {
		for _, tx := range txs {
			_ = tx.Rollback()
		}
	}()
	for i := 0; i < writerCount; i++ {
		tx, err := migration.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		txs = append(txs, tx)
		id := fmt.Sprintf("uncommitted-%02d", i)
		if _, err = tx.ExecContext(ctx, `INSERT INTO moderation.audit(id,time,actor,target,action,school,reason,result,data) VALUES($1,$2,'admin','task/1','review','school','','success','{}'::jsonb)`, id, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.Transaction(ctx, func(tx m.Transaction) error {
		return tx.Event(m.Event{ID: "committed-3", Actor: "admin", SchoolID: "school", Type: "review", Subject: "task/1", At: at})
	}); err != nil {
		t.Fatal(err)
	}

	q := m.AuditRequest{
		Principal: "viewer",
		Scopes:    []m.AuditScope{{School: "*", Group: "*", Module: "moderation"}},
		Until:     at.Add(time.Second),
		Limit:     2,
	}
	first, err := repo.ReadAudit(ctx, q)
	if err != nil {
		t.Fatalf("ReadAudit failed when xip_list exceeded 256 bytes: %v", err)
	}
	if len(first.Snapshot) == 0 || len(first.Snapshot) > 256 {
		t.Fatalf("Snapshot length violated 1..256 contract: len=%d snapshot=%q", len(first.Snapshot), first.Snapshot)
	}
	if len(first.Records) != 2 || first.Records[0].ID != "committed-3" || first.Records[1].ID != "committed-2" {
		t.Fatalf("unexpected first page records: %+v", first.Records)
	}

	// Commit all 65 concurrent writers between page 1 and page 2: page 2 using first.Snapshot must still exclude all 65!
	for _, tx := range txs {
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	txs = nil

	q.Snapshot = first.Snapshot
	q.Before = &m.AuditPosition{Time: at, Source: "moderation", ID: "committed-2"}
	q.Limit = 100
	second, err := repo.ReadAudit(ctx, q)
	if err != nil {
		t.Fatalf("ReadAudit second page failed with compact snapshot: %v", err)
	}
	if len(second.Records) != 1 || second.Records[0].ID != "committed-1" {
		t.Fatalf("compact snapshot leaked late-committed transactions: %+v", second.Records)
	}
}
