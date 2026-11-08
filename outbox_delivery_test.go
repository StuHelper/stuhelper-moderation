package moderation_test

import (
	"context"
	"errors"
	"fmt"
	m "github.com/StuHelper/stuhelper-moderation"
	"github.com/jackc/pgx/v5"
	"os"
	"testing"
	"time"
)

func TestOutboxCommitNotificationAndRollback(t *testing.T) {
	repo, db := database(t)
	var name string
	if err := db.QueryRow(`SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(os.Getenv("STUHELPER_MODERATION_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = name
	listener, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close(context.Background())
	if _, err = listener.Exec(context.Background(), "LISTEN moderation_outbox"); err != nil {
		t.Fatal(err)
	}
	publish := func(id string, rollback bool) error {
		return repo.Transaction(context.Background(), func(tx m.Transaction) error {
			err := tx.Event(m.Event{ID: id, Type: "moderation.test.v1", Subject: "object/1", Revision: 1, At: time.Now().UTC()})
			if err != nil {
				return err
			}
			if rollback {
				return errors.New("rollback")
			}
			return nil
		})
	}
	if err := publish("rollback", true); err == nil {
		t.Fatal("expected rollback")
	}
	wait, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, err = listener.WaitForNotification(wait)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("rollback notification: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM moderation.outbox`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rollback leaked: %d %v", count, err)
	}
	if err := publish("commit", false); err != nil {
		t.Fatal(err)
	}
	wait, cancel = context.WithTimeout(context.Background(), time.Second)
	n, err := listener.WaitForNotification(wait)
	cancel()
	if err != nil || n.Channel != m.OutboxChannel || n.Payload != "" {
		t.Fatalf("missing commit notification: %v %v", n, err)
	}
	// No listener is required to retain a durable backlog.
	if _, err = listener.Exec(context.Background(), "UNLISTEN *"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 101; i++ {
		if err := publish(fmt.Sprintf("backlog-%03d", i), false); err != nil {
			t.Fatal(err)
		}
	}

	events, err := repo.PendingOutbox(context.Background(), 100, nil)
	if err != nil || len(events) != 100 {
		t.Fatalf("batch: %d %v", len(events), err)
	}
	again, err := repo.PendingOutbox(context.Background(), 100, nil)
	if err != nil || again[0].ID != events[0].ID {
		t.Fatal("redelivery changed ID", err)
	}
	for _, event := range events {
		if event.SpecVersion != "1.0" || event.Source != "moderation" || event.Data.Revision != 1 {
			t.Fatal("invalid envelope", event)
		}
		for range 2 {
			if err := repo.ConfirmOutbox(context.Background(), event.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	rest, err := repo.PendingOutbox(context.Background(), 100, nil)
	if err != nil || len(rest) != 2 {
		t.Fatalf("remaining: %d %v", len(rest), err)
	}
	for _, limit := range []int{0, 101} {
		if _, err := repo.PendingOutbox(context.Background(), limit, nil); !errors.Is(err, m.ErrInput) {
			t.Fatal("unbounded read", err)
		}
	}
	if err := repo.ConfirmOutbox(context.Background(), "missing"); !errors.Is(err, m.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestDecisionResultsAreDurableAndReplaySafe(t *testing.T) {
	for _, kind := range []string{"review", "report", "delete_request"} {
		for _, action := range []string{"publish", "dismiss", "hide"} {
			t.Run(kind+"/"+action, func(t *testing.T) {
				s, _, _ := fixture(t)
				relay := s.Repo.(m.OutboxReader)
				p := m.Principal{Subject: "author"}
				if kind == "report" {
					p.Subject = "reporter"
				}
				if kind == "review" {
					p.Subject = "admin"
				}
				task, err := s.Submit(context.Background(), p, "submit", m.Submission{ObjectID: "review", Kind: kind, Reason: "private evidence"})
				if err != nil {
					t.Fatal(err)
				}
				in := m.Decide{Revision: task.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: action, Reason: "private reason"}}
				for range 2 {
					if _, err = s.Decide(context.Background(), m.Principal{Subject: "admin"}, task.ID, "decide", in); err != nil {
						t.Fatal(err)
					}
				}
				if _, err = s.Decide(context.Background(), m.Principal{Subject: "admin"}, task.ID, "stale", in); !errors.Is(err, m.ErrConflict) {
					t.Fatal("stale decision accepted", err)
				}
				for range 2 {
					if _, err = s.Work(context.Background(), 50); err != nil {
						t.Fatal(err)
					}
				}
				events, err := relay.PendingOutbox(context.Background(), 100, nil)
				if err != nil {
					t.Fatal(err)
				}
				results := 0
				for _, event := range events {
					if event.Type != "moderation.result.v1" {
						continue
					}
					results++
					if event.Data.Action != action || event.Data.RequestKind != kind || event.Data.Owner != p.Subject || event.Data.ContentOwner != "author" || event.Data.State != "applied" || event.Data.Revision <= in.Revision {
						t.Fatalf("wrong result: %+v", event)
					}
				}
				if results != 1 {
					t.Fatalf("results=%d", results)
				}
			})
		}
	}
}

func TestDecisionOutboxFailureRollsBackDecision(t *testing.T) {
	repo, db := database(t)
	c := &content{revision: 1, applied: map[string]bool{}}
	s := &m.Service{Repo: repo, Content: c, Access: access{}}
	task, err := s.Submit(context.Background(), m.Principal{Subject: "reporter"}, "submit", m.Submission{ObjectID: "review", Kind: "report", Reason: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE FUNCTION moderation.fail_outbox() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic'; END$$; CREATE TRIGGER fail_outbox BEFORE INSERT ON moderation.outbox FOR EACH ROW EXECUTE FUNCTION moderation.fail_outbox()`)
	if err != nil {
		t.Fatal(err)
	}
	in := m.Decide{Revision: task.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "dismiss", Reason: "synthetic"}}
	if _, err = s.Decide(context.Background(), m.Principal{Subject: "admin"}, task.ID, "decide", in); !errors.Is(err, m.ErrUnavailable) {
		t.Fatal(err)
	}
	current, err := s.Get(context.Background(), m.Principal{Subject: "reporter"}, task.ID)
	if err != nil || current.State != "waiting" || current.Revision != task.Revision || current.Decision != nil {
		t.Fatal("decision escaped rollback", current, err)
	}
	events, err := repo.PendingOutbox(context.Background(), 100, nil)
	if err != nil || len(events) != 1 || events[0].Type != "moderation.submitted.v1" {
		t.Fatal("result escaped rollback", events, err)
	}
	_, err = db.Exec(`DROP TRIGGER fail_outbox ON moderation.outbox`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Decide(context.Background(), m.Principal{Subject: "admin"}, task.ID, "decide", in); err != nil {
		t.Fatal(err)
	}
}
