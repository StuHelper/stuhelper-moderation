package moderation_test

import (
	"context"
	"errors"
	"fmt"
	m "github.com/StuHelper/stuhelper-moderation"
	"reflect"
	"testing"
	"time"
)

func TestOutboxExcludesDeferredSubjectsBeforeLimit(t *testing.T) {
	repo, _ := database(t)
	err := repo.Transaction(context.Background(), func(tx m.Transaction) error {
		// A full first batch from a deferred subject must not hide other subjects.
		for i := 0; i < 105; i++ {
			if err := tx.Event(m.Event{ID: fmt.Sprintf("blocked-%03d", i), Subject: "a-blocked", Revision: int64(i + 1), At: time.Now().UTC(), Type: "moderation.test.v1"}); err != nil {
				return err
			}
		}
		for _, e := range []m.Event{
			{ID: "z", Subject: "b-ready", Revision: 10},
			{ID: "y", Subject: "b-ready", Revision: 2},
			{ID: "x", Subject: "b-ready", Revision: 2},
			{ID: "w", Subject: "c-ready", Revision: 1},
		} {
			e.At = time.Now().UTC()
			e.Type = "moderation.test.v1"
			if err := tx.Event(e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := repo.PendingOutbox(context.Background(), 100, nil)
	if err != nil || len(baseline) != 100 {
		t.Fatal(len(baseline), err)
	}
	empty, err := repo.PendingOutbox(context.Background(), 100, []string{})
	if err != nil || !reflect.DeepEqual(empty, baseline) {
		t.Fatal("empty differs from nil", err)
	}
	for _, event := range baseline {
		if event.Subject != "a-blocked" {
			t.Fatal("fixture did not reproduce queue head", event)
		}
	}
	exclusions := []string{"a-blocked"}
	for len(exclusions) < 1000 {
		exclusions = append(exclusions, fmt.Sprintf("missing-%d", len(exclusions)))
	}
	ready, err := repo.PendingOutbox(context.Background(), 100, exclusions)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, event := range ready {
		ids = append(ids, event.ID)
	}
	if !reflect.DeepEqual(ids, []string{"x", "y", "z", "w"}) {
		t.Fatal("remaining subject order", ids)
	}
	if err := repo.ConfirmOutbox(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	next, err := repo.PendingOutbox(context.Background(), 1, []string{"a-blocked", "c-ready", "a-blocked"})
	if err != nil || len(next) != 1 || next[0].ID != "y" {
		t.Fatal("sent filtering and order", next, err)
	}
	all, err := repo.PendingOutbox(context.Background(), 100, []string{"a-blocked", "b-ready", "c-ready"})
	if err != nil || len(all) != 0 {
		t.Fatal("all subjects excluded", all, err)
	}
	if _, err := repo.PendingOutbox(context.Background(), 100, append(exclusions, "too-many")); !errors.Is(err, m.ErrInput) {
		t.Fatal("exclusion bound", err)
	}
}
