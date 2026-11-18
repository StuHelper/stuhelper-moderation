package moderation_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	m "github.com/StuHelper/stuhelper-moderation"
)

func TestSubmissionReplaysLegacyNilEvidence(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	p := m.Principal{Subject: "author"}
	for _, kind := range []string{"report", "delete_request"} {
		t.Run(kind, func(t *testing.T) {
			in := m.Submission{ObjectID: "review", Kind: kind, Reason: "reason"}
			first, err := s.Submit(ctx, p, "legacy", in)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			if err = s.Repo.Transaction(ctx, func(tx m.Transaction) error {
				r, err := tx.Replay(first.ID)
				if err != nil {
					return err
				}
				r.Digest = hex.EncodeToString(sum[:])
				return tx.SaveReplay(first.ID, r)
			}); err != nil {
				t.Fatal(err)
			}
			got, err := s.Submit(ctx, p, "legacy", in)
			if err != nil || got.ID != first.ID || got.Revision != first.Revision {
				t.Fatalf("replayed receipt = %+v, %v", got, err)
			}
			in.Reason = "changed"
			if _, err = s.Submit(ctx, p, "legacy", in); !errors.Is(err, m.ErrConflict) {
				t.Fatalf("changed reason: %v", err)
			}
		})
	}
}
