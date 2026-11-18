package moderation_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	f "github.com/StuHelper/stuhelper-moderation/feedback"
	pg "github.com/StuHelper/stuhelper-moderation/postgres"
	"testing"
	"time"
)

func TestFeedbackValidationEnforcesAttachmentLimitsSenderNormalizationAndHeaderSafety(t *testing.T) {
	repo, migration := database(t)
	clock := time.Date(2026, 11, 18, 4, 0, 0, 0, time.UTC)
	blobs := &feedbackBlobs{values: map[string][]byte{}}
	s := &f.Service{Repo: &pg.FeedbackRepository{DB: repo.DB}, Access: &feedbackAccess{}, Blobs: blobs, Now: func() time.Time { return clock }}
	ctx := context.Background()

	// 1. Oversized stored attachment (> 5 MiB) and under-reported Bytes must be rejected without creating rows.
	oversized := bytes.Repeat([]byte("a"), (5<<20)+1)
	badSize := feedbackInput("oversized-part")
	badSize.Message.Attachments = []f.Attachment{{ID: "big", Name: "big.bin", ContentType: "application/pdf", Size: int64(len(oversized)), Status: "stored"}}
	badSize.Parts = map[string][]byte{"big": oversized}
	badSize.Message.Bytes = int64(len(badSize.Message.Body) + len(oversized))
	if _, err := s.Ingest(ctx, badSize); !errors.Is(err, f.ErrInvalid) {
		t.Fatalf("expected ErrInvalid for >5 MiB stored attachment, got: %v", err)
	}

	underReported := feedbackInput("under-reported")
	underReported.Message.Bytes = 1 // less than len(Body)+attachment size
	if _, err := s.Ingest(ctx, underReported); !errors.Is(err, f.ErrInvalid) {
		t.Fatalf("expected ErrInvalid for under-reported Bytes, got: %v", err)
	}

	missingPart := feedbackInput("missing-part")
	missingPart.Parts = map[string][]byte{}
	if _, err := s.Ingest(ctx, missingPart); !errors.Is(err, f.ErrInvalid) {
		t.Fatalf("expected ErrInvalid for missing part bytes, got: %v", err)
	}
	var orphanCount int
	if err := migration.QueryRow(`SELECT count(*) FROM moderation.feedback`).Scan(&orphanCount); err != nil || orphanCount != 0 {
		t.Fatalf("rejected ingest leaked staged orphan rows: count=%d err=%v", orphanCount, err)
	}

	// 2. CRLF in Subject or MessageID must be rejected.
	crlfSubject := feedbackInput("crlf-subj")
	crlfSubject.Message.Subject = "Hello\r\nBcc: victim@example.test"
	if _, err := s.Ingest(ctx, crlfSubject); !errors.Is(err, f.ErrInvalid) {
		t.Fatalf("expected ErrInvalid for CRLF subject, got: %v", err)
	}
	crlfMsgID := feedbackInput("crlf-msgid")
	crlfMsgID.Message.MessageID = "<id@example.test>\r\nBcc: victim@example.test"
	if _, err := s.Ingest(ctx, crlfMsgID); !errors.Is(err, f.ErrInvalid) {
		t.Fatalf("expected ErrInvalid for CRLF Message-ID, got: %v", err)
	}

	// 3. Sender display-name and casing variations normalize to canonical lowercase address for 20/h rate limit.
	for i := 0; i < 20; i++ {
		in := feedbackInput(fmt.Sprintf("norm-%d", i))
		in.Message.Sender = fmt.Sprintf("Alias %d <User@Example.TEST>", i)
		got, err := s.Ingest(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		if got.Sender != "user@example.test" {
			t.Fatalf("expected normalized sender 'user@example.test', got %q", got.Sender)
		}
	}
	over := feedbackInput("norm-20")
	over.Message.Sender = "Different Alias <USER@example.test>"
	throttled, err := s.Ingest(ctx, over)
	if err != nil {
		t.Fatal(err)
	}
	if throttled.State != "spam" || throttled.Body != "" || len(throttled.Attachments) != 0 {
		t.Fatalf("sender display-name/casing bypassed hourly rate limit: %+v", throttled)
	}
}

type blockingDeleteBlobs struct {
	*feedbackBlobs
	entered chan struct{}
	release chan struct{}
}

func (b *blockingDeleteBlobs) Delete(ctx context.Context, key string) error {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	select {
	case <-b.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return b.feedbackBlobs.Delete(ctx, key)
}

func TestFeedbackSlowCleanupBlobDeleteDoesNotBlockConcurrentReplyOrUpdate(t *testing.T) {
	repo, _ := database(t)
	clock := time.Date(2026, 11, 18, 4, 0, 0, 0, time.UTC)
	baseBlobs := &feedbackBlobs{values: map[string][]byte{}}
	slowBlobs := &blockingDeleteBlobs{
		feedbackBlobs: baseBlobs,
		entered:       make(chan struct{}, 1),
		release:       make(chan struct{}),
	}
	sender := &feedbackSender{state: "sent"}
	s := &f.Service{
		Repo:   &pg.FeedbackRepository{DB: repo.DB},
		Access: &feedbackAccess{},
		Blobs:  slowBlobs,
		Sender: sender,
		Now:    func() time.Time { return clock },
	}
	ctx := context.Background()

	oldCase, err := s.Ingest(ctx, feedbackInput("old-case"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Update(ctx, "operator", oldCase.ID, "close-old-case", f.Update{Revision: oldCase.Revision, State: "resolved"}); err != nil {
		t.Fatal(err)
	}
	clock = clock.AddDate(1, 0, 1)

	activeCase, err := s.Ingest(ctx, feedbackInput("active-case"))
	if err != nil {
		t.Fatal(err)
	}

	cleanupDone := make(chan error, 1)
	go func() {
		cleanupDone <- s.Cleanup(ctx)
	}()
	select {
	case <-slowBlobs.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("Cleanup did not reach Blobs.Delete")
	}

	// While Cleanup is blocked inside external Blobs.Delete, active Reply and Update must complete promptly without waiting on Cleanup.
	replyDone := make(chan error, 1)
	var replyOut f.Reply
	go func() {
		var e error
		replyOut, e = s.Reply(ctx, "operator", activeCase.ID, "reply-active-1", "We have handled your feedback.")
		replyDone <- e
	}()
	select {
	case e := <-replyDone:
		if e != nil || replyOut.State != "sent" {
			close(slowBlobs.release)
			<-cleanupDone
			t.Fatalf("concurrent Reply failed or lost sent state during Cleanup: %+v %v", replyOut, e)
		}
	case <-time.After(500 * time.Millisecond):
		close(slowBlobs.release)
		<-cleanupDone
		t.Fatal("concurrent Reply was blocked by slow Cleanup Blobs.Delete")
	}

	close(slowBlobs.release)
	if e := <-cleanupDone; e != nil {
		t.Fatal(e)
	}
	gotActive, err := s.Get(ctx, "operator", activeCase.ID)
	if err != nil || len(gotActive.Replies) != 1 || gotActive.Replies[0].State != "sent" {
		t.Fatalf("active case reply state corrupted: %+v %v", gotActive, err)
	}
}
