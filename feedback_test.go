package moderation_test

import (
	"context"
	"errors"
	f "github.com/StuHelper/stuhelper-moderation/feedback"
	pg "github.com/StuHelper/stuhelper-moderation/postgres"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type feedbackAccess struct{ denied bool }

func (a *feedbackAccess) Check(_ context.Context, actor, action string) error {
	if a.denied || actor != "operator" {
		return f.ErrDenied
	}
	return nil
}

type feedbackBlobs struct {
	mu      sync.Mutex
	values  map[string][]byte
	deleted int
}

func (b *feedbackBlobs) Put(_ context.Context, key string, _ f.Attachment, data []byte) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.values[key] = append([]byte{}, data...)
	return key, nil
}
func (b *feedbackBlobs) Download(_ context.Context, key string, w io.Writer) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, e := w.Write(b.values[key])
	return e
}
func (b *feedbackBlobs) Delete(_ context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.values, key)
	b.deleted++
	return nil
}

type feedbackSender struct {
	calls int
	state string
}

func (s *feedbackSender) Send(context.Context, string, string, string, string, string) (string, error) {
	s.calls++
	return s.state, nil
}
func feedbackInput(key string) f.Input {
	return f.Input{Message: f.Message{Dedupe: f.Digest(key), Sender: "sender@example.test", Subject: "Question", Body: "Private message", AuthenticationResults: "example.test; spf=fail", Suspicious: true, Bytes: 20, Attachments: []f.Attachment{{ID: "one", Name: "evidence.txt", ContentType: "text/plain", Size: 5, Status: "stored"}}}, Parts: map[string][]byte{"one": []byte("hello")}}
}
func TestFeedbackConcurrentIngestAuthorizationAndAudit(t *testing.T) {
	repo, migration := database(t)
	clock := time.Now().UTC()
	access := &feedbackAccess{}
	blobs := &feedbackBlobs{values: map[string][]byte{}}
	s := &f.Service{Repo: &pg.FeedbackRepository{DB: repo.DB}, Access: access, Blobs: blobs, Now: func() time.Time { return clock }}
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := s.Ingest(ctx, feedbackInput("same")); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	var count int
	if e := migration.QueryRow(`SELECT count(*) FROM moderation.feedback`).Scan(&count); e != nil || count != 1 {
		t.Fatalf("duplicate rows: %d %v", count, e)
	}
	page, e := s.List(ctx, "operator", f.Filter{})
	if e != nil || len(page.Items) != 1 || page.Items[0].Body != "" {
		t.Fatalf("list projection: %+v %v", page, e)
	}
	id := page.Items[0].ID
	v, e := s.Get(ctx, "operator", id)
	if e != nil || v.Body != "Private message" || !v.Suspicious {
		t.Fatal(v, e)
	}
	if _, e = s.Get(ctx, "other-school-operator", id); !errors.Is(e, f.ErrDenied) {
		t.Fatal(e)
	}
	var dst strings.Builder
	if e = s.Download(ctx, "operator", id, "one", &dst); e != nil || dst.String() != "hello" {
		t.Fatal(e, dst.String())
	}
	update := f.Update{Revision: v.Revision, State: "processing", Note: "Investigating"}
	v, e = s.Update(ctx, "operator", id, "update-key", update)
	if e != nil {
		t.Fatal(e)
	}
	again, e := s.Update(ctx, "operator", id, "update-key", update)
	if e != nil || again.Revision != v.Revision {
		t.Fatal(again, e)
	}
	update.Note = "Different"
	if _, e = s.Update(ctx, "operator", id, "update-key", update); !errors.Is(e, f.ErrConflict) {
		t.Fatal(e)
	}
	if _, e = s.Update(ctx, "operator", id, "stale-key", update); !errors.Is(e, f.ErrConflict) {
		t.Fatal(e)
	}
	access.denied = true
	if _, e = s.List(ctx, "operator", f.Filter{}); !errors.Is(e, f.ErrDenied) {
		t.Fatal(e)
	}
	if e = s.Download(ctx, "operator", id, "one", io.Discard); !errors.Is(e, f.ErrDenied) {
		t.Fatal(e)
	}
	if e = migration.QueryRow(`SELECT count(*) FROM moderation.audit WHERE action='feedback.update'`).Scan(&count); e != nil || count != 1 {
		t.Fatal(count, e)
	}
	var sensitive int
	if e = migration.QueryRow(`SELECT count(*) FROM moderation.audit WHERE data::text LIKE '%Private message%' OR data::text LIKE '%sender@example.test%'`).Scan(&sensitive); e != nil || sensitive != 0 {
		t.Fatal(sensitive, e)
	}
}
func TestFeedbackReplyUnknownIsNeverResentAndRetentionDeletesMaterials(t *testing.T) {
	repo, migration := database(t)
	clock := time.Now().UTC().Truncate(time.Microsecond)
	blobs := &feedbackBlobs{values: map[string][]byte{}}
	sender := &feedbackSender{state: "unknown"}
	s := &f.Service{Repo: &pg.FeedbackRepository{DB: repo.DB}, Access: &feedbackAccess{}, Blobs: blobs, Sender: sender, Now: func() time.Time { return clock }}
	ctx := context.Background()
	v, e := s.Ingest(ctx, feedbackInput("reply"))
	if e != nil {
		t.Fatal(e)
	}
	reply, e := s.Reply(ctx, "operator", v.ID, "reply-key", "Response")
	if e != nil || reply.State != "unknown" {
		t.Fatal(reply, e)
	}
	same, e := s.Reply(ctx, "operator", v.ID, "reply-key", "Response")
	if e != nil || same.ID != reply.ID || same.State != "unknown" || sender.calls != 1 {
		t.Fatal(same, e, sender.calls)
	}
	if _, e = s.Reply(ctx, "operator", v.ID, "reply-key", "Changed"); !errors.Is(e, f.ErrConflict) {
		t.Fatal(e)
	}
	v, e = s.Get(ctx, "operator", v.ID)
	if e != nil {
		t.Fatal(e)
	}
	v, e = s.Update(ctx, "operator", v.ID, "close-key", f.Update{Revision: v.Revision, State: "resolved"})
	if e != nil {
		t.Fatal(e)
	}
	clock = clock.AddDate(1, 0, 0).Add(-time.Second)
	if e = s.Cleanup(ctx); e != nil || blobs.deleted != 0 {
		t.Fatal(e, blobs.deleted)
	}
	clock = clock.Add(time.Second)
	if _, e = s.Get(ctx, "operator", v.ID); !errors.Is(e, f.ErrNotFound) {
		t.Fatal(e)
	}
	if e = s.Cleanup(ctx); e != nil || blobs.deleted != 1 {
		t.Fatal(e, blobs.deleted)
	}
	if duplicate, err := s.Ingest(ctx, feedbackInput("reply")); err != nil || !duplicate.Ready {
		t.Fatal("deleted case resurrected", duplicate, err)
	}
	var receipts int
	if err := migration.QueryRow(`SELECT count(*) FROM moderation.feedback_receipts`).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("retained personal replay data", receipts, err)
	}
	var count int
	if e = migration.QueryRow(`SELECT count(*) FROM moderation.feedback`).Scan(&count); e != nil || count != 0 {
		t.Fatal(count, e)
	}
}
func TestFeedbackRateCapacityAndCursor(t *testing.T) {
	repo, migration := database(t)
	clock := time.Now().UTC()
	s := &f.Service{Repo: &pg.FeedbackRepository{DB: repo.DB}, Access: &feedbackAccess{}, Blobs: &feedbackBlobs{values: map[string][]byte{}}, Now: func() time.Time { return clock }}
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		v := feedbackInput(string(rune('a' + i)))
		if _, e := s.Ingest(ctx, v); e != nil {
			t.Fatal(e)
		}
	}
	if v, e := s.Ingest(ctx, feedbackInput("over-limit")); e != nil || v.State != "spam" || v.Body != "" || len(v.Attachments) != 0 {
		t.Fatal(v, e)
	}
	if _, e := s.Ingest(ctx, feedbackInput("a")); e != nil {
		t.Fatal("replay consumed rate", e)
	}
	if _, e := migration.Exec(`UPDATE moderation.feedback SET bytes=2147483648 WHERE id=(SELECT min(id) FROM moderation.feedback)`); e != nil {
		t.Fatal(e)
	}
	in := feedbackInput("capacity")
	in.Message.Sender = "other@example.test"
	if _, e := s.Ingest(ctx, in); !errors.Is(e, f.ErrLimit) {
		t.Fatal(e)
	}
	cursor := &pg.FeedbackRepository{DB: repo.DB}
	if e := cursor.Advance(ctx, "mailbox", 5, 99); e != nil {
		t.Fatal(e)
	}
	if e := cursor.Advance(ctx, "mailbox", 5, 10); e != nil {
		t.Fatal(e)
	}
	if uid, e := cursor.Cursor(ctx, "mailbox", 5); e != nil || uid != 99 {
		t.Fatal(uid, e)
	}
	if uid, e := cursor.Cursor(ctx, "mailbox", 6); e != nil || uid != 0 {
		t.Fatal(uid, e)
	}
}
