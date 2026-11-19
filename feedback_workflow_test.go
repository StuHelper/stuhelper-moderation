package moderation_test

import (
	"bytes"
	"context"
	m "github.com/StuHelper/stuhelper-moderation"
	f "github.com/StuHelper/stuhelper-moderation/feedback"
	"github.com/StuHelper/stuhelper-moderation/httpapi"
	pg "github.com/StuHelper/stuhelper-moderation/postgres"
	"github.com/StuHelper/stuhelper-moderation/sdk"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type multiOperatorFeedbackAccess struct{}

func (multiOperatorFeedbackAccess) Check(_ context.Context, actor, action string) error {
	if actor == "alice" || actor == "bob" || actor == "operator" {
		return nil
	}
	return f.ErrDenied
}

func TestFeedbackHTTPHandlerAssignmentRelatedLinksAndSpamReplyGuard(t *testing.T) {
	repo, migration := database(t)
	clock := time.Date(2026, 11, 18, 4, 0, 0, 0, time.UTC)
	blobs := &feedbackBlobs{values: map[string][]byte{}}
	sender := &feedbackSender{state: "sent"}
	svc := &f.Service{
		Repo:   &pg.FeedbackRepository{DB: repo.DB},
		Access: multiOperatorFeedbackAccess{},
		Blobs:  blobs,
		Sender: sender,
		Now:    func() time.Time { return clock },
	}
	ctx := context.Background()

	// Ingest two messages: one suspicious HTML attachment mail, one clean mail.
	htmlPayload := []byte("<script>alert('xss')</script>")
	msgSuspicious, err := svc.Ingest(ctx, f.Input{
		Message: f.Message{
			Dedupe:                f.Digest("msg-suspicious"),
			Sender:                "spoof@example.test",
			Subject:               "Suspicious Copyright Notice",
			Body:                  "Claim body",
			AuthenticationResults: "example.test; spf=fail",
			Suspicious:            true,
			Bytes:                 int64(len(htmlPayload) + 10),
			Attachments: []f.Attachment{{
				ID:          "att-html",
				Name:        "proof.html",
				ContentType: "text/html",
				Size:        int64(len(htmlPayload)),
				Status:      "stored",
			}},
		},
		Parts: map[string][]byte{"att-html": htmlPayload},
	})
	if err != nil {
		t.Fatal(err)
	}
	msgNormal, err := svc.Ingest(ctx, f.Input{
		Message: f.Message{
			Dedupe:                f.Digest("msg-normal"),
			Sender:                "teacher@example.edu",
			Subject:               "Wrong course instructor attribution",
			Body:                  "Please check review-42",
			AuthenticationResults: "example.edu; spf=pass; dkim=pass",
			Suspicious:            false,
			Bytes:                 30,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(httpapi.FeedbackHandler{
		Service: svc,
		Authenticate: func(r *http.Request) (m.Principal, error) {
			return m.Principal{Subject: r.Header.Get("X-Test-Actor")}, nil
		},
	}.Routes())
	defer srv.Close()

	client, err := sdk.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	asActor := func(actor string) sdk.RequestEditorFn {
		return func(_ context.Context, r *http.Request) error {
			r.Header.Set("X-Test-Actor", actor)
			return nil
		}
	}

	// 1. Unauthorized school-only operator gets 403.
	deniedResp, err := client.ListFeedbackWithResponse(ctx, &sdk.ListFeedbackParams{}, asActor("school-mod"))
	if err != nil || deniedResp.StatusCode() != 403 {
		t.Fatalf("expected 403 for unauthorized operator, got %v %+v", err, deniedResp)
	}

	// 2. Filter unassigned (?assignee="") returns both new tickets; suspicious=true returns only msgSuspicious.
	empty := ""
	unassignedResp, err := client.ListFeedbackWithResponse(ctx, &sdk.ListFeedbackParams{Assignee: &empty}, asActor("alice"))
	if err != nil || unassignedResp.StatusCode() != 200 || unassignedResp.JSON200 == nil || len(unassignedResp.JSON200.Items) != 2 {
		t.Fatalf("unassigned filter failed: %v %+v", err, unassignedResp)
	}
	suspiciousTrue := true
	suspResp, err := client.ListFeedbackWithResponse(ctx, &sdk.ListFeedbackParams{Suspicious: &suspiciousTrue}, asActor("alice"))
	if err != nil || suspResp.StatusCode() != 200 || suspResp.JSON200 == nil || len(suspResp.JSON200.Items) != 1 || suspResp.JSON200.Items[0].Id != msgSuspicious.ID {
		t.Fatalf("suspicious filter failed: %v %+v", err, suspResp)
	}

	// 3. Alice claims msgNormal (omitting assignee auto-claims unassigned ticket), links related_task_id and related_object_id.
	relatedTask := "task-123"
	relatedObj := "review-42"
	claimedResp, err := client.UpdateFeedbackWithResponse(ctx, msgNormal.ID, &sdk.UpdateFeedbackParams{IdempotencyKey: "claim-0001"}, sdk.FeedbackUpdate{
		Revision:        1,
		State:           sdk.FeedbackUpdateState("processing"),
		Note:            "Verifying course instructor",
		RelatedTaskId:   &relatedTask,
		RelatedObjectId: &relatedObj,
	}, asActor("alice"))
	if err != nil || claimedResp.StatusCode() != 200 || claimedResp.JSON200 == nil {
		t.Fatalf("alice claim failed: %v %+v", err, claimedResp)
	}
	if claimedResp.JSON200.Assignee != "alice" ||
		claimedResp.JSON200.RelatedTaskId == nil || *claimedResp.JSON200.RelatedTaskId != relatedTask ||
		claimedResp.JSON200.RelatedObjectId == nil || *claimedResp.JSON200.RelatedObjectId != relatedObj {
		t.Fatalf("unexpected claimed state: %+v", claimedResp.JSON200)
	}

	// 4. Bob updates note without passing assignee -> retains Alice as assignee!
	noteResp, err := client.UpdateFeedbackWithResponse(ctx, msgNormal.ID, &sdk.UpdateFeedbackParams{IdempotencyKey: "note-0002"}, sdk.FeedbackUpdate{
		Revision: claimedResp.JSON200.Revision,
		State:    sdk.FeedbackUpdateState("processing"),
		Note:     "Confirmed enrollment record",
	}, asActor("bob"))
	if err != nil || noteResp.StatusCode() != 200 || noteResp.JSON200 == nil || noteResp.JSON200.Assignee != "alice" {
		t.Fatalf("updating note overwrote assignee: %v %+v", err, noteResp)
	}

	// 5. Alice explicitly transfers to Bob, then Bob unassigns (assignee="").
	bob := "bob"
	transferResp, err := client.UpdateFeedbackWithResponse(ctx, msgNormal.ID, &sdk.UpdateFeedbackParams{IdempotencyKey: "xfer-0003"}, sdk.FeedbackUpdate{
		Revision: noteResp.JSON200.Revision,
		State:    sdk.FeedbackUpdateState("processing"),
		Note:     "Handing off to Bob",
		Assignee: &bob,
	}, asActor("alice"))
	if err != nil || transferResp.StatusCode() != 200 || transferResp.JSON200 == nil || transferResp.JSON200.Assignee != "bob" {
		t.Fatalf("transfer to bob failed: %v %+v", err, transferResp)
	}
	bobList, err := client.ListFeedbackWithResponse(ctx, &sdk.ListFeedbackParams{Assignee: &bob}, asActor("bob"))
	if err != nil || bobList.StatusCode() != 200 || len(bobList.JSON200.Items) != 1 || bobList.JSON200.Items[0].Id != msgNormal.ID {
		t.Fatalf("assignee=bob filter failed: %v %+v", err, bobList)
	}

	unassignResp, err := client.UpdateFeedbackWithResponse(ctx, msgNormal.ID, &sdk.UpdateFeedbackParams{IdempotencyKey: "unassign-0004"}, sdk.FeedbackUpdate{
		Revision: transferResp.JSON200.Revision,
		State:    sdk.FeedbackUpdateState("new"),
		Note:     "Back to queue",
		Assignee: &empty,
	}, asActor("bob"))
	if err != nil || unassignResp.StatusCode() != 200 || unassignResp.JSON200 == nil || unassignResp.JSON200.Assignee != "" {
		t.Fatalf("unassign failed: %v %+v", err, unassignResp)
	}

	// 6. Spam reply protection: mark msgSuspicious as spam -> Reply is blocked (409) without calling SMTP Sender!
	spamUpdate, err := client.UpdateFeedbackWithResponse(ctx, msgSuspicious.ID, &sdk.UpdateFeedbackParams{IdempotencyKey: "mark-spam-1"}, sdk.FeedbackUpdate{
		Revision: 1,
		State:    sdk.FeedbackUpdateState("spam"),
		Note:     "SPF failed, suspicious sender",
	}, asActor("alice"))
	if err != nil || spamUpdate.StatusCode() != 200 {
		t.Fatalf("mark spam failed: %v %+v", err, spamUpdate)
	}
	blockedReply, err := client.ReplyFeedbackWithResponse(ctx, msgSuspicious.ID, &sdk.ReplyFeedbackParams{IdempotencyKey: "spam-reply-1"}, sdk.FeedbackReplyInput{
		Body: "Accidental reply to spam",
	}, asActor("alice"))
	if err != nil || blockedReply.StatusCode() != 409 || sender.calls != 0 {
		t.Fatalf("expected 409 blocking reply to spam without SMTP call, got status=%d calls=%d err=%v", blockedReply.StatusCode(), sender.calls, err)
	}

	// Moving out of spam to processing allows explicit reply.
	reopenResp, err := client.UpdateFeedbackWithResponse(ctx, msgSuspicious.ID, &sdk.UpdateFeedbackParams{IdempotencyKey: "reopen-spam-1"}, sdk.FeedbackUpdate{
		Revision: spamUpdate.JSON200.Revision,
		State:    sdk.FeedbackUpdateState("processing"),
		Note:     "Manually verified legitimate sender",
	}, asActor("alice"))
	if err != nil || reopenResp.StatusCode() != 200 {
		t.Fatalf("reopen failed: %v %+v", err, reopenResp)
	}
	okReply, err := client.ReplyFeedbackWithResponse(ctx, msgSuspicious.ID, &sdk.ReplyFeedbackParams{IdempotencyKey: "valid-reply-1"}, sdk.FeedbackReplyInput{
		Body: "Official response",
	}, asActor("alice"))
	if err != nil || okReply.StatusCode() != 200 || okReply.JSON200 == nil || okReply.JSON200.State != sdk.FeedbackReplyState("sent") || sender.calls != 1 {
		t.Fatalf("reply after moving to processing failed: %v %+v", err, okReply)
	}

	// 7. Attachment download enforces security headers against HTML/SVG sniffing and logs feedback.download only for existing attachments.
	missingAtt, err := client.DownloadFeedbackAttachmentWithResponse(ctx, msgSuspicious.ID, "missing-part", asActor("alice"))
	if err != nil || missingAtt.StatusCode() != 404 {
		t.Fatalf("expected 404 on missing attachment, got %v %+v", err, missingAtt)
	}
	dlResp, err := client.DownloadFeedbackAttachmentWithResponse(ctx, msgSuspicious.ID, "att-html", asActor("alice"))
	if err != nil || dlResp.StatusCode() != 200 || !bytes.Equal(dlResp.Body, htmlPayload) {
		t.Fatalf("attachment download failed: %v %+v", err, dlResp)
	}
	hdr := dlResp.HTTPResponse.Header
	if hdr.Get("Content-Type") != "application/octet-stream" ||
		hdr.Get("X-Content-Type-Options") != "nosniff" ||
		hdr.Get("Content-Security-Policy") != "sandbox" ||
		hdr.Get("Content-Disposition") != `attachment; filename="feedback-attachment"` {
		t.Fatalf("missing mandatory attachment security headers: %+v", hdr)
	}

	var downloadAudits int
	if err = migration.QueryRow(`SELECT count(*) FROM moderation.audit WHERE action='feedback.download'`).Scan(&downloadAudits); err != nil || downloadAudits != 1 {
		t.Fatalf("expected 1 feedback.download audit record, got %d (%v)", downloadAudits, err)
	}
	// A storage error after a partial write must be visible to a real HTTP client.
	svc.Blobs = interruptedAttachment{blobs}
	if partial, err := client.DownloadFeedbackAttachmentWithResponse(ctx, msgSuspicious.ID, "att-html", asActor("alice")); err == nil {
		t.Fatalf("client accepted truncated download: %v", partial.StatusCode())
	}
}

type interruptedAttachment struct{ *feedbackBlobs }

func (interruptedAttachment) Download(_ context.Context, _ string, w io.Writer) error {
	if _, err := w.Write([]byte("part")); err != nil {
		return err
	}
	return io.ErrUnexpectedEOF
}
