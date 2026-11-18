package moderation_test

import (
	"context"
	"errors"
	m "github.com/StuHelper/stuhelper-moderation"
	"github.com/StuHelper/stuhelper-moderation/httpapi"
	"github.com/StuHelper/stuhelper-moderation/sdk"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

type recusalAccess struct{}

func (recusalAccess) Authorize(ctx context.Context, p m.Principal, action, school string) error {
	if p.Subject == "super-admin" {
		return nil
	}
	// author is a school-scoped student moderator (has manage on "school", NOT global self_approve on "*").
	if p.Subject == "author" && action == "manage" && school == "school" {
		return nil
	}
	return (access{}).Authorize(ctx, p, action, school)
}

func TestModeratorConflictOfInterestRecusalAndSuperAdminExemption(t *testing.T) {
	s, _, _ := fixture(t)
	s.Access = recusalAccess{}
	ctx := context.Background()
	authorMod := m.Principal{Subject: "author"}
	otherMod := m.Principal{Subject: "admin"}
	superAdmin := m.Principal{Subject: "super-admin"}

	// 1. Report by another student against authorMod's content: authorMod cannot dismiss, publish, restore, or feature.
	report, err := s.Submit(ctx, m.Principal{Subject: "student-reporter"}, "rep-self", m.Submission{
		ObjectID: "review",
		Kind:     "report",
		Reason:   "Alleged spam",
		Evidence: []string{"Screenshot"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"dismiss", "publish", "restore", "feature"} {
		if _, err = s.Decide(ctx, authorMod, report.ID, "self-"+action, m.Decide{
			Revision: report.Revision,
			Decision: m.Decision{ObjectID: "review", Revision: 1, Action: action, Reason: "Self approval"},
		}); !errors.Is(err, m.ErrForbidden) {
			t.Fatalf("student moderator self-decided %s on own content: %v", action, err)
		}
	}

	// PreviewBatch also marks self-favorable action as rejected (forbidden).
	preview, err := s.PreviewBatch(ctx, authorMod, m.BatchRequest{
		Items: []m.BatchItem{{
			ID:       report.ID,
			Revision: report.Revision,
			Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "dismiss", Reason: "Self batch dismiss"},
		}},
	})
	if err != nil || len(preview.Items) != 1 || preview.Items[0].State != "rejected" || preview.Items[0].Code != "forbidden" {
		t.Fatalf("expected PreviewBatch to reject self-approval: %+v %v", preview, err)
	}

	// Another independent school moderator can dismiss the report.
	if _, err = s.Decide(ctx, otherMod, report.ID, "peer-dismiss", m.Decide{
		Revision: report.Revision,
		Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "dismiss", Reason: "Verified valid review"},
	}); err != nil {
		t.Fatalf("independent school moderator blocked: %v", err)
	}

	// 2. Pending upload owned by authorMod: authorMod is blocked from self-publish, while super-admin is exempted.
	pendingUpload, err := s.Track(ctx, "self-upload", m.Object{
		ID:       "review",
		Kind:     "course",
		SchoolID: "school",
		Owner:    "author",
		Revision: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Decide(ctx, authorMod, pendingUpload.ID, "self-pub", m.Decide{
		Revision: pendingUpload.Revision,
		Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "publish", Reason: "Approve own upload"},
	}); !errors.Is(err, m.ErrForbidden) {
		t.Fatalf("author moderator self-published pending upload: %v", err)
	}
	if _, err = s.Decide(ctx, superAdmin, pendingUpload.ID, "super-pub", m.Decide{
		Revision: pendingUpload.Revision,
		Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "publish", Reason: "Platform super-admin exemption"},
	}); err != nil {
		t.Fatalf("super-admin exemption failed: %v", err)
	}
}

func TestBlockedTermsNormalizationAndPolicyDryRunPreview(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	admin := m.Principal{Subject: "admin"}

	// SetPolicy trims whitespace, lowercases, and deduplicates blocked_terms.
	if err := s.SetPolicy(ctx, admin, "norm-policy", m.Policy{
		SchoolID:     "school",
		Kind:         "course",
		Mode:         "published",
		BlockedTerms: []string{"  代考  ", "代考", " BuyEssay ", "buyessay"},
		Revision:     0,
	}); err != nil {
		t.Fatal(err)
	}
	policyView, err := s.GetPolicy(ctx, admin, "school", "course")
	if err != nil || !reflect.DeepEqual(policyView.Effective.BlockedTerms, []string{"代考", "buyessay"}) {
		t.Fatalf("unexpected normalized blocked_terms: %+v %v", policyView, err)
	}
	mode, err := s.Check(ctx, "school", "course", "课程评价", "这里没有代考广告")
	if err != nil || mode != "blocked" {
		t.Fatalf("trimmed term did not match: mode=%s err=%v", mode, err)
	}

	srv := httptest.NewServer(httpapi.Handler{
		Service: s,
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

	// Unauthorized user cannot preview policies or probe blocked terms.
	unauthResp, err := client.PreviewPolicyWithResponse(ctx, sdk.PolicyPreviewInput{
		SchoolId: "school",
		Kind:     sdk.PolicyPreviewInputKind("course"),
		Body:     "代考",
	}, asActor("author"))
	if err != nil || unauthResp.StatusCode() != 403 {
		t.Fatalf("unauthorized preview allowed: %v %+v", err, unauthResp)
	}

	// Dry-run candidate terms catches overbroad substring "ad" hitting "Advanced".
	title := "Advanced Programming"
	candTerms := []string{" ad ", "代写", "AD"}
	candMode := sdk.PolicyPreviewInputMode("review")
	candResp, err := client.PreviewPolicyWithResponse(ctx, sdk.PolicyPreviewInput{
		SchoolId:     "school",
		Kind:         sdk.PolicyPreviewInputKind("course"),
		Title:        &title,
		Body:         "Normal course review with 代写 test",
		Mode:         &candMode,
		BlockedTerms: &candTerms,
	}, asActor("admin"))
	if err != nil || candResp.StatusCode() != 200 || candResp.JSON200 == nil {
		t.Fatalf("candidate preview failed: %v %+v", err, candResp)
	}
	if candResp.JSON200.Result != sdk.PolicyPreviewResult("blocked") ||
		candResp.JSON200.Source != sdk.PolicyPreviewSource("candidate") ||
		!reflect.DeepEqual(candResp.JSON200.MatchedTerms, []string{"ad", "代写"}) {
		t.Fatalf("unexpected candidate preview output: %+v", candResp.JSON200)
	}

	// Preview against persisted school policy without candidate overrides.
	savedResp, err := client.PreviewPolicyWithResponse(ctx, sdk.PolicyPreviewInput{
		SchoolId: "school",
		Kind:     sdk.PolicyPreviewInputKind("course"),
		Body:     "Clean course feedback",
	}, asActor("admin"))
	if err != nil || savedResp.StatusCode() != 200 || savedResp.JSON200 == nil {
		t.Fatalf("saved policy preview failed: %v %+v", err, savedResp)
	}
	if savedResp.JSON200.Result != sdk.PolicyPreviewResult("published") ||
		savedResp.JSON200.Source != sdk.PolicyPreviewSource("school") ||
		len(savedResp.JSON200.MatchedTerms) != 0 {
		t.Fatalf("unexpected saved policy preview: %+v", savedResp.JSON200)
	}
}
