package moderation_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	m "github.com/StuHelper/stuhelper-moderation"
	"github.com/StuHelper/stuhelper-moderation/httpapi"
)

type teacherComplaintContent struct {
	id        string
	revision  int64
	visible   bool
	inspect   error
	delivered []m.Decision
}

func (c *teacherComplaintContent) InspectTeacherHomepage(_ context.Context, _ m.Principal, id string) (m.Object, error) {
	if c.inspect != nil {
		return m.Object{}, c.inspect
	}
	if id != c.id {
		return m.Object{}, m.ErrNotFound
	}
	return m.Object{ID: id, Kind: m.TeacherHomepageContentKind, SchoolID: "school", Revision: c.revision, Visible: c.visible}, nil
}

func (c *teacherComplaintContent) ApplyTeacherHomepageDecision(_ context.Context, p m.Principal, d m.Decision) error {
	if p.Subject != "admin" {
		return m.ErrForbidden
	}
	if d.Revision != c.revision || d.ObjectID != c.id || d.Action != "hide" {
		return m.ErrConflict
	}
	c.delivered = append(c.delivered, d)
	c.visible = false
	c.revision++
	return nil
}

type teacherComplaintAccess struct{}

func (teacherComplaintAccess) Authorize(_ context.Context, p m.Principal, action, school string) error {
	if action == "manage" && school == "school" && p.Subject == "admin" {
		return nil
	}
	return m.ErrForbidden
}

func TestTeacherHomepageComplaintQueueAndScope(t *testing.T) {
	ctx := context.Background()
	repo, _ := database(t)
	teacher := &teacherComplaintContent{id: strings.Repeat("t", 128), revision: 500, visible: true}
	s := &m.Service{Repo: repo, Access: teacherComplaintAccess{}, TeacherHomepageContent: teacher}
	h := httpapi.Handler{Service: s, Authenticate: func(req *http.Request) (m.Principal, error) {
		return m.Principal{Subject: req.Header.Get("Test-Principal")}, nil
	}}.Routes()
	root := "/api/v1/moderation/teacher-homepage-complaints/"
	reportPath := root + teacher.id
	body := `{"category":"defamation_rumor","reason":"Synthetic complaint reason","evidence":["Synthetic evidence"]}`

	request := func(method, path, subject, key, body string, want int) []byte {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Test-Principal", subject)
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: got %d, want %d: %s", method, path, w.Code, want, w.Body.String())
		}
		return w.Body.Bytes()
	}
	request(http.MethodPost, reportPath, "", "report", body, http.StatusUnauthorized)
	request(http.MethodPost, root+"outside-school", "reporter", "report", body, http.StatusNotFound)
	request(http.MethodPost, reportPath, "reporter", "report", `{"reason":"detail","evidence":[]}`, http.StatusBadRequest)
	request(http.MethodPost, reportPath, "reporter", "report", `{"category":"other","reason":"detail"}`, http.StatusBadRequest)
	request(http.MethodPost, reportPath, "reporter", "report", `{"category":"other","reason":"detail","evidence":[],"school_id":"other"}`, http.StatusBadRequest)

	var task m.TaskView
	if err := json.Unmarshal(request(http.MethodPost, reportPath, "reporter", "report", body, http.StatusOK), &task); err != nil {
		t.Fatal(err)
	}
	if task.ContentKind != m.TeacherHomepageContentKind || task.State != "waiting" || task.ObjectRevision != 500 ||
		task.Submission.Category != "defamation_rumor" || task.Submission.ObjectID != "teacher-homepage:"+teacher.id {
		t.Fatalf("incorrect report receipt: %+v", task)
	}

	teacher.inspect = m.ErrUnavailable
	var replay m.TaskView
	if err := json.Unmarshal(request(http.MethodPost, reportPath, "reporter", "report", body, http.StatusOK), &replay); err != nil || replay.ID != task.ID {
		t.Fatal("replay needed new content authorization", replay, err)
	}
	request(http.MethodPost, reportPath, "reporter", "report", strings.Replace(body, "Synthetic evidence", "Different evidence", 1), http.StatusConflict)
	teacher.inspect = nil
	request(http.MethodGet, reportPath+"/target", "reporter", "", "", http.StatusForbidden)
	var target m.TeacherHomepageComplaintTarget
	if err := json.Unmarshal(request(http.MethodGet, reportPath+"/target", "admin", "", "", http.StatusOK), &target); err != nil ||
		target.ObjectID != task.Submission.ObjectID || !target.Visible || target.Revision != 500 {
		t.Fatal("moderator reference", target, err)
	}
	request(http.MethodGet, "/api/v1/moderation/tasks/"+task.ID, "other", "", "", http.StatusNotFound)
	if response := request(http.MethodGet, "/api/v1/moderation/tasks/page?admin=true&school_id=school", "admin", "", "", http.StatusOK); strings.Contains(string(response), task.ID) {
		t.Fatalf("default queue included teacher complaints: %s", response)
	}
	if response := request(http.MethodGet, "/api/v1/moderation/tasks/page?admin=true&school_id=school&content_kind=teacher_homepage", "admin", "", "", http.StatusOK); !strings.Contains(string(response), task.ID) {
		t.Fatalf("teacher complaint not present: %s", response)
	}
	request(http.MethodGet, "/api/v1/moderation/tasks/page?admin=true&school_id=elsewhere&content_kind=teacher_homepage", "admin", "", "", http.StatusForbidden)
	var counts m.QueueSummary
	if err := json.Unmarshal(request(http.MethodGet, "/api/v1/moderation/tasks/summary?school_id=school&include_teacher_homepage=true",
		"admin", "", "", http.StatusOK), &counts); err != nil || counts.ByContentKind.TeacherHomepage != 1 || counts.ByCategory["defamation_rumor"] != 1 {
		t.Fatal("teacher complaint summary", counts, err)
	}
	if _, err := s.Submit(ctx, m.Principal{Subject: "other"}, "generic", m.Submission{
		ObjectID: "teacher-homepage:short", Kind: "report", Category: "other", Reason: "Test", Evidence: []string{},
	}); !errors.Is(err, m.ErrInput) {
		t.Fatalf("generic report reached reserved target: %v", err)
	}

	// The version is an opaque equality token. Changing from 500 to 1200 must
	// not let a current decision resolve unrelated reports filed at version 500.
	teacher.revision = 1200
	second, err := s.SubmitTeacherHomepageComplaint(ctx, m.Principal{Subject: "reporter-two"}, "ready", teacher.id,
		m.TeacherHomepageComplaint{Category: "privacy_leak", Reason: "Another private submission", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	admin := m.Principal{Subject: "admin"}
	decision := m.Decide{Revision: second.Revision, Decision: m.Decision{ObjectID: second.Submission.ObjectID, Revision: 500, Action: "hide", Reason: "Confirmed"}}
	if _, err := s.Decide(ctx, admin, second.ID, "stale", decision); !errors.Is(err, m.ErrConflict) {
		t.Fatal("stale profile revision", err)
	}
	decision.Decision.Revision = 1200
	decision.Decision.Action = "delete"
	if _, err := s.Decide(ctx, admin, second.ID, "invalid", decision); !errors.Is(err, m.ErrInput) {
		t.Fatal("unsupported directory mutation", err)
	}
	decision.Decision.Action = "hide"
	if _, err := s.Decide(ctx, m.Principal{Subject: "reporter-two"}, second.ID, "deny", decision); !errors.Is(err, m.ErrForbidden) {
		t.Fatal("reporter decided own report", err)
	}
	if _, err := s.Decide(ctx, admin, second.ID, "decision", decision); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Work(ctx, 1); n != 1 || err != nil || teacher.visible || len(teacher.delivered) != 1 {
		t.Fatalf("worker failed to apply teacher hide: %d %v", n, err)
	}
	if got, err := s.Get(ctx, m.Principal{Subject: "reporter"}, task.ID); err != nil || got.State != "waiting" {
		t.Fatal("an unrelated revision was linked to the decision", got, err)
	}
	if got, err := s.Get(ctx, m.Principal{Subject: "reporter-two"}, second.ID); err != nil || got.State != "applied" {
		t.Fatal("report receipt missed outcome", got, err)
	}
	events, err := repo.PendingOutbox(ctx, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := false
	for _, event := range events {
		if event.Type == "moderation.result.v1" && event.Data.TaskID == second.ID {
			result = true
			if event.Data.Owner != "reporter-two" || event.Data.ContentOwner != "" || event.Data.Action != "hide" {
				t.Fatal("unexpected result notification audience", event.Data)
			}
			raw, err := json.Marshal(event.Data)
			if err != nil || strings.Contains(string(raw), "Another private submission") {
				t.Fatal("private complaint material entered the outbox", err)
			}
		}
	}
	if !result {
		t.Fatal("missing report result event")
	}

	// An authorized moderator can close an old complaint after a directory
	// merge without applying the old target to the replacement teacher.
	teacher.inspect = m.ErrNotFound
	decision = m.Decide{Revision: task.Revision, Decision: m.Decision{
		ObjectID: task.Submission.ObjectID, Revision: task.ObjectRevision, Action: "dismiss", Reason: "Directory target removed",
	}}
	if got, err := s.Decide(ctx, admin, task.ID, "dismiss-removed", decision); err != nil || got.State != "applied" {
		t.Fatal("removed target complaint not dismissed", got, err)
	}
}

func TestTeacherHomepageComplaintRetention(t *testing.T) {
	ctx := context.Background()
	repo, migration := database(t)
	now := time.Now().UTC().Truncate(time.Second)
	old := now.AddDate(-1, 0, -10)
	s := &m.Service{Repo: repo, Clock: func() time.Time { return now }}
	if err := repo.Transaction(ctx, func(tx m.Transaction) error {
		for _, task := range []m.Task{
			{ID: "expired", State: "applied", ContentKind: m.TeacherHomepageContentKind, UpdatedAt: old},
			{ID: "held", State: "applied", ContentKind: m.TeacherHomepageContentKind, UpdatedAt: old},
			{ID: "waiting", State: "waiting", ContentKind: m.TeacherHomepageContentKind, UpdatedAt: old},
			{ID: "recent", State: "applied", ContentKind: m.TeacherHomepageContentKind, UpdatedAt: now},
			{ID: "review-complaint", State: "applied", ContentKind: "course", UpdatedAt: old},
		} {
			task.CreatedAt = old
			task.Revision = 1
			task.ObjectRevision = 1
			task.Owner = "caller-" + task.ID
			task.SchoolID = "school"
			task.Submission = m.Submission{Kind: "report", ObjectID: "target", Category: "other", Reason: "Synthetic material", Evidence: []string{"Private evidence"}}
			if err := tx.SaveTask(task); err != nil {
				return err
			}
			if err := tx.SaveReplay("replay-"+task.ID, m.Replay{TaskID: task.ID, Digest: "d", Until: now.Add(time.Hour)}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := migration.Exec(`INSERT INTO moderation.teacher_homepage_complaint_holds(task_id,basis,purpose,end_condition,review_at,ends_at)
 VALUES ('held','Dispute','Review','Resolved',$1,$2)`, now.Add(24*time.Hour), now.Add(72*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DB.Exec(`DELETE FROM moderation.tasks WHERE id='held'`); err == nil {
		t.Fatal("runtime can directly remove complaint evidence")
	}
	if _, err := repo.DB.Exec(`UPDATE moderation.teacher_homepage_complaint_holds SET ends_at=clock_timestamp()`); err == nil {
		t.Fatal("runtime can change a hold")
	}
	if err := repo.DB.QueryRow(`SELECT moderation.cleanup_teacher_homepage_complaints($1,$2)`, now, 500).Scan(new(int)); err == nil {
		t.Fatal("future cutoff bypasses calendar retention")
	}
	if number, err := s.CleanupRetention(ctx, 1); err != nil || number.TeacherHomepageComplaintsDeleted != 1 {
		t.Fatal("unexpected bounded cleanup", number, err)
	}
	if err := repo.Transaction(ctx, func(tx m.Transaction) error {
		if _, err := tx.Task("expired"); !errors.Is(err, m.ErrNotFound) {
			t.Errorf("expired material exists: %v", err)
		}
		if _, err := tx.Replay("replay-expired"); !errors.Is(err, m.ErrNotFound) {
			t.Errorf("expired private replay exists: %v", err)
		}
		for _, id := range []string{"held", "waiting", "recent", "review-complaint"} {
			if _, err := tx.Task(id); err != nil {
				t.Errorf("task %s pruned unexpectedly: %v", id, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := migration.Exec(`UPDATE moderation.teacher_homepage_complaint_holds SET released_at=clock_timestamp() WHERE task_id='held'`); err != nil {
		t.Fatal(err)
	}
	if number, err := s.CleanupRetention(ctx, 1); err != nil || number.TeacherHomepageComplaintsDeleted != 1 {
		t.Fatal("released hold was not eligible for expiry", number, err)
	}
}
