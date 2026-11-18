package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	m "github.com/StuHelper/stuhelper-moderation"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"os"
)

func assertNoSeqScan(t *testing.T, label string, raw []byte) {
	t.Helper()
	type planNode struct {
		NodeType     string     `json:"Node Type"`
		RelationName string     `json:"Relation Name"`
		Plans        []planNode `json:"Plans"`
	}
	var plans []struct {
		Plan planNode `json:"Plan"`
	}
	if err := json.Unmarshal(raw, &plans); err != nil {
		t.Fatal(label, err)
	}
	var visit func(planNode)
	visit = func(node planNode) {
		if node.NodeType == "Seq Scan" && node.RelationName != "feedback_stats" {
			t.Fatalf("%s triggered Seq Scan on %s: %s", label, node.RelationName, raw)
		}
		for _, child := range node.Plans {
			visit(child)
		}
	}
	visit(plans[0].Plan)
}

func TestTasksAndFeedbackQueriesAvoidSeqScanOnPopulatedTables(t *testing.T) {
	dsn := os.Getenv("STUHELPER_MODERATION_TEST_DSN")
	if dsn == "" {
		t.Fatal("isolated PostgreSQL DSN required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test DSN")
	}
	admin := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { admin.Close() })
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	name := "query_plan_" + hex.EncodeToString(random)
	if _, err := admin.ExecContext(context.Background(), `CREATE DATABASE `+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP DATABASE ` + name + ` WITH (FORCE)`); err != nil {
			t.Error(err)
		}
	})
	local := cfg.Copy()
	local.Database = name
	db := stdlib.OpenDB(*local)
	defer db.Close()
	if _, err := db.Exec(Schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		INSERT INTO moderation.tasks(id,owner,content_owner,content_kind,school_id,object_id,kind,state,created_at,next_attempt,lease_until,data)
		SELECT 'task-'||lpad(i::text,6,'0'),
		       'user-'||(i%5000),
		       'author-'||(i%5000),
		       CASE WHEN i%2=0 THEN 'course' ELSE 'resource' END,
		       'school-'||(i%20),
		       'obj-'||(i%2003),
		       'report',
		       CASE WHEN i%10=0 THEN 'waiting' ELSE 'applied' END,
		       now() - (i * interval '1 second'),
		       now(),
		       now(),
		       '{}'::jsonb
		FROM generate_series(1,15000) i;

		INSERT INTO moderation.feedback(id,dedupe,sender,state,ready,received_at,closed_at,bytes,data)
		SELECT 'fb-'||lpad(i::text,6,'0'),
		       'dedupe-'||lpad(i::text,6,'0'),
		       'sender-'||(i%3000)||'@example.test',
		       CASE WHEN i%20=0 THEN 'new' ELSE 'resolved' END,
		       true,
		       now() - (i * interval '1 second'),
		       CASE WHEN i%20=0 THEN NULL ELSE now() - interval '1 day' END,
		       512,
		       '{}'::jsonb
		FROM generate_series(1,15000) i;

		INSERT INTO moderation.feedback_tombstones(id,dedupe)
		SELECT 'tomb-'||i, 'tomb-dedupe-'||i FROM generate_series(1,20000) i;

		ANALYZE moderation.tasks;
		ANALYZE moderation.feedback;
		ANALYZE moderation.feedback_tombstones;
		ANALYZE moderation.feedback_stats;
	`); err != nil {
		t.Fatal(err)
	}

	studentSQL, studentArgs := buildTaskQuery(m.TaskFilter{Owner: "rare-student", Limit: 20}, false, time.Time{})
	adminQueueSQL, adminQueueArgs := buildTaskQuery(m.TaskFilter{School: "school-1", State: "waiting", Limit: 20, Admin: true}, false, time.Time{})
	objectHistSQL, objectHistArgs := buildTaskQuery(m.TaskFilter{School: "school-1", ObjectID: "obj-42", Limit: 100, Admin: true}, false, time.Time{})
	fbAllSQL, fbAllArgs := buildFeedbackListQuery("", false, time.Time{}, "", 26, time.Now().UTC())
	fbStateSQL, fbStateArgs := buildFeedbackListQuery("new", false, time.Time{}, "", 26, time.Now().UTC())

	for _, tc := range []struct {
		name string
		q    string
		args []any
	}{
		{"student_list", studentSQL, studentArgs},
		{"admin_waiting_queue", adminQueueSQL, adminQueueArgs},
		{"admin_object_history", objectHistSQL, objectHistArgs},
		{"feedback_list_all", fbAllSQL, fbAllArgs},
		{"feedback_list_new", fbStateSQL, fbStateArgs},
		{"feedback_sender_rate", `SELECT count(*) FROM moderation.feedback WHERE sender=$1 AND received_at>=$2`, []any{"sender-1@example.test", time.Now().UTC().Add(-time.Hour)}},
	} {
		var raw []byte
		if err := db.QueryRow(`EXPLAIN (ANALYZE, FORMAT JSON) `+tc.q, tc.args...).Scan(&raw); err != nil {
			t.Fatalf("%s explain failed: %v", tc.name, err)
		}
		assertNoSeqScan(t, tc.name, raw)
	}
}
