package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Exercise the exact production query with normal planner settings and a
// representative mix of retained confirmations and pending subjects.
func TestPendingOutboxPlanUsesPartialIndex(t *testing.T) {
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
	name := "outbox_plan_" + hex.EncodeToString(random)
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
	if _, err := db.Exec(`INSERT INTO moderation.outbox(id,data,sent_at)
 SELECT 'sent-'||i,jsonb_build_object('subject','history','data',jsonb_build_object('revision',i),'payload',repeat('x',128)),now()
 FROM generate_series(1,20000) i;
 INSERT INTO moderation.outbox(id,data)
 SELECT 'pending-'||i,jsonb_build_object('subject','subject-'||lpad(i::text,4,'0'),'data',jsonb_build_object('revision',1))
 FROM generate_series(0,1199) i;
 ANALYZE moderation.outbox`); err != nil {
		t.Fatal(err)
	}
	excluded := make([]string, 1000)
	for i := range excluded {
		excluded[i] = fmt.Sprintf("subject-%04d", i)
	}
	for _, subjects := range [][]string{{}, {"subject-0000"}, excluded} {
		var raw []byte
		if err := db.QueryRow(`EXPLAIN (ANALYZE, FORMAT JSON) `+pendingOutboxQuery, 100, subjects).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		type planNode struct {
			NodeType  string `json:"Node Type"`
			IndexName string `json:"Index Name"`
			Plans     []planNode
		}
		var plans []struct{ Plan planNode }
		if err := json.Unmarshal(raw, &plans); err != nil {
			t.Fatal(err)
		}
		found := false
		var visit func(planNode)
		visit = func(plan planNode) {
			if plan.NodeType == "Seq Scan" {
				t.Errorf("full scan: %s", raw)
			}
			if plan.IndexName == "moderation_outbox_pending" {
				found = true
			}
			for _, child := range plan.Plans {
				visit(child)
			}
		}
		visit(plans[0].Plan)
		if !found {
			t.Fatalf("pending partial index missing: %s", raw)
		}
	}
}
