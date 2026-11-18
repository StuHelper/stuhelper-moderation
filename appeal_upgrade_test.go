package moderation_test

import (
	"errors"
	"github.com/StuHelper/stuhelper-moderation/postgres"
	"github.com/jackc/pgx/v5/pgconn"
	"testing"
)

func TestAppealMigrationPreservesHistoricalDuplicates(t *testing.T) {
	_, db := database(t)
	if _, err := db.Exec("DROP INDEX moderation.moderation_appeal_previous"); err != nil {
		t.Fatal(err)
	}
	const insert = `INSERT INTO moderation.tasks(id,owner,school_id,object_id,kind,state,next_attempt,lease_until,data)
		VALUES($1,'author','school','object','appeal','applied',now(),now(),jsonb_build_object('submission',jsonb_build_object('previous_task_id','previous'),'history',$1::text))`
	for _, id := range []string{"appeal-a", "appeal-b"} {
		if _, err := db.Exec(insert, id); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := db.Exec(postgres.Schema); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM moderation.tasks WHERE state='applied' AND data->'submission'->>'previous_task_id'='previous' AND data->>'history'=id").Scan(&count); err != nil || count != 2 {
		t.Fatal("historical appeals", count, err)
	}
	_, err := db.Exec(insert, "appeal-c")
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatal("new duplicate", err)
	}
}
