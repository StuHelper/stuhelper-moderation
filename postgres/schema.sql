CREATE SCHEMA IF NOT EXISTS moderation;
CREATE TABLE IF NOT EXISTS moderation.tasks (
 id text PRIMARY KEY, owner text NOT NULL, content_owner text NOT NULL DEFAULT '',
 content_kind text NOT NULL DEFAULT '', school_id text NOT NULL,
 object_id text NOT NULL, kind text NOT NULL, state text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 next_attempt timestamptz NOT NULL, lease_until timestamptz NOT NULL, data jsonb NOT NULL
);
ALTER TABLE moderation.tasks ADD COLUMN IF NOT EXISTS content_owner text NOT NULL DEFAULT '';
ALTER TABLE moderation.tasks ADD COLUMN IF NOT EXISTS content_kind text NOT NULL DEFAULT '';
ALTER TABLE moderation.tasks ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
UPDATE moderation.tasks
 SET content_owner=COALESCE(data->>'content_owner',''),
     content_kind=COALESCE(data->>'content_kind',''),
     created_at=COALESCE((data->>'created_at')::timestamptz,now())
 WHERE content_owner='' AND (data ? 'content_owner');
CREATE UNIQUE INDEX IF NOT EXISTS moderation_active_request ON moderation.tasks(owner,object_id,kind)
 WHERE state IN ('waiting','decided') AND kind IN ('report','edit_request','delete_request');
CREATE INDEX IF NOT EXISTS moderation_school_queue ON moderation.tasks(school_id,state,id);
CREATE INDEX IF NOT EXISTS moderation_owner_queue ON moderation.tasks(owner,id);
CREATE INDEX IF NOT EXISTS moderation_owner_created ON moderation.tasks(owner,created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS moderation_content_owner_created ON moderation.tasks(content_owner,created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS moderation_school_state_created ON moderation.tasks(school_id,state,created_at ASC,id ASC);
CREATE INDEX IF NOT EXISTS moderation_school_created ON moderation.tasks(school_id,created_at ASC,id ASC);
CREATE INDEX IF NOT EXISTS moderation_school_object_created ON moderation.tasks(school_id,object_id,created_at ASC,id ASC);
CREATE INDEX IF NOT EXISTS moderation_delivery ON moderation.tasks(next_attempt,lease_until) WHERE state='decided';
CREATE TABLE IF NOT EXISTS moderation.policies(school_id text NOT NULL,kind text NOT NULL,data jsonb NOT NULL,PRIMARY KEY(school_id,kind));
CREATE TABLE IF NOT EXISTS moderation.replays(key text PRIMARY KEY,data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS moderation.audit (
 id text PRIMARY KEY, time timestamptz NOT NULL, data jsonb NOT NULL,
 actor text NOT NULL, target text NOT NULL, action text NOT NULL,
 school text NOT NULL, group_id text NOT NULL DEFAULT '*', module text NOT NULL DEFAULT 'moderation' CHECK(module='moderation'),
 reason text NOT NULL DEFAULT '' CHECK(octet_length(reason)<=512),
 result text NOT NULL DEFAULT 'unknown' CHECK(result IN ('success','denied','failed','unknown')),
 recorded_xid xid8 NOT NULL DEFAULT pg_current_xact_id()
);
CREATE INDEX IF NOT EXISTS moderation_audit_order ON moderation.audit(time DESC,id COLLATE "C" DESC);
CREATE INDEX IF NOT EXISTS moderation_audit_scope ON moderation.audit(school,group_id,module,time DESC);
CREATE TABLE IF NOT EXISTS moderation.audit_retention(singleton boolean PRIMARY KEY CHECK(singleton),revision bigint NOT NULL);
INSERT INTO moderation.audit_retention VALUES(true,1) ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION moderation.invalidate_audit_snapshot() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN UPDATE moderation.audit_retention SET revision=revision+1 WHERE singleton; RETURN NULL; END $$;
CREATE OR REPLACE TRIGGER audit_changed AFTER UPDATE OR DELETE OR TRUNCATE ON moderation.audit
 FOR EACH STATEMENT EXECUTE FUNCTION moderation.invalidate_audit_snapshot();
CREATE TABLE IF NOT EXISTS moderation.outbox(id text PRIMARY KEY,data jsonb NOT NULL,delivered boolean NOT NULL DEFAULT false);
REVOKE ALL ON SCHEMA moderation FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA moderation FROM PUBLIC;

CREATE TABLE IF NOT EXISTS moderation.submission_limits(owner_key text PRIMARY KEY, started_at timestamptz NOT NULL, used integer NOT NULL CHECK(used>0));

ALTER TABLE moderation.outbox ADD COLUMN IF NOT EXISTS sent_at timestamptz;
UPDATE moderation.outbox SET sent_at=now() WHERE delivered AND sent_at IS NULL;
CREATE INDEX IF NOT EXISTS moderation_outbox_pending ON moderation.outbox ((data->>'subject'), ((data->'data'->>'revision')::bigint), id) WHERE sent_at IS NULL;

-- Feedback is global operator correspondence; school-scoped grants do not
-- expose a sender's identity or complaint materials.
CREATE TABLE IF NOT EXISTS moderation.feedback (
 id text PRIMARY KEY, dedupe text NOT NULL UNIQUE, sender text NOT NULL,
 state text NOT NULL CHECK(state IN ('new','processing','resolved','spam')),
 ready boolean NOT NULL, received_at timestamptz NOT NULL, closed_at timestamptz,
 bytes bigint NOT NULL CHECK(bytes>=0), data jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS feedback_sender_rate ON moderation.feedback(sender,received_at);
CREATE INDEX IF NOT EXISTS feedback_expiry ON moderation.feedback(closed_at,id) WHERE closed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS feedback_ready_order ON moderation.feedback(received_at DESC,id DESC) WHERE ready;
CREATE INDEX IF NOT EXISTS feedback_ready_state_order ON moderation.feedback(state,received_at DESC,id DESC) WHERE ready;
CREATE TABLE IF NOT EXISTS moderation.feedback_receipts (
 key text PRIMARY KEY, hash text NOT NULL, target text NOT NULL REFERENCES moderation.feedback(id) ON DELETE CASCADE, data jsonb NOT NULL, created_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS feedback_receipt_expiry ON moderation.feedback_receipts(created_at);
CREATE TABLE IF NOT EXISTS moderation.feedback_cursors (
 mailbox text PRIMARY KEY, validity bigint NOT NULL, uid bigint NOT NULL
);
REVOKE ALL ON moderation.feedback, moderation.feedback_receipts, moderation.feedback_cursors FROM PUBLIC;

CREATE TABLE IF NOT EXISTS moderation.feedback_tombstones(id text PRIMARY KEY, dedupe text NOT NULL UNIQUE);
REVOKE ALL ON moderation.feedback_tombstones FROM PUBLIC;

CREATE TABLE IF NOT EXISTS moderation.feedback_stats (
 singleton boolean PRIMARY KEY CHECK(singleton),
 active_count bigint NOT NULL DEFAULT 0,
 active_bytes bigint NOT NULL DEFAULT 0,
 tombstone_count bigint NOT NULL DEFAULT 0
);
INSERT INTO moderation.feedback_stats(singleton,active_count,active_bytes,tombstone_count)
 SELECT true,
        (SELECT count(*) FROM moderation.feedback),
        (SELECT coalesce(sum(bytes),0)::bigint FROM moderation.feedback),
        (SELECT count(*) FROM moderation.feedback_tombstones)
 ON CONFLICT (singleton) DO NOTHING;
REVOKE ALL ON moderation.feedback_stats FROM PUBLIC;

CREATE OR REPLACE FUNCTION moderation.sync_feedback_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE moderation.feedback_stats
  SET active_count = active_count + s.c, active_bytes = active_bytes + s.b
  FROM (SELECT count(*) AS c, coalesce(sum(bytes),0)::bigint AS b FROM new_rows) s
  WHERE singleton AND s.c > 0;
 RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION moderation.sync_feedback_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS (SELECT 1 FROM new_rows) THEN
  UPDATE moderation.feedback_stats
   SET active_bytes = active_bytes + (SELECT coalesce(sum(bytes),0)::bigint FROM new_rows) - (SELECT coalesce(sum(bytes),0)::bigint FROM old_rows)
   WHERE singleton;
 END IF;
 RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION moderation.sync_feedback_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE moderation.feedback_stats
  SET active_count = active_count - s.c, active_bytes = active_bytes - s.b
  FROM (SELECT count(*) AS c, coalesce(sum(bytes),0)::bigint AS b FROM old_rows) s
  WHERE singleton AND s.c > 0;
 RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION moderation.sync_feedback_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE moderation.feedback_stats SET active_count = 0, active_bytes = 0 WHERE singleton;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS feedback_stats_insert ON moderation.feedback;
DROP TRIGGER IF EXISTS feedback_stats_update ON moderation.feedback;
DROP TRIGGER IF EXISTS feedback_stats_delete ON moderation.feedback;
DROP TRIGGER IF EXISTS feedback_stats_truncate ON moderation.feedback;
CREATE TRIGGER feedback_stats_insert AFTER INSERT ON moderation.feedback
 REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION moderation.sync_feedback_insert();
CREATE TRIGGER feedback_stats_update AFTER UPDATE ON moderation.feedback
 REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION moderation.sync_feedback_update();
CREATE TRIGGER feedback_stats_delete AFTER DELETE ON moderation.feedback
 REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION moderation.sync_feedback_delete();
CREATE TRIGGER feedback_stats_truncate AFTER TRUNCATE ON moderation.feedback
 FOR EACH STATEMENT EXECUTE FUNCTION moderation.sync_feedback_truncate();

CREATE OR REPLACE FUNCTION moderation.sync_tombstone_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE moderation.feedback_stats
  SET tombstone_count = tombstone_count + s.c
  FROM (SELECT count(*) AS c FROM new_rows) s
  WHERE singleton AND s.c > 0;
 RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION moderation.sync_tombstone_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE moderation.feedback_stats
  SET tombstone_count = tombstone_count - s.c
  FROM (SELECT count(*) AS c FROM old_rows) s
  WHERE singleton AND s.c > 0;
 RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION moderation.sync_tombstone_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE moderation.feedback_stats SET tombstone_count = 0 WHERE singleton;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS tombstone_stats_insert ON moderation.feedback_tombstones;
DROP TRIGGER IF EXISTS tombstone_stats_delete ON moderation.feedback_tombstones;
DROP TRIGGER IF EXISTS tombstone_stats_truncate ON moderation.feedback_tombstones;
CREATE TRIGGER tombstone_stats_insert AFTER INSERT ON moderation.feedback_tombstones
 REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION moderation.sync_tombstone_insert();
CREATE TRIGGER tombstone_stats_delete AFTER DELETE ON moderation.feedback_tombstones
 REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION moderation.sync_tombstone_delete();
CREATE TRIGGER tombstone_stats_truncate AFTER TRUNCATE ON moderation.feedback_tombstones
 FOR EACH STATEMENT EXECUTE FUNCTION moderation.sync_tombstone_truncate();

-- Only this bounded retention operation can delete feedback audit rows. The
-- application role retains no general UPDATE/DELETE permission on audit.
CREATE OR REPLACE FUNCTION moderation.cleanup_feedback_audit() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE removed integer;
BEGIN
 DELETE FROM moderation.audit WHERE id IN (
  SELECT id FROM moderation.audit WHERE action LIKE 'feedback.%'
   AND time < current_timestamp - interval '12 months' ORDER BY time,id LIMIT 100
 );
 GET DIAGNOSTICS removed = ROW_COUNT;
 RETURN removed;
END $$;
REVOKE ALL ON FUNCTION moderation.cleanup_feedback_audit() FROM PUBLIC;
