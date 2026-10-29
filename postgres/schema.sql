CREATE SCHEMA IF NOT EXISTS moderation;
CREATE TABLE IF NOT EXISTS moderation.tasks (
 id text PRIMARY KEY, owner text NOT NULL, school_id text NOT NULL,
 object_id text NOT NULL, kind text NOT NULL, state text NOT NULL,
 next_attempt timestamptz NOT NULL, lease_until timestamptz NOT NULL, data jsonb NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS moderation_active_request ON moderation.tasks(owner,object_id,kind)
 WHERE state IN ('waiting','decided') AND kind IN ('report','edit_request','delete_request');
CREATE INDEX IF NOT EXISTS moderation_school_queue ON moderation.tasks(school_id,state,id);
CREATE INDEX IF NOT EXISTS moderation_owner_queue ON moderation.tasks(owner,id);
CREATE INDEX IF NOT EXISTS moderation_delivery ON moderation.tasks(next_attempt,lease_until) WHERE state='decided';
CREATE TABLE IF NOT EXISTS moderation.policies(school_id text NOT NULL,kind text NOT NULL,data jsonb NOT NULL,PRIMARY KEY(school_id,kind));
CREATE TABLE IF NOT EXISTS moderation.replays(key text PRIMARY KEY,data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS moderation.audit(id text PRIMARY KEY,data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS moderation.outbox(id text PRIMARY KEY,data jsonb NOT NULL,delivered boolean NOT NULL DEFAULT false);
REVOKE ALL ON SCHEMA moderation FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA moderation FROM PUBLIC;
