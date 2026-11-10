package postgres

import (
	"context"
	moderation "github.com/StuHelper/stuhelper-moderation"
)

// CheckRuntime rejects migration identities and privileges crossing module schemas.
func (r *Repository) CheckRuntime(ctx context.Context) error {
	var unsafe bool
	err := r.DB.QueryRowContext(ctx, `SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls
 OR has_schema_privilege(current_user,'moderation','CREATE')
 OR has_database_privilege(current_user,current_database(),'CREATE')
 OR pg_has_role(current_user,'pg_read_all_data','MEMBER')
 OR pg_has_role(current_user,'pg_write_all_data','MEMBER')
 OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspname NOT IN ('moderation','public','information_schema') AND nspname NOT LIKE 'pg_%' AND has_schema_privilege(current_user,oid,'USAGE'))
 FROM pg_roles WHERE rolname=current_user`).Scan(&unsafe)
	if err != nil || unsafe {
		return moderation.ErrUnavailable
	}
	return nil
}
