"""
Database-level enforcement that audit rows can never be changed (PostgreSQL only).

Even if application code or a compromised credential tries UPDATE / DELETE /
TRUNCATE on auditing_auditlog, the database refuses. In production also run the
app as a DB role that only has INSERT and SELECT on this table (see docs).
"""
from django.db import migrations

FORWARD = """
CREATE OR REPLACE FUNCTION auditing_auditlog_block_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'auditing_auditlog is append-only' USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER auditing_auditlog_no_update_delete
    BEFORE UPDATE OR DELETE ON auditing_auditlog
    FOR EACH ROW EXECUTE FUNCTION auditing_auditlog_block_mutation();

CREATE TRIGGER auditing_auditlog_no_truncate
    BEFORE TRUNCATE ON auditing_auditlog
    FOR EACH STATEMENT EXECUTE FUNCTION auditing_auditlog_block_mutation();
"""

REVERSE = """
DROP TRIGGER IF EXISTS auditing_auditlog_no_truncate ON auditing_auditlog;
DROP TRIGGER IF EXISTS auditing_auditlog_no_update_delete ON auditing_auditlog;
DROP FUNCTION IF EXISTS auditing_auditlog_block_mutation();
"""


def install(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(FORWARD, None)


def uninstall(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(REVERSE, None)


class Migration(migrations.Migration):
    dependencies = [("auditing", "0001_initial")]
    operations = [migrations.RunPython(install, uninstall)]
