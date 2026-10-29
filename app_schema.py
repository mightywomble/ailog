"""Idempotent additive schema changes.

ailog has no migration tool. New *tables* appear automatically through
``db.create_all()``; new *columns* on tables that already exist do not, so they
have to be added explicitly. That logic used to be copy-pasted per feature
(``_ensure_suricata_endpoint_columns``, ``_ensure_sshkey_encryption_columns``);
this module is the single implementation.

Rules for adding a column here:

* only ever **add** - never rename or drop, because an older image may still be
  running against the same database during a rollout
* always give a default or allow NULL
* keep the DDL dialect-neutral-ish (SQLite and Postgres both accept it)
"""

from __future__ import annotations

import logging

from sqlalchemy import inspect, text

log = logging.getLogger(__name__)

# table -> [(column, DDL), ...]
COLUMNS = {
    # v2.11 - suricata endpoint statistics
    'suricata_fast_alert_buckets': [
        ('src_ip', 'TEXT'), ('dst_ip', 'TEXT'),
        ('src_port', 'INTEGER'), ('dst_port', 'INTEGER'),
    ],
    'suricata_alert_buckets': [
        ('src_ip', 'TEXT'), ('dst_ip', 'TEXT'),
        ('src_port', 'INTEGER'), ('dst_port', 'INTEGER'),
        ('proto', 'TEXT'), ('app_proto', 'TEXT'),
    ],
    # v2.10 - encrypted SSH keys at rest
    'ssh_keys': [
        ('is_encrypted', 'BOOLEAN DEFAULT 0'),
        ('enc_version', 'TEXT'),
    ],
    # v2.13.1 - report diffing
    'log_reports': [
        ('clusters_json', 'TEXT'),
    ],
    # v2.13.1 - scheduled reports
    'schedules': [
        ('kind', "VARCHAR(16) DEFAULT 'log'"),
        ('report_window_minutes', 'INTEGER'),
        ('report_depth', 'INTEGER'),
        ('report_model', 'VARCHAR(128)'),
        ('report_scope_json', 'TEXT'),
        ('last_run_at', 'DATETIME'),
        ('last_status', 'TEXT'),
    ],
}


def add_missing_columns(db, specs=None, verbose=False):
    """Add any missing columns. Returns ``[(table, column), ...]`` added.

    Never raises: a failed ALTER is logged and skipped, because a broken
    migration must not stop the app from booting on a database it can still
    mostly use.
    """
    specs = COLUMNS if specs is None else specs
    added = []
    try:
        inspector = inspect(db.engine)
    except Exception as exc:
        log.warning('[schema] cannot inspect database: %s', exc)
        return added

    for table, columns in specs.items():
        try:
            if not inspector.has_table(table):
                continue
            existing = {col['name'] for col in inspector.get_columns(table)}
        except Exception as exc:
            log.debug('[schema] cannot read %s: %s', table, exc)
            continue
        for name, ddl in columns:
            if name in existing:
                continue
            try:
                with db.engine.begin() as conn:
                    conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {name} {ddl}'))
                added.append((table, name))
                if verbose:
                    log.info('[schema] added %s.%s', table, name)
            except Exception as exc:
                log.warning('[schema] could not add %s.%s: %s', table, name, exc)
    return added
