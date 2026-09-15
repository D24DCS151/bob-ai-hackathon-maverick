"""
Database migration runner.

Applies versioned SQL migration files in order.
Uses a schema_migrations table to track applied migrations.

Usage:
    python -m threaticap.storage.migrations --dsn "postgresql://..."
    or via ThreatPipeline.from_config_file() with storage.backend=postgresql
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).parent.parent.parent / "scripts" / "db" / "migrations"


def run_migrations(dsn: str) -> int:
    """
    Apply all pending migrations.
    Returns number of migrations applied.
    """
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        raise RuntimeError("psycopg2 required for migrations")

    conn = psycopg2.connect(dsn, cursor_factory=psycopg2.extras.RealDictCursor)
    conn.autocommit = False

    try:
        with conn.cursor() as cur:
            # Ensure migration tracking table exists
            cur.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version     TEXT PRIMARY KEY,
                    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    checksum    TEXT
                )
            """)
            conn.commit()

            # Get applied migrations
            cur.execute("SELECT version FROM schema_migrations ORDER BY version")
            applied = {row["version"] for row in cur.fetchall()}

        # Find migration files
        if not MIGRATIONS_DIR.exists():
            logger.warning("Migrations directory not found: %s", MIGRATIONS_DIR)
            return 0

        migration_files = sorted(MIGRATIONS_DIR.glob("*.sql"))
        applied_count = 0

        for mf in migration_files:
            version = mf.stem  # e.g. "001_initial_schema"
            if version in applied:
                logger.debug("Migration already applied: %s", version)
                continue

            logger.info("Applying migration: %s", version)
            sql = mf.read_text(encoding="utf-8")

            import hashlib
            checksum = hashlib.sha256(sql.encode()).hexdigest()[:16]

            with conn.cursor() as cur:
                cur.execute(sql)
                cur.execute(
                    "INSERT INTO schema_migrations (version, checksum) VALUES (%s, %s)",
                    (version, checksum)
                )
            conn.commit()
            applied_count += 1
            logger.info("Migration applied: %s (checksum %s)", version, checksum)

        return applied_count

    except Exception as exc:
        conn.rollback()
        logger.error("Migration failed: %s", exc)
        raise
    finally:
        conn.close()


class MigrationRunner:
    """
    Class wrapper around run_migrations for dependency injection and testing.

    Usage:
        runner = MigrationRunner(dsn="postgresql://...")
        applied = runner.run()
    """

    def __init__(self, dsn: str, migrations_dir: Path | None = None) -> None:
        self._dsn = dsn
        self._migrations_dir = migrations_dir or MIGRATIONS_DIR

    def run(self) -> int:
        """Run all pending migrations. Returns count of migrations applied."""
        return run_migrations(self._dsn)

    def check(self) -> list[str]:
        """Return list of applied migration versions."""
        try:
            import psycopg2
            import psycopg2.extras
        except ImportError:
            return []
        try:
            conn = psycopg2.connect(self._dsn, cursor_factory=psycopg2.extras.RealDictCursor)
            with conn.cursor() as cur:
                cur.execute("SELECT version FROM schema_migrations ORDER BY version")
                return [row["version"] for row in cur.fetchall()]
        except Exception:
            return []
