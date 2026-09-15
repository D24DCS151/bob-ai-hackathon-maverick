"""
Storage layer — abstract repository interfaces plus in-memory and PostgreSQL
implementations.

Architecture:
    BaseAlertRepository         — abstract interface
    ├── InMemoryAlertRepository — for testing / demo / dev mode
    └── PostgresAlertRepository — production, full-featured (Phase 2)

    BaseThreatRepository        — abstract interface
    ├── InMemoryThreatRepository
    └── PostgresThreatRepository

    BaseAuditRepository         — abstract interface
    ├── InMemoryAuditRepository
    └── PostgresAuditRepository

    BaseReportRepository        — abstract interface
    ├── InMemoryReportRepository
    └── PostgresReportRepository

    BaseFeedbackRepository      — abstract interface (Phase 2)
    └── InMemoryFeedbackRepository

All FastAPI and pipeline code depends only on the abstract base interfaces.
Swapping storage backends requires no changes to business logic.

PostgreSQL backend is activated via:
    storage.backend = "postgresql" in config.yaml
    and POSTGRES_DSN environment variable set.
"""
from .repositories import (
    BaseAlertRepository,
    BaseThreatRepository,
    BaseAuditRepository,
    BaseReportRepository,
    InMemoryAlertRepository,
    InMemoryThreatRepository,
    InMemoryAuditRepository,
    InMemoryReportRepository,
)
from .feedback_repository import (
    BaseFeedbackRepository,
    InMemoryFeedbackRepository,
)

# PostgreSQL implementations — only imported when psycopg2 is available
try:
    from .postgres_repositories import (
        PostgresAlertRepository,
        PostgresThreatRepository,
        PostgresAuditRepository,
        PostgresReportRepository,
        PostgresConnectionPool,
        create_postgres_repositories,
    )
    _HAS_POSTGRES = True
except ImportError:
    _HAS_POSTGRES = False

from .migrations import MigrationRunner

__all__ = [
    # Abstract bases
    "BaseAlertRepository",
    "BaseThreatRepository",
    "BaseAuditRepository",
    "BaseReportRepository",
    "BaseFeedbackRepository",
    # In-memory implementations
    "InMemoryAlertRepository",
    "InMemoryThreatRepository",
    "InMemoryAuditRepository",
    "InMemoryReportRepository",
    "InMemoryFeedbackRepository",
    # Migrations
    "MigrationRunner",
    # PostgreSQL (available when psycopg2 installed)
    "_HAS_POSTGRES",
]

if _HAS_POSTGRES:
    __all__ += [
        "PostgresAlertRepository",
        "PostgresThreatRepository",
        "PostgresAuditRepository",
        "PostgresReportRepository",
        "PostgresConnectionPool",
        "create_postgres_repositories",
    ]
