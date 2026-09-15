"""
Structured logging configuration for THREATICAP.

Produces JSON-structured logs suitable for SIEM ingestion, Splunk, Elasticsearch,
or any log aggregation platform. Falls back to readable console format in
development mode.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Any

# Optional: structured logging with structlog
# If structlog is not available, use standard logging with JSON formatter
try:
    import structlog
    _HAS_STRUCTLOG = True
except ImportError:
    _HAS_STRUCTLOG = False


class JsonFormatter(logging.Formatter):
    """
    Minimal JSON log formatter — no external dependencies.
    Produces one JSON object per log line.
    """

    def format(self, record: logging.LogRecord) -> str:
        import json
        from datetime import datetime, timezone

        log_obj: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        if hasattr(record, "request_id"):
            log_obj["request_id"] = record.request_id

        for key in ("threat_id", "alert_id", "component"):
            if hasattr(record, key):
                log_obj[key] = getattr(record, key)

        return json.dumps(log_obj)


def configure_logging(
    level: str | None = None,
    json_logs: bool | None = None,
    log_file: str | None = None,
) -> None:
    """
    Configure application-wide logging.

    Args:
        level:     Log level (DEBUG/INFO/WARNING/ERROR). Defaults to env var LOG_LEVEL or INFO.
        json_logs: Use JSON formatter. Defaults to env var JSON_LOGS=true or False.
        log_file:  Optional log file path. Defaults to env var LOG_FILE.
    """
    effective_level = level or os.environ.get("LOG_LEVEL", "INFO")
    effective_json = json_logs if json_logs is not None else (
        os.environ.get("JSON_LOGS", "false").lower() == "true"
    )
    effective_file = log_file or os.environ.get("LOG_FILE")

    numeric_level = getattr(logging, effective_level.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)

    if effective_json:
        console_handler.setFormatter(JsonFormatter())
    else:
        console_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        ))

    root_logger.addHandler(console_handler)

    # File handler (optional)
    if effective_file:
        file_handler = logging.FileHandler(effective_file, encoding="utf-8")
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(JsonFormatter())
        root_logger.addHandler(file_handler)

    # Quieten noisy third-party loggers
    for noisy in ("urllib3", "httpx", "httpcore", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
