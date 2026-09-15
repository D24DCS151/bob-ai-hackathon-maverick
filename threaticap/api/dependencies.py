"""
FastAPI dependency injection — provides pipeline instances to route handlers.
"""
from __future__ import annotations

from fastapi import Request

from threaticap.ingestion.pipeline import IngestionPipeline
from threaticap.pipeline import ThreatPipeline
from threaticap.storage.feedback_repository import InMemoryFeedbackRepository


def get_pipeline(request: Request) -> ThreatPipeline:
    """Dependency: returns the application-scoped ThreatPipeline."""
    return request.app.state.pipeline


def get_ingestion_pipeline(request: Request) -> IngestionPipeline:
    """Dependency: returns the application-scoped IngestionPipeline."""
    return request.app.state.ingest_pipeline


def get_feedback_repo(request: Request) -> InMemoryFeedbackRepository:
    """Dependency: returns the application-scoped feedback repository."""
    return request.app.state.feedback_repo
