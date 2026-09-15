"""
Test suite for THREATICAP.

Tests are organised by component:
- test_models.py       — Pydantic model validation
- test_ingestion.py    — Connector normalisation and deduplication
- test_correlation.py  — Correlation engine and individual correlators
- test_scoring.py      — Priority scoring
- test_bluf.py         — BLUF generation
- test_pipeline.py     — End-to-end pipeline integration
- test_api.py          — FastAPI endpoint tests
"""
