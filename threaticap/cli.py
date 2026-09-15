"""
THREATICAP CLI — command-line interface for offline / air-gapped operation.

Commands:
    threaticap run         — Run full pipeline from sample data or file
    threaticap ingest      — Ingest from a specific connector / file
    threaticap report      — Display BLUF reports
    threaticap serve       — Start the FastAPI server
    threaticap version     — Show version info
    threaticap demo        — Run a full demonstration with sample data

Usage:
    python -m threaticap.cli run --config config/config.yaml --data data/sample/
    python -m threaticap.cli report --threat-id <id> --format text
    python -m threaticap.cli serve --host 0.0.0.0 --port 8080
    python -m threaticap.cli demo
"""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import click
import yaml

from threaticap import __version__
from threaticap.logging_config import configure_logging

logger = logging.getLogger(__name__)


@click.group()
@click.option("--config", "-c", default="config/config.yaml",
              help="Path to configuration file", envvar="THREATICAP_CONFIG")
@click.option("--log-level", default="INFO",
              type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
              envvar="LOG_LEVEL")
@click.option("--json-logs", is_flag=True, default=False, envvar="JSON_LOGS")
@click.pass_context
def cli(ctx: click.Context, config: str, log_level: str, json_logs: bool) -> None:
    """THREATICAP — Threat Intelligence Correlation & Alert Prioritisation System"""
    configure_logging(level=log_level, json_logs=json_logs)
    ctx.ensure_object(dict)
    ctx.obj["config"] = config


@cli.command()
def version() -> None:
    """Show version and build information."""
    click.echo(f"THREATICAP v{__version__}")
    click.echo(f"Python {sys.version}")


@cli.command()
@click.option("--data-dir", "-d", default="data/sample",
              help="Directory containing sample data files")
@click.option("--output", "-o", default=None,
              help="Output directory for BLUF reports (JSON)")
@click.option("--format", "-f", type=click.Choice(["text", "json"]), default="text")
@click.pass_context
def demo(ctx: click.Context, data_dir: str, output: str | None, format: str) -> None:
    """
    Run a full demonstration using sample data.

    Loads all sample alert files, runs the complete pipeline, and displays
    prioritised threats with BLUF reports.
    """
    from threaticap.pipeline import ThreatPipeline
    from threaticap.ingestion.pipeline import IngestionPipeline, IngestionConfig
    from threaticap.ingestion.base_connector import ConnectorConfig
    from threaticap.ingestion.connectors.siem_connector import SiemConnector
    from threaticap.ingestion.connectors.edr_connector import EdrConnector
    from threaticap.ingestion.connectors.intel_report_connector import IntelReportConnector
    from threaticap.ingestion.connectors.stix_connector import StixConnector

    config_path = ctx.obj["config"]
    click.echo(click.style(f"\n{'='*60}", fg="cyan"))
    click.echo(click.style("  THREATICAP DEMONSTRATION", fg="cyan", bold=True))
    click.echo(click.style(f"  v{__version__}", fg="cyan"))
    click.echo(click.style(f"{'='*60}\n", fg="cyan"))

    data_path = Path(data_dir)
    if not data_path.exists():
        click.echo(click.style(f"Data directory not found: {data_dir}", fg="red"))
        raise SystemExit(1)

    # Build ingestion pipeline
    ingest_cfg = IngestionConfig()
    ingest = IngestionPipeline(config=ingest_cfg)

    # Register connectors for each sample file found
    sample_files: dict[str, list[Path]] = {
        "siem": sorted(data_path.glob("siem_*.json")),
        "edr":  sorted(data_path.glob("edr_*.json")),
        "intel": sorted(data_path.glob("intel_*.json")),
        "stix": sorted(data_path.glob("stix_*.json")),
    }

    total_files = sum(len(v) for v in sample_files.values())
    if total_files == 0:
        click.echo(click.style("No sample data files found", fg="yellow"))
        click.echo(f"Place JSON files in: {data_path.absolute()}")
        raise SystemExit(1)

    for siem_file in sample_files["siem"]:
        conn = SiemConnector(ConnectorConfig(
            connector_id=f"siem-{siem_file.stem}",
            source_type="SIEM",
            source_reliability=0.85,
            extra={"mode": "file", "file_path": str(siem_file)},
        ))
        ingest.register_connector(conn)

    for edr_file in sample_files["edr"]:
        conn = EdrConnector(ConnectorConfig(
            connector_id=f"edr-{edr_file.stem}",
            source_type="EDR",
            source_reliability=0.9,
            extra={"mode": "file", "file_path": str(edr_file)},
        ))
        ingest.register_connector(conn)

    for intel_file in sample_files["intel"]:
        conn = IntelReportConnector(ConnectorConfig(
            connector_id=f"intel-{intel_file.stem}",
            source_type="HUMINT",
            source_reliability=0.75,
            extra={"mode": "file", "file_path": str(intel_file), "source_subtype": "humint"},
        ))
        ingest.register_connector(conn)

    for stix_file in sample_files["stix"]:
        conn = StixConnector(ConnectorConfig(
            connector_id=f"stix-{stix_file.stem}",
            source_type="STIX_TAXII",
            source_reliability=0.8,
            extra={"mode": "file", "file_path": str(stix_file)},
        ))
        ingest.register_connector(conn)

    click.echo(f"Ingesting from {total_files} data file(s)...")
    alerts = ingest.run_batch()
    click.echo(click.style(f"[OK] Ingested {len(alerts)} alert(s)\n", fg="green"))

    if not alerts:
        click.echo(click.style("No alerts ingested. Check data files.", fg="yellow"))
        raise SystemExit(1)

    # Run pipeline
    pipeline = ThreatPipeline.from_config_file(config_path)
    click.echo("Running correlation and prioritisation pipeline...")
    result = pipeline.run(alerts)

    click.echo(click.style(
        f"[OK] Pipeline complete: {result.threats_created} threat(s) identified\n", fg="green"
    ))

    # Display results
    _print_summary(result)

    # Display BLUF reports
    for bluf in result.reports:
        if format == "text":
            click.echo(bluf.to_text())
        else:
            click.echo(json.dumps(bluf.model_dump(mode="json"), indent=2))

    # Save reports if output dir specified
    if output:
        out_path = Path(output)
        out_path.mkdir(parents=True, exist_ok=True)
        for bluf in result.reports:
            fname = out_path / f"bluf_{bluf.report_id[:8]}_{bluf.priority_tier}.json"
            with open(fname, "w", encoding="utf-8") as fh:
                json.dump(bluf.model_dump(mode="json"), fh, indent=2, default=str)
        click.echo(click.style(f"\n[OK] Saved {len(result.reports)} report(s) to {out_path}", fg="green"))


@cli.command()
@click.option("--threat-id", "-t", required=True, help="Threat ID")
@click.option("--format", "-f", type=click.Choice(["text", "json"]), default="text")
@click.pass_context
def report(ctx: click.Context, threat_id: str, format: str) -> None:
    """Display a BLUF report for a specific threat."""
    click.echo("Note: 'report' command requires a running service or persisted state.")
    click.echo("Use 'demo' to run the full pipeline and view reports.")


@cli.command()
@click.option("--host", default="0.0.0.0", envvar="HOST")
@click.option("--port", default=8080, type=int, envvar="PORT")
@click.option("--workers", default=1, type=int)
@click.option("--reload", is_flag=True, default=False)
@click.pass_context
def serve(ctx: click.Context, host: str, port: int, workers: int, reload: bool) -> None:
    """Start the THREATICAP FastAPI server."""
    import uvicorn
    os.environ["THREATICAP_CONFIG"] = ctx.obj["config"]
    click.echo(f"Starting THREATICAP API on {host}:{port}")
    uvicorn.run(
        "threaticap.api.app:app",
        host=host,
        port=port,
        workers=workers,
        reload=reload,
        log_level="info",
    )


def _print_summary(result: Any) -> None:
    """Print a formatted pipeline summary."""
    click.echo(click.style("THREAT SUMMARY", bold=True))
    click.echo(f"  Alerts Processed : {result.alerts_ingested}")
    click.echo(f"  Threats Created  : {result.threats_created}")

    if result.threats_critical:
        click.echo(click.style(f"  [!] CRITICAL     : {result.threats_critical}", fg="red", bold=True))
    if result.threats_high:
        click.echo(click.style(f"  [!] HIGH         : {result.threats_high}", fg="yellow", bold=True))
    if result.threats_medium:
        click.echo(click.style(f"  [-] MEDIUM       : {result.threats_medium}", fg="blue"))
    if result.threats_low:
        click.echo(click.style(f"  [.] LOW          : {result.threats_low}", fg="white"))
    click.echo(f"  Reports Generated: {result.reports_generated}")
    click.echo()


if __name__ == "__main__":
    cli()
