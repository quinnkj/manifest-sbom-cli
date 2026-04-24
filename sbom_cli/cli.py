"""Typer CLI for the `sbom-cli` console script.

Skeleton: defines the CLI surface (subcommands and options) so the entry
point is wired up and `sbom-cli --help` is meaningful. The command bodies
are stubs to be filled in by later commits.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer

# noinspection PyPackageRequirements
from sqlalchemy import Engine
from sqlmodel import Session

from sbom_cli import db, parsers
from sbom_cli.db import Document
from sbom_cli.parsers import ParsedDocument

app: typer.Typer = typer.Typer(
    help="Ingest CycloneDX/SPDX SBOMs and query them.",
    no_args_is_help=True,
)


@app.command()
def ingest(
    sbom_file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    db_path: Annotated[
        Path | None, typer.Option("--db", help="SQLite path (default: ./sbom.db or $SBOM_DB).")
    ] = None,
) -> None:
    """Parse an SBOM file and store its components."""

    payload: dict[str, Any] = json.loads(sbom_file.read_text())
    parsed: ParsedDocument = parsers.parse(sbom_file, payload)
    engine: Engine = db.make_engine(db_path)

    with Session(engine) as session:
        doc: Document = db.insert_parsed(session, parsed)

    typer.echo(
        f"Ingested {len(parsed.components)} components "
        f"from {sbom_file} (format={parsed.format}, document_id={doc.id})"
    )


@app.command()
def query(
    component: Annotated[
        str | None,
        typer.Option("--component", help="Component name."),
    ] = None,
    version: Annotated[
        str | None,
        typer.Option("--version", help="Filter component by version."),
    ] = None,
    license: Annotated[
        str | None,
        typer.Option("--license", help="License id or name."),
    ] = None,
    db_path: Annotated[
        Path | None,
        typer.Option("--db", help="SQLite path (default: ./sbom.db or $SBOM_DB)."),
    ] = None,
) -> None:
    """Query stored SBOMs by component (optionally version) or by license."""
    typer.echo(
        "`query`: not yet implemented "
        f"(component={component}, version={version}, license={license}, "
        f"db={db_path})"
    )


if __name__ == "__main__":
    # Enables `python -m sbom_cli.cli ...` and PyCharm's "Module name" run/debug
    # configuration (which sets breakpoints in this file's code path). The
    # installed `sbom-cli` console script defined in pyproject.toml uses the
    # `app` object directly and does not go through this branch.
    app()
