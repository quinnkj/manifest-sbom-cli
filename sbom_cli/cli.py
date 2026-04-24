"""Typer CLI for the `sbom-cli` console script.

Skeleton: defines the CLI surface (subcommands and options) so the entry
point is wired up and `sbom-cli --help` is meaningful. The command bodies
are stubs to be filled in by later commits.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

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
    typer.echo(f"`ingest`: not yet implemented (would read {sbom_file}, db={db_path})")


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
