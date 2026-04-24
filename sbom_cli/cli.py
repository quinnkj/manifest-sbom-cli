"""Typer CLI for the `sbom-cli` console script.

Defines two subcommands — `ingest` and `query` — that wrap the parser and persistence layers.

The Typer `app` object is the entry point referenced by `[project.scripts]` in `pyproject.toml`.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Annotated, Any

import typer

# noinspection PyPackageRequirements
from sqlalchemy import Engine
from sqlmodel import Session

from sbom_cli import db, parsers
from sbom_cli.db import Component, Document
from sbom_cli.parsers import ParsedDocument

app: typer.Typer = typer.Typer(
    help="Ingest CycloneDX SBOMs and query them.",
    no_args_is_help=True,
)

_TABLE_HEADERS: list[str] = ["document", "source_path", "component", "version", "licenses"]


def _results_to_rows(
    results: Iterable[tuple[Document, Component, list[str]]],
) -> list[dict[str, Any]]:
    """Flatten query result tuples into JSON-ready dictionaries.

    Args:
        results: The `(document, component, licenses)` tuples returned by
            the `db.query_by_*` helpers.

    Returns:
        One dict per input tuple, with keys suitable for table rendering.
        `licenses` is preserved as a list so JSON consumers see structured data.
    """
    return [
        {
            "document": doc.name,
            "source_path": doc.source_path,
            "format": doc.format,
            "component": comp.name,
            "version": comp.version,
            "purl": comp.purl,
            "licenses": licenses,
        }
        for doc, comp, licenses in results
    ]


def _render_table(rows: list[dict[str, Any]]) -> str:
    """Render rows as a left-aligned fixed-width text table.

    Only the columns listed in `_TABLE_HEADERS` are shown; `purl` and
    `format` are omitted to keep the table narrow. The `licenses` list is
    joined with `", "`.

    Args:
        rows: The dicts produced by `_results_to_rows`.

    Returns:
        A multi-line string ready for `typer.echo`. Returns `"(no matches)"`
        when `rows` is empty.
    """
    if not rows:
        return "(no matches)"

    widths: dict[str, int] = {h: len(h) for h in _TABLE_HEADERS}
    display: list[dict[str, str]] = []
    for r in rows:
        cells: dict[str, str] = {
            "document": r["document"] or "",
            "source_path": r["source_path"],
            "component": r["component"],
            "version": r["version"] or "",
            "licenses": ", ".join(r["licenses"]) or "",
        }
        for h in _TABLE_HEADERS:
            widths[h] = max(widths[h], len(cells[h]))
        display.append(cells)

    lines: list[str] = [
        "  ".join(h.ljust(widths[h]) for h in _TABLE_HEADERS),
        "  ".join("-" * widths[h] for h in _TABLE_HEADERS),
    ]
    lines.extend("  ".join(d[h].ljust(widths[h]) for h in _TABLE_HEADERS) for d in display)
    return "\n".join(lines)


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
    """Query stored SBOMs by component (optionally version) or by license.

    Exactly one of `--component` or `--license` must be supplied; `--version`
    is only valid alongside `--component`. Results are rendered as a
    fixed-width text table.

    Args:
        component: Component name to look up. Mutually exclusive with `license`.
        version: Optional exact version to narrow a component query.
        license: License string to look up. Mutually exclusive with `component`.
        db_path: Override the default SQLite path. Falls back to
            `db.default_db_path()` when omitted.

    Raises:
        typer.BadParameter: If neither or both of `component`/`license` are
            given, or if `version` is supplied without `component`.
    """

    if (component is None) == (license is None):
        raise typer.BadParameter("Provide exactly one of --component or --license.")

    if version is not None and component is None:
        raise typer.BadParameter("--version requires --component.")

    engine: Engine = db.make_engine(db_path)

    with Session(engine) as session:
        if component is not None:
            results = db.query_by_component(session, component, version)
        else:
            assert license is not None
            results = db.query_by_license(session, license)

        rows: list[dict[str, Any]] = _results_to_rows(results)

    typer.echo(_render_table(rows))


if __name__ == "__main__":
    # Enables `python -m sbom_cli.cli ...` and PyCharm's "Module name" run/debug
    # configuration (which sets breakpoints in this file's code path). The
    # installed `sbom-cli` console script defined in pyproject.toml uses the
    # `app` object directly and does not go through this branch.
    app()
