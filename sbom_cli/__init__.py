"""sbom-cli: ingest CycloneDX 1.6/SPDX 3.0 SBOMs into SQLite and query them.

Public submodules:
    cli:     The Typer application exposed as the `sbom-cli` console script.
    db:      SQLModel schema and persistence helpers.
    parsers: Format detection and conversion of raw SBOM JSON into the internal
             `ParsedDocument` shape consumed by `db`.
"""

__version__: str = "0.1.0"
