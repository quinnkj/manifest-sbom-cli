# sbom-cli

A small CLI for ingesting `CycloneDX` JSON SBOMs into a local SQLite database and querying them by
component or license.

## Install

Requires Python 3.14 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

## Usage

The CLI is invoked via `uv run sbom-cli`.
