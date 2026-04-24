# sbom-cli

A small CLI for ingesting CycloneDX JSON SBOMs into a local SQLite database and querying them by component or license.

Please note that the brief permits either CycloneDX 1.6 or SPDX 3.0; this implementation supports **CycloneDX only**.

## Install

Requires Python 3.14 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

## Usage

Note: the local database defaults to `./sbom.db`; override with `--db <path>` or the `SBOM_DB` environment variable.

### Ingest an SBOM into the local database:

```bash
uv run sbom-cli ingest samples/sample-cyclonedx-1.6.json
```

```text
Ingested 517 components from samples/sample-cyclonedx-1.6.json (format=cyclonedx, document_id=1)
```

### Query by component name (optionally narrowed by exact version):

```bash
uv run sbom-cli query --component "@floating-ui/core"
```

```text
document  source_path                        component          version  licenses
--------  ---------------------------------  -----------------  -------  --------
forklab   samples/sample-cyclonedx-1.6.json  @floating-ui/core  1.7.5    MIT
```

```bash
uv run sbom-cli query --component "@floating-ui/core" --version 1.7.5
```

### Query by license identifier:

```bash
uv run sbom-cli query --license MIT
```

```text
document  source_path                        component                version  licenses
--------  ---------------------------------  -----------------------  -------  --------
forklab   samples/sample-cyclonedx-1.6.json  @floating-ui/core        1.7.5    MIT
forklab   samples/sample-cyclonedx-1.6.json  @floating-ui/dom         1.7.6    MIT
forklab   samples/sample-cyclonedx-1.6.json  @floating-ui/react-dom   2.1.8    MIT
forklab   samples/sample-cyclonedx-1.6.json  @radix-ui/primitive      1.1.3    MIT
... (truncated)
```

### Notes:

- `--component` and `--license` are mutually exclusive; `--version` is only valid with `--component`.
- Re-running `ingest` on the same file inserts a new document row (deduplication is intentionally out of scope — please
  see the explanation doc).