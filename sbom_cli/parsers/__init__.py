"""SBOM format detection and dispatch."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sbom_cli.parsers import cyclonedx
from sbom_cli.parsers.types import ParsedDocument


class UnknownFormatError(ValueError):
    """Raised when an SBOM payload does not match any supported format."""


def detect_format(payload: dict[str, Any]) -> str:
    """Identify the SBOM format of a parsed JSON payload.

    Detection is purely structural: CycloneDX is identified by its
    `bomFormat` discriminator. SPDX is intentionally not supported.

    Args:
        payload: The parsed JSON object loaded from an SBOM file.

    Returns:
        `"cyclonedx"`.

    Raises:
        UnknownFormatError: If the payload is not a CycloneDX SBOM.
    """

    if payload.get("bomFormat") == "CycloneDX":
        return "cyclonedx"

    raise UnknownFormatError("Could not detect SBOM format (expected CycloneDX).")


def parse(path: Path, payload: dict[str, Any]) -> ParsedDocument:
    """Parse an SBOM payload using the format-appropriate parser.

    Args:
        path: The on-disk path the payload was loaded from. Stored on the
            returned `ParsedDocument` for traceability; not re-read.
        payload: The parsed JSON object loaded from `path`.

    Returns:
        A `ParsedDocument` whose `format` field reflects the detected format.

    Raises:
        UnknownFormatError: If the payload is not a supported format.
    """

    fmt: str = detect_format(payload)

    if fmt == "cyclonedx":
        return cyclonedx.parse(path, payload)

    raise UnknownFormatError(f"Unsupported SBOM format: {fmt}")
