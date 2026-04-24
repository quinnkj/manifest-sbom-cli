"""SBOM format detection and dispatch."""

from __future__ import annotations


class UnknownFormatError(ValueError):
    """Raised when an SBOM payload does not match any supported format."""
