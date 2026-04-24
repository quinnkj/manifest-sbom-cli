"""Format-agnostic data shapes shared between parsers and persistence.

Each format parser (currently just `cyclonedx`) is responsible for translating
its raw JSON into a `ParsedDocument`, so that `db` insertion does not need to
know anything about the source format.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParsedComponent:
    """A single software component extracted from an SBOM.

    Attributes:
        name: The component's package name (e.g. `@floating-ui/core`, `requests`).
        version: The component's version string, when present.
        purl: The Package URL (purl) identifier, when present.
        licenses: Zero or more license strings. May be SPDX identifiers
            (`MIT`), full names, or compound expressions (`MIT OR Apache-2.0`)
            stored verbatim.
    """

    name: str
    version: str | None = None
    purl: str | None = None
    licenses: list[str] = field(default_factory=list)


@dataclass
class ParsedDocument:
    """An SBOM document and its components.

    Attributes:
        source_path: The on-disk path of the file that was parsed.
        format: The detected SBOM format (currently always `"cyclonedx"`).
        spec_version: The format's spec version (e.g. `"1.6"`), or `None` if
            not declared in the document.
        serial_number: The CycloneDX `serialNumber`. May be `None`.
        name: The document's top-level name from `metadata.component.name`.
            May be `None`.
        components: All software components discovered in the document.
    """

    source_path: str
    format: str
    spec_version: str | None
    serial_number: str | None
    name: str | None
    components: list[ParsedComponent]
