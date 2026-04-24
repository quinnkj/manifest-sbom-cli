"""CycloneDX SBOM parser.

Thin wrapper over `cyclonedx-python-lib` that converts a parsed CycloneDX
JSON payload into our format-agnostic `ParsedDocument`. The library handles
schema-version detection, the union of license shapes, and PURL parsing —
this module only normalizes the result into `ParsedComponent` rows.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cyclonedx.model.bom import Bom
from cyclonedx.model.license import DisjunctiveLicense, License, LicenseExpression

from sbom_cli.parsers.types import ParsedComponent, ParsedDocument


def _license_str(lic: License) -> str | None:
    """Render a CycloneDX license object as a single string.

    Args:
        lic: A `DisjunctiveLicense` (with `.id`/`.name`) or `LicenseExpression`
            (with `.value`).

    Returns:
        The SPDX id when present, then the free-form name, then the compound
        expression — in that order of preference. `None` if none of those
        fields are populated.
    """

    if isinstance(lic, LicenseExpression):
        return lic.value

    return lic.id or lic.name if isinstance(lic, DisjunctiveLicense) else None


def parse(path: Path, payload: dict[str, Any]) -> ParsedDocument:
    """Convert a CycloneDX JSON payload into a `ParsedDocument`.

    Args:
        path: The on-disk path the payload was loaded from. Stored on the
            returned document for traceability.
        payload: The parsed CycloneDX JSON object. The spec version is read
            from the raw payload (the library's `Bom` model is
            spec-version-agnostic at runtime).

    Returns:
        A `ParsedDocument` with `format == "cyclonedx"`.
    """

    bom: Bom = Bom.from_json(payload)  # type: ignore[attr-defined]

    components: list[ParsedComponent] = []
    for component in bom.components:
        licenses: list[str] = []

        for lic in component.licenses:
            if rendered := _license_str(lic):
                licenses.append(rendered)

        components.append(
            ParsedComponent(
                name=component.name,
                version=component.version,
                purl=component.purl.to_string() if component.purl is not None else None,
                licenses=licenses,
            )
        )

    doc_name: str | None = None

    if bom.metadata is not None and bom.metadata.component is not None:
        doc_name = bom.metadata.component.name

    return ParsedDocument(
        source_path=str(path),
        format="cyclonedx",
        spec_version=payload.get("specVersion"),
        serial_number=str(bom.serial_number) if bom.serial_number is not None else None,
        name=doc_name,
        components=components,
    )
