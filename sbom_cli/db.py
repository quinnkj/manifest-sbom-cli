"""SQLModel schema and persistence helpers.

Skeleton: schema and query helpers will be filled in by a later commit.
"""

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

# noinspection PyPackageRequirements
from sqlalchemy import Index
from sqlmodel import Field, Relationship, Session, SQLModel, create_engine

from sbom_cli.parsers.types import ParsedDocument

if TYPE_CHECKING:
    # noinspection PyPackageRequirements
    from sqlalchemy import Engine


class Document(SQLModel, table=True):
    """An ingested SBOM file.

    Attributes:
        id: Auto-assigned primary key.
        source_path: The on-disk path of the file when it was ingested.
        format: The detected format (`"cyclonedx"` or `"spdx"`).
        spec_version: The format's spec version, when present in the source.
        serial_number: A document-scoped identifier — CycloneDX `serialNumber`
            or SPDX `SpdxDocument.spdxId`.
        name: The document's top-level name, when present in the source.
        ingested_at: UTC timestamp set at insertion time.
        components: Cascade-deleted child components.
    """

    id: int | None = Field(default=None, primary_key=True)
    source_path: str
    format: str = Field(index=True)
    spec_version: str | None = None
    serial_number: str | None = Field(default=None, index=True)
    name: str | None = None
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    components: list[Component] = Relationship(
        back_populates="document",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )


class Component(SQLModel, table=True):
    """A single software component belonging to a `Document`.

    Attributes:
        id: Auto-assigned primary key.
        document_id: Foreign key to `Document.id`.
        name: The component's package name (indexed for query lookups).
        version: The component's version string, when known.
        purl: The Package URL identifier, when known.
        document: Back-reference to the owning `Document`.
        licenses: Cascade-deleted child license rows.
    """

    id: int | None = Field(default=None, primary_key=True)
    document_id: int = Field(foreign_key="document.id", index=True)
    name: str = Field(index=True)
    version: str | None = None
    purl: str | None = None

    document: Document = Relationship(back_populates="components")
    licenses: list[ComponentLicense] = Relationship(
        back_populates="component",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )

    __table_args__ = (Index("idx_component_name_version", "name", "version"),)


class ComponentLicense(SQLModel, table=True):
    """One license declared by a `Component`.

    A component may have multiple rows here (CycloneDX `licenses[]` or SPDX
    multiple `hasDeclaredLicense`/`hasConcludedLicense` relationships).

    Attributes:
        id: Auto-assigned primary key.
        component_id: Foreign key to `Component.id`.
        license: License string — SPDX id, name, or compound expression,
            stored verbatim from the source SBOM.
        component: Back-reference to the owning `Component`.
    """

    id: int | None = Field(default=None, primary_key=True)
    component_id: int = Field(foreign_key="component.id", index=True)
    license: str = Field(index=True)

    component: Component = Relationship(back_populates="licenses")


def default_db_path() -> Path:
    """Return the SQLite path the CLI will use when none is supplied.

    Reads the `SBOM_DB` environment variable, falling back to `./sbom.db`
    in the current working directory.

    Returns:
        The resolved database path. The file is not required to exist; it
        will be created by `make_engine` if missing.
    """

    return Path(os.environ.get("SBOM_DB", "sbom.db"))


def make_engine(db_path: Path | str | None = None) -> Engine:
    """Build a SQLAlchemy engine and ensure the schema exists.

    Args:
        db_path: An explicit SQLite path, or `None` to fall back to
            `default_db_path()`.

    Returns:
        A ready-to-use `sqlalchemy.engine.Engine` whose tables and indexes
        have been created (idempotently) via `SQLModel.metadata.create_all`.
    """

    path: Path = Path(db_path) if db_path is not None else default_db_path()
    engine: Engine = create_engine(f"sqlite:///{path}", echo=False)
    SQLModel.metadata.create_all(engine)

    return engine


def insert_parsed(session: Session, parsed: ParsedDocument) -> Document:
    """Persist a `ParsedDocument` and all its components and licenses.

    Inserts are flushed eagerly so that auto-assigned primary keys propagate
    to child rows; a single `commit()` finalizes the whole document.

    Args:
        session: An active SQLModel session bound to the target engine.
        parsed: The format-agnostic document produced by `parsers.parse`.

    Returns:
        The inserted `Document`, refreshed so that its `id` and other
        server-assigned fields are populated.
    """

    doc: Document = Document(
        source_path=parsed.source_path,
        format=parsed.format,
        spec_version=parsed.spec_version,
        serial_number=parsed.serial_number,
        name=parsed.name,
    )
    session.add(doc)
    session.flush()

    for parsed_component in parsed.components:
        component: Component = Component(
            document_id=doc.id,
            name=parsed_component.name,
            version=parsed_component.version,
            purl=parsed_component.purl,
        )
        session.add(component)
        session.flush()

        for lic in parsed_component.licenses:
            session.add(ComponentLicense(component_id=component.id, license=lic))

    session.commit()
    session.refresh(doc)

    return doc
