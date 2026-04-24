"""SQLModel schema and persistence helpers.

Skeleton: schema and query helpers will be filled in by a later commit.
"""

import os
from pathlib import Path
from typing import TYPE_CHECKING

from sqlmodel import SQLModel, create_engine

if TYPE_CHECKING:
    # noinspection PyPackageRequirements
    from sqlalchemy import Engine


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
