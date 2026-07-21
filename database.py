import sqlite3
from pathlib import Path

from flask import current_app, g


def get_db() -> sqlite3.Connection:
    """Return one SQLite database connection per request."""

    if "db" not in g:
        database_path = current_app.config["DATABASE"]

        g.db = sqlite3.connect(database_path)
        g.db.row_factory = sqlite3.Row

    return g.db


def close_db(exception: Exception | None = None) -> None:
    """Close the database connection after each request."""

    db = g.pop("db", None)

    if db is not None:
        db.close()


def init_db() -> None:
    """Create the database tables using schema.sql."""

    db = get_db()

    schema_path = Path(current_app.root_path) / "schema.sql"

    with schema_path.open("r", encoding="utf-8") as schema_file:
        db.executescript(schema_file.read())

    db.commit()


def init_app(app) -> None:
    """Register database cleanup with Flask."""

    app.teardown_appcontext(close_db)