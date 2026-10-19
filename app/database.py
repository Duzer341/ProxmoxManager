"""SQLAlchemy engine / session setup (SQLite by default)."""

from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    # The background poller writes from a worker thread.
    connect_args = {"check_same_thread": False, "timeout": 30}

engine = create_engine(settings.DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)

if settings.DATABASE_URL.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - trivial
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    """FastAPI dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def db_session():
    """Context manager for non-request code (poller, CLI)."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    from . import models  # noqa: F401  (register tables)

    Base.metadata.create_all(bind=engine)
    _add_missing_columns()


def _add_missing_columns() -> None:
    """Poor man's migration: add columns that exist in the models but not in the
    database (create_all only creates missing tables). Good enough for SQLite and
    additive changes between releases."""
    from sqlalchemy import inspect, text

    insp = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            existing = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in existing:
                    continue
                coltype = col.type.compile(engine.dialect)
                default = col.default.arg if col.default is not None and not callable(col.default.arg) else None
                ddl = f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {coltype}'
                if default is not None:
                    if isinstance(default, bool):
                        ddl += f" DEFAULT {1 if default else 0}"
                    elif isinstance(default, (int, float)):
                        ddl += f" DEFAULT {default}"
                    else:
                        ddl += " DEFAULT '" + str(default).replace("'", "''") + "'"
                elif not col.nullable:
                    ddl += " DEFAULT ''"
                conn.execute(text(ddl))
