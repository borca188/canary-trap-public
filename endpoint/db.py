import contextlib
import glob
import logging
import os
import sqlite3
from datetime import datetime, timezone

from config import DATABASE_PATH, INSTANCE_DIR, SCHEMA_PATH

logger = logging.getLogger(__name__)


def get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
    except BaseException:
        conn.close()
        raise
    return conn


def _set_mode(path, mode):
    """Best effort: a file the app can't change (owned by another user, read-only
    mount) shouldn't stop it starting, but the operator should know."""
    try:
        os.chmod(path, mode)
    except OSError as exc:
        logger.warning("Could not restrict %s to mode %o: %s", path, mode, exc)


def _create_private_file(path):
    """Create the file before SQLite does, which would use the default permissions.
    SQLite gives its journal files the same mode as the database."""
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600))


def _make_database_private():
    """Limit the database and its backups to the app's user: they hold logged IPs and
    token URLs, and a token URL is enough to fake a hit. Windows ignores these modes."""
    directory = os.path.dirname(DATABASE_PATH)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    # Only the default folder is ours to tighten once it exists: HONEYPOT_DB may
    # point into a directory other things use, such as /tmp.
    if os.path.abspath(directory) == INSTANCE_DIR:
        _set_mode(directory, 0o700)
    # If this fails, let SQLite report the problem as it always has.
    with contextlib.suppress(OSError):
        _create_private_file(DATABASE_PATH)
    # The database, its backups and any leftover journal. Links are skipped so this
    # can't change the mode of a file elsewhere.
    for path in glob.glob(glob.escape(DATABASE_PATH) + "*"):
        if os.path.isfile(path) and not os.path.islink(path):
            _set_mode(path, 0o600)


def init_db():
    _make_database_private()
    conn = get_connection()
    try:
        with open(SCHEMA_PATH, "r") as f:
            conn.executescript(f.read())
        conn.commit()
        _migrate(conn)
    finally:
        conn.close()


# Token columns added after the first release; an existing table missing any of
# them is about to be altered.
_ADDED_TOKEN_COLUMNS = {"is_active", "custom_path", "callback_path"}


def _backup(conn):
    """Copy the database next to itself before a schema change (SQLite backup API,
    so it is consistent even while the file is in use)."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = f"{DATABASE_PATH}.bak-{stamp}"
    _create_private_file(path)
    dest = sqlite3.connect(path)
    try:
        conn.backup(dest)
    except BaseException:
        # A half-written file would look like a usable backup; don't leave one.
        dest.close()
        with contextlib.suppress(OSError):
            os.remove(path)
        raise
    dest.close()


def _create_unique_index(conn, name, column):
    """Create a case-insensitive unique index on tokens, explaining the failure
    when existing rows already collide (which would otherwise abort startup with
    a bare "UNIQUE constraint failed")."""
    try:
        conn.execute(
            f"CREATE UNIQUE INDEX IF NOT EXISTS {name} ON tokens ({column} COLLATE NOCASE)"
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        raise RuntimeError(
            f"Cannot create unique index {name}: existing tokens have {column} values that"
            " are duplicates ignoring case. Fix or remove them and restart."
        ) from exc


def _migrate(conn):
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(tokens)")}
    if _ADDED_TOKEN_COLUMNS - columns:
        _backup(conn)
    if "is_active" not in columns:
        conn.execute("ALTER TABLE tokens ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
        conn.commit()
    if "custom_path" not in columns:
        conn.execute("ALTER TABLE tokens ADD COLUMN custom_path TEXT")
        conn.commit()
    # Created here rather than in schema.sql, which runs before the column exists
    # on older databases. NULLs never collide, so tokens without a path are fine;
    # NOCASE stops look-alike paths that differ only in case.
    _create_unique_index(conn, "idx_tokens_custom_path", "custom_path")

    # Randomised callback path (e.g. "assets/<random>"); NULL for tokens created
    # before it existed, which keep answering on /token/<token_id>.
    if "callback_path" not in columns:
        conn.execute("ALTER TABLE tokens ADD COLUMN callback_path TEXT")
        conn.commit()
    _create_unique_index(conn, "idx_tokens_callback_path", "callback_path")

    event_columns = {row["name"] for row in conn.execute("PRAGMA table_info(events)")}
    if "archived_at" not in event_columns:
        conn.execute("ALTER TABLE events ADD COLUMN archived_at TEXT")
        conn.commit()
