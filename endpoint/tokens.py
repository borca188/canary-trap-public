import re
import secrets
import sqlite3
from datetime import datetime, timezone

from config import DISPLAY_TZ
from db import get_connection


def generate_token_id():
    return secrets.token_urlsafe(16)


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def format_local(iso_string):
    if not iso_string:
        return iso_string
    return datetime.fromisoformat(iso_string).astimezone(DISPLAY_TZ).strftime("%Y-%m-%d %H:%M:%S %Z")


CUSTOM_PATH_MAX_LENGTH = 200
DOCUMENT_REF_MAX_LENGTH = 200
# One custom-path segment: starts with a letter or digit (so never "." or ".."),
# then letters, digits, ".", "_" or "-". Everything else (%, \, :, ?, #, spaces,
# empty segments) is rejected, so a stored path is always a plain local path.
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def normalize_custom_path(raw, reserved=()):
    """Validate a user-supplied custom URL path such as "products/line-finder".

    Returns it without its leading/trailing slash, or None when blank. reserved
    holds lowercase first segments owned by app routes (e.g. "token", "static").
    Raises ValueError with a user-facing message.
    """
    path = (raw or "").strip().removeprefix("/").removesuffix("/")
    if not path:
        return None
    if len(path) > CUSTOM_PATH_MAX_LENGTH:
        raise ValueError(f"Custom URL path must be at most {CUSTOM_PATH_MAX_LENGTH} characters.")
    segments = path.split("/")
    if not all(_PATH_SEGMENT.fullmatch(segment) for segment in segments):
        raise ValueError(
            "Custom URL path can only use letters, numbers, hyphens, underscores, dots"
            " and slashes, e.g. products/line-finder."
        )
    if segments[0].lower() in reserved:
        raise ValueError(f"/{segments[0]} is used by the application. Choose a different custom URL path.")
    return path


# First segments for randomised callback paths: ordinary resource folders, none of
# them a route of this app (tests assert that against the live URL map; callers
# also pass the reserved set to create_token as a belt-and-braces filter).
CALLBACK_PREFIXES = (
    "assets", "media", "resources", "images", "files", "docs", "downloads", "content",
)
CALLBACK_PATH_ATTEMPTS = 5


class TokenCreationError(RuntimeError):
    """A token could not be created for a reason that is not the caller's input.
    The message is safe to show to the user."""


def new_callback_path(token_id, reserved=()):
    """A "<random prefix>/<token_id>" path. Using the token's own (already random)
    id keeps the dashboard's Token and the URL's identifier the same value."""
    prefixes = [prefix for prefix in CALLBACK_PREFIXES if prefix not in reserved]
    if not prefixes:
        raise TokenCreationError("Every callback path prefix is reserved by an application route.")
    return f"{secrets.choice(prefixes)}/{token_id}"


def _path_in_use(conn, path):
    """True if path is already some token's custom or callback path (case-insensitive,
    deactivated tokens included: they keep their paths)."""
    row = conn.execute(
        "SELECT 1 FROM tokens WHERE custom_path = ? COLLATE NOCASE"
        " OR callback_path = ? COLLATE NOCASE",
        (path, path),
    ).fetchone()
    return row is not None


def create_token(document_ref, custom_path=None, reserved=()):
    """custom_path must already be normalized (see normalize_custom_path). reserved
    holds lowercase route segments the random path prefix must avoid.

    Every token gets a random callback_path. Unique indexes are the final word on
    collisions: a clash on the random values is retried with fresh ones, a clash on
    the caller's custom_path is reported as ValueError. Running out of attempts
    raises TokenCreationError, chained to the last collision.
    """
    if len(document_ref) > DOCUMENT_REF_MAX_LENGTH:
        raise ValueError(f"Document reference must be at most {DOCUMENT_REF_MAX_LENGTH} characters.")
    created_at = utc_now_iso()
    last_collision = None

    conn = get_connection()
    try:
        # The two path columns have separate indexes, so a custom path equal to
        # another token's random path is only caught here. Deleted tokens keep
        # their paths, so an old document's URL can never trigger a different token.
        if custom_path is not None and _path_in_use(conn, custom_path):
            raise ValueError(f"/{custom_path} is already used by another token.")

        for _ in range(CALLBACK_PATH_ATTEMPTS):
            token_id = generate_token_id()
            callback_path = new_callback_path(token_id, reserved)
            if _path_in_use(conn, callback_path):
                continue
            try:
                conn.execute(
                    "INSERT INTO tokens (token_id, document_ref, created_at, custom_path, callback_path)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (token_id, document_ref, created_at, custom_path, callback_path),
                )
                conn.commit()
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                # Lost a race for the caller's own path: theirs to fix. Anything
                # else was a collision on the random values, so draw again.
                if custom_path is not None and _path_in_use(conn, custom_path):
                    raise ValueError(f"/{custom_path} is already used by another token.") from exc
                last_collision = exc
                continue
            return {
                "token_id": token_id,
                "document_ref": document_ref,
                "created_at": created_at,
                "custom_path": custom_path,
                "callback_path": callback_path,
            }
        raise TokenCreationError(
            "Could not generate a unique callback path; please try again."
        ) from last_collision
    finally:
        conn.close()


def get_token(token_id):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM tokens WHERE token_id = ?", (token_id,)
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def get_token_by_custom_path(custom_path):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM tokens WHERE custom_path = ?", (custom_path,)
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def get_token_by_callback_path(callback_path):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM tokens WHERE callback_path = ?", (callback_path,)
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def count_tokens(active_only=False):
    conn = get_connection()
    try:
        query = "SELECT COUNT(*) AS count FROM tokens"
        if active_only:
            query += " WHERE is_active = 1"
        row = conn.execute(query).fetchone()
    finally:
        conn.close()
    return row["count"]


def list_tokens(active_only=False):
    conn = get_connection()
    try:
        query = """
            SELECT
                t.token_id,
                t.document_ref,
                t.created_at,
                t.is_active,
                t.custom_path,
                t.callback_path,
                COUNT(e.id) AS event_count,
                MAX(e.timestamp) AS last_triggered_at
            FROM tokens t
            LEFT JOIN events e ON e.token_id = t.token_id AND e.archived_at IS NULL
        """
        if active_only:
            query += " WHERE t.is_active = 1"
        query += " GROUP BY t.token_id ORDER BY t.created_at DESC"
        rows = conn.execute(query).fetchall()
    finally:
        conn.close()
    return [dict(row) for row in rows]


def list_document_refs():
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT DISTINCT document_ref FROM tokens ORDER BY document_ref"
        ).fetchall()
    finally:
        conn.close()
    return [row["document_ref"] for row in rows]


def deactivate_token(token_id):
    """Returns the number of tokens matched (0 when token_id is unknown)."""
    conn = get_connection()
    try:
        cursor = conn.execute(
            "UPDATE tokens SET is_active = 0 WHERE token_id = ?", (token_id,)
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()
