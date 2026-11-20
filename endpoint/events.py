from datetime import datetime, timedelta, timezone
from typing import NamedTuple

from db import get_connection
from tokens import utc_now_iso

# Callback URLs are public, so anyone holding one can flood it. Past this many
# hits from one IP on one token within the window, further hits are counted (in
# suppressed_events) instead of stored, so a flood can't bury real evidence or
# bloat the database. A normal agent retrying a few times never gets near it.
EVENT_RATE_LIMIT = 30
EVENT_RATE_WINDOW_SECONDS = 60
# Visitor-controlled strings are cut to this length before they are stored.
EVENT_FIELD_MAX_LENGTH = 1024

# Explicit list so the legacy `referer` column (no longer collected) is never returned.
EVENT_COLUMNS = "id, token_id, timestamp, ip_address, user_agent, method, path, archived_at"

# Searchable fields -> columns (case-insensitive substring match). A search
# targets one field, or all of them when its field is None. This dict is the
# allowlist: only these column expressions are ever placed in SQL.
SEARCH_FIELDS = {
    "document_ref": "t.document_ref",
    "token_id": "e.token_id",
    "ip_address": "e.ip_address",
    "user_agent": "e.user_agent",
    "path": "e.path",
}


class LogOutcome(NamedTuple):
    recorded: bool
    # Hits suppressed so far in this token+IP+window bucket, this one included;
    # 0 when the hit was recorded.
    suppressed_in_window: int = 0


def _utcnow():
    return datetime.now(timezone.utc)


def _truncate(value):
    return value[:EVENT_FIELD_MAX_LENGTH] if value is not None else None


def _count_suppressed_hit(conn, token_id, ip_address, now):
    """Add one to the suppressed-hit counter for this token+IP and rate-limit
    window; returns the bucket's count after the increment."""
    bucket = int(now.timestamp()) // EVENT_RATE_WINDOW_SECONDS * EVENT_RATE_WINDOW_SECONDS
    window_start = datetime.fromtimestamp(bucket, timezone.utc).isoformat()
    key = (token_id, ip_address, window_start)
    conn.execute(
        """
        INSERT INTO suppressed_events (token_id, ip_address, window_start, first_seen, last_seen, count)
        VALUES (?, ?, ?, ?, ?, 1)
        ON CONFLICT (token_id, ip_address, window_start)
        DO UPDATE SET count = count + 1, last_seen = excluded.last_seen
        """,
        (*key, now.isoformat(), now.isoformat()),
    )
    row = conn.execute(
        "SELECT count FROM suppressed_events WHERE token_id = ? AND ip_address = ? AND window_start = ?",
        key,
    ).fetchone()
    return row["count"]


def log_event(token_id, ip_address, user_agent, method, path):
    """Store a callback hit, unless this IP already hit EVENT_RATE_LIMIT on this
    token within the window; then only the suppressed counter is incremented.
    Archived events still count towards the limit."""
    now = _utcnow()
    cutoff = (now - timedelta(seconds=EVENT_RATE_WINDOW_SECONDS)).isoformat()
    conn = get_connection()
    try:
        recent = conn.execute(
            "SELECT COUNT(*) AS count FROM events WHERE token_id = ? AND ip_address = ? AND timestamp >= ?",
            (token_id, ip_address, cutoff),
        ).fetchone()["count"]
        if recent >= EVENT_RATE_LIMIT:
            suppressed = _count_suppressed_hit(conn, token_id, ip_address, now)
            conn.commit()
            return LogOutcome(recorded=False, suppressed_in_window=suppressed)

        conn.execute(
            """
            INSERT INTO events (token_id, timestamp, ip_address, user_agent, method, path)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (token_id, now.isoformat(), ip_address, _truncate(user_agent), method, _truncate(path)),
        )
        conn.commit()
        return LogOutcome(recorded=True)
    finally:
        conn.close()


def count_suppressed(token_id=None):
    """Hits dropped by the rate limit, for one token or overall."""
    query = "SELECT COALESCE(SUM(count), 0) AS total FROM suppressed_events"
    params = ()
    if token_id is not None:
        query += " WHERE token_id = ?"
        params = (token_id,)

    conn = get_connection()
    try:
        row = conn.execute(query, params).fetchone()
    finally:
        conn.close()
    return row["total"]


def list_events_for_token(token_id, include_archived=False, archived_only=False):
    query = f"SELECT {EVENT_COLUMNS} FROM events WHERE token_id = ?"
    if archived_only:
        query += " AND archived_at IS NOT NULL"
    elif not include_archived:
        query += " AND archived_at IS NULL"
    query += " ORDER BY timestamp DESC"

    conn = get_connection()
    try:
        rows = conn.execute(query, (token_id,)).fetchall()
    finally:
        conn.close()
    return [dict(row) for row in rows]


def _like_pattern(text):
    """Substring LIKE pattern with wildcards escaped, so text is matched literally."""
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _event_filters(
    token_id=None,
    include_archived=False,
    archived_only=False,
    document_ref=None,
    searches=None,
    date_from=None,
    date_to=None,
    event_ids=None,
):
    """Build the WHERE clause shared by list_all_events and count_all_events.

    searches is a list of (field, text) pairs, field being a SEARCH_FIELDS key or
    None for all fields. Texts on the same field are OR'ed; different fields are
    AND'ed; each all-fields text is its own AND'ed clause. Values are always bound
    as parameters, never interpolated.
    """
    clauses = []
    params = []

    if archived_only:
        clauses.append("e.archived_at IS NOT NULL")
    elif not include_archived:
        clauses.append("e.archived_at IS NULL")
    if token_id:
        clauses.append("e.token_id = ?")
        params.append(token_id)
    if document_ref:
        clauses.append("t.document_ref = ?")
        params.append(document_ref)
    by_field = {}
    for field, text in searches or []:
        if field is None:
            columns = list(SEARCH_FIELDS.values())
            clauses.append("(" + " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in columns) + ")")
            params.extend([_like_pattern(text)] * len(columns))
        elif field in SEARCH_FIELDS:
            by_field.setdefault(field, []).append(text)
        else:
            raise ValueError(f"Unknown search field: {field}")
    for field, texts in by_field.items():
        column = SEARCH_FIELDS[field]
        clauses.append("(" + " OR ".join(f"{column} LIKE ? ESCAPE '\\'" for _ in texts) + ")")
        params.extend(_like_pattern(text) for text in texts)
    if date_from:
        clauses.append("e.timestamp >= ?")
        params.append(date_from)
    if date_to:
        clauses.append("e.timestamp < ?")
        params.append(date_to)
    if event_ids is not None:
        clauses.append("e.id IN ({})".format(",".join("?" * len(event_ids))))
        params.extend(event_ids)

    return (" WHERE " + " AND ".join(clauses) if clauses else ""), params


def list_all_events(limit=None, event_ids=None, **filters):
    """Filters are those of _event_filters; date_from is inclusive and date_to
    exclusive, both UTC ISO strings."""
    if event_ids is not None and not event_ids:
        return []
    columns = ", ".join("e." + c.strip() for c in EVENT_COLUMNS.split(","))
    where, params = _event_filters(event_ids=event_ids, **filters)
    query = f"""
        SELECT {columns}, t.document_ref FROM events e
        JOIN tokens t ON t.token_id = e.token_id
        {where}
        ORDER BY e.timestamp DESC
    """
    if limit:
        query += " LIMIT ?"
        params.append(limit)

    conn = get_connection()
    try:
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    return [dict(row) for row in rows]


def count_all_events(**filters):
    """Count events matching the same filters as list_all_events (ignoring any limit)."""
    where, params = _event_filters(**filters)
    query = f"SELECT COUNT(*) AS count FROM events e JOIN tokens t ON t.token_id = e.token_id{where}"

    conn = get_connection()
    try:
        row = conn.execute(query, params).fetchone()
    finally:
        conn.close()
    return row["count"]


def count_events(include_archived=False, archived_only=False):
    query = "SELECT COUNT(*) AS count FROM events"
    if archived_only:
        query += " WHERE archived_at IS NOT NULL"
    elif not include_archived:
        query += " WHERE archived_at IS NULL"

    conn = get_connection()
    try:
        row = conn.execute(query).fetchone()
    finally:
        conn.close()
    return row["count"]


def archive_events(event_ids):
    """Soft-delete: rows stay in the database and can be restored."""
    if not event_ids:
        return 0
    conn = get_connection()
    try:
        cursor = conn.execute(
            "UPDATE events SET archived_at = ? WHERE archived_at IS NULL AND id IN ({})".format(
                ",".join("?" * len(event_ids))
            ),
            [utc_now_iso(), *event_ids],
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def restore_events(event_ids):
    if not event_ids:
        return 0
    conn = get_connection()
    try:
        cursor = conn.execute(
            "UPDATE events SET archived_at = NULL WHERE archived_at IS NOT NULL AND id IN ({})".format(
                ",".join("?" * len(event_ids))
            ),
            event_ids,
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()
