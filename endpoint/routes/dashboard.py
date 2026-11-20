import csv
import io
import json
from datetime import date, datetime, time, timedelta, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit

from flask import Blueprint, Response, abort, redirect, render_template, request, url_for

from config import DISPLAY_TZ
from routes.honeypot import callback_url_for, custom_url, public_url_for, reserved_path_segments
from events import (
    archive_events,
    EVENT_RATE_LIMIT,
    EVENT_RATE_WINDOW_SECONDS,
    count_all_events,
    count_events,
    count_suppressed,
    list_all_events,
    list_events_for_token,
    restore_events,
)
from security import add_frame_headers, guard_dashboard, is_local_path
from tokens import (
    CUSTOM_PATH_MAX_LENGTH,
    DOCUMENT_REF_MAX_LENGTH,
    TokenCreationError,
    count_tokens,
    create_token,
    deactivate_token,
    format_local,
    get_token,
    list_document_refs,
    list_tokens,
    normalize_custom_path,
)

dashboard_bp = Blueprint("dashboard", __name__)
dashboard_bp.before_request(guard_dashboard)
dashboard_bp.after_request(add_frame_headers)

CSV_FIELDS = [
    "timestamp",
    "document_ref",
    "token_id",
    "ip_address",
    "user_agent",
    "method",
    "path",
]
ARCHIVED_FIELD = "archived_at"
# Spreadsheets run a cell that starts with one of these as a formula.
_CSV_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")
TIMESTAMP_FIELDS = ("timestamp", ARCHIVED_FIELD)

def _csv_safe(value):
    """Neutralise spreadsheet formulas: callback fields (user agent, path) come from
    whoever hits a public URL, so a cell like =HYPERLINK(...) must not be live when
    the analyst opens the export. The leading ' makes Excel/LibreOffice show text."""
    return "'" + value if value.startswith(_CSV_FORMULA_TRIGGERS) else value


# Query params that carry one-shot banners; dropped when redirecting back.
_BANNER_PARAMS = {"archived", "restored", "no_selection", "undo"}


def _add_urls(token):
    token["callback_url"] = callback_url_for(token)
    token["custom_url"] = custom_url(token["custom_path"]) if token["custom_path"] else None
    return token


RECENT_EVENTS_LIMIT = 100


def _event_ids_from_request():
    return _parse_event_ids(request.values.getlist("event_ids"))


def _undo_ids_from_request():
    """Event IDs an archive banner's Undo should restore (comma-separated `undo` param)."""
    return _parse_event_ids(request.args.get("undo", "").split(","))


# SQLite integers are signed 64-bit; binding anything larger raises OverflowError.
_SQLITE_INT_MIN, _SQLITE_INT_MAX = -(2**63), 2**63 - 1


def _parse_event_ids(values):
    """Valid event IDs from raw form/query values; anything that is not a
    SQLite-sized integer cannot match a row and is skipped."""
    ids = []
    for raw in values:
        try:
            event_id = int(raw)
        except ValueError:
            continue
        if _SQLITE_INT_MIN <= event_id <= _SQLITE_INT_MAX:
            ids.append(event_id)
    return ids


def _redirect_back(**params):
    """Redirect to the page the form came from (local paths only), plus banner params."""
    target = request.values.get("next", "")
    if not is_local_path(target):
        return redirect(url_for("dashboard.index", **params))
    try:
        parts = urlsplit(target)
    except ValueError:
        # Not a parseable URL at all (e.g. "//[" is an invalid IPv6 host).
        return redirect(url_for("dashboard.index", **params))
    if parts.netloc:
        return redirect(url_for("dashboard.index", **params))

    query = [(k, v) for k, v in parse_qsl(parts.query) if k not in _BANNER_PARAMS]
    query.extend(params.items())
    return redirect(parts.path + ("?" + urlencode(query) if query else ""))


# Date-range presets for the event filters: value -> (label, look-back window).
DATE_RANGES = {
    "all": ("All time", None),
    "24h": ("Last 24 hours", timedelta(hours=24)),
    "7d": ("Last 7 days", timedelta(days=7)),
    "30d": ("Last 30 days", timedelta(days=30)),
    "custom": ("Custom range", None),
}
# Search field selector: value -> (label, placeholder). Values other than
# "all" are keys of events.SEARCH_FIELDS.
SEARCH_FIELD_OPTIONS = {
    "all": ("All fields", "Search all event fields..."),
    "document_ref": ("Document reference", "Search document names..."),
    "token_id": ("Token ID", "Search token IDs..."),
    "ip_address": ("IP address", "Search IP addresses..."),
    "user_agent": ("User-Agent", "Search user agents..."),
    "path": ("Request path", "Search request paths..."),
}
# What the selector offers. "all" stays valid above (a bare q=, old f=all:<text>
# links and exports) but is not offered: its box had nothing specific to prompt.
SEARCH_FIELD_CHOICES = {k: v for k, v in SEARCH_FIELD_OPTIONS.items() if k != "all"}
FILTER_PARAMS = ("q", "field", "range", "date_from", "time_from", "date_to", "time_to")
DATE_PARAMS = ("date_from", "time_from", "date_to", "time_to")
# Stacked filters travel as repeatable f=<field>:<value> params (field is a
# SEARCH_FIELD_OPTIONS key, so the first colon always separates the two).
FILTER_PARAM = "f"
MAX_FILTERS = 20
SEARCH_MAX_LENGTH = 200


def _parse_local(day_value, time_value, label):
    """Parse a Perth-local YYYY-MM-DD date and optional HH:MM time into an aware datetime."""
    try:
        day = date.fromisoformat(day_value)
    except ValueError:
        raise ValueError(f"{label} date must be formatted YYYY-MM-DD.") from None
    if not time_value:
        return datetime.combine(day, time(), tzinfo=DISPLAY_TZ)
    try:
        clock = time.fromisoformat(time_value)
    except ValueError:
        raise ValueError(f"{label} time must be formatted HH:MM.") from None
    return datetime.combine(day, clock, tzinfo=DISPLAY_TZ)


def _split_filter(raw):
    field, _, value = raw.partition(":")
    return field.strip(), value.strip()


def _dedupe_filters(pairs):
    """Drop empty values and repeats (same field, same value ignoring case, since
    matching is case-insensitive), keeping first-added order."""
    seen = set()
    filters = []
    for field, value in pairs:
        key = (field, value.casefold())
        if value and key not in seen:
            seen.add(key)
            filters.append((field, value))
    return filters


def _filter_query(params):
    """Turn raw filter params into list_all_events kwargs plus chips describing
    the active filters. params["filters"] is a list of (field, value) pairs.
    Raises ValueError with a user-facing message.

    Each chip is {"label", "value", "filter"}: filter is the (field, value) pair
    it shows, or None for the date-range chip."""
    filters = params.get("filters", [])
    if params["field"] not in SEARCH_FIELD_OPTIONS:
        raise ValueError("Unknown search field.")
    if len(filters) > MAX_FILTERS:
        raise ValueError(f"Use at most {MAX_FILTERS} filters at once.")
    for field, value in filters:
        if field not in SEARCH_FIELD_OPTIONS:
            raise ValueError("Unknown search field.")
        if len(value) > SEARCH_MAX_LENGTH:
            raise ValueError(f"Search text must be at most {SEARCH_MAX_LENGTH} characters.")
    if params["range"] not in DATE_RANGES:
        raise ValueError("Unknown date range.")

    chips = [
        {"label": SEARCH_FIELD_OPTIONS[field][0], "value": f"\u201c{value}\u201d", "filter": (field, value)}
        for field, value in filters
    ]
    start = end = None
    label, window = DATE_RANGES[params["range"]]
    date_chip = None

    if window:
        start = datetime.now(timezone.utc).replace(microsecond=0) - window
        date_chip = label
    elif params["range"] == "custom":
        for side in ("from", "to"):
            if params["time_" + side] and not params["date_" + side]:
                raise ValueError(f"Choose a {'start' if side == 'from' else 'end'} date to go with the time.")
        if not params["date_from"] and not params["date_to"]:
            raise ValueError("Choose a start and/or end date for the custom range.")
        if params["date_from"]:
            start = _parse_local(params["date_from"], params["time_from"], "Start")
        if params["date_to"]:
            end = _parse_local(params["date_to"], params["time_to"], "End")
            # The end is inclusive: a whole day runs to the next local midnight,
            # an HH:MM time to the end of that minute.
            try:
                end += timedelta(minutes=1) if params["time_to"] else timedelta(days=1)
            except OverflowError as exc:
                raise ValueError("End date is out of the supported range.") from exc
        if start and end and start >= end:
            raise ValueError("The start of the date range must be before its end.")

        start_text = " ".join(filter(None, (params["date_from"], params["time_from"])))
        end_text = " ".join(filter(None, (params["date_to"], params["time_to"])))
        if start_text and end_text:
            date_chip = f"{start_text} \u2192 {end_text}"
        else:
            date_chip = f"From {start_text}" if start_text else f"Until {end_text}"
    if date_chip:
        chips.append({"label": "Date", "value": date_chip, "filter": None})

    try:
        date_from = start.astimezone(timezone.utc).isoformat() if start else None
        date_to = end.astimezone(timezone.utc).isoformat() if end else None
    except OverflowError as exc:
        raise ValueError("Date is out of the supported range.") from exc
    query = {
        "searches": [(None if field == "all" else field, value) for field, value in filters] or None,
        "date_from": date_from,
        "date_to": date_to,
    }
    return query, chips


def _event_filters_from_request():
    """Read the search/date filters shared by the dashboard table and exports.

    Returns (params, query, chips, error): params echoes the raw values back to
    the form (params["filters"] holds the stacked (field, value) pairs), query
    holds list_all_events kwargs, chips describes the active filters. A q/field
    pair from the search box is added to the f= filters. On invalid input, query
    and chips are empty and error says why. Legacy exports that send only
    date_from/date_to are treated as a custom range.
    """
    params = {name: request.values.get(name, "").strip() for name in FILTER_PARAMS}
    params["field"] = params["field"] or "all"
    if not params["range"]:
        params["range"] = "custom" if params["date_from"] or params["date_to"] else "all"
    pairs = [_split_filter(raw) for raw in request.values.getlist(FILTER_PARAM)]
    if params["q"]:
        pairs.append((params["field"], params["q"]))
    params["filters"] = _dedupe_filters(pairs)
    try:
        query, chips = _filter_query(params)
    except ValueError as exc:
        return params, {}, [], str(exc)
    return params, query, chips, None


def _filter_state(params, filters, include_date=True, include_field=False):
    """Query params that reproduce a filter state: one f=<field>:<value> per
    filter plus the date range. include_field also keeps the search selector's
    choice (UI state only; a field with no text filters nothing)."""
    state = {}
    if filters:
        state[FILTER_PARAM] = [f"{field}:{value}" for field, value in filters]
    if include_field and params["field"] != "all":
        state["field"] = params["field"]
    if include_date and params["range"] != "all":
        state["range"] = params["range"]
        if params["range"] == "custom":
            state.update({k: params[k] for k in DATE_PARAMS if params[k]})
    return state


@dashboard_bp.route("/")
def index():
    created_token = None
    created_token_id = request.args.get("created")
    if created_token_id:
        created_token = get_token(created_token_id)
        if created_token:
            _add_urls(created_token)

    active_tokens = [_add_urls(token) for token in list_tokens(active_only=True)]

    show_archived = request.args.get("show") == "archived"
    show_param = {"show": "archived"} if show_archived else {}
    filters, filter_query, filter_chips, filter_error = _event_filters_from_request()
    if "q" in request.args and not filter_error:
        # The search box was submitted: its text is now one of the stacked
        # filters, so redirect to the canonical URL with an empty search box.
        return redirect(url_for(
            "dashboard.index", **show_param, **_filter_state(filters, filters["filters"], include_field=True)
        ))
    active_filters = _filter_state(filters, filters["filters"]) if filter_chips else {}
    for chip in filter_chips:
        if chip["filter"]:
            remaining = [f for f in filters["filters"] if f != chip["filter"]]
            state = _filter_state(filters, remaining, include_field=True)
        else:
            state = _filter_state(filters, filters["filters"], include_date=False, include_field=True)
        chip["remove_url"] = url_for("dashboard.index", **show_param, **state)

    recent_events = list_all_events(
        limit=RECENT_EVENTS_LIMIT, archived_only=show_archived, **filter_query
    )
    # Filters are applied before the limit; only count separately when it truncated.
    match_count = None
    if filter_chips:
        match_count = len(recent_events)
        if match_count == RECENT_EVENTS_LIMIT:
            match_count = count_all_events(archived_only=show_archived, **filter_query)

    return render_template(
        "dashboard.html",
        tokens_count=count_tokens(active_only=True),
        callbacks_count=count_events(),
        archived_count=count_events(archived_only=True),
        suppressed_count=count_suppressed(),
        rate_limit=EVENT_RATE_LIMIT,
        rate_window_seconds=EVENT_RATE_WINDOW_SECONDS,
        recent_events=recent_events,
        show_archived=show_archived,
        filters=filters,
        filter_chips=filter_chips,
        filter_error=filter_error,
        match_count=match_count,
        date_ranges=[(value, label) for value, (label, _) in DATE_RANGES.items()],
        search_fields=SEARCH_FIELD_CHOICES,
        active_url=url_for("dashboard.index", **active_filters),
        archived_url=url_for("dashboard.index", show="archived", **active_filters),
        clear_filters_url=url_for("dashboard.index", **show_param),
        export_params=dict(active_filters, **show_param),
        document_refs=list_document_refs(),
        export_fields=CSV_FIELDS,
        active_tokens=active_tokens,
        created_token=created_token,
        error=request.args.get("error"),
        custom_path_base=public_url_for("dashboard.index"),
        deactivated=request.args.get("deactivated"),
        archived=request.args.get("archived"),
        undo_ids=_undo_ids_from_request(),
        restored=request.args.get("restored"),
        no_selection=request.args.get("no_selection"),
    )


@dashboard_bp.route("/tokens", methods=["POST"])
def create_token_route():
    document_ref = request.form.get("document_ref", "").strip()
    raw_path = request.form.get("custom_path", "").strip()
    try:
        if not document_ref:
            raise ValueError("Document label is required.")
        reserved = reserved_path_segments()
        token = create_token(document_ref, normalize_custom_path(raw_path, reserved), reserved)
    except (ValueError, TokenCreationError) as exc:
        # Echo the inputs back so a rejected path doesn't mean retyping the form.
        # Capped so an oversized value can't turn into an oversized Location header.
        return redirect(url_for(
            "dashboard.index",
            error=str(exc),
            document_ref=document_ref[:DOCUMENT_REF_MAX_LENGTH],
            custom_path=raw_path[:CUSTOM_PATH_MAX_LENGTH],
        ))
    return redirect(url_for("dashboard.index", created=token["token_id"]))


@dashboard_bp.route("/tokens/<token_id>/delete", methods=["POST"])
def deactivate_token_route(token_id):
    if not deactivate_token(token_id):
        return "Not found", 404
    return redirect(url_for("dashboard.index", deactivated="1"))


@dashboard_bp.route("/tokens/<token_id>")
def token_detail(token_id):
    token = get_token(token_id)
    if token is None:
        return "Not found", 404

    _add_urls(token)
    show_archived = request.args.get("show") == "archived"
    events = list_events_for_token(token_id, archived_only=show_archived)
    return render_template(
        "token_detail.html",
        token=token,
        events=events,
        show_archived=show_archived,
        archived_count=len(list_events_for_token(token_id, archived_only=True)),
        suppressed_count=count_suppressed(token_id),
        rate_limit=EVENT_RATE_LIMIT,
        rate_window_seconds=EVENT_RATE_WINDOW_SECONDS,
        export_fields=CSV_FIELDS,
        archived=request.args.get("archived"),
        undo_ids=_undo_ids_from_request(),
        restored=request.args.get("restored"),
        no_selection=request.args.get("no_selection"),
    )


@dashboard_bp.route("/events/archive", methods=["POST"])
def archive_events_route():
    event_ids = _event_ids_from_request()
    if not event_ids:
        return _redirect_back(no_selection="1")
    return _redirect_back(
        archived=archive_events(event_ids), undo=",".join(str(i) for i in event_ids)
    )


@dashboard_bp.route("/events/restore", methods=["POST"])
def restore_events_route():
    event_ids = _event_ids_from_request()
    if not event_ids:
        return _redirect_back(no_selection="1")
    return _redirect_back(restored=restore_events(event_ids))


@dashboard_bp.route("/export/events.csv", methods=["GET", "POST"])
def export_events_csv():
    """Export events as CSV (default) or JSON.

    Query/form params: token_id, document_ref, the dashboard filters (q, range,
    date_from/time_from, date_to/time_to as Perth-local values, end inclusive),
    columns (repeatable), format (csv|json), tz (local|utc), include_archived,
    show=archived (archived events only). A POST with event_ids exports exactly
    those events, archived or not.
    """
    export_format = request.values.get("format", "csv")
    if export_format not in ("csv", "json"):
        abort(400, description="format must be csv or json.")

    tz = request.values.get("tz", "local")
    if tz not in ("local", "utc"):
        abort(400, description="tz must be local or utc.")

    event_ids = None
    if request.method == "POST":
        event_ids = _event_ids_from_request()
        if not event_ids:
            return _redirect_back(no_selection="1")

    include_archived = bool(request.values.get("include_archived")) or event_ids is not None
    archived_only = request.values.get("show") == "archived" and event_ids is None

    _, filter_query, _, filter_error = _event_filters_from_request()
    if filter_error:
        abort(400, description=filter_error)

    allowed_fields = CSV_FIELDS + [ARCHIVED_FIELD]
    requested = request.values.getlist("columns")
    unknown = [c for c in requested if c not in allowed_fields]
    if unknown:
        abort(400, description="Unknown column(s): " + ", ".join(unknown))
    if requested:
        fields = [f for f in allowed_fields if f in requested]
    else:
        fields = CSV_FIELDS + ([ARCHIVED_FIELD] if include_archived or archived_only else [])

    events = list_all_events(
        token_id=request.values.get("token_id") or None,
        document_ref=request.values.get("document_ref") or None,
        include_archived=include_archived,
        archived_only=archived_only,
        event_ids=event_ids,
        **filter_query,
    )

    rows = []
    for event in events:
        row = {field: event.get(field) or "" for field in fields}
        if tz == "local":
            for field in TIMESTAMP_FIELDS:
                if field in row:
                    row[field] = format_local(row[field])
        rows.append(row)

    if export_format == "json":
        return Response(
            json.dumps(rows, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=events.json"},
        )

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields)
    writer.writeheader()
    writer.writerows({k: _csv_safe(v) for k, v in row.items()} for row in rows)

    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=events.csv"},
    )
