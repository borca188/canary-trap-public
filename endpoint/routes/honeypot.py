import logging
import sqlite3

from flask import Blueprint, Response, abort, current_app, redirect, request, url_for

from config import PUBLIC_BASE_URL
from events import EVENT_RATE_LIMIT, EVENT_RATE_WINDOW_SECONDS, log_event
from tokens import get_token, get_token_by_callback_path, get_token_by_custom_path

honeypot_bp = Blueprint("honeypot", __name__)

# 1x1 transparent GIF, served so the callback looks like an ordinary tracking pixel
# rather than revealing anything about the honeypot mechanism.
_TRANSPARENT_GIF = (
    b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00"
    b"\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00"
    b"\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"
)


@honeypot_bp.route("/token/<token_id>", methods=["GET"])
def callback(token_id):
    token = get_token(token_id)
    if token is None or not token["is_active"]:
        return "Not found", 404

    try:
        outcome = log_event(
            token_id=token_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            method=request.method,
            path=request.path,
        )
    except sqlite3.Error:
        # The hit can't be recorded, but an error page would tell the visitor
        # something is off. Log what was lost and answer like any other pixel.
        current_app.logger.exception(
            "Failed to record callback event: token_id=%s ip=%s method=%s path=%s",
            token_id, request.remote_addr, request.method, request.path,
        )
    else:
        if not outcome.recorded:
            # Visitor still gets the pixel, so a flooder can't tell it is being
            # throttled. Warn when suppression starts in a window; later hits in
            # the same window are only counted (dashboard) to keep the log readable.
            first = outcome.suppressed_in_window == 1
            current_app.logger.log(
                logging.WARNING if first else logging.DEBUG,
                "Callback hit not recorded, rate limit of %d per %ds exceeded:"
                " token_id=%s ip=%s suppressed_this_window=%d",
                EVENT_RATE_LIMIT, EVENT_RATE_WINDOW_SECONDS,
                token_id, request.remote_addr, outcome.suppressed_in_window,
            )

    return Response(_TRANSPARENT_GIF, mimetype="image/gif")


# Off-limits as a custom path's first segment even without a matching route:
# browsers fetch favicon.ico/robots.txt on their own, which would log false hits.
_ALWAYS_RESERVED = {"admin", "favicon.ico", "robots.txt"}


def reserved_path_segments():
    """Lowercase first path segments that custom paths may not use: every
    static first segment of the app's routes (token, tokens, api, static, ...)."""
    reserved = set(_ALWAYS_RESERVED)
    for rule in current_app.url_map.iter_rules():
        first = rule.rule.lstrip("/").split("/", 1)[0]
        if first and "<" not in first:
            reserved.add(first.lower())
    return reserved


def public_url_for(endpoint, **values):
    """Absolute URL shown to the operator. Built on PUBLIC_BASE_URL when it is
    set (the dashboard is usually opened on localhost, which is not what an
    agent should fetch), otherwise on the address of the current request."""
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL + url_for(endpoint, _external=False, **values)
    return url_for(endpoint, _external=True, **values)


def custom_url(custom_path):
    return public_url_for("honeypot.custom_redirect", custom_path=custom_path)


def callback_url_for(token, external=True):
    """The token's callback URL: its randomised path, or /token/<token_id> for
    tokens created before randomised paths existed. external=False is the local
    path used for redirects and never carries the public base."""
    if token.get("callback_path"):
        endpoint, values = "honeypot.custom_redirect", {"custom_path": token["callback_path"]}
    else:
        endpoint, values = "honeypot.callback", {"token_id": token["token_id"]}
    if external:
        return public_url_for(endpoint, **values)
    return url_for(endpoint, _external=False, **values)


# Static route segments always outrank this <path:> rule, so it only sees paths
# no other route claims. Redirect targets are built from the stored token, never
# from the request, so they can only ever point at this app's callback.
@honeypot_bp.route("/<path:custom_path>", methods=["GET"])
def custom_redirect(custom_path):
    # A randomised callback path is the callback itself: no redirect, and the
    # existing callback() validates the token and logs the one event.
    token = get_token_by_callback_path(custom_path)
    if token is not None:
        return callback(token["token_id"])

    token = get_token_by_custom_path(custom_path)
    if token is None or not token["is_active"]:
        abort(404)
    # Not logged here: the callback logs the request it redirects to.
    return redirect(callback_url_for(token, external=False), code=302)
