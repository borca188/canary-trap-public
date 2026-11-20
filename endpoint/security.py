"""Browser-attack guards for the dashboard and API blueprints.

The honeypot callback routes are deliberately not guarded: they must answer any
Host and any origin, and must never set a cookie.

Layers, cheapest first (each failure returns before the view runs):
  1. Host allowlist     - DNS rebinding, and a tunnel forwarding more than it should.
  2. Fetch metadata     - cross-site / cross-origin state-changing requests.
  3. Synchronizer token - dashboard form POSTs only; the JSON API has no session.
"""
import hmac
import os
import secrets
from urllib.parse import urlsplit

from flask import request, session

import db
from config import DASHBOARD_HOSTS

CSRF_SESSION_KEY = "csrf_token"
CSRF_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

SECRET_KEY_FILENAME = "secret_key"

def is_local_path(target):
    """True for "/some/path" only: no scheme, no host, and no backslash or control
    character, which browsers read as "/" or drop ("/\\evil.example" and
    "/\t/evil.example" both end up at //evil.example)."""
    if not target.startswith("/") or target.startswith("//"):
        return False
    return not any(c == "\\" or ord(c) < 0x20 or ord(c) == 0x7F for c in target)


def csrf_token():
    """The session's form token, created on first use (exposed to templates)."""
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def _request_hostname():
    try:
        return urlsplit("//" + request.host).hostname
    except ValueError:  # e.g. "[" without a closing bracket
        return None


def _cross_site_request():
    """True when a browser says this request was initiated by another site/origin.
    Requests carrying neither header (curl, scripts) are not browser-initiated, so
    they cannot be a victim's browser being driven by a third-party page."""
    site = request.headers.get("Sec-Fetch-Site")
    if site is not None:
        return site not in ("same-origin", "none")
    origin = request.headers.get("Origin")
    if origin is not None:
        try:
            return urlsplit(origin).netloc.lower() != request.host.lower()
        except ValueError:
            return True
    return False


def _token_is_valid():
    expected = session.get(CSRF_SESSION_KEY)
    submitted = request.form.get(CSRF_FIELD) or request.headers.get(CSRF_HEADER)
    # Reject missing/empty values explicitly; never let "" compare equal to "".
    if not isinstance(expected, str) or not expected:
        return False
    if not isinstance(submitted, str) or not submitted:
        return False
    return hmac.compare_digest(submitted.encode(), expected.encode())


def _guard(require_token):
    hostname = _request_hostname()
    if hostname is None or hostname not in DASHBOARD_HOSTS:
        # Same body as the honeypot's own 404: don't reveal that a dashboard exists.
        return "Not found", 404

    if request.method in SAFE_METHODS:
        return None
    if _cross_site_request():
        return "Forbidden: cross-site request refused.", 403
    if require_token and not _token_is_valid():
        return "Forbidden: missing or invalid form token. Reload the page and try again.", 403
    return None


def guard_dashboard():
    return _guard(require_token=True)


def guard_api():
    # JSON API: no session to hold a token. It needs Content-Type: application/json,
    # which a cross-site page cannot send without a CORS preflight, on top of layer 2.
    return _guard(require_token=False)


def add_frame_headers(response):
    """Stop the dashboard being framed (clickjacking its archive/delete buttons)."""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    return response


def load_secret_key():
    """SECRET_KEY from the environment, else a random key persisted next to the
    database (mode 0600) so sessions survive restarts and are shared by workers."""
    from_env = os.environ.get("SECRET_KEY")
    if from_env:
        return from_env

    directory = os.path.dirname(db.DATABASE_PATH)
    path = os.path.join(directory, SECRET_KEY_FILENAME)
    os.makedirs(directory, mode=0o700, exist_ok=True)

    if not os.path.exists(path):
        # Write a private temp file, then hard-link it into place: link() fails if
        # another worker got there first, so readers never see a half-written key.
        tmp = f"{path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_hex(32))
            try:
                os.link(tmp, path)
            except FileExistsError:
                pass
        finally:
            os.remove(tmp)

    try:
        with open(path) as f:
            key = f.read().strip()
    except OSError as exc:
        raise RuntimeError(f"Cannot read the session secret key at {path}: {exc}") from exc
    if not key:
        raise RuntimeError(f"The session secret key file {path} is empty; delete it to generate a new one.")
    return key
