import os
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# HONEYPOT_DB overrides the default location (e.g. to point tests at a scratch DB).
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DATABASE_PATH = os.environ.get("HONEYPOT_DB") or os.path.join(INSTANCE_DIR, "honeypot.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")

# Timezone used to display timestamps and interpret dashboard date filters.
# Timestamps are always stored in UTC.
DISPLAY_TZ = ZoneInfo("Australia/Perth")

# Number of reverse proxy hops in front of this app that are trusted to set
# X-Forwarded-For. 0 (default) = no proxy in front; trust request.remote_addr
# as-is. Only raise this once a real proxy (e.g. Cloudflare, nginx) actually
# terminates connections in front of this app, or any client can spoof their
# logged IP via the X-Forwarded-For header.
_raw_proxy_hops = os.environ.get("TRUSTED_PROXY_HOPS", "0")
try:
    TRUSTED_PROXY_HOPS = int(_raw_proxy_hops)
except ValueError:
    TRUSTED_PROXY_HOPS = -1

if TRUSTED_PROXY_HOPS < 0:
    raise ValueError(f"TRUSTED_PROXY_HOPS must be a non-negative integer, got {_raw_proxy_hops!r}")

# Hostnames (no port) the dashboard and API answer to, comma-separated. Requests
# for any other Host get a 404 there, which stops DNS-rebinding pages and a
# tunnel that forwards more than the callback paths. The callback routes ignore
# this: they must answer on whatever public hostname the tunnel serves.
_raw_dashboard_hosts = os.environ.get("DASHBOARD_HOSTS", "localhost,127.0.0.1,::1")
DASHBOARD_HOSTS = frozenset(
    host.strip().strip("[]").lower() for host in _raw_dashboard_hosts.split(",") if host.strip()
)
if not DASHBOARD_HOSTS or any("/" in host or " " in host for host in DASHBOARD_HOSTS):
    raise ValueError(
        f"DASHBOARD_HOSTS must be a comma-separated list of hostnames, got {_raw_dashboard_hosts!r}"
    )

# Set SESSION_COOKIE_SECURE=1 when the dashboard is served over HTTPS so the
# browser never sends the session cookie (it holds the form token) over plain
# HTTP. Off by default so http://localhost and VM-IP development keep working.
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "").strip().lower() in (
    "1", "true", "yes", "on",
)

# Public address of the callback URLs, e.g. https://trap.example.com (the
# Cloudflare tunnel hostname). The dashboard is usually opened on localhost, so
# URLs built from the request would show that address; with this set, the
# callback and custom URLs shown and copied in the dashboard and returned by the
# API use it instead. Display only: callback matching and redirects are unchanged.
# Unset (default) keeps building URLs from the address the dashboard was opened on.
_raw_public_base_url = os.environ.get("PUBLIC_BASE_URL", "").strip()
PUBLIC_BASE_URL = ""
if _raw_public_base_url:
    _bad_public_base_url = ValueError(
        "PUBLIC_BASE_URL must be a scheme and host with no path, e.g. https://trap.example.com,"
        f" got {_raw_public_base_url!r}"
    )
    try:
        _parts = urlsplit(_raw_public_base_url)
        _port = _parts.port  # raises ValueError for a non-numeric port
    except ValueError as exc:
        raise _bad_public_base_url from exc
    if (
        _parts.scheme.lower() not in ("http", "https")
        or not _parts.hostname
        or _parts.username is not None
        or _parts.path not in ("", "/")
        or _parts.query
        or _parts.fragment
    ):
        raise _bad_public_base_url
    PUBLIC_BASE_URL = f"{_parts.scheme.lower()}://{_parts.netloc.lower()}"
