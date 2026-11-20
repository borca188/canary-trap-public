from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from config import SESSION_COOKIE_SECURE, TRUSTED_PROXY_HOPS
from db import init_db
from routes.api import api_bp
from routes.dashboard import dashboard_bp
from routes.honeypot import honeypot_bp
from security import csrf_token, load_secret_key
from tokens import format_local


def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=load_secret_key(),
        # Cookies are shared across ports on localhost, so don't use the default
        # name another local Flask app would also use. Only the dashboard ever
        # touches the session; callback responses never set a cookie.
        SESSION_COOKIE_NAME="canary_trap_session",
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
    )

    if TRUSTED_PROXY_HOPS > 0:
        # Only trust X-Forwarded-For for the real client IP; leave
        # proto/host/port/prefix alone since only IP logging is in scope.
        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=TRUSTED_PROXY_HOPS, x_proto=0, x_host=0, x_port=0, x_prefix=0
        )

    app.register_blueprint(honeypot_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(dashboard_bp)

    app.jinja_env.filters["local_time"] = format_local
    app.jinja_env.globals["csrf_token"] = csrf_token

    with app.app_context():
        init_db()

    return app


app = create_app()

if __name__ == "__main__":
    # Development server only; prefer `flask --app app run`. Debug mode is left
    # off on purpose: the Werkzeug debugger can execute code in the browser.
    app.run()
