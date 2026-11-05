"""Loopback-only read views over the shared RansomLab application service.

This module creates a WSGI application. It does not bind a socket, start a worker,
or implement any simulation, investigation, or recovery operation.
"""

from datetime import datetime, timedelta
import hmac
import re
import secrets
from uuid import UUID

from flask import Flask, jsonify, render_template, request, session
from werkzeug.exceptions import HTTPException


_HOST = re.compile(r"(?:localhost|127\.0\.0\.1|\[::1\])(?::([0-9]{1,5}))?\Z", re.ASCII)
_LOOPBACK = frozenset({"127.0.0.1", "::1"})
_TONES = {
    "critical": "danger", "high": "danger", "failed": "danger",
    "recovery_failed": "danger", "verification_lost": "danger", "interrupted": "warning", "warning": "warning",
    "changed": "warning", "missing": "danger", "running": "warning",
    "contained": "warning", "verified": "success", "unchanged": "success", "intact": "success",
    "prepared": "success", "success": "success", "completed": "success",
    "info": "neutral", "declared": "neutral", "unknown": "neutral",
}


def _lab_id(value):
    """Require the canonical UUID form used by the core, never a path."""
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError, TypeError):
        return None
    return value if str(parsed) == value else None


def _byte_label(value):
    if type(value) is not int or value < 0:
        return "—"
    for divisor, suffix in ((1024 ** 3, "GiB"), (1024 ** 2, "MiB"), (1024, "KiB")):
        if value >= divisor:
            return f"{value / divisor:.1f} {suffix}"
    return f"{value:,} B"


def _time_label(value):
    if not value:
        return "Not recorded"
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return "Unknown time"
    return stamp.strftime("%H:%M:%S UTC") if stamp.utcoffset() == timedelta(0) else stamp.isoformat()


def create_app(service=None, access_token=None):
    """Build the read-only dashboard; the caller supplies the loopback server.

    Launch with ``http://127.0.0.1:PORT/#token=TOKEN``. The fragment is processed
    locally and exchanged for a private session cookie using POST /session.
    If no token is supplied, the generated token is accessible only to the
    local launcher in ``app.extensions['ransomlab']['access_token']``.
    """
    if service is None:
        from .services import LabService
        service = LabService.default()

    token = access_token if access_token is not None else secrets.token_urlsafe(32)
    if not isinstance(token, str) or len(token) < 32 or len(token) > 256 or not token.isascii():
        raise ValueError("Dashboard access token must be 32 to 256 ASCII characters.")

    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.update(
        SECRET_KEY=secrets.token_bytes(32),
        SESSION_COOKIE_NAME="ransomlab_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=False,  # Deliberate: HTTP over the loopback interface only.
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=1024,
        MAX_FORM_MEMORY_SIZE=1024,
        DEBUG=False,
    )
    app.extensions["ransomlab"] = {"access_token": token, "service": service}
    app.jinja_env.filters.update(
        bytes_label=_byte_label,
        time_label=_time_label,
        tone=lambda value: _TONES.get(str(value).lower(), "neutral"),
        label=lambda value: str(value or "not recorded").replace("_", " ").replace(".", " · "),
        recovery_state=lambda value: value.get("state", value.get("status", "not recorded")) if value else "Not run",
    )

    def error(code, status):
        return jsonify(error=code), status

    def bearer_valid():
        authorization = request.headers.get("Authorization", "")
        if len(authorization) > 300 or not authorization.startswith("Bearer "):
            return False
        supplied = authorization[7:]
        return supplied.isascii() and hmac.compare_digest(supplied, token)

    def authenticated():
        return session.get("authenticated") is True or bearer_valid()

    @app.before_request
    def check_request_boundary():
        host = request.host
        match = _HOST.fullmatch(host)
        if not match or (match.group(1) and not 1 <= int(match.group(1)) <= 65535):
            return error("invalid_host", 400)
        if request.remote_addr not in _LOOPBACK:
            return error("loopback_required", 403)
        origin = request.headers.get("Origin")
        if origin is not None and origin != f"{request.scheme}://{host}":
            return error("invalid_origin", 403)
        if request.headers.get("Sec-Fetch-Site") == "cross-site":
            return error("cross_site_request_denied", 403)
        if len(request.query_string) > 256:
            return error("query_too_large", 400)
        permitted_args = {"after", "limit"} if request.endpoint == "event_page" else set()
        if any(key not in permitted_args for key in request.args):
            return error("unsupported_query", 400)
        if any(len(request.args.getlist(key)) != 1 for key in request.args):
            return error("duplicate_query", 400)
        if request.endpoint in {"static", "index", "open_session"} or request.endpoint is None:
            return None
        if not authenticated():
            return error("authentication_required", 401)
        return None

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; font-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    @app.errorhandler(HTTPException)
    def http_error(exc):
        names = {404: "not_found", 405: "method_not_allowed", 413: "request_too_large"}
        return error(names.get(exc.code, "request_rejected"), exc.code or 500)

    # Application errors are not reflected verbatim: they may carry local paths.
    from .core.errors import LabError

    @app.errorhandler(LabError)
    def service_error(_exc):
        return error("lab_unavailable", 409)

    @app.post("/session")
    def open_session():
        if not bearer_valid():
            return error("authentication_required", 401)
        if request.content_length not in (None, 0):
            return error("session_body_not_allowed", 400)
        session.clear()
        session["authenticated"] = True
        return "", 204

    @app.get("/")
    def index():
        if not authenticated():
            return render_template("dashboard.html", locked=True, labs=[], lab=None)
        return render_template("dashboard.html", locked=False, labs=service.list_labs(), lab=None)

    @app.get("/labs/<identifier>")
    def lab_view(identifier):
        if _lab_id(identifier) is None:
            return error("invalid_lab_id", 400)
        return render_template("dashboard.html", locked=False, labs=service.list_labs(),
                               lab=service.status(identifier))

    @app.get("/api/labs")
    def lab_list():
        return jsonify(service.list_labs())

    @app.get("/api/labs/<identifier>/status")
    def lab_status(identifier):
        if _lab_id(identifier) is None:
            return error("invalid_lab_id", 400)
        return jsonify(service.status(identifier))

    @app.get("/api/labs/<identifier>/report")
    def lab_report(identifier):
        if _lab_id(identifier) is None:
            return error("invalid_lab_id", 400)
        response = jsonify(service.report(identifier))
        response.headers["Content-Disposition"] = f'attachment; filename="ransomlab-{identifier}.json"'
        return response

    @app.get("/api/labs/<identifier>/events")
    def event_page(identifier):
        if _lab_id(identifier) is None:
            return error("invalid_lab_id", 400)
        after = request.args.get("after", "0")
        limit = request.args.get("limit", "100")
        if not re.fullmatch(r"[0-9]{1,15}", after) or not re.fullmatch(r"[0-9]{1,3}", limit):
            return error("invalid_pagination", 400)
        after_number, limit_number = int(after), int(limit)
        if not 1 <= limit_number <= 200:
            return error("invalid_pagination", 400)
        # This pages only the shared service's bounded recent-event window.
        recent = service.status(identifier).get("events", [])
        available = [event for event in recent if event.get("sequence", 0) > after_number]
        items = available[:limit_number]
        return jsonify(items=items, after=after_number,
                       last_sequence=items[-1]["sequence"] if items else after_number,
                       has_more=len(available) > limit_number, window="recent")

    return app
