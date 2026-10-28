"""
Security utilities for SecurePhone:
- Password hashing and verification (Werkzeug PBKDF2/Scrypt)
- Session-based authentication & RBAC decorators
- Synchronizer CSRF token generation and validation
- In-memory rate limiting for sensitive endpoints
- Input validation and sanitization helpers
"""

import functools
import html
import re
import secrets
import time
from collections import defaultdict
from flask import abort, flash, jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

# In-memory rate limiter store: { (ip, bucket): [timestamps] }
_RATE_LIMIT_STORE = defaultdict(list)

# Paths exempt from session CSRF checks (must perform their own signature verification)
CSRF_EXEMPT_PREFIXES = ("/webhooks/",)


def hash_password(password: str) -> str:
    """Hash a plaintext password using Werkzeug's secure default algorithm."""
    return generate_password_hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verify a plaintext password against a stored password hash."""
    if not password_hash or not password:
        return False
    return check_password_hash(password_hash, password)


def generate_csrf_token() -> str:
    """Generate or retrieve the current session's CSRF token."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf() -> None:
    """Validate CSRF token on state-changing requests (POST, PUT, DELETE, PATCH)."""
    # Provider webhooks (e.g. Twilio delivery receipts) carry no session; they are
    # authenticated by provider signature verification inside the route instead.
    if request.path.startswith(CSRF_EXEMPT_PREFIXES):
        return
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        session_token = session.get("_csrf_token")
        form_token = (
            request.form.get("csrf_token")
            or request.headers.get("X-CSRF-Token")
            or (request.get_json(silent=True) or {}).get("csrf_token")
        )
        if not session_token or not form_token or not secrets.compare_digest(session_token, form_token):
            if request.is_json or request.path.startswith("/api/"):
                abort(400, description="CSRF token missing or invalid.")
            flash("Security token expired or invalid. Please try submitting the form again.", "error")
            abort(400, description="CSRF validation failed.")


def rate_limit(bucket: str, max_requests: int = 10, window_seconds: int = 60):
    """Decorator to rate-limit sensitive routes per client IP."""
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped(*args, **kwargs):
            # Allow test runner to bypass or reset rate limits when needed
            ip = request.remote_addr or "127.0.0.1"
            key = (ip, bucket)
            now = time.time()
            timestamps = _RATE_LIMIT_STORE[key]
            # Prune expired timestamps
            _RATE_LIMIT_STORE[key] = [t for t in timestamps if now - t < window_seconds]
            if len(_RATE_LIMIT_STORE[key]) >= max_requests:
                if request.is_json or request.path.startswith("/api/"):
                    return jsonify({
                        "ok": False,
                        "error": "Too many attempts. Please wait a moment before retrying."
                    }), 429
                flash("Too many requests detected. Please wait a moment and try again.", "error")
                return redirect(request.referrer or url_for("home"))
            _RATE_LIMIT_STORE[key].append(now)
            return view_func(*args, **kwargs)
        return wrapped
    return decorator


def clear_rate_limits():
    """Clear in-memory rate limits (useful for automated tests)."""
    _RATE_LIMIT_STORE.clear()


def login_required(view_func):
    """Ensure the user is authenticated before accessing a route."""
    @functools.wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Authentication required."}), 401
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)
    return wrapped


def admin_required(view_func):
    """Ensure the signed-in user has the 'admin' role."""
    @functools.wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Authentication required."}), 401
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        if session.get("user_role") != "admin":
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Administrator privileges required."}), 403
            flash("Access denied: Administrator privileges are required for this area.", "error")
            return redirect(url_for("owner_dashboard"))
        return view_func(*args, **kwargs)
    return wrapped


def clean_text(value: str, max_length: int = 500) -> str:
    """Strip control characters and whitespace, enforcing a maximum length."""
    if value is None:
        return ""
    cleaned = str(value).strip()
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", cleaned)
    return cleaned[:max_length]


def is_valid_email(email: str) -> bool:
    """Validate basic email address format."""
    if not email or len(email) > 150:
        return False
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return bool(re.match(pattern, email))


def is_valid_demo_pin(pin: str) -> bool:
    """Validate a 4-to-6 digit simulation demo PIN."""
    if not pin:
        return False
    return bool(re.match(r"^\d{4,6}$", pin))


def sanitize_last4(value: str) -> str:
    """Extract at most 4 alphanumeric characters for safe hardware partial ID storage."""
    if not value:
        return ""
    alnum = re.sub(r"[^A-Za-z0-9]", "", value)
    return alnum[-4:].upper() if alnum else ""
