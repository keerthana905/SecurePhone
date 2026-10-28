"""
SecurePhone — Intelligent Mobile Security and Anti-Theft Platform
Tagline: Protect. Locate. Recover.

Main Flask application implementing all 16 required pages, REST/JSON endpoints
for the Shutdown-Authentication Simulator and Permission-Based Location Sharing,
Lost Mode & Theft Reporting, Lost-and-Found Matching, Recovery Case Lifecycle,
and Owner/Administrator Dashboards.
"""

import datetime
import os
from datetime import timedelta
from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from database import (
    DEFAULT_DB_PATH,
    generate_unique_case_number,
    get_db_connection,
    init_db,
    log_audit,
    run_matching_engine,
    utc_now_str,
)
from geocoding import (
    build_map_links,
    format_dms_coordinates,
    format_local_time,
    format_sos_alert_message,
    now_ist_str,
    reverse_geocode_coordinates,
)
from family_sharing import (
    dispatch_sms_via_provider,
    evaluate_location_freshness,
    generate_verification_otp,
    get_sms_provider_status,
    is_valid_phone_number,
    parse_utc_timestamp,
    start_or_notify_family_sharing,
    stop_family_sharing_for_device,
)
from security import (
    admin_required,
    clean_text,
    generate_csrf_token,
    hash_password,
    is_valid_demo_pin,
    is_valid_email,
    login_required,
    rate_limit,
    sanitize_last4,
    validate_csrf,
    verify_password,
)
from ai_alerts import (
    apply_provider_status,
    get_ai_provider_status,
    refresh_twilio_status,
    retry_ai_alert,
    trigger_lost_mode_ai_alerts,
    verify_twilio_signature,
)


def load_env_file(path: str = ".env") -> None:
    """
    Minimal .env loader (no extra dependency). Existing OS environment variables win.
    Used only when running the server directly so automated tests never pick up real keys.
    """
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def summarize_ai_alert_outcome(outcome: dict) -> str:
    """Human-readable, honest summary of an AI trusted-contact alert run."""
    alerts = outcome.get("alerts", [])
    if not alerts:
        if outcome.get("duplicates_prevented"):
            return "AI trusted-contact alert already sent for this event (duplicate prevented)."
        return "No verified & authorized trusted contact found — add one under Profile & Privacy to receive AI alerts."
    counts: dict = {}
    for a in alerts:
        counts[a["notification_status"]] = counts.get(a["notification_status"], 0) + 1
    parts = ", ".join(f"{n} {s.replace('_', ' ')}" for s, n in counts.items())
    text = f"AI trusted-contact alert: {parts}."
    if "Demo_Notification" in counts:
        text += " (Demo only — no real SMS sent because no SMS provider is configured.)"
    if any(a["generation_status"] == "Fallback_Template" for a in alerts):
        text += " (AI unavailable — message built from event details by template.)"
    return text


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get(
            "SECUREPHONE_SECRET_KEY",
            "securephone-smartcity-dev-secret-key-2026-protect-locate-recover",
        ),
        DATABASE=os.environ.get("SECUREPHONE_DB_PATH", DEFAULT_DB_PATH),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        SEED_DEMO=True,
    )

    if test_config:
        app.config.update(test_config)

    # Initialize database schema and optional sample demo records
    init_db(app.config["DATABASE"], seed_demo=app.config.get("SEED_DEMO", True))

    def get_db():
        if "db" not in g:
            g.db = get_db_connection(app.config["DATABASE"])
        return g.db

    @app.teardown_appcontext
    def close_db(exception=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.before_request
    def before_request_security():
        # Enforce CSRF token check on all state-changing requests
        validate_csrf()
        # Load current signed-in user into g.current_user
        g.current_user = None
        if "user_id" in session:
            db = get_db()
            user = db.execute(
                "SELECT id, full_name, email, phone_number, role, location_consent, privacy_alerts, is_sample, created_at FROM users WHERE id = ?",
                (session["user_id"],),
            ).fetchone()
            if user:
                g.current_user = dict(user)
                session["user_role"] = user["role"]
                session["user_name"] = user["full_name"]
                session["user_email"] = user["email"]
            else:
                session.clear()

    @app.template_filter("local_time")
    def local_time_filter(value):
        return format_local_time(value)

    @app.context_processor
    def inject_globals():
        return {
            "csrf_token": generate_csrf_token,
            "current_user": getattr(g, "current_user", None),
            "format_local_time": format_local_time,
            "format_dms_coordinates": format_dms_coordinates,
            "build_map_links": build_map_links,
            "format_sos_alert_message": format_sos_alert_message,
            "evaluate_location_freshness": evaluate_location_freshness,
            "get_sms_provider_status": get_sms_provider_status,
            "get_ai_provider_status": get_ai_provider_status,
        }

    # -------------------------------------------------------------------------
    # PAGE 1: Home Page
    # -------------------------------------------------------------------------
    @app.route("/")
    def home():
        db = get_db()
        stats = {
            "registered_devices": db.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
            "active_cases": db.execute(
                "SELECT COUNT(*) FROM recovery_cases WHERE status NOT IN ('Recovered', 'Closed', 'Rejected')"
            ).fetchone()[0],
            "recovered_devices": db.execute(
                "SELECT COUNT(*) FROM devices WHERE status = 'Recovered'"
            ).fetchone()[0],
            "potential_matches": db.execute("SELECT COUNT(*) FROM potential_matches").fetchone()[0],
        }
        return render_template("home.html", stats=stats)

    # -------------------------------------------------------------------------
    # PAGE 2: About and Security Information Page
    # -------------------------------------------------------------------------
    @app.route("/about")
    def about():
        return render_template("about.html")

    # -------------------------------------------------------------------------
    # PAGE 3: Registration Page
    # -------------------------------------------------------------------------
    @app.route("/register", methods=["GET", "POST"])
    @rate_limit("register", max_requests=10, window_seconds=60)
    def register():
        if g.current_user:
            return redirect(url_for("owner_dashboard"))

        if request.method == "POST":
            full_name = clean_text(request.form.get("full_name", ""), 100)
            email = clean_text(request.form.get("email", ""), 150).lower()
            phone_number = clean_text(request.form.get("phone_number", ""), 30)
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            location_consent = 1 if request.form.get("location_consent") == "on" else 0

            errors = []
            if len(full_name) < 2:
                errors.append("Please enter your full name (at least 2 characters).")
            if not is_valid_email(email):
                errors.append("Please enter a valid email address.")
            if len(password) < 8:
                errors.append("Password must be at least 8 characters long.")
            if password != confirm_password:
                errors.append("Passwords do not match.")

            db = get_db()
            if not errors:
                existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
                if existing:
                    errors.append("An account with this email address is already registered.")

            if errors:
                for err in errors:
                    flash(err, "error")
                return render_template(
                    "register.html",
                    form_data={"full_name": full_name, "email": email, "phone_number": phone_number},
                )

            now = utc_now_str()
            cur = db.cursor()
            cur.execute(
                """
                INSERT INTO users (full_name, email, phone_number, password_hash, role, location_consent, privacy_alerts, is_sample, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'owner', ?, 1, 0, ?, ?)
                """,
                (full_name, email, phone_number, hash_password(password), location_consent, now, now),
            )
            user_id = cur.lastrowid
            log_audit(
                db,
                user_id,
                email,
                "owner",
                "USER_REGISTER",
                "user",
                str(user_id),
                f"Registered new device owner account ({email}).",
                request.remote_addr or "127.0.0.1",
            )
            db.commit()

            session.clear()
            session.permanent = True
            session["user_id"] = user_id
            session["user_role"] = "owner"
            session["user_name"] = full_name
            session["user_email"] = email
            flash("Welcome to SecurePhone! Your owner account has been created.", "success")
            return redirect(url_for("owner_dashboard"))

        return render_template("register.html", form_data={})

    # -------------------------------------------------------------------------
    # PAGE 4: Login Page & Logout
    # -------------------------------------------------------------------------
    @app.route("/login", methods=["GET", "POST"])
    @rate_limit("login", max_requests=15, window_seconds=60)
    def login():
        if g.current_user:
            if g.current_user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("owner_dashboard"))

        if request.method == "POST":
            email = clean_text(request.form.get("email", ""), 150).lower()
            password = request.form.get("password", "")

            db = get_db()
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

            if not user or not verify_password(user["password_hash"], password):
                log_audit(
                    db,
                    None,
                    email or "unknown",
                    "anonymous",
                    "LOGIN_FAILED",
                    "auth",
                    email or "unknown",
                    "Failed login attempt.",
                    request.remote_addr or "127.0.0.1",
                )
                db.commit()
                flash("Invalid email address or password.", "error")
                return render_template("login.html", email=email)

            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["user_role"] = user["role"]
            session["user_name"] = user["full_name"]
            session["user_email"] = user["email"]

            log_audit(
                db,
                user["id"],
                user["email"],
                user["role"],
                "LOGIN_SUCCESS",
                "user",
                str(user["id"]),
                f"User signed in ({user['role']}).",
                request.remote_addr or "127.0.0.1",
            )
            db.commit()

            flash(f"Signed in as {user['full_name']}.", "success")
            next_url = request.args.get("next")
            if next_url and next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("owner_dashboard"))

        return render_template("login.html", email="")

    @app.route("/logout", methods=["POST"])
    def logout():
        if g.current_user:
            db = get_db()
            log_audit(
                db,
                g.current_user["id"],
                g.current_user["email"],
                g.current_user["role"],
                "LOGOUT",
                "user",
                str(g.current_user["id"]),
                "User signed out.",
                request.remote_addr or "127.0.0.1",
            )
            db.commit()
        session.clear()
        flash("You have been signed out safely.", "info")
        return redirect(url_for("home"))

    # -------------------------------------------------------------------------
    # PAGE 5: Owner Dashboard
    # -------------------------------------------------------------------------
    @app.route("/dashboard")
    @login_required
    def owner_dashboard():
        db = get_db()
        uid = g.current_user["id"]

        devices = db.execute(
            "SELECT * FROM devices WHERE user_id = ? ORDER BY updated_at DESC", (uid,)
        ).fetchall()

        total_devices = len(devices)
        protected_count = sum(1 for d in devices if d["status"] == "Protected")
        lost_count = sum(1 for d in devices if d["status"] == "Lost")
        recovered_count = sum(1 for d in devices if d["status"] == "Recovered")
        sharing_active_count = sum(1 for d in devices if d["location_sharing_enabled"])

        potential_matches_count = db.execute(
            """
            SELECT COUNT(*)
            FROM potential_matches pm
            JOIN recovery_cases rc ON rc.id = pm.case_id
            WHERE rc.user_id = ? AND pm.status != 'Rejected'
            """,
            (uid,),
        ).fetchone()[0]

        recent_reports = db.execute(
            """
            SELECT lr.*, d.device_name, d.brand, d.model, rc.case_number, rc.status AS case_status
            FROM lost_reports lr
            JOIN devices d ON d.id = lr.device_id
            LEFT JOIN recovery_cases rc ON rc.lost_report_id = lr.id
            WHERE lr.user_id = ?
            ORDER BY lr.created_at DESC
            LIMIT 5
            """,
            (uid,),
        ).fetchall()

        status_filter = clean_text(request.args.get("status", ""), 40)

        open_cases_all = db.execute(
            """
            SELECT rc.*, d.device_name, d.brand, d.model, d.color,
                   (SELECT COUNT(*) FROM potential_matches pm WHERE pm.case_id = rc.id AND pm.status != 'Rejected') AS match_count
            FROM recovery_cases rc
            JOIN devices d ON d.id = rc.device_id
            WHERE rc.user_id = ? AND rc.status NOT IN ('Closed', 'Rejected')
            ORDER BY rc.updated_at DESC
            """,
            (uid,),
        ).fetchall()

        if status_filter:
            open_cases = [c for c in open_cases_all if c["status"] == status_filter]
        else:
            open_cases = open_cases_all

        owner_matches = db.execute(
            """
            SELECT pm.id, pm.confidence_score, pm.match_summary, pm.status, pm.updated_at,
                   rc.case_number,
                   fr.brand AS found_brand, fr.model AS found_model, fr.color AS found_color,
                   fr.found_location, fr.date_found, fr.current_custody
            FROM potential_matches pm
            JOIN recovery_cases rc ON rc.id = pm.case_id
            JOIN found_reports fr ON fr.id = pm.found_report_id
            WHERE rc.user_id = ? AND pm.status != 'Rejected'
            ORDER BY pm.confidence_score DESC, pm.updated_at DESC
            LIMIT 5
            """,
            (uid,),
        ).fetchall()

        recent_case_history = db.execute(
            """
            SELECT rsh.*, rc.case_number, d.brand, d.model
            FROM recovery_status_history rsh
            JOIN recovery_cases rc ON rc.id = rsh.case_id
            JOIN devices d ON d.id = rc.device_id
            WHERE rc.user_id = ?
            ORDER BY rsh.id DESC
            LIMIT 6
            """,
            (uid,),
        ).fetchall()

        last_location = db.execute(
            """
            SELECT lu.*, d.device_name, d.brand, d.model, d.status AS device_status,
                   d.location_sharing_enabled
            FROM location_updates lu
            JOIN devices d ON d.id = lu.device_id
            WHERE lu.user_id = ?
            ORDER BY lu.recorded_at DESC, lu.id DESC
            LIMIT 1
            """,
            (uid,),
        ).fetchone()

        verified_contacts = db.execute(
            """
            SELECT * FROM trusted_contacts
            WHERE user_id = ? AND verification_status = 'Verified' AND consent_confirmed = 1
            ORDER BY id ASC
            """,
            (uid,),
        ).fetchall()
        total_contacts_count = db.execute(
            "SELECT COUNT(*) FROM trusted_contacts WHERE user_id = ?", (uid,)
        ).fetchone()[0]

        active_family_sessions = db.execute(
            """
            SELECT fss.*, d.device_name, d.brand, d.model, d.status AS device_status,
                   d.last_location_label, d.last_location_at
            FROM family_share_sessions fss
            JOIN devices d ON d.id = fss.device_id
            WHERE fss.user_id = ? AND fss.status = 'Active'
            ORDER BY fss.id DESC
            """,
            (uid,),
        ).fetchall()

        recent_family_alerts = db.execute(
            """
            SELECT fal.*, d.device_name
            FROM family_alert_logs fal
            JOIN devices d ON d.id = fal.device_id
            WHERE fal.user_id = ?
            ORDER BY fal.id DESC
            LIMIT 6
            """,
            (uid,),
        ).fetchall()

        recent_ai_alerts = db.execute(
            """
            SELECT ata.*, d.device_name
            FROM ai_trusted_alerts ata
            JOIN devices d ON d.id = ata.device_id
            WHERE ata.user_id = ?
            ORDER BY ata.id DESC
            LIMIT 6
            """,
            (uid,),
        ).fetchall()

        return render_template(
            "owner_dashboard.html",
            devices=devices,
            metrics={
                "total_devices": total_devices,
                "protected_count": protected_count,
                "lost_count": lost_count,
                "recovered_count": recovered_count,
                "open_cases_count": len(open_cases_all),
                "potential_matches_count": potential_matches_count,
                "sharing_active_count": sharing_active_count,
                "verified_contacts_count": len(verified_contacts),
                "total_contacts_count": total_contacts_count,
                "active_family_shares_count": len(active_family_sessions),
                "recent_ai_alerts_count": len(recent_ai_alerts),
            },
            status_filter=status_filter,
            recent_reports=recent_reports,
            open_cases=open_cases,
            owner_matches=owner_matches,
            recent_case_history=recent_case_history,
            last_location=last_location,
            verified_contacts=verified_contacts,
            active_family_sessions=active_family_sessions,
            recent_family_alerts=recent_family_alerts,
            recent_ai_alerts=recent_ai_alerts,
        )

    # -------------------------------------------------------------------------
    # PAGE 6: Registered Devices Page
    # -------------------------------------------------------------------------
    @app.route("/devices")
    @login_required
    def devices_list():
        db = get_db()
        uid = g.current_user["id"]
        devices = db.execute(
            """
            SELECT d.*,
                   (SELECT rc.case_number FROM recovery_cases rc
                    WHERE rc.device_id = d.id AND rc.status NOT IN ('Closed', 'Rejected')
                    ORDER BY rc.id DESC LIMIT 1) AS active_case_number
            FROM devices d
            WHERE d.user_id = ?
            ORDER BY d.created_at DESC
            """,
            (uid,),
        ).fetchall()
        return render_template("devices.html", devices=devices)

    # -------------------------------------------------------------------------
    # PAGE 7: Add / Edit Device Page
    # -------------------------------------------------------------------------
    @app.route("/devices/add", methods=["GET", "POST"])
    @login_required
    def device_add():
        if request.method == "POST":
            device_name = clean_text(request.form.get("device_name", ""), 80)
            brand = clean_text(request.form.get("brand", ""), 60)
            model = clean_text(request.form.get("model", ""), 80)
            color = clean_text(request.form.get("color", ""), 40)
            os_type = clean_text(request.form.get("os_type", "Android"), 40)
            identifier_last4 = sanitize_last4(request.form.get("identifier_last4", ""))
            demo_sim_pin = clean_text(request.form.get("demo_sim_pin", "2580"), 6)
            lock_screen_notice = clean_text(
                request.form.get(
                    "lock_screen_notice",
                    "This device is protected by SecurePhone Smart City Recovery.",
                ),
                200,
            )

            errors = []
            if len(device_name) < 2:
                errors.append("Device nickname is required (at least 2 characters).")
            if not brand:
                errors.append("Device brand is required.")
            if not model:
                errors.append("Device model is required.")
            if not color:
                errors.append("Device color is required.")
            if not is_valid_demo_pin(demo_sim_pin):
                errors.append("Simulation Demo PIN must be 4 to 6 digits (never use your real phone unlock PIN).")

            if errors:
                for err in errors:
                    flash(err, "error")
                return render_template(
                    "device_form.html",
                    mode="add",
                    device=request.form,
                )

            now = utc_now_str()
            db = get_db()
            cur = db.cursor()
            cur.execute(
                """
                INSERT INTO devices (
                    user_id, device_name, brand, model, color, os_type,
                    identifier_last4, demo_sim_pin, status, location_sharing_enabled,
                    lock_screen_notice, is_sample, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Protected', 0, ?, 0, ?, ?)
                """,
                (
                    g.current_user["id"],
                    device_name,
                    brand,
                    model,
                    color,
                    os_type,
                    identifier_last4,
                    demo_sim_pin,
                    lock_screen_notice,
                    now,
                    now,
                ),
            )
            device_id = cur.lastrowid
            log_audit(
                db,
                g.current_user["id"],
                g.current_user["email"],
                g.current_user["role"],
                "DEVICE_ADDED",
                "device",
                str(device_id),
                f"Registered device '{device_name}' ({brand} {model}).",
                request.remote_addr or "127.0.0.1",
            )
            db.commit()
            flash(f"Device '{device_name}' registered successfully.", "success")
            return redirect(url_for("devices_list"))

        return render_template("device_form.html", mode="add", device={})

    @app.route("/devices/<int:device_id>/edit", methods=["GET", "POST"])
    @login_required
    def device_edit(device_id: int):
        db = get_db()
        device = db.execute(
            "SELECT * FROM devices WHERE id = ? AND user_id = ?",
            (device_id, g.current_user["id"]),
        ).fetchone()
        if not device:
            abort(404, description="Device not found or access denied.")

        if request.method == "POST":
            device_name = clean_text(request.form.get("device_name", ""), 80)
            brand = clean_text(request.form.get("brand", ""), 60)
            model = clean_text(request.form.get("model", ""), 80)
            color = clean_text(request.form.get("color", ""), 40)
            os_type = clean_text(request.form.get("os_type", "Android"), 40)
            identifier_last4 = sanitize_last4(request.form.get("identifier_last4", ""))
            demo_sim_pin = clean_text(request.form.get("demo_sim_pin", device["demo_sim_pin"]), 6)
            lock_screen_notice = clean_text(request.form.get("lock_screen_notice", ""), 200)

            errors = []
            if len(device_name) < 2:
                errors.append("Device nickname is required.")
            if not brand or not model or not color:
                errors.append("Brand, model, and color are required.")
            if not is_valid_demo_pin(demo_sim_pin):
                errors.append("Simulation Demo PIN must be 4 to 6 digits.")

            if errors:
                for err in errors:
                    flash(err, "error")
                return render_template("device_form.html", mode="edit", device=device)

            now = utc_now_str()
            db.execute(
                """
                UPDATE devices
                SET device_name = ?, brand = ?, model = ?, color = ?, os_type = ?,
                    identifier_last4 = ?, demo_sim_pin = ?, lock_screen_notice = ?, updated_at = ?
                WHERE id = ? AND user_id = ?
                """,
                (
                    device_name,
                    brand,
                    model,
                    color,
                    os_type,
                    identifier_last4,
                    demo_sim_pin,
                    lock_screen_notice,
                    now,
                    device_id,
                    g.current_user["id"],
                ),
            )
            log_audit(
                db,
                g.current_user["id"],
                g.current_user["email"],
                g.current_user["role"],
                "DEVICE_UPDATED",
                "device",
                str(device_id),
                f"Updated device '{device_name}' ({brand} {model}).",
                request.remote_addr or "127.0.0.1",
            )
            db.commit()
            flash(f"Device '{device_name}' updated.", "success")
            return redirect(url_for("devices_list"))

        return render_template("device_form.html", mode="edit", device=device)

    @app.route("/devices/<int:device_id>/delete", methods=["POST"])
    @login_required
    def device_delete(device_id: int):
        db = get_db()
        device = db.execute(
            "SELECT * FROM devices WHERE id = ? AND user_id = ?",
            (device_id, g.current_user["id"]),
        ).fetchone()
        if not device:
            abort(404, description="Device not found or access denied.")

        device_name = device["device_name"]
        brand_model = f"{device['brand']} {device['model']}"

        # Clean up dependent records before removing the device
        case_rows = db.execute(
            "SELECT id FROM recovery_cases WHERE device_id = ? AND user_id = ?",
            (device_id, g.current_user["id"]),
        ).fetchall()
        for c in case_rows:
            db.execute("DELETE FROM recovery_status_history WHERE case_id = ?", (c["id"],))
            db.execute("DELETE FROM potential_matches WHERE case_id = ?", (c["id"],))
        db.execute(
            "DELETE FROM recovery_cases WHERE device_id = ? AND user_id = ?",
            (device_id, g.current_user["id"]),
        )
        db.execute(
            "DELETE FROM lost_reports WHERE device_id = ? AND user_id = ?",
            (device_id, g.current_user["id"]),
        )
        db.execute(
            "DELETE FROM location_updates WHERE device_id = ? AND user_id = ?",
            (device_id, g.current_user["id"]),
        )
        db.execute(
            "DELETE FROM devices WHERE id = ? AND user_id = ?",
            (device_id, g.current_user["id"]),
        )

        log_audit(
            db,
            g.current_user["id"],
            g.current_user["email"],
            g.current_user["role"],
            "DEVICE_REMOVED",
            "device",
            str(device_id),
            f"Removed registered device '{device_name}' ({brand_model}).",
            request.remote_addr or "127.0.0.1",
        )
        db.commit()
        flash(f"Device '{device_name}' has been removed from your account.", "info")
        return redirect(url_for("devices_list"))

    # -------------------------------------------------------------------------
    # PAGE 8: Shutdown-Authentication Simulator
    # -------------------------------------------------------------------------
    @app.route("/simulator")
    def simulator():
        devices = []
        selected_device = None
        recent_sim_logs = []
        if g.current_user:
            db = get_db()
            devices = db.execute(
                "SELECT id, device_name, brand, model, status, demo_sim_pin, lock_screen_notice FROM devices WHERE user_id = ? ORDER BY id ASC",
                (g.current_user["id"],),
            ).fetchall()
            req_device_id = request.args.get("device_id", type=int)
            if req_device_id:
                for d in devices:
                    if d["id"] == req_device_id:
                        selected_device = d
                        break
            if not selected_device and devices:
                selected_device = devices[0]
            recent_sim_logs = db.execute(
                """
                SELECT created_at, details
                FROM audit_logs
                WHERE user_id = ? AND action = 'SIMULATOR_SHUTDOWN_AUTH'
                ORDER BY id DESC
                LIMIT 10
                """,
                (g.current_user["id"],),
            ).fetchall()
        return render_template(
            "simulator.html",
            devices=devices,
            selected_device=selected_device,
            recent_sim_logs=recent_sim_logs,
        )

    @app.route("/api/simulator/verify", methods=["POST"])
    @rate_limit("simulator_verify", max_requests=40, window_seconds=60)
    def api_simulator_verify():
        data = request.get_json(silent=True) or {}
        method = clean_text(data.get("method", "pin"), 20).lower()
        entered_pin = clean_text(data.get("pin", ""), 10)
        biometric_mode = clean_text(data.get("biometric_outcome", ""), 20).lower()
        stage = clean_text(data.get("stage", ""), 40)
        device_id = data.get("device_id")

        expected_pin = "2580"
        device_label = "Public Demo Virtual Handset"

        db = get_db()
        if device_id and g.current_user:
            device = db.execute(
                "SELECT id, device_name, demo_sim_pin FROM devices WHERE id = ? AND user_id = ?",
                (device_id, g.current_user["id"]),
            ).fetchone()
            if device:
                expected_pin = device["demo_sim_pin"]
                device_label = device["device_name"]

        cancelled = False
        restarted = False
        if method == "power_hold":
            success = False
            outcome = "ATTEMPT"
            reason = f"Virtual power button held on {device_label}. Shutdown confirmation menu displayed (Simulation)."
        elif method == "cancel":
            success = False
            cancelled = True
            outcome = "CANCELLED"
            stage_note = f" ({stage})" if stage else ""
            reason = f"Shutdown request cancelled{stage_note} on {device_label}. Virtual handset remains powered ON and protected."
        elif method == "restart":
            success = False
            restarted = True
            outcome = "RESTARTED"
            reason = f"Virtual smartphone '{device_label}' restarted from powered-off simulation state and returned to active lock screen."
        elif method == "biometric":
            success = biometric_mode == "pass"
            outcome = "SUCCESS" if success else "FAILED"
            reason = (
                f"Demo biometric verification succeeded for {device_label}. Simulated shutdown authorized — Device Powered Off (Simulation)."
                if success
                else f"Demo biometric verification failed for {device_label}. Simulated shutdown prevented; handset remains active."
            )
        else:
            method = "pin"
            success = entered_pin == expected_pin and len(entered_pin) >= 4
            outcome = "SUCCESS" if success else "FAILED"
            reason = (
                f"Demo PIN verified for {device_label}. Simulated shutdown authorized — Device Powered Off (Simulation)."
                if success
                else f"Invalid Demo PIN entered for {device_label}. Simulated shutdown prevented to preserve active security & connectivity."
            )

        now = utc_now_str()
        now_local = format_local_time(now)

        log_audit(
            db,
            g.current_user["id"] if g.current_user else None,
            g.current_user["email"] if g.current_user else "anonymous@simulator",
            g.current_user["role"] if g.current_user else "simulator_guest",
            "SIMULATOR_SHUTDOWN_AUTH",
            "simulator",
            str(device_id or "demo"),
            f"[SIMULATION] Method={method.upper()} | Outcome={outcome} | {reason}",
            request.remote_addr or "127.0.0.1",
        )
        db.commit()

        return jsonify({
            "ok": True,
            "authorized": success,
            "cancelled": cancelled,
            "restarted": restarted,
            "outcome": outcome,
            "method": method,
            "device_label": device_label,
            "message": reason,
            "timestamp": now,
            "timestamp_local": now_local,
        })

    # -------------------------------------------------------------------------
    # PAGE 9: Permission-Based Location Sharing and Map Page
    # -------------------------------------------------------------------------
    @app.route("/location")
    @login_required
    def location_page():
        db = get_db()
        uid = g.current_user["id"]
        devices = db.execute(
            "SELECT * FROM devices WHERE user_id = ? ORDER BY id ASC", (uid,)
        ).fetchall()

        selected_device_id = request.args.get("device_id", type=int)
        selected_device = None
        if selected_device_id:
            for d in devices:
                if d["id"] == selected_device_id:
                    selected_device = d
                    break
        if not selected_device and devices:
            selected_device = devices[0]

        location_history = []
        sos_history = []
        if selected_device:
            location_history = db.execute(
                """
                SELECT * FROM location_updates
                WHERE device_id = ? AND user_id = ?
                ORDER BY recorded_at DESC, id DESC
                LIMIT 12
                """,
                (selected_device["id"], uid),
            ).fetchall()
            sos_history = db.execute(
                """
                SELECT * FROM sos_alerts
                WHERE device_id = ? AND user_id = ?
                ORDER BY id DESC
                LIMIT 6
                """,
                (selected_device["id"], uid),
            ).fetchall()

        return render_template(
            "location.html",
            devices=devices,
            selected_device=selected_device,
            location_history=location_history,
            sos_history=sos_history,
        )

    @app.route("/api/location/toggle", methods=["POST"])
    @login_required
    def api_location_toggle():
        data = request.get_json(silent=True) or {}
        device_id = data.get("device_id")
        enabled = 1 if data.get("enabled") else 0

        db = get_db()
        device = db.execute(
            "SELECT * FROM devices WHERE id = ? AND user_id = ?",
            (device_id, g.current_user["id"]),
        ).fetchone()
        if not device:
            return jsonify({"ok": False, "error": "Device not found or unauthorized."}), 403

        now = utc_now_str()
        db.execute(
            "UPDATE devices SET location_sharing_enabled = ?, updated_at = ? WHERE id = ? AND user_id = ?",
            (enabled, now, device_id, g.current_user["id"]),
        )
        if enabled:
            db.execute(
                "UPDATE users SET location_consent = 1, updated_at = ? WHERE id = ?",
                (now, g.current_user["id"]),
            )
        log_audit(
            db,
            g.current_user["id"],
            g.current_user["email"],
            g.current_user["role"],
            "LOCATION_SHARING_TOGGLED",
            "device",
            str(device_id),
            f"Owner {'ENABLED' if enabled else 'STOPPED'} permission-based location sharing for '{device['device_name']}'.",
            request.remote_addr or "127.0.0.1",
        )
        db.commit()
        return jsonify({
            "ok": True,
            "device_id": device_id,
            "location_sharing_enabled": bool(enabled),
            "message": (
                f"Location sharing enabled for {device['device_name']}."
                if enabled
                else f"Location sharing stopped for {device['device_name']}."
            ),
        })

    @app.route("/api/location/update", methods=["POST"])
    @login_required
    @rate_limit("location_update", max_requests=30, window_seconds=60)
    def api_location_update():
        data = request.get_json(silent=True) or {}
        device_id = data.get("device_id")

        db = get_db()
        device = db.execute(
            "SELECT * FROM devices WHERE id = ? AND user_id = ?",
            (device_id, g.current_user["id"]),
        ).fetchone()
        if not device:
            return jsonify({"ok": False, "error": "Device not found or unauthorized."}), 403

        if not device["location_sharing_enabled"]:
            return jsonify({
                "ok": False,
                "error": "Location sharing is currently disabled for this device. Please enable sharing permission first.",
            }), 400

        try:
            lat = float(data.get("latitude"))
            lng = float(data.get("longitude"))
            accuracy = float(data.get("accuracy") or 15.0)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "Invalid latitude or longitude coordinates."}), 400

        if not (-90.0 <= lat <= 90.0 and -180.0 <= lng <= 180.0):
            return jsonify({"ok": False, "error": "Coordinates out of valid geographic bounds."}), 400

        source = clean_text(data.get("source", "browser_geolocation"), 40)
        client_resolved = clean_text(data.get("resolved_address", ""), 280)

        # Reject legacy synthetic placeholder strings so we never store fake addresses
        placeholder_prefixes = (
            "Browser Session Fix",
            "Active Browser Geolocation Fix",
            "Smart City Wi-Fi/Browser Check-In",
            "[SAMPLE DEMO] Smart City Wi-Fi/Browser Check-In",
        )
        if client_resolved and any(client_resolved.startswith(p) for p in placeholder_prefixes):
            client_resolved = ""

        now = utc_now_str()
        if client_resolved and client_resolved != "Address unavailable":
            readable_address = client_resolved
            try:
                db.execute(
                    """
                    INSERT OR REPLACE INTO geocoding_cache (lat_r, lng_r, readable_address, updated_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (round(lat, 4), round(lng, 4), readable_address, now_ist_str()),
                )
            except Exception:
                pass
        else:
            readable_address = reverse_geocode_coordinates(lat, lng, conn=db)

        if not readable_address:
            readable_address = "Address unavailable"

        label = readable_address
        recorded_at_local = format_local_time(now)
        map_links = build_map_links(lat, lng)
        sos_message = format_sos_alert_message(
            device_name=device["device_name"],
            brand=device["brand"],
            model=device["model"],
            readable_address=readable_address,
            lat=lat,
            lng=lng,
            accuracy=accuracy,
            recorded_at_str=now,
            is_live=True,
        )

        db.execute(
            """
            INSERT INTO location_updates (device_id, user_id, latitude, longitude, accuracy, source, location_label, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (device_id, g.current_user["id"], lat, lng, accuracy, source, label, now),
        )
        db.execute(
            """
            UPDATE devices
            SET last_lat = ?, last_lng = ?, last_accuracy = ?, last_location_label = ?, last_location_at = ?, updated_at = ?
            WHERE id = ? AND user_id = ?
            """,
            (lat, lng, accuracy, label, now, now, device_id, g.current_user["id"]),
        )
        log_audit(
            db,
            g.current_user["id"],
            g.current_user["email"],
            g.current_user["role"],
            "LOCATION_RECORDED",
            "device",
            str(device_id),
            f"Recorded live location ({lat:.5f}, {lng:.5f}, ±{accuracy:.0f}m) -> '{readable_address}' via {source}.",
            request.remote_addr or "127.0.0.1",
        )
        db.commit()

        return jsonify({
            "ok": True,
            "device_id": device_id,
            "latitude": lat,
            "longitude": lng,
            "dms_coordinates": format_dms_coordinates(lat, lng),
            "accuracy": accuracy,
            "readable_address": readable_address,
            "location_label": label,
            "recorded_at": now,
            "recorded_at_local": recorded_at_local,
            "is_live": True,
            "map_links": map_links,
            "sos_message": sos_message,
            "source": source,
        })

    @app.route("/api/location/device/<int:device_id>")
    @login_required
    def api_get_device_location(device_id: int):
        db = get_db()
        device = db.execute(
            "SELECT * FROM devices WHERE id = ? AND user_id = ?",
            (device_id, g.current_user["id"]),
        ).fetchone()
        if not device:
            return jsonify({"ok": False, "error": "Unauthorized access to device location."}), 403

        updates = db.execute(
            """
            SELECT latitude, longitude, accuracy, source, location_label, recorded_at
            FROM location_updates
            WHERE device_id = ? AND user_id = ?
            ORDER BY recorded_at DESC, id DESC
            LIMIT 10
            """,
            (device_id, g.current_user["id"]),
        ).fetchall()

        readable_addr = device["last_location_label"] or "Address unavailable"
        map_links = build_map_links(device["last_lat"], device["last_lng"])
        sos_message = ""
        if device["last_lat"] is not None and device["last_lng"] is not None:
            sos_message = format_sos_alert_message(
                device_name=device["device_name"],
                brand=device["brand"],
                model=device["model"],
                readable_address=readable_addr,
                lat=device["last_lat"],
                lng=device["last_lng"],
                accuracy=device["last_accuracy"],
                recorded_at_str=device["last_location_at"],
                is_live=False,
            )

        history_list = []
        for u in updates:
            item = dict(u)
            item["recorded_at_local"] = format_local_time(u["recorded_at"])
            item["map_links"] = build_map_links(u["latitude"], u["longitude"])
            history_list.append(item)

        return jsonify({
            "ok": True,
            "device": {
                "id": device["id"],
                "device_name": device["device_name"],
                "brand": device["brand"],
                "model": device["model"],
                "status": device["status"],
                "location_sharing_enabled": bool(device["location_sharing_enabled"]),
                "last_lat": device["last_lat"],
                "last_lng": device["last_lng"],
                "dms_coordinates": format_dms_coordinates(device["last_lat"], device["last_lng"]),
                "last_accuracy": device["last_accuracy"],
                "readable_address": readable_addr,
                "last_location_label": readable_addr,
                "last_location_at": device["last_location_at"],
                "last_location_at_local": format_local_time(device["last_location_at"]),
                "is_live": False,
                "map_links": map_links,
                "sos_message": sos_message,
            },
            "history": history_list,
        })

    @app.route("/api/location/sos", methods=["POST"])
    @login_required
    @rate_limit("location_sos", max_requests=15, window_seconds=60)
    def api_location_sos():
        data = request.get_json(silent=True) or {}
        device_id = data.get("device_id")
        is_live = bool(data.get("is_live", False))
        trusted_contact = clean_text(data.get("trusted_contact", ""), 120)

        db = get_db()
        device = db.execute(
            "SELECT * FROM devices WHERE id = ? AND user_id = ?",
            (device_id, g.current_user["id"]),
        ).fetchone()
        if not device:
            return jsonify({"ok": False, "error": "Device not found or unauthorized."}), 403

        if device["last_lat"] is None or device["last_lng"] is None:
            return jsonify({
                "ok": False,
                "error": "No recorded GPS coordinates are available for this device yet.",
            }), 400

        readable_address = device["last_location_label"] or reverse_geocode_coordinates(
            device["last_lat"], device["last_lng"], conn=db
        )
        sos_text = format_sos_alert_message(
            device_name=device["device_name"],
            brand=device["brand"],
            model=device["model"],
            readable_address=readable_address,
            lat=device["last_lat"],
            lng=device["last_lng"],
            accuracy=device["last_accuracy"],
            recorded_at_str=device["last_location_at"],
            is_live=is_live,
        )
        now = utc_now_str()
        cur = db.cursor()
        cur.execute(
            """
            INSERT INTO sos_alerts (
                user_id, device_id, trusted_contact, is_live,
                latitude, longitude, accuracy, readable_address, sos_message, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                g.current_user["id"],
                device_id,
                trusted_contact,
                1 if is_live else 0,
                device["last_lat"],
                device["last_lng"],
                device["last_accuracy"] or 15.0,
                readable_address,
                sos_text,
                now,
            ),
        )
        sos_id = cur.lastrowid

        log_audit(
            db,
            g.current_user["id"],
            g.current_user["email"],
            g.current_user["role"],
            "TRUSTED_CONTACT_SOS_PREPARED",
            "device",
            str(device_id),
            f"Persisted Trusted Contact SOS alert #{sos_id} ({'LIVE' if is_live else 'LAST RECORDED'}) for '{device['device_name']}'"
            + (f" -> {trusted_contact}" if trusted_contact else ""),
            request.remote_addr or "127.0.0.1",
        )
        db.commit()

        return jsonify({
            "ok": True,
            "sos_id": sos_id,
            "device_id": device_id,
            "is_live": is_live,
            "trusted_contact": trusted_contact,
            "readable_address": readable_address,
            "recorded_at_local": format_local_time(device["last_location_at"]),
            "dispatched_at_local": format_local_time(now),
            "map_links": build_map_links(device["last_lat"], device["last_lng"]),
            "sos_message": sos_text,
        })

    # -------------------------------------------------------------------------
    # PAGE 10: Lost Mode and Theft-Reporting Page
    # -------------------------------------------------------------------------
    @app.route("/lost-mode", methods=["GET", "POST"])
    @login_required
    def lost_mode_page():
        db = get_db()
        uid = g.current_user["id"]
        devices = db.execute(
            "SELECT * FROM devices WHERE user_id = ? ORDER BY id ASC", (uid,)
        ).fetchall()

        selected_device_id = request.args.get("device_id", type=int)
        verified_contacts = db.execute(
            """
            SELECT * FROM trusted_contacts
            WHERE user_id = ? AND verification_status = 'Verified' AND consent_confirmed = 1
            ORDER BY id ASC
            """,
            (uid,),
        ).fetchall()
        recent_lost_reports = db.execute(
            """
            SELECT lr.*, d.device_name, d.brand, d.model, rc.case_number, rc.status AS case_status
            FROM lost_reports lr
            JOIN devices d ON d.id = lr.device_id
            LEFT JOIN recovery_cases rc ON rc.lost_report_id = lr.id
            WHERE lr.user_id = ?
            ORDER BY lr.created_at DESC
            LIMIT 8
            """,
            (uid,),
        ).fetchall()

        if request.method == "POST":
            device_id = request.form.get("device_id", type=int)
            incident_type = clean_text(request.form.get("incident_type", "Lost"), 20)
            incident_time = clean_text(request.form.get("incident_time", ""), 60)
            last_known_location = clean_text(request.form.get("last_known_location", ""), 200)
            description = clean_text(request.form.get("description", ""), 1000)
            distinguishing_features = clean_text(request.form.get("distinguishing_features", ""), 400)
            lock_screen_notice = clean_text(request.form.get("lock_screen_notice", ""), 200)
            notify_family = request.form.get("notify_family_contacts") == "on"
            selected_contact_ids = [
                int(x) for x in request.form.getlist("family_contact_ids") if str(x).isdigit()
            ]

            device = db.execute(
                "SELECT * FROM devices WHERE id = ? AND user_id = ?",
                (device_id, uid),
            ).fetchone()
            if not device:
                abort(403, description="You can only activate Lost Mode for your own registered devices.")

            # Prevent duplicate/conflicting open recovery cases for the same device
            existing_open_case = db.execute(
                """
                SELECT case_number, status
                FROM recovery_cases
                WHERE device_id = ? AND user_id = ? AND status NOT IN ('Recovered', 'Closed', 'Rejected')
                ORDER BY id DESC
                LIMIT 1
                """,
                (device_id, uid),
            ).fetchone()
            if existing_open_case:
                flash(
                    f"Device '{device['device_name']}' already has an active recovery case "
                    f"({existing_open_case['case_number']} — {existing_open_case['status']}). "
                    f"Duplicate submission prevented.",
                    "warning",
                )
                return redirect(url_for("case_details", case_number=existing_open_case["case_number"]))

            if incident_type not in ("Lost", "Stolen"):
                incident_type = "Lost"

            errors = []
            if not incident_time:
                errors.append("Please provide the approximate date and time of the incident.")
            if len(last_known_location) < 3:
                errors.append("Please specify the last known location or area.")
            if len(description) < 10:
                errors.append("Please enter a clear incident description (at least 10 characters).")

            if errors:
                for err in errors:
                    flash(err, "error")
                return render_template(
                    "lost_mode.html",
                    devices=devices,
                    selected_device_id=device_id,
                    verified_contacts=verified_contacts,
                    recent_lost_reports=recent_lost_reports,
                    form_data=request.form,
                )

            now = utc_now_str()
            if not lock_screen_notice:
                lock_screen_notice = f"LOST MODE ACTIVE: {device['brand']} {device['model']} reported missing via SecurePhone."

            # Optional fresh browser GPS coordinates obtained with permission during Lost Mode activation
            fresh_lat_raw = request.form.get("fresh_lat", "").strip()
            fresh_lng_raw = request.form.get("fresh_lng", "").strip()
            fresh_acc_raw = request.form.get("fresh_accuracy", "15").strip()
            if fresh_lat_raw and fresh_lng_raw and device["location_sharing_enabled"]:
                try:
                    f_lat = float(fresh_lat_raw)
                    f_lng = float(fresh_lng_raw)
                    f_acc = float(fresh_acc_raw or 15.0)
                    if -90.0 <= f_lat <= 90.0 and -180.0 <= f_lng <= 180.0:
                        f_addr = reverse_geocode_coordinates(f_lat, f_lng, conn=db)
                        if f_addr and f_addr != "Address unavailable":
                            last_known_location = f_addr
                        db.execute(
                            """
                            INSERT INTO location_updates (device_id, user_id, latitude, longitude, accuracy, source, location_label, recorded_at)
                            VALUES (?, ?, ?, ?, ?, 'lost_mode_browser_gps', ?, ?)
                            """,
                            (device_id, uid, f_lat, f_lng, f_acc, last_known_location, now),
                        )
                        db.execute(
                            """
                            UPDATE devices
                            SET last_lat = ?, last_lng = ?, last_accuracy = ?, last_location_label = ?, last_location_at = ?, updated_at = ?
                            WHERE id = ? AND user_id = ?
                            """,
                            (f_lat, f_lng, f_acc, last_known_location, now, now, device_id, uid),
                        )
                        device = db.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
                except (TypeError, ValueError):
                    pass

            # Update device status to Lost
            db.execute(
                """
                UPDATE devices
                SET status = 'Lost', lock_screen_notice = ?, updated_at = ?
                WHERE id = ? AND user_id = ?
                """,
                (lock_screen_notice, now, device_id, uid),
            )

            # Create Lost Report
            cur = db.cursor()
            cur.execute(
                """
                INSERT INTO lost_reports (
                    user_id, device_id, incident_type, incident_time, last_known_location,
                    last_lat, last_lng, description, distinguishing_features, status,
                    is_sample, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', 0, ?, ?)
                """,
                (
                    uid,
                    device_id,
                    incident_type,
                    incident_time,
                    last_known_location,
                    device["last_lat"],
                    device["last_lng"],
                    description,
                    distinguishing_features,
                    now,
                    now,
                ),
            )
            lost_report_id = cur.lastrowid

            # Generate Unique Recovery Case
            case_number = generate_unique_case_number(db)
            cur.execute(
                """
                INSERT INTO recovery_cases (
                    case_number, lost_report_id, device_id, user_id, status,
                    ownership_verified, verification_notes, is_sample, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'Pending', 0, 'Lost Mode activated by device owner. Awaiting verification and matching.', 0, ?, ?)
                """,
                (case_number, lost_report_id, device_id, uid, now, now),
            )
            case_id = cur.lastrowid

            # Record initial Recovery Status History
            cur.execute(
                """
                INSERT INTO recovery_status_history (
                    case_id, old_status, new_status, changed_by_user_id, actor_role, note, created_at
                ) VALUES (?, NULL, 'Pending', ?, 'owner', ?, ?)
                """,
                (
                    case_id,
                    uid,
                    f"Lost Mode activated ({incident_type} report submitted). Recovery case {case_number} generated.",
                    now,
                ),
            )

            # Run automated Lost-and-Found matching against existing Found Reports
            new_matches = run_matching_engine(db)

            # If owner confirmed Family Emergency Sharing during Lost Mode activation, create the
            # secure tracking session. SMS is NOT sent here: the AI trusted-contact alert below is
            # the single notification for this Lost Mode event (prevents double texts).
            family_note = ""
            family_share_url = ""
            if notify_family:
                updated_dev = db.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
                share_outcome = start_or_notify_family_sharing(
                    conn=db,
                    user_row=g.current_user,
                    device_row=dict(updated_dev),
                    contact_ids=selected_contact_ids if selected_contact_ids else None,
                    case_id=case_id,
                    case_number=case_number,
                    created_reason=f"Lost Mode Activation ({case_number})",
                    base_url=request.host_url.rstrip("/"),
                    dispatch_alerts=False,
                )
                family_share_url = share_outcome["family_share_url"]
                family_note = " Family Emergency Sharing started (secure tracking link created)."
                log_audit(
                    db,
                    uid,
                    g.current_user["email"],
                    g.current_user["role"],
                    "FAMILY_SHARE_STARTED",
                    "recovery_case",
                    case_number,
                    f"Started Family Emergency Sharing for '{device['device_name']}' (Session #{share_outcome['session_id']}).",
                    request.remote_addr or "127.0.0.1",
                )

            log_audit(
                db,
                uid,
                g.current_user["email"],
                g.current_user["role"],
                "LOST_MODE_ACTIVATED",
                "recovery_case",
                case_number,
                f"Activated Lost Mode for '{device['device_name']}' ({incident_type}). Case {case_number} created ({new_matches} potential matches flagged).{family_note}",
                request.remote_addr or "127.0.0.1",
            )
            # Persist the case first so AI/SMS failures can never undo Lost Mode activation
            db.commit()

            # AI-powered trusted contact alert (automatic on Lost Mode activation)
            ai_note = ""
            try:
                updated_dev = db.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
                ai_outcome = trigger_lost_mode_ai_alerts(
                    conn=db,
                    user_row=g.current_user,
                    device_row=dict(updated_dev),
                    case_id=case_id,
                    case_number=case_number,
                    lost_report_id=lost_report_id,
                    incident_type=incident_type,
                    incident_time=incident_time,
                    contact_ids=selected_contact_ids if selected_contact_ids else None,
                    family_share_url=family_share_url,
                )
                ai_note = " " + summarize_ai_alert_outcome(ai_outcome)
                log_audit(
                    db,
                    uid,
                    g.current_user["email"],
                    g.current_user["role"],
                    "AI_TRUSTED_ALERT_TRIGGERED",
                    "recovery_case",
                    case_number,
                    f"AI trusted-contact alert processed for case {case_number}: "
                    + (", ".join(f"{a['contact_name']}={a['notification_status']} ({a['generation_status']})" for a in ai_outcome["alerts"]) or "no authorized contacts")
                    + f"; duplicates prevented={ai_outcome['duplicates_prevented']}.",
                    request.remote_addr or "127.0.0.1",
                )
                db.commit()
            except Exception as exc:  # never let AI/SMS errors break Lost Mode
                db.rollback()
                app.logger.exception("AI trusted-contact alert failed for case %s", case_number)
                ai_note = f" AI trusted-contact alert could not be processed ({str(exc)[:120]}). You can retry from the case page."

            flash(
                f"Lost Mode activated for '{device['device_name']}'. Recovery Case {case_number} has been created.{family_note}{ai_note}",
                "success",
            )
            return redirect(url_for("case_details", case_number=case_number))

        return render_template(
            "lost_mode.html",
            devices=devices,
            selected_device_id=selected_device_id,
            verified_contacts=verified_contacts,
            recent_lost_reports=recent_lost_reports,
            form_data={},
        )

    # -------------------------------------------------------------------------
    # PAGE 11: Found-Phone Reporting Page
    # -------------------------------------------------------------------------
    @app.route("/found-report", methods=["GET", "POST"])
    @rate_limit("found_report", max_requests=12, window_seconds=60)
    def found_report_page():
        if request.method == "POST":
            reporter_name = clean_text(request.form.get("reporter_name", ""), 100)
            reporter_contact = clean_text(request.form.get("reporter_contact", ""), 120)
            brand = clean_text(request.form.get("brand", ""), 60)
            model = clean_text(request.form.get("model", ""), 80)
            color = clean_text(request.form.get("color", ""), 40)
            identifier_last4 = sanitize_last4(request.form.get("identifier_last4", ""))
            found_location = clean_text(request.form.get("found_location", ""), 200)
            date_found = clean_text(request.form.get("date_found", ""), 40)
            description = clean_text(request.form.get("description", ""), 1000)
            current_custody = clean_text(
                request.form.get("current_custody", "Smart City Precinct Desk / Finder Hold"),
                150,
            )

            if g.current_user and not reporter_name:
                reporter_name = g.current_user["full_name"]
            if g.current_user and not reporter_contact:
                reporter_contact = g.current_user["email"]

            errors = []
            if len(reporter_name) < 2:
                errors.append("Please provide your name so recovery administrators can coordinate handoff.")
            if len(reporter_contact) < 5:
                errors.append("Please provide a valid contact email or phone number for administrators.")
            if not brand or not model or not color:
                errors.append("Brand, approximate model, and color are required.")
            if len(found_location) < 3:
                errors.append("General found location is required.")
            if not date_found:
                errors.append("Date found is required.")
            if len(description) < 10:
                errors.append("Please provide a brief description of the found phone or its condition.")

            if errors:
                for err in errors:
                    flash(err, "error")
                return render_template("found_report.html", form_data=request.form)

            now = utc_now_str()
            db = get_db()
            cur = db.cursor()
            uid = g.current_user["id"] if g.current_user else None

            cur.execute(
                """
                INSERT INTO found_reports (
                    reported_by_user_id, reporter_name, reporter_contact, brand, model, color,
                    identifier_last4, found_location, date_found, description, current_custody,
                    status, is_sample, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending Review', 0, ?, ?)
                """,
                (
                    uid,
                    reporter_name,
                    reporter_contact,
                    brand,
                    model,
                    color,
                    identifier_last4,
                    found_location,
                    date_found,
                    description,
                    current_custody,
                    now,
                    now,
                ),
            )
            found_id = cur.lastrowid

            # Run automated Lost-and-Found matching
            new_matches = run_matching_engine(db)

            log_audit(
                db,
                uid,
                g.current_user["email"] if g.current_user else reporter_contact,
                g.current_user["role"] if g.current_user else "public_finder",
                "FOUND_REPORT_SUBMITTED",
                "found_report",
                str(found_id),
                f"Submitted found-device report #{found_id} ({brand} {model}, {color}) at '{found_location}'. Flagged {new_matches} new unverified match(es).",
                request.remote_addr or "127.0.0.1",
            )
            db.commit()

            flash(
                f"Thank you! Found-device report #{found_id} has been recorded. "
                f"Our automated matcher identified {new_matches} potential unverified match(es) for administrator review.",
                "success",
            )
            if g.current_user:
                return redirect(url_for("my_reports"))
            return redirect(url_for("found_report_page", submitted=found_id))

        return render_template("found_report.html", form_data={})

    # -------------------------------------------------------------------------
    # PAGE 12: My Reports Page
    # -------------------------------------------------------------------------
    @app.route("/my-reports")
    @login_required
    def my_reports():
        db = get_db()
        uid = g.current_user["id"]
        status_filter = clean_text(request.args.get("status", ""), 40)

        query = """
            SELECT lr.*, d.device_name, d.brand, d.model, d.color,
                   rc.case_number, rc.status AS case_status, rc.ownership_verified,
                   (SELECT COUNT(*) FROM potential_matches pm WHERE pm.case_id = rc.id AND pm.status != 'Rejected') AS match_count
            FROM lost_reports lr
            JOIN devices d ON d.id = lr.device_id
            LEFT JOIN recovery_cases rc ON rc.lost_report_id = lr.id
            WHERE lr.user_id = ?
        """
        params: list = [uid]
        if status_filter:
            query += " AND rc.status = ?"
            params.append(status_filter)
        query += " ORDER BY lr.created_at DESC"

        lost_reports = db.execute(query, params).fetchall()

        my_found_reports = db.execute(
            """
            SELECT * FROM found_reports
            WHERE reported_by_user_id = ?
            ORDER BY created_at DESC
            """,
            (uid,),
        ).fetchall()

        return render_template(
            "my_reports.html",
            lost_reports=lost_reports,
            my_found_reports=my_found_reports,
            status_filter=status_filter,
        )

    # -------------------------------------------------------------------------
    # PAGE 13: Recovery Case Details Page
    # -------------------------------------------------------------------------
    @app.route("/cases/<case_number>")
    @login_required
    def case_details(case_number: str):
        db = get_db()
        case = db.execute(
            """
            SELECT rc.*,
                   lr.incident_type, lr.incident_time, lr.last_known_location,
                   lr.last_lat, lr.last_lng,
                   lr.description AS incident_description, lr.distinguishing_features,
                   d.device_name, d.brand, d.model, d.color, d.os_type, d.identifier_last4, d.status AS device_status,
                   d.last_lat AS device_lat, d.last_lng AS device_lng, d.last_accuracy AS device_accuracy,
                   d.last_location_label AS device_location_label, d.last_location_at AS device_location_at,
                   u.full_name AS owner_name, u.email AS owner_email
            FROM recovery_cases rc
            JOIN lost_reports lr ON lr.id = rc.lost_report_id
            JOIN devices d ON d.id = rc.device_id
            JOIN users u ON u.id = rc.user_id
            WHERE rc.case_number = ?
            """,
            (case_number,),
        ).fetchone()

        if not case:
            abort(404, description="Recovery case not found.")

        # Enforce strict authorization: Only the case owner or an administrator can view
        if g.current_user["role"] != "admin" and case["user_id"] != g.current_user["id"]:
            abort(403, description="Access denied: You are not authorized to view another owner's recovery case.")

        # Fetch potential matches (sanitized for owners: never expose finder's private contact details to owners directly)
        matches = db.execute(
            """
            SELECT pm.*,
                   fr.brand AS found_brand, fr.model AS found_model, fr.color AS found_color,
                   fr.found_location, fr.date_found, fr.description AS found_description,
                   fr.current_custody, fr.status AS found_status, fr.is_sample AS found_is_sample,
                   fr.reporter_name, fr.reporter_contact
            FROM potential_matches pm
            JOIN found_reports fr ON fr.id = pm.found_report_id
            WHERE pm.case_id = ?
            ORDER BY pm.confidence_score DESC, pm.created_at DESC
            """,
            (case["id"],),
        ).fetchall()

        history = db.execute(
            """
            SELECT rsh.*, u.full_name AS actor_name
            FROM recovery_status_history rsh
            LEFT JOIN users u ON u.id = rsh.changed_by_user_id
            WHERE rsh.case_id = ?
            ORDER BY rsh.id ASC
            """,
            (case["id"],),
        ).fetchall()

        active_family_session = db.execute(
            """
            SELECT * FROM family_share_sessions
            WHERE device_id = ? AND user_id = ? AND status = 'Active'
            ORDER BY id DESC LIMIT 1
            """,
            (case["device_id"], case["user_id"]),
        ).fetchone()

        family_alerts = db.execute(
            """
            SELECT * FROM family_alert_logs
            WHERE device_id = ? AND user_id = ?
            ORDER BY id DESC LIMIT 10
            """,
            (case["device_id"], case["user_id"]),
        ).fetchall()

        verified_contacts = db.execute(
            """
            SELECT * FROM trusted_contacts
            WHERE user_id = ? AND verification_status = 'Verified' AND consent_confirmed = 1
            ORDER BY id ASC
            """,
            (case["user_id"],),
        ).fetchall()

        ai_alerts = db.execute(
            "SELECT * FROM ai_trusted_alerts WHERE case_id = ? ORDER BY id DESC",
            (case["id"],),
        ).fetchall()

        return render_template(
            "case_details.html",
            case=case,
            matches=matches,
            history=history,
            active_family_session=active_family_session,
            family_alerts=family_alerts,
            verified_contacts=verified_contacts,
            ai_alerts=ai_alerts,
        )

    # -------------------------------------------------------------------------
    # PAGE 14: Administrator Dashboard
    # -------------------------------------------------------------------------
    @app.route("/admin")
    @admin_required
    def admin_dashboard():
        db = get_db()

        metrics = {
            "total_users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "total_devices": db.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
            "open_lost_reports": db.execute(
                "SELECT COUNT(*) FROM lost_reports WHERE status IN ('Open', 'Under Verification', 'Matched')"
            ).fetchone()[0],
            "pending_found_reports": db.execute(
                "SELECT COUNT(*) FROM found_reports WHERE status IN ('Pending Review', 'Under Verification')"
            ).fetchone()[0],
            "unverified_matches": db.execute(
                "SELECT COUNT(*) FROM potential_matches WHERE status IN ('Unverified', 'Under Verification')"
            ).fetchone()[0],
            "recovered_cases": db.execute(
                "SELECT COUNT(*) FROM recovery_cases WHERE status = 'Recovered'"
            ).fetchone()[0],
        }

        status_rows = db.execute(
            "SELECT status, COUNT(*) AS count FROM recovery_cases GROUP BY status"
        ).fetchall()
        cases_by_status = {r["status"]: r["count"] for r in status_rows}
        for st in ("Pending", "Under Verification", "Match Found", "Recovered", "Closed", "Rejected"):
            cases_by_status.setdefault(st, 0)

        pending_matches = db.execute(
            """
            SELECT pm.*, rc.case_number, rc.status AS case_status,
                   d.brand AS lost_brand, d.model AS lost_model, d.color AS lost_color,
                   fr.brand AS found_brand, fr.model AS found_model, fr.color AS found_color,
                   fr.found_location, fr.date_found
            FROM potential_matches pm
            JOIN recovery_cases rc ON rc.id = pm.case_id
            JOIN devices d ON d.id = rc.device_id
            JOIN found_reports fr ON fr.id = pm.found_report_id
            WHERE pm.status IN ('Unverified', 'Under Verification')
            ORDER BY pm.confidence_score DESC
            LIMIT 6
            """
        ).fetchall()

        recent_audits = db.execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 10"
        ).fetchall()

        return render_template(
            "admin_dashboard.html",
            metrics=metrics,
            cases_by_status=cases_by_status,
            pending_matches=pending_matches,
            recent_audits=recent_audits,
        )

    # -------------------------------------------------------------------------
    # PAGE 15: Administrative Report, Matching, and Recovery-Management Page
    # -------------------------------------------------------------------------
    @app.route("/admin/management")
    @admin_required
    def admin_management():
        db = get_db()
        tab = clean_text(request.args.get("tab", "cases"), 30)
        q = clean_text(request.args.get("q", ""), 100)
        status_filter = clean_text(request.args.get("status", ""), 40)
        page = max(1, request.args.get("page", 1, type=int))
        per_page = 10
        offset = (page - 1) * per_page

        # 1. Recovery Cases query with search & status filter
        case_sql = """
            SELECT rc.*, d.device_name, d.brand, d.model, d.color, d.identifier_last4,
                   u.full_name AS owner_name, u.email AS owner_email,
                   lr.incident_type, lr.last_known_location,
                   (SELECT COUNT(*) FROM potential_matches pm WHERE pm.case_id = rc.id) AS total_matches
            FROM recovery_cases rc
            JOIN devices d ON d.id = rc.device_id
            JOIN users u ON u.id = rc.user_id
            JOIN lost_reports lr ON lr.id = rc.lost_report_id
            WHERE 1=1
        """
        case_params: list = []
        if q:
            case_sql += " AND (rc.case_number LIKE ? OR d.brand LIKE ? OR d.model LIKE ? OR u.full_name LIKE ? OR lr.last_known_location LIKE ?)"
            like_q = f"%{q}%"
            case_params.extend([like_q, like_q, like_q, like_q, like_q])
        if status_filter and tab == "cases":
            case_sql += " AND rc.status = ?"
            case_params.append(status_filter)
        case_sql += " ORDER BY rc.updated_at DESC LIMIT ? OFFSET ?"
        cases = db.execute(case_sql, case_params + [per_page, offset]).fetchall()

        # 2. Potential Matches query
        match_sql = """
            SELECT pm.*,
                   rc.case_number, rc.status AS case_status, rc.ownership_verified,
                   d.brand AS lost_brand, d.model AS lost_model, d.color AS lost_color, d.identifier_last4 AS lost_last4,
                   lr.last_known_location, lr.distinguishing_features,
                   fr.brand AS found_brand, fr.model AS found_model, fr.color AS found_color,
                   fr.identifier_last4 AS found_last4, fr.found_location, fr.date_found,
                   fr.description AS found_description, fr.current_custody, fr.reporter_name, fr.reporter_contact
            FROM potential_matches pm
            JOIN recovery_cases rc ON rc.id = pm.case_id
            JOIN devices d ON d.id = rc.device_id
            JOIN lost_reports lr ON lr.id = pm.lost_report_id
            JOIN found_reports fr ON fr.id = pm.found_report_id
            WHERE 1=1
        """
        match_params: list = []
        if status_filter and tab == "matches":
            match_sql += " AND pm.status = ?"
            match_params.append(status_filter)
        match_sql += " ORDER BY pm.confidence_score DESC, pm.updated_at DESC"
        matches = db.execute(match_sql, match_params).fetchall()

        # 3. Found Reports query
        found_sql = "SELECT * FROM found_reports WHERE 1=1"
        found_params: list = []
        if q and tab == "found":
            found_sql += " AND (brand LIKE ? OR model LIKE ? OR found_location LIKE ? OR description LIKE ?)"
            like_q = f"%{q}%"
            found_params.extend([like_q, like_q, like_q, like_q])
        if status_filter and tab == "found":
            found_sql += " AND status = ?"
            found_params.append(status_filter)
        found_sql += " ORDER BY created_at DESC"
        found_reports = db.execute(found_sql, found_params).fetchall()

        # 4. Audit logs
        audits = db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 30").fetchall()

        return render_template(
            "admin_management.html",
            tab=tab,
            q=q,
            status_filter=status_filter,
            page=page,
            cases=cases,
            matches=matches,
            found_reports=found_reports,
            audits=audits,
        )

    @app.route("/admin/matches/<int:match_id>/review", methods=["POST"])
    @admin_required
    def admin_review_match(match_id: int):
        decision = clean_text(request.form.get("decision", ""), 30)
        review_notes = clean_text(request.form.get("review_notes", ""), 500)

        if decision not in ("Approved", "Under Verification", "Rejected"):
            flash("Invalid match review action.", "error")
            return redirect(url_for("admin_management", tab="matches"))

        db = get_db()
        match = db.execute(
            """
            SELECT pm.*, rc.case_number, rc.status AS case_status
            FROM potential_matches pm
            JOIN recovery_cases rc ON rc.id = pm.case_id
            WHERE pm.id = ?
            """,
            (match_id,),
        ).fetchone()
        if not match:
            abort(404, description="Potential match record not found.")

        now = utc_now_str()
        db.execute(
            """
            UPDATE potential_matches
            SET status = ?, reviewed_by = ?, review_notes = ?, updated_at = ?
            WHERE id = ?
            """,
            (decision, g.current_user["id"], review_notes, now, match_id),
        )

        # Synchronize Recovery Case and Found Report statuses based on admin decision
        old_case_status = match["case_status"]
        new_case_status = old_case_status
        if decision == "Approved":
            new_case_status = "Match Found"
            db.execute(
                """
                UPDATE recovery_cases
                SET status = 'Match Found', matched_found_report_id = ?, verification_notes = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    match["found_report_id"],
                    review_notes or "Administrator approved found-device match. Ownership verification required before handoff.",
                    now,
                    match["case_id"],
                ),
            )
            db.execute(
                "UPDATE found_reports SET status = 'Matched', updated_at = ? WHERE id = ?",
                (now, match["found_report_id"]),
            )
            db.execute(
                "UPDATE lost_reports SET status = 'Matched', updated_at = ? WHERE id = ?",
                (now, match["lost_report_id"]),
            )
        elif decision == "Under Verification":
            new_case_status = "Under Verification"
            db.execute(
                "UPDATE recovery_cases SET status = 'Under Verification', verification_notes = ?, updated_at = ? WHERE id = ?",
                (review_notes or "Further verification requested by administrator.", now, match["case_id"]),
            )
            db.execute(
                "UPDATE found_reports SET status = 'Under Verification', updated_at = ? WHERE id = ?",
                (now, match["found_report_id"]),
            )

        if new_case_status != old_case_status:
            db.execute(
                """
                INSERT INTO recovery_status_history (
                    case_id, old_status, new_status, changed_by_user_id, actor_role, note, created_at
                ) VALUES (?, ?, ?, ?, 'admin', ?, ?)
                """,
                (
                    match["case_id"],
                    old_case_status,
                    new_case_status,
                    g.current_user["id"],
                    f"Match #{match_id} marked '{decision}'. {review_notes}".strip(),
                    now,
                ),
            )

        log_audit(
            db,
            g.current_user["id"],
            g.current_user["email"],
            "admin",
            "MATCH_REVIEWED",
            "potential_match",
            str(match_id),
            f"Admin set match #{match_id} (Case {match['case_number']}) to '{decision}'. Notes: {review_notes}",
            request.remote_addr or "127.0.0.1",
        )
        db.commit()
        flash(f"Potential match #{match_id} updated to '{decision}'.", "success")
        return redirect(request.referrer or url_for("admin_management", tab="matches"))

    @app.route("/admin/cases/<case_number>/status", methods=["POST"])
    @admin_required
    def admin_update_case_status(case_number: str):
        new_status = clean_text(request.form.get("new_status", ""), 30)
        ownership_verified = 1 if request.form.get("ownership_verified") == "on" else 0
        note = clean_text(request.form.get("note", ""), 500)

        valid_statuses = ("Pending", "Under Verification", "Match Found", "Recovered", "Closed", "Rejected")
        if new_status not in valid_statuses:
            flash("Invalid recovery case status selected.", "error")
            return redirect(url_for("case_details", case_number=case_number))

        db = get_db()
        case = db.execute(
            "SELECT * FROM recovery_cases WHERE case_number = ?", (case_number,)
        ).fetchone()
        if not case:
            abort(404, description="Recovery case not found.")

        # Enforce requirement: Require reasonable ownership verification before marking a device as Returned/Recovered
        effective_verified = ownership_verified or case["ownership_verified"]
        if new_status == "Recovered" and not effective_verified:
            flash(
                "Ownership verification is required before marking a recovery case as 'Recovered'. "
                "Please confirm ownership verification (e.g., purchase receipt, box serial, or carrier proof).",
                "error",
            )
            return redirect(request.referrer or url_for("case_details", case_number=case_number))

        now = utc_now_str()
        old_status = case["status"]

        db.execute(
            """
            UPDATE recovery_cases
            SET status = ?, ownership_verified = ?, verification_notes = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                new_status,
                1 if effective_verified else 0,
                note or case["verification_notes"],
                now,
                case["id"],
            ),
        )

        # Synchronize related device, lost report, and found report statuses
        if new_status == "Recovered":
            db.execute(
                "UPDATE devices SET status = 'Recovered', updated_at = ? WHERE id = ?",
                (now, case["device_id"]),
            )
            db.execute(
                "UPDATE lost_reports SET status = 'Recovered', updated_at = ? WHERE id = ?",
                (now, case["lost_report_id"]),
            )
            if case["matched_found_report_id"]:
                db.execute(
                    "UPDATE found_reports SET status = 'Returned', updated_at = ? WHERE id = ?",
                    (now, case["matched_found_report_id"]),
                )
            stop_family_sharing_for_device(
                db,
                user_id=g.current_user["id"],
                device_id=case["device_id"],
                new_status="Stopped_Recovered",
                actor_role="admin",
                reason_note="Device marked as Recovered by administrator; emergency family location sharing stopped and access link revoked.",
            )
        elif new_status in ("Closed", "Rejected"):
            db.execute(
                "UPDATE lost_reports SET status = 'Closed', updated_at = ? WHERE id = ?",
                (now, case["lost_report_id"]),
            )
            stop_family_sharing_for_device(
                db,
                user_id=g.current_user["id"],
                device_id=case["device_id"],
                new_status="Revoked",
                actor_role="admin",
                reason_note=f"Case marked as {new_status} by administrator; emergency family sharing stopped.",
            )
        elif new_status == "Under Verification":
            db.execute(
                "UPDATE lost_reports SET status = 'Under Verification', updated_at = ? WHERE id = ?",
                (now, case["lost_report_id"]),
            )

        db.execute(
            """
            INSERT INTO recovery_status_history (
                case_id, old_status, new_status, changed_by_user_id, actor_role, note, created_at
            ) VALUES (?, ?, ?, ?, 'admin', ?, ?)
            """,
            (
                case["id"],
                old_status,
                new_status,
                g.current_user["id"],
                note or f"Status transitioned from {old_status} to {new_status} by administrator.",
                now,
            ),
        )

        log_audit(
            db,
            g.current_user["id"],
            g.current_user["email"],
            "admin",
            "CASE_STATUS_UPDATED",
            "recovery_case",
            case_number,
            f"Case {case_number} transitioned {old_status} -> {new_status} (OwnershipVerified={bool(effective_verified)}). Note: {note}",
            request.remote_addr or "127.0.0.1",
        )
        db.commit()
        flash(f"Recovery Case {case_number} updated to '{new_status}'.", "success")
        return redirect(request.referrer or url_for("case_details", case_number=case_number))

    @app.route("/admin/run-matching", methods=["POST"])
    @admin_required
    def admin_run_matching():
        db = get_db()
        new_matches = run_matching_engine(db)
        log_audit(
            db,
            g.current_user["id"],
            g.current_user["email"],
            "admin",
            "MATCHING_ENGINE_RUN",
            "system",
            "matcher",
            f"Manually executed Lost-and-Found matching scan ({new_matches} new match(es) discovered).",
            request.remote_addr or "127.0.0.1",
        )
        db.commit()
        flash(f"Matching scan completed: {new_matches} new potential match(es) identified.", "info")
        return redirect(url_for("admin_management", tab="matches"))

    @app.route("/admin/found-reports/<int:found_id>/status", methods=["POST"])
    @admin_required
    def admin_update_found_report(found_id: int):
        new_status = clean_text(request.form.get("new_status", ""), 30)
        custody = clean_text(request.form.get("current_custody", ""), 150)

        valid_found_statuses = ("Pending Review", "Under Verification", "Matched", "Returned", "Rejected")
        if new_status not in valid_found_statuses:
            flash("Invalid found-device report status.", "error")
            return redirect(url_for("admin_management", tab="found"))

        db = get_db()
        found_row = db.execute("SELECT * FROM found_reports WHERE id = ?", (found_id,)).fetchone()
        if not found_row:
            abort(404, description="Found-device report not found.")

        now = utc_now_str()
        effective_custody = custody or found_row["current_custody"]
        db.execute(
            """
            UPDATE found_reports
            SET status = ?, current_custody = ?, updated_at = ?
            WHERE id = ?
            """,
            (new_status, effective_custody, now, found_id),
        )
        log_audit(
            db,
            g.current_user["id"],
            g.current_user["email"],
            "admin",
            "FOUND_REPORT_UPDATED",
            "found_report",
            str(found_id),
            f"Updated found report #{found_id} status to '{new_status}' (Custody: '{effective_custody}').",
            request.remote_addr or "127.0.0.1",
        )
        db.commit()
        flash(f"Found-device report #{found_id} updated to '{new_status}'.", "success")
        return redirect(request.referrer or url_for("admin_management", tab="found"))

    # -------------------------------------------------------------------------
    # PAGE 16: Profile and Privacy Settings Page
    # -------------------------------------------------------------------------
    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile_page():
        db = get_db()
        uid = g.current_user["id"]

        if request.method == "POST":
            action = request.form.get("action", "update_profile")
            now = utc_now_str()

            if action == "update_profile":
                full_name = clean_text(request.form.get("full_name", ""), 100)
                phone_number = clean_text(request.form.get("phone_number", ""), 30)
                location_consent = 1 if request.form.get("location_consent") == "on" else 0
                privacy_alerts = 1 if request.form.get("privacy_alerts") == "on" else 0

                if len(full_name) < 2:
                    flash("Full name must be at least 2 characters.", "error")
                    return redirect(url_for("profile_page"))

                db.execute(
                    """
                    UPDATE users
                    SET full_name = ?, phone_number = ?, location_consent = ?, privacy_alerts = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (full_name, phone_number, location_consent, privacy_alerts, now, uid),
                )
                if not location_consent:
                    # Automatically disable active device location sharing if master consent is unchecked
                    db.execute(
                        "UPDATE devices SET location_sharing_enabled = 0, updated_at = ? WHERE user_id = ?",
                        (now, uid),
                    )
                log_audit(
                    db,
                    uid,
                    g.current_user["email"],
                    g.current_user["role"],
                    "PROFILE_UPDATED",
                    "user",
                    str(uid),
                    f"Updated profile and privacy preferences (LocationConsent={bool(location_consent)}).",
                    request.remote_addr or "127.0.0.1",
                )
                db.commit()
                session["user_name"] = full_name
                flash("Profile and privacy settings saved.", "success")

            elif action == "change_password":
                current_pw = request.form.get("current_password", "")
                new_pw = request.form.get("new_password", "")
                confirm_pw = request.form.get("confirm_password", "")

                user_row = db.execute("SELECT password_hash FROM users WHERE id = ?", (uid,)).fetchone()
                if not verify_password(user_row["password_hash"], current_pw):
                    flash("Current password is incorrect.", "error")
                    return redirect(url_for("profile_page"))
                if len(new_pw) < 8:
                    flash("New password must be at least 8 characters.", "error")
                    return redirect(url_for("profile_page"))
                if new_pw != confirm_pw:
                    flash("New passwords do not match.", "error")
                    return redirect(url_for("profile_page"))

                db.execute(
                    "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                    (hash_password(new_pw), now, uid),
                )
                log_audit(
                    db,
                    uid,
                    g.current_user["email"],
                    g.current_user["role"],
                    "PASSWORD_CHANGED",
                    "user",
                    str(uid),
                    "User updated account password.",
                    request.remote_addr or "127.0.0.1",
                )
                db.commit()
                flash("Password changed successfully.", "success")

            elif action == "revoke_all_location":
                db.execute(
                    "UPDATE devices SET location_sharing_enabled = 0, updated_at = ? WHERE user_id = ?",
                    (now, uid),
                )
                db.execute(
                    "UPDATE users SET location_consent = 0, updated_at = ? WHERE id = ?",
                    (now, uid),
                )
                db.execute(
                    "UPDATE family_share_sessions SET status = 'Revoked', stopped_at = ? WHERE user_id = ? AND status = 'Active'",
                    (now, uid),
                )
                log_audit(
                    db,
                    uid,
                    g.current_user["email"],
                    g.current_user["role"],
                    "LOCATION_REVOKED_ALL",
                    "user",
                    str(uid),
                    "Revoked location sharing and active family share tokens across all registered devices.",
                    request.remote_addr or "127.0.0.1",
                )
                db.commit()
                flash("Location sharing has been stopped across all of your devices and active family links have been revoked.", "info")

            elif action == "add_trusted_contact":
                contact_name = clean_text(request.form.get("contact_name", ""), 100)
                phone_number = clean_text(request.form.get("phone_number", ""), 30)
                relationship = clean_text(request.form.get("relationship", "Family"), 50) or "Family"
                notification_preference = clean_text(
                    request.form.get("notification_preference", "SMS + Secure Link"), 40
                )
                if notification_preference not in ("SMS", "SMS + Secure Link"):
                    notification_preference = "SMS + Secure Link"
                consent_confirmed = 1 if request.form.get("consent_confirmed") == "on" else 0
                min_interval = max(1, min(180, request.form.get("min_alert_interval_minutes", 15, type=int) or 15))
                assigned_device_ids = [
                    int(x) for x in request.form.getlist("assigned_device_ids") if str(x).isdigit()
                ]

                if len(contact_name) < 2:
                    flash("Trusted contact name must be at least 2 characters.", "error")
                    return redirect(url_for("profile_page"))
                if not is_valid_phone_number(phone_number):
                    flash("Please enter a valid phone number (7 to 15 digits) for the trusted contact.", "error")
                    return redirect(url_for("profile_page"))
                if not consent_confirmed:
                    flash(
                        "Explicit family contact consent confirmation is required before adding a trusted contact.",
                        "error",
                    )
                    return redirect(url_for("profile_page"))

                otp_code = generate_verification_otp()
                cur = db.cursor()
                cur.execute(
                    """
                    INSERT INTO trusted_contacts (
                        user_id, contact_name, phone_number, relationship, notification_preference,
                        consent_confirmed, verification_status, verification_code, verified_at,
                        min_alert_interval_minutes, is_sample, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 1, 'Pending Verification', ?, NULL, ?, 0, ?, ?)
                    """,
                    (
                        uid,
                        contact_name,
                        phone_number,
                        relationship,
                        notification_preference,
                        otp_code,
                        min_interval,
                        now,
                        now,
                    ),
                )
                new_cid = cur.lastrowid

                # Save device assignments (only for devices owned by current user)
                owner_devs = {
                    r["id"]
                    for r in db.execute("SELECT id FROM devices WHERE user_id = ?", (uid,)).fetchall()
                }
                for did in (assigned_device_ids or list(owner_devs)):
                    if did in owner_devs:
                        db.execute(
                            """
                            INSERT OR IGNORE INTO device_trusted_contacts (device_id, contact_id, user_id, created_at)
                            VALUES (?, ?, ?, ?)
                            """,
                            (did, new_cid, uid, now),
                        )

                log_audit(
                    db,
                    uid,
                    g.current_user["email"],
                    g.current_user["role"],
                    "TRUSTED_CONTACT_ADDED",
                    "trusted_contact",
                    str(new_cid),
                    f"Added trusted family contact '{contact_name}' ({relationship}). Verification required before emergency alerts.",
                    request.remote_addr or "127.0.0.1",
                )
                db.commit()
                flash(
                    f"Trusted contact '{contact_name}' added. Please complete phone verification using the verification code before sending emergency alerts.",
                    "success",
                )

            elif action == "verify_trusted_contact":
                contact_id = request.form.get("contact_id", type=int)
                entered_code = clean_text(request.form.get("verification_code", ""), 12)
                contact_row = db.execute(
                    "SELECT * FROM trusted_contacts WHERE id = ? AND user_id = ?",
                    (contact_id, uid),
                ).fetchone()
                if not contact_row:
                    abort(403, description="Unauthorized access to trusted contact.")

                if not entered_code or entered_code != contact_row["verification_code"]:
                    flash("Invalid verification code. Please check the 6-digit OTP code and try again.", "error")
                    return redirect(url_for("profile_page"))

                db.execute(
                    """
                    UPDATE trusted_contacts
                    SET verification_status = 'Verified', verified_at = ?, updated_at = ?
                    WHERE id = ? AND user_id = ?
                    """,
                    (now, now, contact_id, uid),
                )
                log_audit(
                    db,
                    uid,
                    g.current_user["email"],
                    g.current_user["role"],
                    "TRUSTED_CONTACT_VERIFIED",
                    "trusted_contact",
                    str(contact_id),
                    f"Verified phone number for trusted family contact '{contact_row['contact_name']}'.",
                    request.remote_addr or "127.0.0.1",
                )
                db.commit()
                flash(
                    f"Trusted family contact '{contact_row['contact_name']}' is now Verified and eligible for emergency location alerts.",
                    "success",
                )

            elif action == "edit_trusted_contact":
                contact_id = request.form.get("contact_id", type=int)
                contact_row = db.execute(
                    "SELECT * FROM trusted_contacts WHERE id = ? AND user_id = ?",
                    (contact_id, uid),
                ).fetchone()
                if not contact_row:
                    abort(403, description="Unauthorized access to trusted contact.")

                contact_name = clean_text(request.form.get("contact_name", ""), 100)
                phone_number = clean_text(request.form.get("phone_number", ""), 30)
                relationship = clean_text(request.form.get("relationship", "Family"), 50) or "Family"
                notification_preference = clean_text(
                    request.form.get("notification_preference", "SMS + Secure Link"), 40
                )
                if notification_preference not in ("SMS", "SMS + Secure Link"):
                    notification_preference = "SMS + Secure Link"
                min_interval = max(1, min(180, request.form.get("min_alert_interval_minutes", 15, type=int) or 15))
                assigned_device_ids = [
                    int(x) for x in request.form.getlist("assigned_device_ids") if str(x).isdigit()
                ]

                if len(contact_name) < 2 or not is_valid_phone_number(phone_number):
                    flash("Please provide a valid contact name and phone number.", "error")
                    return redirect(url_for("profile_page"))

                # If phone number changed, require re-verification
                new_status = contact_row["verification_status"]
                new_code = contact_row["verification_code"] or generate_verification_otp()
                if phone_number != contact_row["phone_number"]:
                    new_status = "Pending Verification"
                    new_code = generate_verification_otp()

                db.execute(
                    """
                    UPDATE trusted_contacts
                    SET contact_name = ?, phone_number = ?, relationship = ?, notification_preference = ?,
                        min_alert_interval_minutes = ?, verification_status = ?, verification_code = ?, updated_at = ?
                    WHERE id = ? AND user_id = ?
                    """,
                    (
                        contact_name,
                        phone_number,
                        relationship,
                        notification_preference,
                        min_interval,
                        new_status,
                        new_code,
                        now,
                        contact_id,
                        uid,
                    ),
                )

                # Update device assignments for this contact
                db.execute(
                    "DELETE FROM device_trusted_contacts WHERE contact_id = ? AND user_id = ?",
                    (contact_id, uid),
                )
                owner_devs = {
                    r["id"]
                    for r in db.execute("SELECT id FROM devices WHERE user_id = ?", (uid,)).fetchall()
                }
                for did in assigned_device_ids:
                    if did in owner_devs:
                        db.execute(
                            """
                            INSERT OR IGNORE INTO device_trusted_contacts (device_id, contact_id, user_id, created_at)
                            VALUES (?, ?, ?, ?)
                            """,
                            (did, contact_id, uid, now),
                        )

                log_audit(
                    db,
                    uid,
                    g.current_user["email"],
                    g.current_user["role"],
                    "TRUSTED_CONTACT_UPDATED",
                    "trusted_contact",
                    str(contact_id),
                    f"Updated trusted contact '{contact_name}' (Status={new_status}).",
                    request.remote_addr or "127.0.0.1",
                )
                db.commit()
                flash(f"Trusted contact '{contact_name}' updated.", "success")

            elif action == "delete_trusted_contact":
                contact_id = request.form.get("contact_id", type=int)
                contact_row = db.execute(
                    "SELECT * FROM trusted_contacts WHERE id = ? AND user_id = ?",
                    (contact_id, uid),
                ).fetchone()
                if not contact_row:
                    abort(403, description="Unauthorized access to trusted contact.")

                db.execute(
                    "DELETE FROM device_trusted_contacts WHERE contact_id = ? AND user_id = ?",
                    (contact_id, uid),
                )
                db.execute(
                    "DELETE FROM trusted_contacts WHERE id = ? AND user_id = ?",
                    (contact_id, uid),
                )
                log_audit(
                    db,
                    uid,
                    g.current_user["email"],
                    g.current_user["role"],
                    "TRUSTED_CONTACT_REMOVED",
                    "trusted_contact",
                    str(contact_id),
                    f"Removed trusted family contact '{contact_row['contact_name']}'.",
                    request.remote_addr or "127.0.0.1",
                )
                db.commit()
                flash(f"Trusted contact '{contact_row['contact_name']}' removed.", "info")

            return redirect(url_for("profile_page"))

        user_devices = db.execute(
            "SELECT id, device_name, brand, model, location_sharing_enabled, last_location_label, last_location_at, last_lat, last_lng, last_accuracy FROM devices WHERE user_id = ?",
            (uid,),
        ).fetchall()
        trusted_contacts = db.execute(
            "SELECT * FROM trusted_contacts WHERE user_id = ? ORDER BY id ASC",
            (uid,),
        ).fetchall()
        dtc_rows = db.execute(
            "SELECT device_id, contact_id FROM device_trusted_contacts WHERE user_id = ?",
            (uid,),
        ).fetchall()
        contact_devices_map: dict[int, list[int]] = {}
        for r in dtc_rows:
            contact_devices_map.setdefault(r["contact_id"], []).append(r["device_id"])

        personal_audits = db.execute(
            "SELECT * FROM audit_logs WHERE user_id = ? ORDER BY id DESC LIMIT 10",
            (uid,),
        ).fetchall()

        return render_template(
            "profile.html",
            user_devices=user_devices,
            trusted_contacts=trusted_contacts,
            contact_devices_map=contact_devices_map,
            sms_provider_status=get_sms_provider_status(),
            personal_audits=personal_audits,
        )

    # -------------------------------------------------------------------------
    # FEATURE G: Family Live Location Sharing, Alerts, Revocation & Recovery
    # -------------------------------------------------------------------------
    @app.route("/family-sharing/start", methods=["POST"])
    @login_required
    @rate_limit("family_share_start", max_requests=15, window_seconds=60)
    def family_sharing_start():
        db = get_db()
        uid = g.current_user["id"]

        is_json = request.is_json
        data = (request.get_json(silent=True) or {}) if is_json else request.form

        device_id = int(data.get("device_id") or 0)
        device = db.execute(
            "SELECT * FROM devices WHERE id = ? AND user_id = ?",
            (device_id, uid),
        ).fetchone()
        if not device:
            if is_json:
                return jsonify({"ok": False, "error": "Unauthorized or unknown device."}), 403
            abort(403, description="You can only share location for your own registered devices.")

        # Optional fresh browser GPS coordinates obtained with permission
        fresh_lat = data.get("fresh_lat")
        fresh_lng = data.get("fresh_lng")
        fresh_acc = data.get("fresh_accuracy", 12.0)
        now = utc_now_str()

        if fresh_lat is not None and fresh_lng is not None and str(fresh_lat).strip() and str(fresh_lng).strip():
            if device["location_sharing_enabled"]:
                try:
                    lat_f = float(fresh_lat)
                    lng_f = float(fresh_lng)
                    acc_f = float(fresh_acc or 12.0)
                    if -90.0 <= lat_f <= 90.0 and -180.0 <= lng_f <= 180.0:
                        addr = reverse_geocode_coordinates(lat_f, lng_f, conn=db)
                        db.execute(
                            """
                            INSERT INTO location_updates (device_id, user_id, latitude, longitude, accuracy, source, location_label, recorded_at)
                            VALUES (?, ?, ?, ?, ?, 'family_emergency_share_gps', ?, ?)
                            """,
                            (device_id, uid, lat_f, lng_f, acc_f, addr, now),
                        )
                        db.execute(
                            """
                            UPDATE devices
                            SET last_lat = ?, last_lng = ?, last_accuracy = ?, last_location_label = ?, last_location_at = ?, updated_at = ?
                            WHERE id = ? AND user_id = ?
                            """,
                            (lat_f, lng_f, acc_f, addr, now, now, device_id, uid),
                        )
                        device = db.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
                except (TypeError, ValueError):
                    pass

        if device["last_lat"] is None or device["last_lng"] is None:
            msg = "No permitted GPS coordinates are recorded for this device yet. Enable location sharing first."
            if is_json:
                return jsonify({"ok": False, "error": msg}), 400
            flash(msg, "error")
            return redirect(request.referrer or url_for("owner_dashboard"))

        if is_json:
            raw_cids = data.get("contact_ids") or []
            contact_ids = [int(x) for x in raw_cids if str(x).isdigit()]
        else:
            contact_ids = [int(x) for x in request.form.getlist("contact_ids") if str(x).isdigit()]

        # Verify that the owner has at least one verified contact
        verified_cnt = db.execute(
            "SELECT COUNT(*) FROM trusted_contacts WHERE user_id = ? AND verification_status = 'Verified' AND consent_confirmed = 1",
            (uid,),
        ).fetchone()[0]
        if verified_cnt == 0:
            msg = "Please add and verify at least one Trusted Family Contact under Profile & Privacy before sending family alerts."
            if is_json:
                return jsonify({"ok": False, "error": msg}), 400
            flash(msg, "warning")
            return redirect(url_for("profile_page"))

        simulate_failure = bool(data.get("simulate_failure")) if is_json else (request.form.get("simulate_failure") == "1")
        notify_interval = max(1, min(180, int(data.get("notify_interval_minutes") or 15)))

        outcome = start_or_notify_family_sharing(
            conn=db,
            user_row=g.current_user,
            device_row=dict(device),
            contact_ids=contact_ids if contact_ids else None,
            created_reason="Owner Emergency Family Share",
            notify_interval_minutes=notify_interval,
            base_url=request.host_url.rstrip("/"),
            simulate_failure=simulate_failure,
        )

        log_audit(
            db,
            uid,
            g.current_user["email"],
            g.current_user["role"],
            "FAMILY_SHARE_DISPATCHED",
            "device",
            str(device_id),
            f"Emergency family location share active for '{device['device_name']}' ({outcome['freshness']['label']}, {len(outcome['alerts'])} contact(s) processed).",
            request.remote_addr or "127.0.0.1",
        )
        db.commit()

        if is_json:
            return jsonify({"ok": True, **outcome})

        statuses = [a["delivery_status"] for a in outcome["alerts"]]
        if "Failed" in statuses:
            flash(
                f"Family sharing link created, but one or more SMS notifications failed ({', '.join(statuses)}). You can retry from the dashboard.",
                "warning",
            )
        elif "Simulated_Test_Mode" in statuses:
            flash(
                f"Family Emergency Sharing started ({outcome['freshness']['label']}). {len(outcome['alerts'])} verified contact(s) alerted in Test Mode (SMS provider not configured).",
                "success",
            )
        elif "Skipped_Throttled" in statuses and len(set(statuses)) == 1:
            flash(
                "Duplicate alert prevented: verified contacts were already alerted within the configured notification interval.",
                "info",
            )
        else:
            flash(
                f"Family Emergency Sharing active. {len(outcome['alerts'])} verified family contact(s) notified.",
                "success",
            )
        return redirect(request.referrer or url_for("owner_dashboard"))

    @app.route("/family-sharing/<int:session_id>/revoke", methods=["POST"])
    @login_required
    def family_sharing_revoke(session_id: int):
        db = get_db()
        uid = g.current_user["id"]
        sess = db.execute(
            """
            SELECT fss.*, d.device_name
            FROM family_share_sessions fss
            JOIN devices d ON d.id = fss.device_id
            WHERE fss.id = ? AND fss.user_id = ?
            """,
            (session_id, uid),
        ).fetchone()
        if not sess:
            abort(403, description="Unauthorized or unknown family sharing session.")

        stop_family_sharing_for_device(
            db,
            user_id=uid,
            device_id=sess["device_id"],
            new_status="Revoked",
            actor_role="owner",
            reason_note=f"Owner revoked family location sharing session #{session_id} for '{sess['device_name']}'.",
        )
        log_audit(
            db,
            uid,
            g.current_user["email"],
            g.current_user["role"],
            "FAMILY_SHARE_REVOKED",
            "family_share_session",
            str(session_id),
            f"Revoked family location sharing access for '{sess['device_name']}'.",
            request.remote_addr or "127.0.0.1",
        )
        db.commit()
        flash(f"Family location sharing stopped and access link revoked for '{sess['device_name']}'.", "info")
        return redirect(request.referrer or url_for("owner_dashboard"))

    @app.route("/family-sharing/alerts/<int:alert_id>/retry", methods=["POST"])
    @login_required
    def family_alert_retry(alert_id: int):
        db = get_db()
        uid = g.current_user["id"]
        alert_row = db.execute(
            "SELECT * FROM family_alert_logs WHERE id = ? AND user_id = ?",
            (alert_id, uid),
        ).fetchone()
        if not alert_row:
            abort(403, description="Unauthorized access to family alert log.")

        simulate_failure = request.form.get("simulate_failure") == "1"
        provider_name, delivery_status, msg_id, err_msg = dispatch_sms_via_provider(
            alert_row["recipient_phone"],
            alert_row["message_body"],
            simulate_failure=simulate_failure,
        )
        now = utc_now_str()
        db.execute(
            """
            UPDATE family_alert_logs
            SET provider_name = ?, delivery_status = ?, provider_message_id = ?, error_message = ?, updated_at = ?
            WHERE id = ? AND user_id = ?
            """,
            (provider_name, delivery_status, msg_id, err_msg, now, alert_id, uid),
        )
        log_audit(
            db,
            uid,
            g.current_user["email"],
            g.current_user["role"],
            "FAMILY_ALERT_RETRIED",
            "family_alert_log",
            str(alert_id),
            f"Retried family alert #{alert_id} to '{alert_row['recipient_name']}' -> Status={delivery_status}.",
            request.remote_addr or "127.0.0.1",
        )
        db.commit()
        if delivery_status == "Failed":
            flash(f"Retry to {alert_row['recipient_name']} failed: {err_msg}", "error")
        else:
            flash(
                f"Retried alert to {alert_row['recipient_name']} — Status: {delivery_status}.",
                "success",
            )
        return redirect(request.referrer or url_for("owner_dashboard"))

    # -------------------------------------------------------------------------
    # AI-Powered Trusted Contact Alerts: retry, delivery refresh, provider webhook
    # -------------------------------------------------------------------------
    @app.route("/ai-alerts/<int:alert_id>/retry", methods=["POST"])
    @login_required
    @rate_limit("ai_alert_retry", max_requests=10, window_seconds=60)
    def ai_alert_retry(alert_id: int):
        db = get_db()
        uid = g.current_user["id"]
        result = retry_ai_alert(db, alert_id, uid)
        if result is None:
            abort(403, description="Unauthorized access to AI alert record.")
        log_audit(
            db,
            uid,
            g.current_user["email"],
            g.current_user["role"],
            "AI_TRUSTED_ALERT_RETRIED",
            "ai_trusted_alert",
            str(alert_id),
            f"Retried AI trusted-contact alert #{alert_id} -> {result['notification_status']}.",
            request.remote_addr or "127.0.0.1",
        )
        db.commit()
        if result["notification_status"] == "Failed":
            flash(f"Alert retry failed: {result.get('provider_error') or 'unknown error'}", "error")
        else:
            flash(f"Alert retry result: {result['notification_status'].replace('_', ' ')}.", "success")
        return redirect(request.referrer or url_for("owner_dashboard"))

    @app.route("/ai-alerts/<int:alert_id>/refresh-status", methods=["POST"])
    @login_required
    @rate_limit("ai_alert_refresh", max_requests=20, window_seconds=60)
    def ai_alert_refresh_status(alert_id: int):
        db = get_db()
        ok, info = refresh_twilio_status(db, alert_id, g.current_user["id"])
        flash(
            f"Provider status refreshed: {info}." if ok else f"Could not refresh delivery status: {info}",
            "success" if ok else "warning",
        )
        return redirect(request.referrer or url_for("owner_dashboard"))

    @app.route("/webhooks/twilio/ai-alert-status", methods=["POST"])
    def twilio_ai_alert_status_webhook():
        """
        Twilio StatusCallback receiver. Requires SECUREPHONE_PUBLIC_BASE_URL (public HTTPS)
        and validates X-Twilio-Signature with TWILIO_AUTH_TOKEN before updating any record.
        """
        public_base = os.environ.get("SECUREPHONE_PUBLIC_BASE_URL", "").strip().rstrip("/")
        signed_url = f"{public_base}{request.path}" if public_base else request.url
        params = {k: v for k, v in request.form.items()}
        if not verify_twilio_signature(signed_url, params, request.headers.get("X-Twilio-Signature", "")):
            abort(403, description="Invalid provider signature.")
        db = get_db()
        apply_provider_status(
            db,
            params.get("MessageSid", ""),
            params.get("MessageStatus", ""),
            params.get("ErrorCode", "") and f"Twilio error code {params.get('ErrorCode')}",
        )
        return ("", 204)

    @app.route("/cases/<case_number>/owner-recover", methods=["POST"])
    @login_required
    def owner_mark_case_recovered(case_number: str):
        """
        Allow the device owner to confirm recovery of their own device,
        automatically stop emergency family location sharing, revoke family tokens,
        and close/recover the recovery case.
        """
        db = get_db()
        uid = g.current_user["id"]
        case = db.execute(
            """
            SELECT rc.*, d.device_name
            FROM recovery_cases rc
            JOIN devices d ON d.id = rc.device_id
            WHERE rc.case_number = ? AND rc.user_id = ?
            """,
            (case_number, uid),
        ).fetchone()
        if not case:
            abort(403, description="Only the verified owner of this case can confirm owner recovery.")

        now = utc_now_str()
        old_status = case["status"]
        note = clean_text(
            request.form.get("recovery_note", ""),
            400,
        ) or "Device owner confirmed handset recovery, stopped emergency family sharing, and revoked shared links."

        db.execute(
            """
            UPDATE recovery_cases
            SET status = 'Recovered', ownership_verified = 1, verification_notes = ?, updated_at = ?
            WHERE id = ?
            """,
            (note, now, case["id"]),
        )
        db.execute(
            "UPDATE devices SET status = 'Recovered', location_sharing_enabled = 0, updated_at = ? WHERE id = ?",
            (now, case["device_id"]),
        )
        db.execute(
            "UPDATE lost_reports SET status = 'Recovered', updated_at = ? WHERE id = ?",
            (now, case["lost_report_id"]),
        )
        revoked_count = stop_family_sharing_for_device(
            db,
            user_id=uid,
            device_id=case["device_id"],
            new_status="Stopped_Recovered",
            actor_role="owner",
            reason_note=f"Owner marked device '{case['device_name']}' as Recovered; emergency family sharing stopped.",
        )
        db.execute(
            """
            INSERT INTO recovery_status_history (
                case_id, old_status, new_status, changed_by_user_id, actor_role, note, created_at
            ) VALUES (?, ?, 'Recovered', ?, 'owner', ?, ?)
            """,
            (case["id"], old_status, uid, note, now),
        )
        log_audit(
            db,
            uid,
            g.current_user["email"],
            g.current_user["role"],
            "OWNER_CONFIRMED_RECOVERY",
            "recovery_case",
            case_number,
            f"Owner marked Case {case_number} ('{case['device_name']}') as Recovered and revoked {revoked_count} active family share session(s).",
            request.remote_addr or "127.0.0.1",
        )
        db.commit()
        flash(
            f"Device '{case['device_name']}' marked as Recovered. Emergency family sharing has been stopped and access links revoked.",
            "success",
        )
        return redirect(url_for("case_details", case_number=case_number))

    @app.route("/family/track/<share_token>")
    def family_track_page(share_token: str):
        """
        Secure, mobile-friendly page where an authorized family member can view
        the shared location, map, timestamp, device status, and recovery case reference.
        Enforces unpredictable token lookup, expiration check, and revocation check.
        """
        clean_tok = clean_text(share_token, 128)
        db = get_db()
        sess = db.execute(
            """
            SELECT fss.*,
                   d.device_name, d.brand, d.model, d.color, d.status AS device_status,
                   d.location_sharing_enabled, d.last_lat, d.last_lng, d.last_accuracy,
                   d.last_location_label, d.last_location_at,
                   u.full_name AS owner_name,
                   rc.status AS case_status
            FROM family_share_sessions fss
            JOIN devices d ON d.id = fss.device_id
            JOIN users u ON u.id = fss.user_id
            LEFT JOIN recovery_cases rc ON rc.id = fss.case_id
            WHERE fss.share_token = ?
            """,
            (clean_tok,),
        ).fetchone()

        if not sess:
            abort(404, description="This family location sharing link is invalid or does not exist.")

        now_dt = datetime.datetime.now(datetime.timezone.utc)
        now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        # Check expiration
        exp_dt = parse_utc_timestamp(sess["expires_at"])
        if sess["status"] == "Active" and exp_dt and exp_dt <= now_dt:
            db.execute(
                "UPDATE family_share_sessions SET status = 'Expired', stopped_at = ? WHERE id = ?",
                (now_str, sess["id"]),
            )
            db.commit()
            sess = dict(sess)
            sess["status"] = "Expired"

        if sess["status"] in ("Revoked", "Stopped_Recovered", "Expired"):
            return (
                render_template(
                    "family_track.html",
                    share_session=sess,
                    access_denied_reason=sess["status"],
                    freshness=None,
                    map_links={},
                ),
                403 if sess["status"] in ("Revoked", "Stopped_Recovered") else 410,
            )

        freshness = evaluate_location_freshness(
            sess["last_location_at"], bool(sess["location_sharing_enabled"]), now_dt
        )
        map_links = build_map_links(sess["last_lat"], sess["last_lng"])

        return render_template(
            "family_track.html",
            share_session=sess,
            access_denied_reason=None,
            freshness=freshness,
            map_links=map_links,
        )

    @app.route("/api/family/track/<share_token>/status")
    def api_family_track_status(share_token: str):
        """JSON polling endpoint for authorized family members viewing an active share link."""
        clean_tok = clean_text(share_token, 128)
        db = get_db()
        sess = db.execute(
            """
            SELECT fss.*,
                   d.device_name, d.brand, d.model, d.status AS device_status,
                   d.location_sharing_enabled, d.last_lat, d.last_lng, d.last_accuracy,
                   d.last_location_label, d.last_location_at,
                   rc.status AS case_status
            FROM family_share_sessions fss
            JOIN devices d ON d.id = fss.device_id
            LEFT JOIN recovery_cases rc ON rc.id = fss.case_id
            WHERE fss.share_token = ?
            """,
            (clean_tok,),
        ).fetchone()
        if not sess:
            return jsonify({"ok": False, "error": "Invalid share token."}), 404

        now_dt = datetime.datetime.now(datetime.timezone.utc)
        exp_dt = parse_utc_timestamp(sess["expires_at"])
        if sess["status"] == "Active" and exp_dt and exp_dt <= now_dt:
            now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            db.execute(
                "UPDATE family_share_sessions SET status = 'Expired', stopped_at = ? WHERE id = ?",
                (now_str, sess["id"]),
            )
            db.commit()
            return jsonify({"ok": False, "status": "Expired", "error": "Share link has expired."}), 410

        if sess["status"] != "Active":
            return jsonify({
                "ok": False,
                "status": sess["status"],
                "error": "Emergency location sharing has been stopped or revoked.",
            }), 403

        freshness = evaluate_location_freshness(
            sess["last_location_at"], bool(sess["location_sharing_enabled"]), now_dt
        )
        return jsonify({
            "ok": True,
            "status": sess["status"],
            "device_name": sess["device_name"],
            "device_status": sess["device_status"],
            "case_number": sess["case_number"],
            "case_status": sess["case_status"] or "Pending",
            "latitude": sess["last_lat"],
            "longitude": sess["last_lng"],
            "dms_coordinates": format_dms_coordinates(sess["last_lat"], sess["last_lng"]),
            "accuracy": sess["last_accuracy"],
            "readable_address": sess["last_location_label"] or "Address unavailable",
            "recorded_at_local": format_local_time(sess["last_location_at"]),
            "freshness": freshness,
            "map_links": build_map_links(sess["last_lat"], sess["last_lng"]),
        })

    @app.route("/api/native/location/update", methods=["POST"])
    @rate_limit("native_location_update", max_requests=30, window_seconds=60)
    def api_native_location_update():
        """
        Backend endpoint designed to receive authorized GPS updates from a future
        native Android companion app (or active owner session) without triggering
        repeated SMS messages on every GPS coordinate update.
        """
        data = request.get_json(silent=True) or {}
        device_id = data.get("device_id")
        lat_raw = data.get("latitude")
        lng_raw = data.get("longitude")
        acc_raw = data.get("accuracy", 12.0)
        companion_pin = clean_text(str(data.get("device_auth_pin", "")), 10)

        db = get_db()
        device = None
        if g.current_user:
            device = db.execute(
                "SELECT * FROM devices WHERE id = ? AND user_id = ?",
                (device_id, g.current_user["id"]),
            ).fetchone()
        elif device_id and companion_pin:
            device = db.execute(
                "SELECT * FROM devices WHERE id = ? AND demo_sim_pin = ?",
                (device_id, companion_pin),
            ).fetchone()

        if not device:
            return jsonify({"ok": False, "error": "Unauthorized device location update."}), 403

        if not device["location_sharing_enabled"]:
            return jsonify({
                "ok": False,
                "error": "Location sharing permission is disabled for this device.",
            }), 400

        try:
            lat = float(lat_raw)
            lng = float(lng_raw)
            acc = max(1.0, min(float(acc_raw or 12.0), 5000.0))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "Invalid latitude/longitude values."}), 400

        if not (-90.0 <= lat <= 90.0 and -180.0 <= lng <= 180.0):
            return jsonify({"ok": False, "error": "Coordinates out of bounds."}), 400

        now = utc_now_str()
        addr = reverse_geocode_coordinates(lat, lng, conn=db)
        db.execute(
            """
            INSERT INTO location_updates (device_id, user_id, latitude, longitude, accuracy, source, location_label, recorded_at)
            VALUES (?, ?, ?, ?, ?, 'native_android_companion', ?, ?)
            """,
            (device["id"], device["user_id"], lat, lng, acc, addr, now),
        )
        db.execute(
            """
            UPDATE devices
            SET last_lat = ?, last_lng = ?, last_accuracy = ?, last_location_label = ?, last_location_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (lat, lng, acc, addr, now, now, device["id"]),
        )
        db.commit()
        return jsonify({
            "ok": True,
            "device_id": device["id"],
            "latitude": lat,
            "longitude": lng,
            "readable_address": addr,
            "recorded_at_local": format_local_time(now),
            "sms_dispatched": False,
            "note": "Location updated for active family share sessions without sending repeated SMS alerts.",
        })

    # -------------------------------------------------------------------------
    # Error Handlers
    # -------------------------------------------------------------------------
    @app.errorhandler(400)
    def bad_request_error(error):
        return render_template("error.html", code=400, title="Bad Request", message=str(error.description)), 400

    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template("error.html", code=403, title="Access Denied", message=str(error.description)), 403

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template("error.html", code=404, title="Page Not Found", message=str(error.description)), 404

    return app


if __name__ == "__main__":
    load_env_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    app = create_app()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=False)
