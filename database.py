"""
Database layer for SecurePhone (SQLite3):
- Schema creation with foreign keys, constraints, and indexes
- Audit logging helper
- Unique Recovery Case ID generation
- Automated Lost-and-Found Matching Engine
- Safe Demo Data seeding (clearly tagged as [SAMPLE DEMO])
"""

import datetime
import os
import secrets
import sqlite3
from typing import Any, Dict, List, Optional
from family_sharing import ensure_family_sharing_tables
from ai_alerts import ensure_ai_alert_tables
from geocoding import ensure_geocoding_cache_table, format_local_time
from security import hash_password

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "securephone.db")


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Create a SQLite database connection with Row factory and Foreign Keys enabled."""
    target_path = db_path or os.environ.get("SECUREPHONE_DB_PATH", DEFAULT_DB_PATH)
    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def utc_now_str() -> str:
    """Return current UTC timestamp formatted for display and SQLite storage."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def init_db(db_path: Optional[str] = None, seed_demo: bool = True) -> None:
    """Initialize all database tables, constraints, indexes, and optional safe demo records."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone_number TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'owner' CHECK (role IN ('owner', 'admin')),
            location_consent INTEGER NOT NULL DEFAULT 0 CHECK (location_consent IN (0, 1)),
            privacy_alerts INTEGER NOT NULL DEFAULT 1 CHECK (privacy_alerts IN (0, 1)),
            is_sample INTEGER NOT NULL DEFAULT 0 CHECK (is_sample IN (0, 1)),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_name TEXT NOT NULL,
            brand TEXT NOT NULL,
            model TEXT NOT NULL,
            color TEXT NOT NULL,
            os_type TEXT NOT NULL DEFAULT 'Android',
            identifier_last4 TEXT NOT NULL DEFAULT '',
            demo_sim_pin TEXT NOT NULL DEFAULT '2580',
            status TEXT NOT NULL DEFAULT 'Protected' CHECK (status IN ('Protected', 'Lost', 'Recovered')),
            location_sharing_enabled INTEGER NOT NULL DEFAULT 0 CHECK (location_sharing_enabled IN (0, 1)),
            last_lat REAL,
            last_lng REAL,
            last_accuracy REAL,
            last_location_label TEXT DEFAULT '',
            last_location_at TEXT,
            lock_screen_notice TEXT DEFAULT 'This device is protected by SecurePhone Smart City Recovery.',
            is_sample INTEGER NOT NULL DEFAULT 0 CHECK (is_sample IN (0, 1)),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS location_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            accuracy REAL DEFAULT 15.0,
            source TEXT NOT NULL DEFAULT 'browser_geolocation',
            location_label TEXT DEFAULT '',
            recorded_at TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS lost_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            incident_type TEXT NOT NULL DEFAULT 'Lost' CHECK (incident_type IN ('Lost', 'Stolen')),
            incident_time TEXT NOT NULL,
            last_known_location TEXT NOT NULL,
            last_lat REAL,
            last_lng REAL,
            description TEXT NOT NULL,
            distinguishing_features TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Under Verification', 'Matched', 'Recovered', 'Closed')),
            is_sample INTEGER NOT NULL DEFAULT 0 CHECK (is_sample IN (0, 1)),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS found_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reported_by_user_id INTEGER,
            reporter_name TEXT NOT NULL,
            reporter_contact TEXT NOT NULL,
            brand TEXT NOT NULL,
            model TEXT NOT NULL,
            color TEXT NOT NULL,
            identifier_last4 TEXT DEFAULT '',
            found_location TEXT NOT NULL,
            date_found TEXT NOT NULL,
            description TEXT NOT NULL,
            current_custody TEXT NOT NULL DEFAULT 'Smart City Precinct Desk / Finder Hold',
            status TEXT NOT NULL DEFAULT 'Pending Review' CHECK (status IN ('Pending Review', 'Under Verification', 'Matched', 'Returned', 'Rejected')),
            is_sample INTEGER NOT NULL DEFAULT 0 CHECK (is_sample IN (0, 1)),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (reported_by_user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS recovery_cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_number TEXT NOT NULL UNIQUE,
            lost_report_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            matched_found_report_id INTEGER,
            status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'Under Verification', 'Match Found', 'Recovered', 'Closed', 'Rejected')),
            ownership_verified INTEGER NOT NULL DEFAULT 0 CHECK (ownership_verified IN (0, 1)),
            verification_notes TEXT DEFAULT '',
            is_sample INTEGER NOT NULL DEFAULT 0 CHECK (is_sample IN (0, 1)),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (lost_report_id) REFERENCES lost_reports(id) ON DELETE CASCADE,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (matched_found_report_id) REFERENCES found_reports(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS potential_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            lost_report_id INTEGER NOT NULL,
            found_report_id INTEGER NOT NULL,
            confidence_score INTEGER NOT NULL CHECK (confidence_score BETWEEN 0 AND 100),
            match_summary TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Unverified' CHECK (status IN ('Unverified', 'Under Verification', 'Approved', 'Rejected')),
            reviewed_by INTEGER,
            review_notes TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE (case_id, found_report_id),
            FOREIGN KEY (case_id) REFERENCES recovery_cases(id) ON DELETE CASCADE,
            FOREIGN KEY (lost_report_id) REFERENCES lost_reports(id) ON DELETE CASCADE,
            FOREIGN KEY (found_report_id) REFERENCES found_reports(id) ON DELETE CASCADE,
            FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS recovery_status_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            old_status TEXT,
            new_status TEXT NOT NULL,
            changed_by_user_id INTEGER,
            actor_role TEXT NOT NULL,
            note TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES recovery_cases(id) ON DELETE CASCADE,
            FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            actor_email TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            details TEXT NOT NULL,
            ip_address TEXT DEFAULT '127.0.0.1',
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS sos_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            trusted_contact TEXT DEFAULT '',
            is_live INTEGER NOT NULL DEFAULT 0 CHECK (is_live IN (0, 1)),
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            accuracy REAL DEFAULT 15.0,
            readable_address TEXT NOT NULL,
            sos_message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
        CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
        CREATE INDEX IF NOT EXISTS idx_location_device_id ON location_updates(device_id);
        CREATE INDEX IF NOT EXISTS idx_lost_reports_user_id ON lost_reports(user_id);
        CREATE INDEX IF NOT EXISTS idx_lost_reports_status ON lost_reports(status);
        CREATE INDEX IF NOT EXISTS idx_found_reports_status ON found_reports(status);
        CREATE INDEX IF NOT EXISTS idx_recovery_cases_user_id ON recovery_cases(user_id);
        CREATE INDEX IF NOT EXISTS idx_recovery_cases_status ON recovery_cases(status);
        CREATE INDEX IF NOT EXISTS idx_potential_matches_case_id ON potential_matches(case_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
        """
    )
    ensure_geocoding_cache_table(conn)
    ensure_family_sharing_tables(conn)
    ensure_ai_alert_tables(conn)
    conn.commit()

    if seed_demo:
        _seed_demo_data_if_empty(conn)
        _upgrade_sample_addresses(conn)
        _seed_demo_family_contacts_if_empty(conn)
        _seed_additional_phone_and_lost_mode_data(conn)
        _seed_demo_ai_alerts_if_empty(conn)

    conn.close()


def generate_unique_case_number(conn: sqlite3.Connection) -> str:
    """Generate a guaranteed-unique recovery case identifier (e.g., SP-2026-A84F)."""
    year = datetime.datetime.now(datetime.timezone.utc).year
    while True:
        token = secrets.token_hex(3).upper()
        case_number = f"SP-{year}-{token}"
        row = conn.execute(
            "SELECT 1 FROM recovery_cases WHERE case_number = ?", (case_number,)
        ).fetchone()
        if not row:
            return case_number


def log_audit(
    conn: sqlite3.Connection,
    user_id: Optional[int],
    actor_email: str,
    actor_role: str,
    action: str,
    target_type: str,
    target_id: str,
    details: str,
    ip_address: str = "127.0.0.1",
) -> None:
    """Insert an immutable audit record."""
    conn.execute(
        """
        INSERT INTO audit_logs (
            user_id, actor_email, actor_role, action, target_type, target_id, details, ip_address, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            actor_email,
            actor_role,
            action,
            target_type,
            str(target_id),
            details,
            ip_address,
            utc_now_str(),
        ),
    )


def compute_match_score(lost_row: Dict[str, Any], found_row: Dict[str, Any]) -> tuple[int, str]:
    """
    Compare a lost report + device record against a found report using non-sensitive fields:
    - Brand & model similarity (up to 45 pts)
    - Color match (up to 20 pts)
    - Optional last-4 hardware identifier match (up to 20 pts)
    - Location & description keyword overlap (up to 15 pts)
    Returns (score, explanation_string).
    """
    score = 0
    reasons: List[str] = []

    lost_brand = (lost_row.get("brand") or "").strip().lower()
    found_brand = (found_row.get("brand") or "").strip().lower()
    lost_model = (lost_row.get("model") or "").strip().lower()
    found_model = (found_row.get("model") or "").strip().lower()

    if lost_brand and found_brand and (lost_brand == found_brand or lost_brand in found_brand or found_brand in lost_brand):
        score += 15
        reasons.append(f"Brand match ({found_row.get('brand')})")

    if lost_model and found_model:
        if lost_model == found_model:
            score += 30
            reasons.append(f"Exact model match ({found_row.get('model')})")
        elif lost_model in found_model or found_model in lost_model:
            score += 20
            reasons.append(f"Partial model match ({found_row.get('model')})")
        else:
            lost_tokens = set(lost_model.split())
            found_tokens = set(found_model.split())
            common = lost_tokens.intersection(found_tokens)
            if common:
                score += 12
                reasons.append("Shared model keywords")

    lost_color = (lost_row.get("color") or "").strip().lower()
    found_color = (found_row.get("color") or "").strip().lower()
    if lost_color and found_color:
        if lost_color == found_color or lost_color in found_color or found_color in lost_color:
            score += 20
            reasons.append(f"Color match ({found_row.get('color')})")

    lost_last4 = (lost_row.get("identifier_last4") or "").strip().upper()
    found_last4 = (found_row.get("identifier_last4") or "").strip().upper()
    if lost_last4 and found_last4 and len(lost_last4) >= 3 and lost_last4 == found_last4:
        score += 20
        reasons.append("Partial 4-digit hardware tag match")

    # Location & description keyword overlap
    lost_loc_words = {
        w.strip(".,()-").lower()
        for w in ((lost_row.get("last_known_location") or "") + " " + (lost_row.get("description") or "") + " " + (lost_row.get("distinguishing_features") or "")).split()
        if len(w.strip(".,()-")) >= 4
    }
    found_loc_words = {
        w.strip(".,()-").lower()
        for w in ((found_row.get("found_location") or "") + " " + (found_row.get("description") or "")).split()
        if len(w.strip(".,()-")) >= 4
    }
    stopwords = {"phone", "with", "near", "from", "found", "lost", "device", "case", "screen", "black", "blue", "silver"}
    overlap = (lost_loc_words & found_loc_words) - stopwords
    if overlap:
        overlap_pts = min(15, len(overlap) * 5)
        score += overlap_pts
        sample_terms = ", ".join(sorted(list(overlap))[:3])
        reasons.append(f"Shared context/location keywords ({sample_terms})")

    final_score = min(100, score)
    summary = "; ".join(reasons) if reasons else "Low-confidence metadata overlap"
    return final_score, summary


def run_matching_engine(conn: sqlite3.Connection) -> int:
    """
    Evaluate all active recovery cases against available found reports.
    Inserts new potential_matches records (status='Unverified') where confidence_score >= 35.
    Returns the count of newly discovered potential matches.
    """
    active_cases = conn.execute(
        """
        SELECT
            rc.id AS case_id,
            rc.case_number,
            rc.status AS case_status,
            lr.id AS lost_report_id,
            lr.last_known_location,
            lr.description,
            lr.distinguishing_features,
            d.brand,
            d.model,
            d.color,
            d.identifier_last4
        FROM recovery_cases rc
        JOIN lost_reports lr ON lr.id = rc.lost_report_id
        JOIN devices d ON d.id = rc.device_id
        WHERE rc.status NOT IN ('Recovered', 'Closed', 'Rejected')
        """
    ).fetchall()

    found_reports = conn.execute(
        """
        SELECT *
        FROM found_reports
        WHERE status NOT IN ('Returned', 'Rejected')
        """
    ).fetchall()

    new_matches = 0
    now = utc_now_str()

    for case in active_cases:
        case_dict = dict(case)
        for found in found_reports:
            found_dict = dict(found)
            # Check if pair already exists
            existing = conn.execute(
                "SELECT id FROM potential_matches WHERE case_id = ? AND found_report_id = ?",
                (case_dict["case_id"], found_dict["id"]),
            ).fetchone()
            if existing:
                continue

            score, summary = compute_match_score(case_dict, found_dict)
            if score >= 35:
                conn.execute(
                    """
                    INSERT INTO potential_matches (
                        case_id, lost_report_id, found_report_id, confidence_score,
                        match_summary, status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'Unverified', ?, ?)
                    """,
                    (
                        case_dict["case_id"],
                        case_dict["lost_report_id"],
                        found_dict["id"],
                        score,
                        summary,
                        now,
                        now,
                    ),
                )
                new_matches += 1

    return new_matches


def _seed_demo_data_if_empty(conn: sqlite3.Connection) -> None:
    """Seed clearly labelled [SAMPLE DEMO] users, devices, reports, and recovery cases if DB is empty."""
    existing_user = conn.execute("SELECT id FROM users LIMIT 1").fetchone()
    if existing_user:
        return

    now = utc_now_str()

    # 1. Create Demo Owner, Second Demo Owner (for isolation testing), and Demo Administrator
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO users (full_name, email, phone_number, password_hash, role, location_consent, privacy_alerts, is_sample, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'owner', 1, 1, 1, ?, ?)
        """,
        ("Aarav Mehta (Demo Owner)", "owner@securephone.demo", "+91-98201-00101", hash_password("Owner@123"), now, now),
    )
    owner_id = cur.lastrowid

    cur.execute(
        """
        INSERT INTO users (full_name, email, phone_number, password_hash, role, location_consent, privacy_alerts, is_sample, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'owner', 1, 1, 1, ?, ?)
        """,
        ("Priya Nair (Secondary Demo Owner)", "priya@securephone.demo", "+91-98201-00202", hash_password("Priya@123"), now, now),
    )
    owner2_id = cur.lastrowid

    cur.execute(
        """
        INSERT INTO users (full_name, email, phone_number, password_hash, role, location_consent, privacy_alerts, is_sample, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'admin', 1, 1, 1, ?, ?)
        """,
        ("Cmdr. Vikram Rao (Smart City Admin)", "admin@securephone.demo", "+91-98201-00999", hash_password("Admin@123"), now, now),
    )
    admin_id = cur.lastrowid

    # 2. Seed Devices for Demo Owner 1
    cur.execute(
        """
        INSERT INTO devices (
            user_id, device_name, brand, model, color, os_type, identifier_last4,
            demo_sim_pin, status, location_sharing_enabled, last_lat, last_lng,
            last_accuracy, last_location_label, last_location_at, lock_screen_notice,
            is_sample, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Protected', 1, 12.9716, 77.5946, 12.5,
                  '[SAMPLE DEMO] MG Road Metro Concourse, Smart City Core', ?, ?, 1, ?, ?)
        """,
        (
            owner_id,
            "Aarav Primary Handset [SAMPLE DEMO]",
            "Samsung",
            "Galaxy S24 Ultra",
            "Titanium Gray",
            "Android 15",
            "8492",
            "2580",
            now,
            "Protected by SecurePhone Smart City Platform. Return to nearest Smart City Kiosk.",
            now,
            now,
        ),
    )
    device1_id = cur.lastrowid

    cur.execute(
        """
        INSERT INTO devices (
            user_id, device_name, brand, model, color, os_type, identifier_last4,
            demo_sim_pin, status, location_sharing_enabled, last_lat, last_lng,
            last_accuracy, last_location_label, last_location_at, lock_screen_notice,
            is_sample, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Lost', 1, 12.9784, 77.6408, 18.0,
                  '[SAMPLE DEMO] Indiranagar 100ft Transit Hub', ?, ?, 1, ?, ?)
        """,
        (
            owner_id,
            "Aarav Work Commuter [SAMPLE DEMO]",
            "Apple",
            "iPhone 15 Pro",
            "Natural Titanium",
            "iOS 18",
            "4109",
            "1357",
            now,
            "LOST DEVICE [SAMPLE DEMO]: Please contact Smart City Recovery Desk with Case #SP-2026-DEMO01.",
            now,
            now,
        ),
    )
    device2_id = cur.lastrowid

    # Seed a Recovered device for Owner 1 so dashboard shows Protected, Lost, and Recovered states
    cur.execute(
        """
        INSERT INTO devices (
            user_id, device_name, brand, model, color, os_type, identifier_last4,
            demo_sim_pin, status, location_sharing_enabled, last_lat, last_lng,
            last_accuracy, last_location_label, last_location_at, lock_screen_notice,
            is_sample, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Recovered', 0, 12.9352, 77.6245, 20.0,
                  '[SAMPLE DEMO] Koramangala Civic Center', ?, ?, 1, ?, ?)
        """,
        (
            owner_id,
            "Aarav Field TabletPhone [SAMPLE DEMO]",
            "Google",
            "Pixel 8",
            "Obsidian Black",
            "Android 14",
            "7731",
            "2468",
            now,
            "Device recovered and verified.",
            now,
            now,
        ),
    )

    # Seed a device for Secondary Demo Owner (to test ownership isolation)
    cur.execute(
        """
        INSERT INTO devices (
            user_id, device_name, brand, model, color, os_type, identifier_last4,
            demo_sim_pin, status, location_sharing_enabled, last_lat, last_lng,
            last_accuracy, last_location_label, last_location_at, lock_screen_notice,
            is_sample, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Protected', 1, 12.9279, 77.5831, 14.0,
                  '[SAMPLE DEMO] Jayanagar 4th Block Plaza', ?, ?, 1, ?, ?)
        """,
        (
            owner2_id,
            "Priya Personal Phone [SAMPLE DEMO]",
            "OnePlus",
            "OnePlus 12",
            "Flowy Emerald",
            "Android 15",
            "9920",
            "1122",
            now,
            "Protected by SecurePhone.",
            now,
            now,
        ),
    )

    # 3. Seed Location Updates for Owner 1's devices
    cur.execute(
        """
        INSERT INTO location_updates (device_id, user_id, latitude, longitude, accuracy, source, location_label, recorded_at)
        VALUES (?, ?, 12.9716, 77.5946, 12.5, 'sample_demo_seed', '[SAMPLE DEMO] MG Road Metro Concourse', ?)
        """,
        (device1_id, owner_id, now),
    )
    cur.execute(
        """
        INSERT INTO location_updates (device_id, user_id, latitude, longitude, accuracy, source, location_label, recorded_at)
        VALUES (?, ?, 12.9784, 77.6408, 18.0, 'sample_demo_seed', '[SAMPLE DEMO] Indiranagar 100ft Transit Hub', ?)
        """,
        (device2_id, owner_id, now),
    )

    # 4. Seed Lost Report & Recovery Case for Device 2
    cur.execute(
        """
        INSERT INTO lost_reports (
            user_id, device_id, incident_type, incident_time, last_known_location,
            last_lat, last_lng, description, distinguishing_features, status,
            is_sample, created_at, updated_at
        ) VALUES (?, ?, 'Lost', '2026-10-25 18:30 UTC',
                  '[SAMPLE DEMO] Indiranagar 100ft Transit Hub, Platform 2',
                  12.9784, 77.6408,
                  '[SAMPLE DEMO] Left on transit bench near Gate B during evening commute.',
                  'Matte clear bumper case, small blue metro sticker on back.',
                  'Under Verification', 1, ?, ?)
        """,
        (owner_id, device2_id, now, now),
    )
    lost_report_id = cur.lastrowid

    case_number = "SP-2026-DEMO01"
    cur.execute(
        """
        INSERT INTO recovery_cases (
            case_number, lost_report_id, device_id, user_id, status,
            ownership_verified, verification_notes, is_sample, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'Under Verification', 0,
                  '[SAMPLE DEMO] Case opened automatically via Lost Mode activation. Comparing against Smart City transit found-property desk.',
                  1, ?, ?)
        """,
        (case_number, lost_report_id, device2_id, owner_id, now, now),
    )
    case_id = cur.lastrowid

    cur.execute(
        """
        INSERT INTO recovery_status_history (case_id, old_status, new_status, changed_by_user_id, actor_role, note, created_at)
        VALUES
        (?, NULL, 'Pending', ?, 'owner', '[SAMPLE DEMO] Lost Mode activated and recovery case created.', ?),
        (?, 'Pending', 'Under Verification', ?, 'admin', '[SAMPLE DEMO] Assigned to Smart City Transit Recovery Unit for potential match verification.', ?)
        """,
        (case_id, owner_id, now, case_id, admin_id, now),
    )

    # 5. Seed a Found Device Report that matches the Lost Report
    cur.execute(
        """
        INSERT INTO found_reports (
            reported_by_user_id, reporter_name, reporter_contact, brand, model, color,
            identifier_last4, found_location, date_found, description,
            current_custody, status, is_sample, created_at, updated_at
        ) VALUES (
            NULL, 'Rohan Kulkarni (Transit Staff) [SAMPLE DEMO]', 'desk-indiranagar@smartcity.demo',
            'Apple', 'iPhone 15 Pro', 'Natural Titanium', '4109',
            '[SAMPLE DEMO] Indiranagar Transit Hub Bench near Gate B',
            '2026-10-25',
            '[SAMPLE DEMO] Found handset in a matte clear bumper case with a blue metro sticker. Turned in to Station Master.',
            'Indiranagar Smart City Transit Lost & Found Locker #14',
            'Pending Review', 1, ?, ?
        )
        """,
        (now, now),
    )

    # 6. Run matching engine and log initial audit event
    run_matching_engine(conn)
    log_audit(
        conn,
        admin_id,
        "admin@securephone.demo",
        "admin",
        "SYSTEM_SEED",
        "system",
        "init",
        "[SAMPLE DEMO] Initialized SecurePhone Smart City database with sample demonstration records.",
        "127.0.0.1",
    )
    conn.commit()


def _upgrade_sample_addresses(conn: sqlite3.Connection) -> None:
    """
    Ensure pre-seeded [SAMPLE DEMO] records and geocoding cache have full
    building/street/area/city/state/country/postal-code readable addresses.
    """
    now = utc_now_str()
    sample_places = [
        (
            12.968271,
            77.592483,
            "Sree Kanteerava Stadium, Rajaram Mohan Roy Road, Sampangirama Nagar, Bengaluru, Karnataka, India - 560001",
        ),
        (
            12.9716,
            77.5946,
            "MG Road Metro Station, Mahatma Gandhi Road, Shanthala Nagar, Ashok Nagar, Bengaluru, Karnataka, India - 560001",
        ),
        (
            12.9784,
            77.6408,
            "Indiranagar Metro Transit Hub, 100 Feet Road, HAL 2nd Stage, Indiranagar, Bengaluru, Karnataka, India - 560038",
        ),
        (
            12.9352,
            77.6245,
            "Koramangala BDA Complex, 80 Feet Road, Koramangala 4th Block, Bengaluru, Karnataka, India - 560034",
        ),
        (
            12.9279,
            77.5831,
            "Jayanagar 4th Block Shopping Complex, 11th Main Road, Jayanagar, Bengaluru, Karnataka, India - 560011",
        ),
    ]
    for lat, lng, addr in sample_places:
        conn.execute(
            """
            INSERT OR REPLACE INTO geocoding_cache (lat_r, lng_r, readable_address, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            (round(lat, 4), round(lng, 4), addr, now),
        )
        conn.execute(
            """
            UPDATE devices
            SET last_location_label = ?
            WHERE is_sample = 1 AND ABS(last_lat - ?) < 0.0005 AND ABS(last_lng - ?) < 0.0005
            """,
            (addr, lat, lng),
        )
        conn.execute(
            """
            UPDATE location_updates
            SET location_label = ?
            WHERE source = 'sample_demo_seed' AND ABS(latitude - ?) < 0.0005 AND ABS(longitude - ?) < 0.0005
            """,
            (addr, lat, lng),
        )

    conn.execute(
        """
        UPDATE lost_reports
        SET last_known_location = 'Indiranagar Metro Transit Hub (Platform 2), 100 Feet Road, HAL 2nd Stage, Indiranagar, Bengaluru, Karnataka, India - 560038'
        WHERE is_sample = 1 AND last_known_location LIKE '%Indiranagar 100ft Transit Hub%'
        """
    )
    conn.commit()


def _seed_demo_family_contacts_if_empty(conn: sqlite3.Connection) -> None:
    """Seed sample trusted family contacts for the demo owner if none exist yet."""
    existing = conn.execute("SELECT COUNT(*) AS cnt FROM trusted_contacts").fetchone()
    if existing and existing["cnt"] > 0:
        return

    owner_row = conn.execute(
        "SELECT id FROM users WHERE email = 'owner@securephone.demo'"
    ).fetchone()
    if not owner_row:
        return

    owner_id = owner_row["id"]
    now = utc_now_str()
    cur = conn.cursor()

    # 1. Verified Family Contact (Mother)
    cur.execute(
        """
        INSERT INTO trusted_contacts (
            user_id, contact_name, phone_number, relationship, notification_preference,
            consent_confirmed, verification_status, verification_code, verified_at,
            min_alert_interval_minutes, is_sample, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'SMS + Secure Link', 1, 'Verified', '842910', ?, 15, 1, ?, ?)
        """,
        (owner_id, "Meera Sharma [SAMPLE DEMO]", "+91-98800-33445", "Mother", now, now, now),
    )
    contact1_id = cur.lastrowid

    # 2. Pending Verification Family Contact (Brother)
    cur.execute(
        """
        INSERT INTO trusted_contacts (
            user_id, contact_name, phone_number, relationship, notification_preference,
            consent_confirmed, verification_status, verification_code, verified_at,
            min_alert_interval_minutes, is_sample, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'SMS + Secure Link', 1, 'Pending Verification', '519204', NULL, 15, 1, ?, ?)
        """,
        (owner_id, "Vikram Sharma [SAMPLE DEMO]", "+91-98800-77889", "Brother", now, now),
    )

    # Link verified contact to Owner 1's registered devices
    owner_devices = conn.execute(
        "SELECT id FROM devices WHERE user_id = ? ORDER BY id ASC", (owner_id,)
    ).fetchall()
    for d in owner_devices:
        conn.execute(
            """
            INSERT OR IGNORE INTO device_trusted_contacts (device_id, contact_id, user_id, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (d["id"], contact1_id, owner_id, now),
        )
    conn.commit()


def _seed_additional_phone_and_lost_mode_data(conn: sqlite3.Connection) -> None:
    """
    Populate additional realistic phone records so accounts have a clear mix of:
    - Some devices with Lost Mode activated (Lost status, incident report, recovery case, potential match)
    - Other devices kept in Protected or Recovered status (NOT in Lost Mode)
    """
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    now = now_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    earlier_str = (now_dt - datetime.timedelta(minutes=12)).strftime("%Y-%m-%d %H:%M:%S UTC")
    cur = conn.cursor()

    # -------------------------------------------------------------------------
    # A. Enrich Demo Owner (owner@securephone.demo) with mixed Lost & Protected phones
    # -------------------------------------------------------------------------
    owner1 = conn.execute(
        "SELECT id FROM users WHERE email = 'owner@securephone.demo'"
    ).fetchone()
    if owner1:
        uid1 = owner1["id"]
        has_nord = conn.execute(
            "SELECT id FROM devices WHERE user_id = ? AND model = 'Nord CE 4 5G'",
            (uid1,),
        ).fetchone()
        if not has_nord:
            # 1) Additional phone WITH Lost Mode Activated
            cur.execute(
                """
                INSERT INTO devices (
                    user_id, device_name, brand, model, color, os_type, identifier_last4,
                    demo_sim_pin, status, location_sharing_enabled, last_lat, last_lng,
                    last_accuracy, last_location_label, last_location_at, lock_screen_notice,
                    is_sample, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Lost', 1, 12.9767, 77.5713, 15.0,
                          'Kempegowda Bus Station (Majestic), Subhash Nagar, Bengaluru, Karnataka, India - 560009',
                          ?, ?, 1, ?, ?)
                """,
                (
                    uid1,
                    "Aarav Travel Phone [SAMPLE DEMO]",
                    "OnePlus",
                    "Nord CE 4 5G",
                    "Celadon Marble",
                    "Android 15",
                    "3612",
                    "2580",
                    earlier_str,
                    "LOST DEVICE [SAMPLE DEMO]: Return to Majestic Smart City Kiosk (Case #SP-2026-DEMO02).",
                    earlier_str,
                    earlier_str,
                ),
            )
            nord_id = cur.lastrowid

            cur.execute(
                """
                INSERT INTO location_updates (device_id, user_id, latitude, longitude, accuracy, source, location_label, recorded_at)
                VALUES (?, ?, 12.9767, 77.5713, 15.0, 'sample_demo_seed',
                        'Kempegowda Bus Station (Majestic), Subhash Nagar, Bengaluru, Karnataka, India - 560009', ?)
                """,
                (nord_id, uid1, earlier_str),
            )

            cur.execute(
                """
                INSERT INTO lost_reports (
                    user_id, device_id, incident_type, incident_time, last_known_location,
                    last_lat, last_lng, description, distinguishing_features, status,
                    is_sample, created_at, updated_at
                ) VALUES (?, ?, 'Lost', '2026-10-26 14:20 UTC',
                          'Kempegowda Bus Station (Majestic), Bay 12, Subhash Nagar, Bengaluru, Karnataka, India - 560009',
                          12.9767, 77.5713,
                          '[SAMPLE DEMO] Misplaced near intercity ticket counter at Majestic Bus Stand.',
                          'Celadon Marble finish with transparent silicone ring holder.',
                          'Open', 1, ?, ?)
                """,
                (uid1, nord_id, earlier_str, earlier_str),
            )
            nord_lr_id = cur.lastrowid

            cur.execute(
                """
                INSERT OR IGNORE INTO recovery_cases (
                    case_number, lost_report_id, device_id, user_id, status,
                    ownership_verified, verification_notes, is_sample, created_at, updated_at
                ) VALUES ('SP-2026-DEMO02', ?, ?, ?, 'Pending', 0,
                          '[SAMPLE DEMO] Lost Mode activated by owner. Automated scan checking Smart City transit hubs.',
                          1, ?, ?)
                """,
                (nord_lr_id, nord_id, uid1, earlier_str, earlier_str),
            )
            nord_case_id = cur.lastrowid
            if nord_case_id:
                cur.execute(
                    """
                    INSERT INTO recovery_status_history (case_id, old_status, new_status, changed_by_user_id, actor_role, note, created_at)
                    VALUES (?, NULL, 'Pending', ?, 'owner', '[SAMPLE DEMO] Lost Mode activated for OnePlus Nord CE 4 5G.', ?)
                    """,
                    (nord_case_id, uid1, earlier_str),
                )

            # 2) Two additional phones NOT in Lost Mode (Protected)
            cur.execute(
                """
                INSERT INTO devices (
                    user_id, device_name, brand, model, color, os_type, identifier_last4,
                    demo_sim_pin, status, location_sharing_enabled, last_lat, last_lng,
                    last_accuracy, last_location_label, last_location_at, lock_screen_notice,
                    is_sample, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Protected', 1, 12.968271, 77.592483, 11.0,
                          'Sree Kanteerava Stadium, Rajaram Mohan Roy Road, Sampangirama Nagar, Bengaluru, Karnataka, India - 560001',
                          ?, ?, 1, ?, ?)
                """,
                (
                    uid1,
                    "Aarav Studio Phone [SAMPLE DEMO]",
                    "Xiaomi",
                    "14 CIVI",
                    "Cruise Blue",
                    "Android 15",
                    "6048",
                    "2580",
                    earlier_str,
                    "Protected by SecurePhone Smart City Platform.",
                    earlier_str,
                    earlier_str,
                ),
            )

            cur.execute(
                """
                INSERT INTO devices (
                    user_id, device_name, brand, model, color, os_type, identifier_last4,
                    demo_sim_pin, status, location_sharing_enabled, last_lat, last_lng,
                    last_accuracy, last_location_label, last_location_at, lock_screen_notice,
                    is_sample, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Protected', 0, 12.9352, 77.6245, 16.0,
                          'Koramangala BDA Complex, 80 Feet Road, Koramangala 4th Block, Bengaluru, Karnataka, India - 560034',
                          ?, ?, 1, ?, ?)
                """,
                (
                    uid1,
                    "Aarav Secondary Handset [SAMPLE DEMO]",
                    "Nothing",
                    "Phone (2a) Plus",
                    "Metallic Grey",
                    "Android 15",
                    "9185",
                    "2580",
                    earlier_str,
                    "Protected by SecurePhone Smart City Platform.",
                    earlier_str,
                    earlier_str,
                ),
            )

    # -------------------------------------------------------------------------
    # B. Enrich Keerthana G (keerthanag231@gmail.com) if present in database
    # -------------------------------------------------------------------------
    keerthana = conn.execute(
        "SELECT id, full_name FROM users WHERE email = 'keerthanag231@gmail.com'"
    ).fetchone()
    if keerthana:
        k_uid = keerthana["id"]

        # Update existing 'mobile' devices with clearer nicknames and complete coordinates while preserving status
        conn.execute(
            """
            UPDATE devices
            SET device_name = 'Keerthana Primary (Redmi 15C 5G)',
                last_location_label = 'Kyatasandra Main Road, Near VIMTECH College, Tumakuru, Karnataka, India - 572104'
            WHERE user_id = ? AND brand = 'redmi15c 5g' AND device_name = 'mobile'
            """,
            (k_uid,),
        )
        conn.execute(
            """
            UPDATE lost_reports
            SET last_lat = 13.310505,
                last_lng = 77.148171,
                last_known_location = 'VIMTECH College Campus, Kyatasandra, Tumakuru, Karnataka, India - 572104',
                distinguishing_features = 'Lavender finish with college ID sticker on back cover'
            WHERE user_id = ? AND last_lat IS NULL
            """,
            (k_uid,),
        )

        # Ensure her OnePlus CPH2619 stays Protected (NOT in Lost Mode) and has a valid readable location
        conn.execute(
            """
            UPDATE devices
            SET device_name = 'Keerthana OnePlus (CPH2619)',
                status = 'Protected',
                location_sharing_enabled = 1,
                last_lat = 13.3269,
                last_lng = 77.1261,
                last_accuracy = 14.0,
                last_location_label = 'SIT Main Road, Ashok Nagar, Tumakuru, Karnataka, India - 572103',
                last_location_at = ?
            WHERE user_id = ? AND model = 'CPH2619' AND last_lat IS NULL
            """,
            (now, k_uid),
        )

        # Add 3 more phones for Keerthana if not already added:
        # - 1 with Lost Mode Activated (Samsung Galaxy S23 FE)
        # - 1 Protected / NOT in Lost Mode (Apple iPhone 16)
        # - 1 Recovered / NOT in Lost Mode (Vivo V30 Pro 5G)
        has_k_s23 = conn.execute(
            "SELECT id FROM devices WHERE user_id = ? AND model = 'Galaxy S23 FE'",
            (k_uid,),
        ).fetchone()
        if not has_k_s23:
            # 1) Phone WITH Lost Mode Activated
            cur.execute(
                """
                INSERT INTO devices (
                    user_id, device_name, brand, model, color, os_type, identifier_last4,
                    demo_sim_pin, status, location_sharing_enabled, last_lat, last_lng,
                    last_accuracy, last_location_label, last_location_at, lock_screen_notice,
                    is_sample, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Lost', 1, 12.9716, 77.5946, 12.5,
                          'MG Road Metro Station, Mahatma Gandhi Road, Shanthala Nagar, Ashok Nagar, Bengaluru, Karnataka, India - 560001',
                          ?, ?, 0, ?, ?)
                """,
                (
                    k_uid,
                    "Keerthana Commuter (Galaxy S23 FE)",
                    "Samsung",
                    "Galaxy S23 FE",
                    "Mint Green",
                    "Android 15",
                    "6314",
                    "2580",
                    now,
                    "LOST DEVICE: Please contact Smart City Recovery Desk (Case #SP-2026-KRT02).",
                    now,
                    now,
                ),
            )
            k_s23_id = cur.lastrowid

            cur.execute(
                """
                INSERT INTO location_updates (device_id, user_id, latitude, longitude, accuracy, source, location_label, recorded_at)
                VALUES (?, ?, 12.9716, 77.5946, 12.5, 'browser_geolocation',
                        'MG Road Metro Station, Mahatma Gandhi Road, Shanthala Nagar, Ashok Nagar, Bengaluru, Karnataka, India - 560001', ?)
                """,
                (k_s23_id, k_uid, now),
            )

            cur.execute(
                """
                INSERT INTO lost_reports (
                    user_id, device_id, incident_type, incident_time, last_known_location,
                    last_lat, last_lng, description, distinguishing_features, status,
                    is_sample, created_at, updated_at
                ) VALUES (?, ?, 'Lost', '27 Oct 2026, 04:45:00 PM IST',
                          'MG Road Metro Station, Mahatma Gandhi Road, Shanthala Nagar, Ashok Nagar, Bengaluru, Karnataka, India - 560001',
                          12.9716, 77.5946,
                          'Left on security check tray near MG Road Metro East Entrance during evening travel.',
                          'Mint Green matte case with silver camera ring protector.',
                          'Under Verification', 0, ?, ?)
                """,
                (k_uid, k_s23_id, now, now),
            )
            k_s23_lr_id = cur.lastrowid

            cur.execute(
                """
                INSERT OR IGNORE INTO recovery_cases (
                    case_number, lost_report_id, device_id, user_id, status,
                    ownership_verified, verification_notes, is_sample, created_at, updated_at
                ) VALUES ('SP-2026-KRT02', ?, ?, ?, 'Under Verification', 0,
                          'Lost Mode activated. Matching against Bengaluru Metro transit found-property reports.',
                          0, ?, ?)
                """,
                (k_s23_lr_id, k_s23_id, k_uid, now, now),
            )
            k_s23_case_id = cur.lastrowid
            if k_s23_case_id:
                cur.execute(
                    """
                    INSERT INTO recovery_status_history (case_id, old_status, new_status, changed_by_user_id, actor_role, note, created_at)
                    VALUES
                    (?, NULL, 'Pending', ?, 'owner', 'Lost Mode activated and theft/loss report submitted.', ?),
                    (?, 'Pending', 'Under Verification', 3, 'admin', 'Assigned to Metro Transit Recovery Desk for match verification.', ?)
                    """,
                    (k_s23_case_id, k_uid, now, k_s23_case_id, now),
                )

            # 2) Phone NOT in Lost Mode (Protected)
            cur.execute(
                """
                INSERT INTO devices (
                    user_id, device_name, brand, model, color, os_type, identifier_last4,
                    demo_sim_pin, status, location_sharing_enabled, last_lat, last_lng,
                    last_accuracy, last_location_label, last_location_at, lock_screen_notice,
                    is_sample, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Protected', 1, 12.968271, 77.592483, 10.5,
                          'Sree Kanteerava Stadium, Rajaram Mohan Roy Road, Sampangirama Nagar, Bengaluru, Karnataka, India - 560001',
                          ?, ?, 0, ?, ?)
                """,
                (
                    k_uid,
                    "Keerthana Personal (iPhone 16)",
                    "Apple",
                    "iPhone 16",
                    "Ultramarine Blue",
                    "iOS 18",
                    "9245",
                    "2580",
                    now,
                    "Protected by SecurePhone Smart City Platform.",
                    now,
                    now,
                ),
            )
            k_ip16_id = cur.lastrowid
            cur.execute(
                """
                INSERT INTO location_updates (device_id, user_id, latitude, longitude, accuracy, source, location_label, recorded_at)
                VALUES (?, ?, 12.968271, 77.592483, 10.5, 'browser_geolocation',
                        'Sree Kanteerava Stadium, Rajaram Mohan Roy Road, Sampangirama Nagar, Bengaluru, Karnataka, India - 560001', ?)
                """,
                (k_ip16_id, k_uid, now),
            )

            # 3) Phone NOT in Lost Mode (Recovered)
            cur.execute(
                """
                INSERT INTO devices (
                    user_id, device_name, brand, model, color, os_type, identifier_last4,
                    demo_sim_pin, status, location_sharing_enabled, last_lat, last_lng,
                    last_accuracy, last_location_label, last_location_at, lock_screen_notice,
                    is_sample, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Recovered', 0, 13.3409, 77.1010, 18.0,
                          'Town Hall Circle Smart City Kiosk, Ashoka Road, Tumakuru, Karnataka, India - 572101',
                          ?, ?, 0, ?, ?)
                """,
                (
                    k_uid,
                    "Keerthana Home Phone (Vivo V30 Pro)",
                    "Vivo",
                    "V30 Pro 5G",
                    "Andaman Blue",
                    "Android 14",
                    "5518",
                    "2580",
                    now,
                    "Device recovered and verified.",
                    now,
                    now,
                ),
            )

            # Matching Found Reports for Keerthana's Lost devices so Potential Matches appear on her dashboard
            cur.execute(
                """
                INSERT INTO found_reports (
                    reported_by_user_id, reporter_name, reporter_contact, brand, model, color,
                    identifier_last4, found_location, date_found, description,
                    current_custody, status, is_sample, created_at, updated_at
                ) VALUES
                (NULL, 'Prakash Gowda (Campus Security)', 'security@vimtech-tumkur.demo',
                 'redmi15c 5g', '2508CRN2BI', 'lavender', '0827',
                 'VIMTECH College Library Reading Hall, Kyatasandra, Tumakuru', '2026-10-27',
                 'Found lavender Redmi 15C 5G handset on study table during college hours.',
                 'VIMTECH Campus Security Office Safe #2', 'Pending Review', 0, ?, ?),
                (NULL, 'Nandini R. (BMRCL Station Staff)', 'mgroad-desk@bmrcl.demo',
                 'Samsung', 'Galaxy S23 FE', 'Mint Green', '6314',
                 'MG Road Metro Station East Baggage Scanner, Bengaluru', '2026-10-27',
                 'Found Mint Green Samsung Galaxy S23 FE near East Entrance scanner tray.',
                 'MG Road Metro Station Master Locker #07', 'Pending Review', 0, ?, ?)
                """,
                (now, now, now, now),
            )

        # Seed Trusted Family Contacts & Active Emergency Share for Keerthana if none exist
        k_contacts = conn.execute(
            "SELECT COUNT(*) AS cnt FROM trusted_contacts WHERE user_id = ?", (k_uid,)
        ).fetchone()
        if not k_contacts or k_contacts["cnt"] == 0:
            cur.execute(
                """
                INSERT INTO trusted_contacts (
                    user_id, contact_name, phone_number, relationship, notification_preference,
                    consent_confirmed, verification_status, verification_code, verified_at,
                    min_alert_interval_minutes, is_sample, created_at, updated_at
                ) VALUES
                (?, 'Lakshmi G', '+91-98450-11223', 'Mother', 'SMS + Secure Link', 1, 'Verified', '739104', ?, 15, 0, ?, ?),
                (?, 'Rakesh G', '+91-98450-44556', 'Brother', 'SMS + Secure Link', 1, 'Verified', '628319', ?, 15, 0, ?, ?),
                (?, 'Sneha G', '+91-98450-88990', 'Sister', 'SMS + Secure Link', 1, 'Pending Verification', '491827', NULL, 15, 0, ?, ?)
                """,
                (k_uid, now, now, now, k_uid, now, now, now, k_uid, now, now),
            )
            verified_k = conn.execute(
                "SELECT id, contact_name, phone_number FROM trusted_contacts WHERE user_id = ? AND verification_status = 'Verified'",
                (k_uid,),
            ).fetchall()
            k_devs = conn.execute(
                "SELECT id FROM devices WHERE user_id = ?", (k_uid,)
            ).fetchall()
            for kd in k_devs:
                for vc in verified_k:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO device_trusted_contacts (device_id, contact_id, user_id, created_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (kd["id"], vc["id"], k_uid, now),
                    )

            # Start an active Family Emergency Sharing session on her Lost Redmi 15C 5G so the dashboard card shows live data
            lost_redmi = conn.execute(
                "SELECT id, device_name, last_location_label FROM devices WHERE user_id = ? AND status = 'Lost' ORDER BY id ASC LIMIT 1",
                (k_uid,),
            ).fetchone()
            redmi_case = conn.execute(
                "SELECT id, case_number FROM recovery_cases WHERE user_id = ? ORDER BY id ASC LIMIT 1",
                (k_uid,),
            ).fetchone()
            if lost_redmi and verified_k:
                tok = secrets.token_urlsafe(32)
                exp_str = (now_dt + datetime.timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S UTC")
                cur.execute(
                    """
                    INSERT INTO family_share_sessions (
                        share_token, user_id, device_id, case_id, case_number, status,
                        notify_interval_minutes, created_reason, started_at, expires_at, last_notified_at
                    ) VALUES (?, ?, ?, ?, ?, 'Active', 15, 'Lost Mode Emergency Share', ?, ?, ?)
                    """,
                    (
                        tok,
                        k_uid,
                        lost_redmi["id"],
                        redmi_case["id"] if redmi_case else None,
                        redmi_case["case_number"] if redmi_case else "SP-2026-76D624",
                        now,
                        exp_str,
                        now,
                    ),
                )
                sess_id = cur.lastrowid
                vc0 = verified_k[0]
                cur.execute(
                    """
                    INSERT INTO family_alert_logs (
                        share_session_id, user_id, device_id, contact_id, case_number,
                        recipient_name, recipient_phone, provider_name, delivery_status,
                        provider_message_id, error_message, message_body, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'Test_Mode_Unconfigured', 'Simulated_Test_Mode',
                              'TEST-SIM-KRT01', '', ?, ?, ?)
                    """,
                    (
                        sess_id,
                        k_uid,
                        lost_redmi["id"],
                        vc0["id"],
                        redmi_case["case_number"] if redmi_case else "SP-2026-76D624",
                        vc0["contact_name"],
                        vc0["phone_number"],
                        f"[SecurePhone Emergency Alert] Device: {lost_redmi['device_name']} | Case: {redmi_case['case_number'] if redmi_case else 'SP-2026-76D624'} | Location: {lost_redmi['last_location_label']} | Track: http://127.0.0.1:5000/family/track/{tok}",
                        now,
                        now,
                    ),
                )

    # -------------------------------------------------------------------------
    # C. Enrich Chinmayi Y (chinmayi123hithesh@gmail.com) if present with 0 devices
    # -------------------------------------------------------------------------
    chinmayi = conn.execute(
        "SELECT id FROM users WHERE email = 'chinmayi123hithesh@gmail.com'"
    ).fetchone()
    if chinmayi:
        c_uid = chinmayi["id"]
        c_dev_cnt = conn.execute(
            "SELECT COUNT(*) AS cnt FROM devices WHERE user_id = ?", (c_uid,)
        ).fetchone()
        if not c_dev_cnt or c_dev_cnt["cnt"] == 0:
            # 1 Lost Mode device + 2 Protected devices (NOT in Lost Mode)
            cur.execute(
                """
                INSERT INTO devices (
                    user_id, device_name, brand, model, color, os_type, identifier_last4,
                    demo_sim_pin, status, location_sharing_enabled, last_lat, last_lng,
                    last_accuracy, last_location_label, last_location_at, lock_screen_notice,
                    is_sample, created_at, updated_at
                ) VALUES (?, 'Chinmayi Primary (iPhone 15)', 'Apple', 'iPhone 15', 'Pink', 'iOS 18', '4812',
                          '2580', 'Lost', 1, 12.9784, 77.6408, 14.0,
                          'Indiranagar Metro Transit Hub, 100 Feet Road, HAL 2nd Stage, Indiranagar, Bengaluru, Karnataka, India - 560038',
                          ?, 'LOST DEVICE: Please contact Smart City Recovery Desk (Case #SP-2026-CHN01).', 0, ?, ?)
                """,
                (c_uid, now, now, now),
            )
            c_lost_id = cur.lastrowid
            cur.execute(
                """
                INSERT INTO lost_reports (
                    user_id, device_id, incident_type, incident_time, last_known_location,
                    last_lat, last_lng, description, distinguishing_features, status,
                    is_sample, created_at, updated_at
                ) VALUES (?, ?, 'Lost', '27 Oct 2026, 05:15:00 PM IST',
                          'Indiranagar Metro Transit Hub, 100 Feet Road, HAL 2nd Stage, Indiranagar, Bengaluru, Karnataka, India - 560038',
                          12.9784, 77.6408, 'Left on cafe table near Indiranagar Metro station.',
                          'Pastel pink silicone case with charm strap.', 'Open', 0, ?, ?)
                """,
                (c_uid, c_lost_id, now, now),
            )
            c_lr_id = cur.lastrowid
            cur.execute(
                """
                INSERT OR IGNORE INTO recovery_cases (
                    case_number, lost_report_id, device_id, user_id, status,
                    ownership_verified, verification_notes, is_sample, created_at, updated_at
                ) VALUES ('SP-2026-CHN01', ?, ?, ?, 'Pending', 0,
                          'Lost Mode activated by owner.', 0, ?, ?)
                """,
                (c_lr_id, c_lost_id, c_uid, now, now),
            )

            # 2 Protected devices (NOT in Lost Mode)
            cur.execute(
                """
                INSERT INTO devices (
                    user_id, device_name, brand, model, color, os_type, identifier_last4,
                    demo_sim_pin, status, location_sharing_enabled, last_lat, last_lng,
                    last_accuracy, last_location_label, last_location_at, lock_screen_notice,
                    is_sample, created_at, updated_at
                ) VALUES
                (?, 'Chinmayi Work Phone (Galaxy S24)', 'Samsung', 'Galaxy S24', 'Amber Yellow', 'Android 15', '3094',
                 '2580', 'Protected', 1, 12.968271, 77.592483, 11.0,
                 'Sree Kanteerava Stadium, Rajaram Mohan Roy Road, Sampangirama Nagar, Bengaluru, Karnataka, India - 560001',
                 ?, 'Protected by SecurePhone Smart City Platform.', 0, ?, ?),
                (?, 'Chinmayi TabletPhone (OnePlus 12R)', 'OnePlus', '12R 5G', 'Cool Blue', 'Android 15', '7421',
                 '2580', 'Protected', 0, 12.9279, 77.5831, 15.0,
                 'Jayanagar 4th Block Shopping Complex, 11th Main Road, Jayanagar, Bengaluru, Karnataka, India - 560011',
                 ?, 'Protected by SecurePhone Smart City Platform.', 0, ?, ?)
                """,
                (c_uid, now, now, now, c_uid, now, now, now),
            )

    run_matching_engine(conn)
    conn.commit()


def _seed_demo_ai_alerts_if_empty(conn: sqlite3.Connection) -> None:
    """Seed sample AI trusted-contact alert history for existing lost cases if table is empty."""
    existing = conn.execute("SELECT COUNT(*) AS cnt FROM ai_trusted_alerts").fetchone()
    if existing and existing["cnt"] > 0:
        return

    now_dt = datetime.datetime.now(datetime.timezone.utc)
    now = now_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    earlier = (now_dt - datetime.timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. Alert for Demo Owner (Aarav Mehta -> Meera Sharma)
    case1 = conn.execute(
        """
        SELECT rc.id, rc.case_number, rc.device_id, rc.user_id, rc.lost_report_id,
               d.device_name, d.brand, d.model, d.last_location_label,
               u.full_name, tc.id AS contact_id, tc.contact_name, tc.phone_number
        FROM recovery_cases rc
        JOIN devices d ON d.id = rc.device_id
        JOIN users u ON u.id = rc.user_id
        JOIN trusted_contacts tc ON tc.user_id = rc.user_id AND tc.verification_status = 'Verified'
        WHERE rc.case_number = 'SP-2026-DEMO01'
        LIMIT 1
        """
    ).fetchone()

    if case1:
        msg1 = (
            f"SECUREPHONE ALERT: Hi Meera, {case1['full_name']} has reported their "
            f"{case1['brand']} {case1['model']} as lost. Please contact them and help coordinate recovery. "
            f"Case ID: {case1['case_number']}. "
            f"Last-known location: {case1['last_location_label']}."
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO ai_trusted_alerts (
                event_key, trigger_event, user_id, device_id, case_id, case_number, lost_report_id,
                contact_id, recipient_name, recipient_phone_masked, ai_provider, ai_model,
                generation_status, generation_error, message_body, location_included,
                notification_status, sms_provider, provider_message_id, provider_error,
                attempt_count, created_at, updated_at
            ) VALUES (?, 'LOST_MODE_ACTIVATED', ?, ?, ?, ?, ?, ?, ?, ?, 'Google_Gemini', 'gemini-2.5-flash',
                      'AI_Generated', '', ?, 1, 'Demo_Notification', 'Test_Mode_Unconfigured',
                      'DEMO-AI-MSG-001', '', 1, ?, ?)
            """,
            (
                f"LOST_MODE_ACTIVATED:case:{case1['id']}:contact:{case1['contact_id']}",
                case1["user_id"],
                case1["device_id"],
                case1["id"],
                case1["case_number"],
                case1["lost_report_id"],
                case1["contact_id"],
                case1["contact_name"],
                "+91******3445",
                msg1,
                earlier,
                earlier,
            ),
        )

    # 2. Alert for Keerthana G (Case SP-2026-KRT02 -> Lakshmi G)
    case2 = conn.execute(
        """
        SELECT rc.id, rc.case_number, rc.device_id, rc.user_id, rc.lost_report_id,
               d.device_name, d.brand, d.model, d.last_location_label,
               u.full_name, tc.id AS contact_id, tc.contact_name, tc.phone_number
        FROM recovery_cases rc
        JOIN devices d ON d.id = rc.device_id
        JOIN users u ON u.id = rc.user_id
        JOIN trusted_contacts tc ON tc.user_id = rc.user_id AND tc.verification_status = 'Verified'
        WHERE rc.case_number IN ('SP-2026-KRT02', 'SP-2026-76D624')
        LIMIT 1
        """
    ).fetchone()

    if case2:
        msg2 = (
            f"SECUREPHONE ALERT: Hi Lakshmi, {case2['full_name']} has reported their "
            f"{case2['brand']} {case2['model']} as lost. Please contact them and help coordinate recovery. "
            f"Case ID: {case2['case_number']}. "
            f"Last-known location: {case2['last_location_label']}."
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO ai_trusted_alerts (
                event_key, trigger_event, user_id, device_id, case_id, case_number, lost_report_id,
                contact_id, recipient_name, recipient_phone_masked, ai_provider, ai_model,
                generation_status, generation_error, message_body, location_included,
                notification_status, sms_provider, provider_message_id, provider_error,
                attempt_count, created_at, updated_at
            ) VALUES (?, 'LOST_MODE_ACTIVATED', ?, ?, ?, ?, ?, ?, ?, ?, 'Google_Gemini', 'gemini-2.5-flash',
                      'AI_Generated', '', ?, 1, 'Demo_Notification', 'Test_Mode_Unconfigured',
                      'DEMO-AI-MSG-002', '', 1, ?, ?)
            """,
            (
                f"LOST_MODE_ACTIVATED:case:{case2['id']}:contact:{case2['contact_id']}",
                case2["user_id"],
                case2["device_id"],
                case2["id"],
                case2["case_number"],
                case2["lost_report_id"],
                case2["contact_id"],
                case2["contact_name"],
                "+91******1223",
                msg2,
                now,
                now,
            ),
        )
    conn.commit()


