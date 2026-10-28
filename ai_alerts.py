"""
AI-Powered Trusted Contact Alerts for SecurePhone.

Scope (intentionally narrow):
- When Lost Mode is activated / a lost-phone report is submitted, generate a short,
  personalized alert message with an AI model (Google Gemini API) using ONLY the real
  event details, then send it to each verified + consenting trusted contact via the
  configured SMS provider (Twilio or generic webhook, reusing family_sharing's gateway).
- The AI's only job is writing the message text. No risk scoring, anomaly detection,
  or analytics are performed here.

Safety & honesty rules implemented:
- API credentials are read from environment variables only (never stored in the DB).
- Only contacts with verification_status='Verified' AND consent_confirmed=1 are alerted.
- Duplicate alerts for the same event (case + contact) are prevented by a UNIQUE event_key.
- Last-known location is included only when the owner has granted location consent AND
  location sharing is enabled for the device AND a recorded location exists.
- If the AI service fails or returns invalid text, a deterministic message built from the
  same real event details is used and the row is labelled 'Fallback_Template'.
- If no SMS provider is configured, the row is labelled 'Demo_Notification' (never 'Sent').
- 'Delivered' is only recorded when the SMS provider confirms delivery.
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from family_sharing import dispatch_sms_via_provider, evaluate_location_freshness, get_sms_provider_status
from geocoding import format_local_time

TRIGGER_LOST_MODE = "LOST_MODE_ACTIVATED"

GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_FALLBACK_MODELS = ["gemini-1.5-flash", "gemini-2.0-flash", "gemini-2.5-flash-lite"]
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
MAX_SMS_CHARS = 480  # ~3 SMS segments; keeps alerts short and readable

# Map the shared SMS gateway's statuses onto the user-facing AI alert statuses.
_GATEWAY_STATUS_MAP = {
    "Delivered": "Delivered",
    "Sent_Unconfirmed": "Sent",
    "Simulated_Test_Mode": "Demo_Notification",
    "Failed": "Failed",
}

# Twilio message status -> AI alert status
_TWILIO_STATUS_MAP = {
    "delivered": "Delivered",
    "failed": "Failed",
    "undelivered": "Failed",
    "canceled": "Failed",
    "queued": "Sent",
    "accepted": "Sent",
    "scheduled": "Sent",
    "sending": "Sent",
    "sent": "Sent",
}


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
def ensure_ai_alert_tables(conn: sqlite3.Connection) -> None:
    """Create the AI trusted-contact alert history table if it does not exist."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS ai_trusted_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT NOT NULL UNIQUE,
            trigger_event TEXT NOT NULL DEFAULT 'LOST_MODE_ACTIVATED',
            user_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            case_id INTEGER,
            case_number TEXT NOT NULL DEFAULT '',
            lost_report_id INTEGER,
            contact_id INTEGER,
            recipient_name TEXT NOT NULL,
            recipient_phone_masked TEXT NOT NULL,
            ai_provider TEXT NOT NULL DEFAULT '',
            ai_model TEXT NOT NULL DEFAULT '',
            generation_status TEXT NOT NULL DEFAULT 'Fallback_Template'
                CHECK (generation_status IN ('AI_Generated', 'Fallback_Template')),
            generation_error TEXT NOT NULL DEFAULT '',
            message_body TEXT NOT NULL DEFAULT '',
            location_included INTEGER NOT NULL DEFAULT 0 CHECK (location_included IN (0, 1)),
            notification_status TEXT NOT NULL DEFAULT 'Pending'
                CHECK (notification_status IN ('Pending', 'Sent', 'Delivered', 'Failed', 'Demo_Notification')),
            sms_provider TEXT NOT NULL DEFAULT '',
            provider_message_id TEXT NOT NULL DEFAULT '',
            provider_error TEXT NOT NULL DEFAULT '',
            attempt_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            sent_at TEXT,
            delivered_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
            FOREIGN KEY (case_id) REFERENCES recovery_cases(id) ON DELETE SET NULL,
            FOREIGN KEY (contact_id) REFERENCES trusted_contacts(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_ai_alerts_case ON ai_trusted_alerts(case_id, id DESC);
        CREATE INDEX IF NOT EXISTS idx_ai_alerts_user ON ai_trusted_alerts(user_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ai_alerts_provider_msg ON ai_trusted_alerts(provider_message_id);
        """
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _now_str() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def mask_phone(phone: str) -> str:
    """Return a non-sensitive recipient reference such as '+91******1223'."""
    digits = re.sub(r"\D", "", phone or "")
    if len(digits) <= 4:
        return "****"
    prefix = "+" if (phone or "").strip().startswith("+") else ""
    return f"{prefix}{digits[:2]}{'*' * max(2, len(digits) - 6)}{digits[-4:]}"


def get_ai_provider_status() -> Dict[str, Any]:
    """Report whether the AI message generator is configured (never exposes secrets)."""
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip() or os.environ.get("GOOGLE_API_KEY", "").strip()
    openai_key = os.environ.get("OPENAI_API_KEY", "").strip()

    if gemini_key:
        model = os.environ.get("GEMINI_MODEL", "").strip() or DEFAULT_GEMINI_MODEL
        return {
            "configured": True,
            "provider_name": "Google_Gemini",
            "model": model,
            "mode_label": f"AI Message Generation Active (Gemini · {model})",
        }
    if openai_key:
        model = os.environ.get("OPENAI_MODEL", "").strip() or DEFAULT_OPENAI_MODEL
        return {
            "configured": True,
            "provider_name": "OpenAI",
            "model": model,
            "mode_label": f"AI Message Generation Active (OpenAI · {model})",
        }
    return {
        "configured": False,
        "provider_name": "Template_Fallback",
        "model": "",
        "mode_label": "AI Not Configured (API key missing) — template fallback in use",
    }


def _first_name(full_name: str) -> str:
    parts = (full_name or "").strip().split()
    return parts[0] if parts else "there"


# ---------------------------------------------------------------------------
# Event facts & location authorization
# ---------------------------------------------------------------------------
def build_event_facts(
    user_row: Dict[str, Any],
    device_row: Dict[str, Any],
    contact_row: Dict[str, Any],
    case_number: str,
    incident_type: str,
    incident_time: str,
    family_share_url: str = "",
) -> Dict[str, Any]:
    """
    Collect the real lost-phone event details passed to the AI.
    Location fields are included ONLY when authorized and available.
    """
    location_authorized = (
        bool(user_row.get("location_consent"))
        and bool(device_row.get("location_sharing_enabled"))
        and device_row.get("last_lat") is not None
        and device_row.get("last_lng") is not None
    )

    facts: Dict[str, Any] = {
        "recipient_first_name": _first_name(contact_row.get("contact_name", "")),
        "recipient_relationship": contact_row.get("relationship") or "Trusted contact",
        "owner_name": user_row.get("full_name") or "Your contact",
        "owner_phone": user_row.get("phone_number") or "",
        "device": f"{device_row.get('brand', '')} {device_row.get('model', '')}".strip(),
        "incident_type": (incident_type or "Lost").lower(),
        "incident_time": incident_time or "",
        "case_id": case_number,
        "location_included": False,
    }

    if location_authorized:
        label = (device_row.get("last_location_label") or "").strip()
        if not label or label == "Address unavailable":
            label = f"{float(device_row['last_lat']):.5f}, {float(device_row['last_lng']):.5f}"
        freshness = evaluate_location_freshness(
            device_row.get("last_location_at"), bool(device_row.get("location_sharing_enabled"))
        )
        facts["location_included"] = True
        facts["last_known_location"] = label
        facts["location_recorded_at"] = format_local_time(device_row.get("last_location_at")) if device_row.get("last_location_at") else ""
        facts["location_label"] = freshness["label"]
        # Secure tracking link only if contact opted into links
        if family_share_url and "Link" in (contact_row.get("notification_preference") or ""):
            facts["secure_tracking_link"] = family_share_url
    return facts


# ---------------------------------------------------------------------------
# Message generation (AI + deterministic fallback)
# ---------------------------------------------------------------------------
_SYSTEM_INSTRUCTION = (
    "You write emergency SMS alerts for SecurePhone, a phone anti-theft platform. "
    "Write ONE plain-text SMS to a trusted contact whose friend/family member just reported their phone lost or stolen. "
    "Rules: start exactly with 'SECUREPHONE ALERT:'; greet the recipient by first name; name the owner; "
    "state the device and whether it was lost or stolen; ask the recipient to contact the owner and help coordinate recovery; "
    "include the Case ID exactly as given; include the last-known location, its time, and the secure tracking link ONLY if "
    "they are present in the facts, copied verbatim; never invent details, phone numbers, links, or locations; "
    "if the owner_phone is empty, do not mention a phone number; no emojis, no markdown, no quotes; "
    f"maximum {MAX_SMS_CHARS - 60} characters. Output only the SMS text."
)


def build_fallback_message(facts: Dict[str, Any]) -> str:
    """Deterministic alert built from the same real event details (used when AI is unavailable)."""
    parts = [
        f"SECUREPHONE ALERT: Hi {facts['recipient_first_name']}, {facts['owner_name']} has reported their "
        f"{facts['device']} as {facts['incident_type']}. Please contact them and help coordinate recovery.",
        f"Case ID: {facts['case_id']}.",
    ]
    if facts.get("location_included"):
        loc = f"{facts.get('location_label', 'Last known location')}: {facts['last_known_location']}"
        if facts.get("location_recorded_at"):
            loc += f" ({facts['location_recorded_at']})"
        parts.append(loc + ".")
        if facts.get("secure_tracking_link"):
            parts.append(f"Track: {facts['secure_tracking_link']}")
    return " ".join(parts)[:MAX_SMS_CHARS]


def _validate_ai_message(text: str, facts: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """Normalize and validate AI output. Returns (message or None, error)."""
    if not text:
        return None, "AI returned an empty response."
    msg = re.sub(r"\s+", " ", text.replace("**", "").replace("`", "")).strip().strip('"').strip()
    if not msg.upper().startswith("SECUREPHONE ALERT"):
        msg = "SECUREPHONE ALERT: " + msg
    if facts["case_id"] not in msg:
        msg = f"{msg} Case ID: {facts['case_id']}."
    link = facts.get("secure_tracking_link")
    if link and link not in msg:
        msg = f"{msg} Track: {link}"
    # Reject any URL the AI invented
    for url in re.findall(r"https?://\S+", msg):
        if not link or url.rstrip(".,)") != link:
            return None, "AI output contained an unapproved link."
    if not facts.get("location_included") and re.search(r"-?\d{1,3}\.\d{4,}", msg):
        return None, "AI output contained coordinates without location authorization."
    if len(msg) > MAX_SMS_CHARS:
        return None, f"AI output exceeded {MAX_SMS_CHARS} characters."
    return msg, ""


def call_gemini_api(prompt: str, system_instruction: str, api_key: str, model: str, timeout: float = 8.0) -> str:
    """Call the Gemini generateContent REST endpoint and return the text output."""
    url = f"{GEMINI_API_BASE}/{urllib.parse.quote(model)}:generateContent"
    body = {
        "systemInstruction": {"parts": [{"text": system_instruction}]},
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.4, "maxOutputTokens": 1024},
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    candidates = payload.get("candidates") or []
    if not candidates:
        raise ValueError("No candidates returned (possibly blocked).")
    parts = (candidates[0].get("content") or {}).get("parts") or []
    return "".join(p.get("text", "") for p in parts if not p.get("thought"))


def call_openai_api(prompt: str, system_instruction: str, api_key: str, model: str, timeout: float = 8.0) -> str:
    """Call the OpenAI Chat Completions REST endpoint and return the text output."""
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.4,
        "max_tokens": 160,
    }
    req = urllib.request.Request(
        OPENAI_API_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    choices = payload.get("choices") or []
    if not choices:
        raise ValueError("No choices returned from OpenAI.")
    return (choices[0].get("message") or {}).get("content", "")


def generate_alert_message(facts: Dict[str, Any]) -> Dict[str, str]:
    """
    Generate the personalized alert text. Returns dict with
    message, generation_status, ai_provider, ai_model, generation_error.
    """
    status = get_ai_provider_status()
    if not status["configured"]:
        return {
            "message": build_fallback_message(facts),
            "generation_status": "Fallback_Template",
            "ai_provider": "Template_Fallback",
            "ai_model": "",
            "generation_error": "AI API key (GEMINI_API_KEY or OPENAI_API_KEY) not configured; message built from event details without AI.",
        }

    provider = status["provider_name"]
    model = status["model"]
    prompt = "Lost-phone event facts (JSON):\n" + json.dumps(facts, ensure_ascii=False, indent=2)
    error = ""

    try:
        if provider == "Google_Gemini":
            api_key = os.environ.get("GEMINI_API_KEY", "").strip() or os.environ.get("GOOGLE_API_KEY", "").strip()
            raw = None
            candidate_models = [model] + [m for m in GEMINI_FALLBACK_MODELS if m != model]
            last_err = None
            for m in candidate_models:
                try:
                    raw = call_gemini_api(prompt, _SYSTEM_INSTRUCTION, api_key, m)
                    model = m
                    break
                except urllib.error.HTTPError as h_err:
                    last_err = h_err
                    if h_err.code in (404, 400):
                        continue
                    raise
            if raw is None and last_err:
                raise last_err
        elif provider == "OpenAI":
            api_key = os.environ.get("OPENAI_API_KEY", "").strip()
            raw = call_openai_api(prompt, _SYSTEM_INSTRUCTION, api_key, model)
        else:
            raw = ""

        msg, err = _validate_ai_message(raw, facts)
        if msg:
            return {
                "message": msg,
                "generation_status": "AI_Generated",
                "ai_provider": provider,
                "ai_model": model,
                "generation_error": "",
            }
        error = err
    except urllib.error.HTTPError as exc:
        error = f"{provider} API HTTP {exc.code}: {exc.reason}"
    except Exception as exc:  # network errors, timeouts, malformed JSON
        error = f"{provider} API error: {str(exc)[:160]}"

    return {
        "message": build_fallback_message(facts),
        "generation_status": "Fallback_Template",
        "ai_provider": provider,
        "ai_model": model,
        "generation_error": f"{error} Fallback template used.",
    }


# ---------------------------------------------------------------------------
# Recipient selection
# ---------------------------------------------------------------------------
def select_authorized_contacts(
    conn: sqlite3.Connection, user_id: int, device_id: int, contact_ids: Optional[List[int]] = None
) -> List[sqlite3.Row]:
    """Return trusted contacts that are verified AND have confirmed consent."""
    base = "verification_status = 'Verified' AND consent_confirmed = 1"
    if contact_ids:
        ph = ",".join("?" for _ in contact_ids)
        return conn.execute(
            f"SELECT * FROM trusted_contacts WHERE user_id = ? AND {base} AND id IN ({ph}) ORDER BY id",
            [user_id] + [int(c) for c in contact_ids],
        ).fetchall()
    rows = conn.execute(
        """
        SELECT tc.* FROM trusted_contacts tc
        JOIN device_trusted_contacts dtc ON dtc.contact_id = tc.id
        WHERE tc.user_id = ? AND dtc.device_id = ?
          AND tc.verification_status = 'Verified' AND tc.consent_confirmed = 1
        ORDER BY tc.id
        """,
        (user_id, device_id),
    ).fetchall()
    if rows:
        return rows
    return conn.execute(
        f"SELECT * FROM trusted_contacts WHERE user_id = ? AND {base} ORDER BY id", (user_id,)
    ).fetchall()


# ---------------------------------------------------------------------------
# SMS dispatch
# ---------------------------------------------------------------------------
def _status_callback_url() -> str:
    """Twilio can only call back a publicly reachable URL (e.g. via ngrok/deployment)."""
    base = os.environ.get("SECUREPHONE_PUBLIC_BASE_URL", "").strip().rstrip("/")
    return f"{base}/webhooks/twilio/ai-alert-status" if base.startswith("https://") else ""


def _send_and_record(conn: sqlite3.Connection, alert_id: int, phone: str, message: str) -> Dict[str, str]:
    provider, gw_status, msg_id, err = dispatch_sms_via_provider(
        phone, message, status_callback=_status_callback_url()
    )
    status = _GATEWAY_STATUS_MAP.get(gw_status, "Failed")
    now = _now_str()
    conn.execute(
        """
        UPDATE ai_trusted_alerts
        SET notification_status = ?, sms_provider = ?, provider_message_id = ?, provider_error = ?,
            attempt_count = attempt_count + 1, updated_at = ?,
            sent_at = CASE WHEN ? IN ('Sent', 'Delivered') THEN ? ELSE sent_at END,
            delivered_at = CASE WHEN ? = 'Delivered' THEN ? ELSE delivered_at END
        WHERE id = ?
        """,
        (status, provider, msg_id, err, now, status, now, status, now, alert_id),
    )
    return {"notification_status": status, "sms_provider": provider, "provider_error": err}


# ---------------------------------------------------------------------------
# Main workflow
# ---------------------------------------------------------------------------
def trigger_lost_mode_ai_alerts(
    conn: sqlite3.Connection,
    user_row: Dict[str, Any],
    device_row: Dict[str, Any],
    case_id: int,
    case_number: str,
    lost_report_id: Optional[int],
    incident_type: str,
    incident_time: str,
    contact_ids: Optional[List[int]] = None,
    family_share_url: str = "",
    trigger_event: str = TRIGGER_LOST_MODE,
) -> Dict[str, Any]:
    """
    Generate and send AI-written alerts to verified trusted contacts for a lost-phone event.
    Each (case, contact) pair is alerted at most once; repeats are reported as duplicates.
    Commits after each alert so 'Pending' rows are visible even if a provider call hangs.
    """
    if trigger_event != TRIGGER_LOST_MODE:
        raise ValueError("AI trusted-contact alerts may only be triggered by Lost Mode activation.")

    uid = user_row["id"]
    device_id = device_row["id"]
    contacts = select_authorized_contacts(conn, uid, device_id, contact_ids)
    results: List[Dict[str, Any]] = []
    duplicates = 0

    for c in contacts:
        c = dict(c)
        event_key = f"{trigger_event}:case:{case_id}:contact:{c['id']}"
        now = _now_str()
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO ai_trusted_alerts (
                event_key, trigger_event, user_id, device_id, case_id, case_number, lost_report_id,
                contact_id, recipient_name, recipient_phone_masked, notification_status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?, ?)
            """,
            (event_key, trigger_event, uid, device_id, case_id, case_number, lost_report_id,
             c["id"], c["contact_name"], mask_phone(c["phone_number"]), now, now),
        )
        if cur.rowcount == 0:
            duplicates += 1
            continue
        alert_id = cur.lastrowid
        conn.commit()

        facts = build_event_facts(user_row, device_row, c, case_number, incident_type, incident_time, family_share_url)
        gen = generate_alert_message(facts)
        conn.execute(
            """
            UPDATE ai_trusted_alerts
            SET message_body = ?, generation_status = ?, ai_provider = ?, ai_model = ?,
                generation_error = ?, location_included = ?, updated_at = ?
            WHERE id = ?
            """,
            (gen["message"], gen["generation_status"], gen["ai_provider"], gen["ai_model"],
             gen["generation_error"], 1 if facts["location_included"] else 0, _now_str(), alert_id),
        )
        sent = _send_and_record(conn, alert_id, c["phone_number"], gen["message"])
        conn.commit()
        results.append({
            "alert_id": alert_id,
            "contact_name": c["contact_name"],
            "generation_status": gen["generation_status"],
            **sent,
        })

    return {
        "alerts": results,
        "authorized_contacts": len(contacts),
        "duplicates_prevented": duplicates,
        "ai_status": get_ai_provider_status(),
        "sms_status": get_sms_provider_status(),
    }


def retry_ai_alert(conn: sqlite3.Connection, alert_id: int, user_id: int) -> Optional[Dict[str, str]]:
    """Re-send a Failed alert (same stored message) if the contact is still verified + consenting."""
    row = conn.execute(
        "SELECT * FROM ai_trusted_alerts WHERE id = ? AND user_id = ?", (alert_id, user_id)
    ).fetchone()
    if not row:
        return None
    if row["notification_status"] != "Failed":
        return {"notification_status": row["notification_status"], "provider_error": "Only failed alerts can be retried."}
    contact = conn.execute(
        """SELECT * FROM trusted_contacts WHERE id = ? AND user_id = ?
           AND verification_status = 'Verified' AND consent_confirmed = 1""",
        (row["contact_id"], user_id),
    ).fetchone()
    if not contact:
        return {"notification_status": "Failed", "provider_error": "Contact is no longer verified or authorized."}
    result = _send_and_record(conn, alert_id, contact["phone_number"], row["message_body"])
    conn.commit()
    return result


# ---------------------------------------------------------------------------
# Delivery confirmation (Twilio)
# ---------------------------------------------------------------------------
def apply_provider_status(conn: sqlite3.Connection, provider_message_id: str, provider_status: str, error: str = "") -> bool:
    """Update an alert from a provider status value. Delivered never downgrades."""
    status = _TWILIO_STATUS_MAP.get((provider_status or "").lower())
    if not status or not provider_message_id:
        return False
    now = _now_str()
    cur = conn.execute(
        """
        UPDATE ai_trusted_alerts
        SET notification_status = ?, provider_error = CASE WHEN ? != '' THEN ? ELSE provider_error END,
            updated_at = ?,
            delivered_at = CASE WHEN ? = 'Delivered' THEN ? ELSE delivered_at END
        WHERE provider_message_id = ? AND notification_status NOT IN ('Delivered', 'Demo_Notification')
        """,
        (status, error, error, now, status, now, provider_message_id),
    )
    conn.commit()
    return cur.rowcount > 0


def refresh_twilio_status(conn: sqlite3.Connection, alert_id: int, user_id: int) -> Tuple[bool, str]:
    """Poll Twilio for the latest status of a sent alert (works without a public callback URL)."""
    row = conn.execute(
        "SELECT * FROM ai_trusted_alerts WHERE id = ? AND user_id = ?", (alert_id, user_id)
    ).fetchone()
    if not row:
        return False, "Alert not found."
    if row["sms_provider"] != "Twilio_API" or not row["provider_message_id"]:
        return False, "Delivery status can only be refreshed for alerts sent via Twilio."
    sid = os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
    token = os.environ.get("TWILIO_AUTH_TOKEN", "").strip()
    if not (sid and token):
        return False, "Twilio credentials are not configured."
    url = (f"https://api.twilio.com/2010-04-01/Accounts/{urllib.parse.quote(sid)}"
           f"/Messages/{urllib.parse.quote(row['provider_message_id'])}.json")
    auth = base64.b64encode(f"{sid}:{token}".encode()).decode("ascii")
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {auth}"})
    try:
        with urllib.request.urlopen(req, timeout=6.0) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return False, f"Could not reach Twilio: {str(exc)[:120]}"
    tw_status = str(payload.get("status", ""))
    err = str(payload.get("error_message") or "")
    apply_provider_status(conn, row["provider_message_id"], tw_status, err)
    return True, tw_status


def verify_twilio_signature(url: str, params: Dict[str, str], signature: str) -> bool:
    """Validate X-Twilio-Signature (HMAC-SHA1 of URL + sorted POST params, keyed by auth token)."""
    token = os.environ.get("TWILIO_AUTH_TOKEN", "").strip()
    if not token or not signature:
        return False
    data = url + "".join(f"{k}{params[k]}" for k in sorted(params))
    digest = base64.b64encode(hmac.new(token.encode(), data.encode(), hashlib.sha1).digest()).decode()
    return hmac.compare_digest(digest, signature)
