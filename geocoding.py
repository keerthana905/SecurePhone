"""
Reverse Geocoding & Local Timezone Formatting for SecurePhone:
- Converts GPS coordinates (latitude, longitude) into a human-readable address
  using the OpenStreetMap Nominatim Reverse Geocoding API.
- Extracts building/place name, street, area/suburb, city, state, country, and postal code.
- Caches resolved addresses by rounded coordinates (4 decimal places ~ 11m) in SQLite
  and memory to respect Nominatim's 1 req/sec usage policy and avoid redundant lookups.
- Falls back honestly to "Address unavailable" when offline or unresolved—never invents addresses.
- Converts timestamps to local time (IST UTC+05:30 by default) for display.
"""

import datetime
import json
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Optional, Tuple

IST_OFFSET = datetime.timezone(datetime.timedelta(hours=5, minutes=30), name="IST")

# In-memory cache and rate-limit tracker for Nominatim
_MEMORY_GEO_CACHE: Dict[Tuple[float, float], str] = {}
_LAST_NOMINATIM_CALL_TS: float = 0.0
NOMINATIM_USER_AGENT = "SecurePhone-SmartCity-AntiTheft-Platform/1.0 (Academic Prototype)"


def now_ist_str() -> str:
    """Return current timestamp formatted in Indian Standard Time (IST, UTC+05:30)."""
    now_ist = datetime.datetime.now(IST_OFFSET)
    return now_ist.strftime("%d %b %Y, %I:%M:%S %p IST")


def format_local_time(timestamp_str: Optional[str]) -> str:
    """
    Convert a stored UTC or ISO timestamp string into a readable local IST timestamp
    (e.g. '27 Oct 2026, 01:50:12 PM IST').
    If already formatted in IST or unparseable, returns a clean string without raw UTC.
    """
    if not timestamp_str:
        return "Not recorded"
    raw = str(timestamp_str).strip()
    if "IST" in raw:
        return raw

    # Try common formats stored in SQLite
    cleaned = raw.replace(" UTC", "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.datetime.strptime(cleaned, fmt)
            if fmt == "%Y-%m-%d":
                return dt.strftime("%d %b %Y")
            dt_utc = dt.replace(tzinfo=datetime.timezone.utc)
            dt_ist = dt_utc.astimezone(IST_OFFSET)
            return dt_ist.strftime("%d %b %Y, %I:%M:%S %p IST")
        except ValueError:
            continue

    return raw


def _deg_to_dms(deg: float, is_lat: bool) -> str:
    direction = ("N" if deg >= 0 else "S") if is_lat else ("E" if deg >= 0 else "W")
    abs_deg = abs(float(deg))
    degrees = int(abs_deg)
    minutes_full = (abs_deg - degrees) * 60.0
    minutes = int(minutes_full)
    seconds = (minutes_full - minutes) * 60.0
    return f"{degrees}°{minutes:02d}'{seconds:04.1f}\"{direction}"


def format_dms_coordinates(lat: Optional[float], lng: Optional[float]) -> str:
    """Format decimal latitude and longitude as DMS (e.g., 12°58'05.8\"N 77°35'32.9\"E)."""
    if lat is None or lng is None:
        return "Unavailable"
    try:
        return f"{_deg_to_dms(float(lat), True)} {_deg_to_dms(float(lng), False)}"
    except (TypeError, ValueError):
        return "Unavailable"


def build_map_links(lat: Optional[float], lng: Optional[float]) -> Dict[str, str]:
    """Build clickable Google Maps and OpenStreetMap URLs for valid coordinates."""
    if lat is None or lng is None:
        return {"google_maps": "", "osm": ""}
    try:
        lat_f = float(lat)
        lng_f = float(lng)
    except (TypeError, ValueError):
        return {"google_maps": "", "osm": ""}
    return {
        "google_maps": f"https://www.google.com/maps?q={lat_f:.6f},{lng_f:.6f}",
        "osm": f"https://www.openstreetmap.org/?mlat={lat_f:.6f}&mlon={lng_f:.6f}#map=17/{lat_f:.6f}/{lng_f:.6f}",
    }


def format_nominatim_payload(payload: dict) -> str:
    """
    Extract building/place name, street, area/suburb, city, state, country, and postal code
    from a Nominatim reverse-geocoding JSON response.
    Returns 'Address unavailable' if no meaningful address fields are present.
    """
    if not isinstance(payload, dict):
        return "Address unavailable"

    addr = payload.get("address") or {}
    if not isinstance(addr, dict):
        addr = {}

    parts = []

    # 1. Building / Place / Amenity name
    place_name = (
        payload.get("name")
        or addr.get("building")
        or addr.get("amenity")
        or addr.get("shop")
        or addr.get("office")
        or addr.get("tourism")
        or addr.get("leisure")
    )
    house_number = addr.get("house_number")
    if place_name and house_number and house_number not in place_name:
        parts.append(f"{place_name} ({house_number})")
    elif place_name:
        parts.append(str(place_name))
    elif house_number:
        parts.append(str(house_number))

    # 2. Street / Road
    street = addr.get("road") or addr.get("pedestrian") or addr.get("street") or addr.get("residential")
    if street and street not in parts:
        parts.append(str(street))

    # 3. Area / Suburb / Neighbourhood
    area = (
        addr.get("Georgetown")
        or addr.get("neighbourhood")
        or addr.get("suburb")
        or addr.get("quarter")
        or addr.get("city_district")
        or addr.get("locality")
    )
    if area and area not in parts:
        parts.append(str(area))

    # 4. City / Town / Village
    city = addr.get("city") or addr.get("town") or addr.get("village") or addr.get("municipality") or addr.get("county")
    if city and city not in parts:
        parts.append(str(city))

    # 5. State
    state = addr.get("state") or addr.get("state_district")
    if state and state not in parts:
        parts.append(str(state))

    # 6. Postal Code
    postcode = addr.get("postcode")

    # 7. Country
    country = addr.get("country")
    if country and postcode:
        parts.append(f"{country} - {postcode}")
    elif country:
        parts.append(str(country))
    elif postcode:
        parts.append(str(postcode))

    if parts:
        return ", ".join(parts)

    display_name = (payload.get("display_name") or "").strip()
    if display_name:
        return display_name

    return "Address unavailable"


def ensure_geocoding_cache_table(conn: sqlite3.Connection) -> None:
    """Ensure the SQLite geocoding_cache table exists."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS geocoding_cache (
            lat_r REAL NOT NULL,
            lng_r REAL NOT NULL,
            readable_address TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (lat_r, lng_r)
        );
        """
    )


def reverse_geocode_coordinates(
    lat: float,
    lng: float,
    conn: Optional[sqlite3.Connection] = None,
    timeout: float = 3.5,
) -> str:
    """
    Resolve (lat, lng) into a readable address using cache + OpenStreetMap Nominatim API.
    If resolution fails or network is unreachable, returns 'Address unavailable' without inventing an address.
    """
    global _LAST_NOMINATIM_CALL_TS

    try:
        lat_f = float(lat)
        lng_f = float(lng)
    except (TypeError, ValueError):
        return "Address unavailable"

    if not (-90.0 <= lat_f <= 90.0 and -180.0 <= lng_f <= 180.0):
        return "Address unavailable"

    key = (round(lat_f, 4), round(lng_f, 4))

    # 1. Check in-memory cache
    if key in _MEMORY_GEO_CACHE:
        return _MEMORY_GEO_CACHE[key]

    # 2. Check SQLite persistent cache
    if conn is not None:
        try:
            ensure_geocoding_cache_table(conn)
            row = conn.execute(
                "SELECT readable_address FROM geocoding_cache WHERE lat_r = ? AND lng_r = ?",
                (key[0], key[1]),
            ).fetchone()
            if row and row["readable_address"] and row["readable_address"] != "Address unavailable":
                _MEMORY_GEO_CACHE[key] = row["readable_address"]
                return row["readable_address"]
        except sqlite3.Error:
            pass

    # 3. Respect Nominatim 1 req/sec rate limit
    now = time.time()
    elapsed = now - _LAST_NOMINATIM_CALL_TS
    if elapsed < 1.0:
        time.sleep(1.0 - elapsed)

    params = urllib.parse.urlencode({
        "format": "jsonv2",
        "lat": f"{lat_f:.6f}",
        "lon": f"{lng_f:.6f}",
        "zoom": "18",
        "addressdetails": "1",
        "accept-language": "en",
    })
    url = f"https://nominatim.openstreetmap.org/reverse?{params}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": NOMINATIM_USER_AGENT,
            "Accept": "application/json",
        },
    )

    try:
        _LAST_NOMINATIM_CALL_TS = time.time()
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                raw_json = resp.read().decode("utf-8", errors="replace")
                data = json.loads(raw_json)
                resolved = format_nominatim_payload(data)
                if resolved and resolved != "Address unavailable":
                    _MEMORY_GEO_CACHE[key] = resolved
                    if conn is not None:
                        try:
                            conn.execute(
                                """
                                INSERT OR REPLACE INTO geocoding_cache (lat_r, lng_r, readable_address, updated_at)
                                VALUES (?, ?, ?, ?)
                                """,
                                (key[0], key[1], resolved, now_ist_str()),
                            )
                        except sqlite3.Error:
                            pass
                    return resolved
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        pass

    return "Address unavailable"


def format_sos_alert_message(
    device_name: str,
    brand: str,
    model: str,
    readable_address: str,
    lat: Optional[float] = None,
    lng: Optional[float] = None,
    accuracy: Optional[float] = None,
    recorded_at_str: Optional[str] = None,
    is_live: bool = False,
    recorded_local_time: Optional[str] = None,
) -> str:
    """
    Generate a Trusted Contact SOS Alert message including readable address,
    recorded local date & time, GPS coordinates, accuracy, and clickable map link.
    Clearly labels whether the location is LIVE or LAST RECORDED.
    """
    mode_tag = "[LIVE LOCATION]" if is_live else "[LAST RECORDED LOCATION]"
    place_text = readable_address if readable_address and readable_address != "Address unavailable" else "Address unavailable"
    links = build_map_links(lat, lng)
    coords_str = f"{lat:.6f}, {lng:.6f}" if (lat is not None and lng is not None) else "Unavailable"
    dms_str = format_dms_coordinates(lat, lng)
    acc_str = f"±{round(accuracy)} metres" if accuracy is not None else "N/A"
    map_url = links["google_maps"] or links["osm"] or "No map link available"
    local_time_display = recorded_local_time or format_local_time(recorded_at_str)

    return (
        f"SECUREPHONE TRUSTED CONTACT SOS ALERT {mode_tag}\n"
        f"Device: {device_name} ({brand} {model})\n"
        f"Detected Location: {place_text}\n"
        f"Last Updated: {local_time_display}\n"
        f"GPS Accuracy: {acc_str}\n"
        f"GPS Coordinates: {coords_str} ({dms_str})\n"
        f"View on Google Maps: {map_url}"
    )
