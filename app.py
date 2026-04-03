import base64
import json
import math
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv
from flask import Flask, g, redirect, render_template, request, session, url_for


load_dotenv()


SSO_METADATA_URL = "https://login.eveonline.com/.well-known/oauth-authorization-server"
ESI_BASE_URL = "https://esi.evetech.net/latest"
ESI_COMPATIBILITY_DATE = "2026-04-02"
PI_ATTENTION_WINDOW_HOURS = 6
CACHE_TTL_SECONDS = 15 * 60
BACKGROUND_REFRESH_INTERVAL_SECONDS = 1 * 60
MANUAL_PULL_COOLDOWN_SECONDS = 60
EVE_SCOPES = [
    "esi-location.read_location.v1",
    "esi-location.read_ship_type.v1",
    "esi-wallet.read_character_wallet.v1",
    "esi-planets.manage_planets.v1",
]


app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", Path(__file__).with_name("eve_dashboard.db")))
REFRESHER_LOCK = threading.Lock()
REFRESHER_STARTED = False


@app.template_filter("isk")
def format_isk(value):
    if value is None:
        return "N/A"
    return f"{value:,.2f} ISK"


@app.template_filter("eve_time")
def format_eve_time(value):
    if not value:
        return "Unknown"
    return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")


@app.template_filter("countdown")
def format_countdown(value):
    if not value:
        return "Unknown"

    target = datetime.fromisoformat(value.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    delta = target - now
    total_seconds = int(delta.total_seconds())

    if total_seconds <= 0:
        return "Expired"

    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)

    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes or not parts:
        parts.append(f"{minutes}m")
    return " ".join(parts)


@app.template_filter("cache_age")
def format_cache_age(value):
    if not value:
        return "Unknown"
    age_seconds = max(0, int(time.time()) - int(value))
    minutes = age_seconds // 60
    if minutes < 1:
        return "just now"
    if minutes == 1:
        return "1 minute ago"
    return f"{minutes} minutes ago"


@app.template_filter("next_update_time")
def format_next_update_time(value):
    if not value:
        return "Unknown"
    next_update = datetime.fromtimestamp(int(value), tz=timezone.utc)
    return next_update.strftime("%Y-%m-%d %H:%M UTC")


def get_required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def get_db():
    if "db" not in g:
        DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db() -> None:
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS characters (
            character_id INTEGER PRIMARY KEY,
            character_name TEXT NOT NULL,
            access_token TEXT NOT NULL,
            refresh_token TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS dashboard_cache (
            character_id INTEGER PRIMARY KEY,
            payload_json TEXT NOT NULL,
            fetched_at INTEGER NOT NULL,
            refresh_requested_at INTEGER,
            FOREIGN KEY(character_id) REFERENCES characters(character_id) ON DELETE CASCADE
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS app_state (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )
    db.commit()


@app.before_request
def ensure_db():
    init_db()


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def save_character_auth(character_id: int, character_name: str, token_data: dict) -> None:
    db = get_db()
    db.execute(
        """
        INSERT INTO characters (character_id, character_name, access_token, refresh_token, expires_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(character_id) DO UPDATE SET
            character_name = excluded.character_name,
            access_token = excluded.access_token,
            refresh_token = excluded.refresh_token,
            expires_at = excluded.expires_at
        """,
        (
            character_id,
            character_name,
            token_data["access_token"],
            token_data["refresh_token"],
            int(time.time()) + int(token_data["expires_in"]),
        ),
    )
    db.commit()


def get_cached_dashboard(character_id: int):
    row = get_db().execute(
        """
        SELECT payload_json, fetched_at, refresh_requested_at
        FROM dashboard_cache
        WHERE character_id = ?
        """,
        (character_id,),
    ).fetchone()
    if not row:
        return None
    payload = json.loads(row["payload_json"])
    payload["_cached_at"] = row["fetched_at"]
    payload["_refresh_requested_at"] = row["refresh_requested_at"]
    return payload


def save_cached_dashboard(character_id: int, payload: dict) -> None:
    db = get_db()
    db.execute(
        """
        INSERT INTO dashboard_cache (character_id, payload_json, fetched_at, refresh_requested_at)
        VALUES (?, ?, ?, NULL)
        ON CONFLICT(character_id) DO UPDATE SET
            payload_json = excluded.payload_json,
            fetched_at = excluded.fetched_at,
            refresh_requested_at = NULL
        """,
        (character_id, json.dumps(payload), int(time.time())),
    )
    db.commit()


def request_dashboard_refresh(character_id: int) -> None:
    db = get_db()
    now = int(time.time())
    db.execute(
        """
        INSERT INTO dashboard_cache (character_id, payload_json, fetched_at, refresh_requested_at)
        VALUES (?, '{}', 0, ?)
        ON CONFLICT(character_id) DO UPDATE SET
            refresh_requested_at = excluded.refresh_requested_at
        """,
        (character_id, now),
    )
    db.commit()


def clear_dashboard_cache(character_id: int | None = None) -> None:
    db = get_db()
    if character_id is None:
        db.execute("DELETE FROM dashboard_cache")
    else:
        db.execute("DELETE FROM dashboard_cache WHERE character_id = ?", (character_id,))
    db.commit()


def get_app_state(key: str) -> str | None:
    row = get_db().execute("SELECT value FROM app_state WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_app_state(key: str, value: str | int | None) -> None:
    db = get_db()
    if value is None:
        db.execute("DELETE FROM app_state WHERE key = ?", (key,))
    else:
        db.execute(
            """
            INSERT INTO app_state (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, str(value)),
        )
    db.commit()


def get_last_manual_pull_at() -> int | None:
    value = get_app_state("last_manual_pull_completed_at")
    return int(value) if value else None


def is_manual_pull_in_progress() -> bool:
    return get_app_state("manual_pull_in_progress") == "1"


def can_manual_pull() -> bool:
    if is_manual_pull_in_progress():
        return False
    last_manual_pull_at = get_last_manual_pull_at()
    if not last_manual_pull_at:
        return True
    return int(time.time()) - int(last_manual_pull_at) >= MANUAL_PULL_COOLDOWN_SECONDS


def get_manual_pull_available_at() -> int | None:
    if is_manual_pull_in_progress():
        return None
    last_manual_pull_at = get_last_manual_pull_at()
    if not last_manual_pull_at:
        return None
    return int(last_manual_pull_at) + MANUAL_PULL_COOLDOWN_SECONDS


def is_cache_fresh(cached_payload: dict | None) -> bool:
    if not cached_payload:
        return False
    cached_at = cached_payload.get("_cached_at")
    if not cached_at:
        return False
    return int(time.time()) - int(cached_at) < CACHE_TTL_SECONDS


def attach_cache_metadata(payload: dict | None) -> dict | None:
    if not payload:
        return payload
    cached_at = payload.get("_cached_at")
    if cached_at:
        payload["_next_update_at"] = int(cached_at) + CACHE_TTL_SECONDS
    return payload


def update_character_tokens(character_id: int, token_data: dict) -> None:
    db = get_db()
    db.execute(
        """
        UPDATE characters
        SET access_token = ?, refresh_token = ?, expires_at = ?
        WHERE character_id = ?
        """,
        (
            token_data["access_token"],
            token_data["refresh_token"],
            int(time.time()) + int(token_data["expires_in"]),
            character_id,
        ),
    )
    db.commit()


def get_saved_characters() -> list[dict]:
    rows = get_db().execute(
        "SELECT character_id, character_name FROM characters ORDER BY character_name COLLATE NOCASE"
    ).fetchall()
    return [dict(row) for row in rows]


def get_overview_wallet_total() -> float:
    rows = get_db().execute(
        """
        SELECT payload_json
        FROM dashboard_cache
        WHERE payload_json IS NOT NULL AND payload_json != '{}'
        """
    ).fetchall()
    total = 0.0
    for row in rows:
        payload = json.loads(row["payload_json"])
        total += float(payload.get("wallet_balance") or 0)
    return total


def get_overview_character_summaries() -> list[dict]:
    rows = get_db().execute(
        """
        SELECT c.character_id, c.character_name, dc.payload_json
        FROM characters c
        LEFT JOIN dashboard_cache dc ON dc.character_id = c.character_id
        ORDER BY c.character_name COLLATE NOCASE
        """
    ).fetchall()

    summaries = []
    for row in rows:
        next_expiry = None
        if row["payload_json"] and row["payload_json"] != "{}":
            payload = json.loads(row["payload_json"])
            next_expiry = payload.get("pi", {}).get("next_expiry")

        summaries.append(
            {
                "character_id": row["character_id"],
                "character_name": row["character_name"],
                "next_expiry": next_expiry,
            }
        )

    return summaries


def get_character_auth(character_id: int | None):
    if not character_id:
        return None
    row = get_db().execute(
        """
        SELECT character_id, character_name, access_token, refresh_token, expires_at
        FROM characters
        WHERE character_id = ?
        """,
        (character_id,),
    ).fetchone()
    return dict(row) if row else None


def get_active_character_auth():
    saved_characters = get_saved_characters()
    if not saved_characters:
        return None

    active_character_id = session.get("active_character_id")
    if active_character_id == "overview":
        return None
    if active_character_id is None:
        active_character_id = saved_characters[0]["character_id"]
        session["active_character_id"] = active_character_id

    active_character = get_character_auth(active_character_id)
    if active_character:
        return active_character

    active_character_id = saved_characters[0]["character_id"]
    session["active_character_id"] = active_character_id
    return get_character_auth(active_character_id)


def get_sso_metadata() -> dict:
    response = requests.get(SSO_METADATA_URL, timeout=15)
    response.raise_for_status()
    return response.json()


def get_esi_headers(access_token: str | None = None) -> dict:
    headers = {"X-Compatibility-Date": ESI_COMPATIBILITY_DATE}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    return headers


def get_basic_auth_header() -> str:
    client_id = get_required_env("EVE_CLIENT_ID")
    client_secret = get_required_env("EVE_CLIENT_SECRET")
    encoded = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("utf-8")
    return f"Basic {encoded}"


def parse_character_id(access_token: str) -> int:
    payload = access_token.split(".")[1]
    padding = "=" * (-len(payload) % 4)
    decoded = base64.urlsafe_b64decode(payload + padding)
    claims = json.loads(decoded)
    subject = claims["sub"]
    return int(subject.rsplit(":", 1)[-1])


def save_token(token_data: dict) -> None:
    session["pending_token_data"] = token_data


def refresh_access_token_if_needed(character_auth: dict | None) -> dict | None:
    if not character_auth:
        return
    if character_auth["expires_at"] > int(time.time()) + 60:
        return character_auth

    metadata = get_sso_metadata()
    response = requests.post(
        metadata["token_endpoint"],
        data={
            "grant_type": "refresh_token",
            "refresh_token": character_auth["refresh_token"],
        },
        headers={
            "Authorization": get_basic_auth_header(),
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "login.eveonline.com",
        },
        timeout=15,
    )
    response.raise_for_status()
    token_data = response.json()
    update_character_tokens(character_auth["character_id"], token_data)
    refreshed_character = get_character_auth(character_auth["character_id"])
    if session.get("active_character_id") == character_auth["character_id"]:
        session["active_character_id"] = character_auth["character_id"]
    return refreshed_character


def refresh_access_token_if_needed_for_worker(character_auth: dict | None) -> dict | None:
    if not character_auth:
        return None
    if character_auth["expires_at"] > int(time.time()) + 60:
        return character_auth

    metadata = get_sso_metadata()
    response = requests.post(
        metadata["token_endpoint"],
        data={
            "grant_type": "refresh_token",
            "refresh_token": character_auth["refresh_token"],
        },
        headers={
            "Authorization": get_basic_auth_header(),
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "login.eveonline.com",
        },
        timeout=15,
    )
    response.raise_for_status()
    token_data = response.json()
    update_character_tokens(character_auth["character_id"], token_data)
    return get_character_auth(character_auth["character_id"])


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        active_character = get_active_character_auth()
        if not active_character:
            return redirect(url_for("index"))
        refresh_access_token_if_needed(active_character)
        return view_func(*args, **kwargs)

    return wrapped_view


@app.route("/")
def index():
    saved_characters = get_saved_characters()
    active_character_id = session.get("active_character_id", "overview")
    active_character = None if active_character_id == "overview" else get_active_character_auth()
    location_summary = None
    overview_summary = None
    error = request.args.get("error")

    if active_character_id == "overview":
        overview_summary = {
            "character_count": len(saved_characters),
            "total_wallet_balance": get_overview_wallet_total(),
            "characters": get_overview_character_summaries(),
        }
    elif active_character:
        try:
            cached_summary = get_cached_dashboard(active_character["character_id"])
            if cached_summary and cached_summary.get("wallet_balance") is not None:
                location_summary = attach_cache_metadata(cached_summary)
        except requests.HTTPError as exc:
            error = f"Failed to fetch location: {exc.response.status_code} {exc.response.text}"

    return render_template(
        "index.html",
        logged_in=bool(saved_characters),
        characters=saved_characters,
        active_character_id=active_character_id,
        overview_summary=overview_summary,
        location_summary=location_summary,
        manual_pull_enabled=can_manual_pull(),
        manual_pull_available_at=get_manual_pull_available_at(),
        manual_pull_in_progress=is_manual_pull_in_progress(),
        error=error,
    )


@app.route("/login")
def login():
    metadata = get_sso_metadata()
    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state

    query = urlencode(
        {
            "response_type": "code",
            "redirect_uri": get_required_env("EVE_REDIRECT_URI"),
            "client_id": get_required_env("EVE_CLIENT_ID"),
            "scope": " ".join(EVE_SCOPES),
            "state": state,
        }
    )
    return redirect(f"{metadata['authorization_endpoint']}?{query}")


@app.route("/callback")
def callback():
    if request.args.get("error"):
        return redirect(url_for("index", error=request.args.get("error_description", request.args["error"])))

    if request.args.get("state") != session.get("oauth_state"):
        return redirect(url_for("index", error="OAuth state mismatch. Please try logging in again."))

    auth_code = request.args.get("code")
    if not auth_code:
        return redirect(url_for("index", error="Missing authorization code from EVE SSO."))

    metadata = get_sso_metadata()
    response = requests.post(
        metadata["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": get_required_env("EVE_REDIRECT_URI"),
        },
        headers={
            "Authorization": get_basic_auth_header(),
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "login.eveonline.com",
        },
        timeout=15,
    )
    response.raise_for_status()
    token_data = response.json()
    save_token(token_data)
    character_id = parse_character_id(token_data["access_token"])
    character = fetch_character_profile(character_id)
    save_character_auth(character_id, character["name"], token_data)
    if session.get("active_character_id") in (None, "overview"):
        session["active_character_id"] = "overview"
    request_dashboard_refresh(character_id)
    session.pop("pending_token_data", None)
    session.pop("oauth_state", None)
    return redirect(url_for("index"))


def fetch_character_location(character_auth: dict) -> dict:
    character_id = character_auth["character_id"]
    response = requests.get(
        f"{ESI_BASE_URL}/characters/{character_id}/location/",
        headers=get_esi_headers(character_auth["access_token"]),
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def fetch_character_profile(character_id: int) -> dict:
    response = requests.get(
        f"{ESI_BASE_URL}/characters/{character_id}/",
        headers=get_esi_headers(),
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def fetch_current_ship(character_auth: dict) -> dict:
    character_id = character_auth["character_id"]
    response = requests.get(
        f"{ESI_BASE_URL}/characters/{character_id}/ship/",
        headers=get_esi_headers(character_auth["access_token"]),
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def fetch_universe_names(ids: list[int]) -> list[dict]:
    if not ids:
        return []
    response = requests.post(
        f"{ESI_BASE_URL}/universe/names/",
        headers={
            **get_esi_headers(),
            "Content-Type": "application/json",
        },
        json=ids,
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def fetch_wallet_balance(character_auth: dict) -> float:
    character_id = character_auth["character_id"]
    response = requests.get(
        f"{ESI_BASE_URL}/characters/{character_id}/wallet/",
        headers=get_esi_headers(character_auth["access_token"]),
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def fetch_wallet_journal(character_auth: dict, limit: int = 5) -> list[dict]:
    character_id = character_auth["character_id"]
    response = requests.get(
        f"{ESI_BASE_URL}/characters/{character_id}/wallet/journal/",
        params={"page": 1},
        headers=get_esi_headers(character_auth["access_token"]),
        timeout=15,
    )
    response.raise_for_status()
    entries = response.json()
    entries.sort(key=lambda entry: (entry.get("date", ""), entry.get("id", 0)), reverse=True)
    return entries[:limit]


def fetch_planetary_colonies(character_auth: dict) -> list[dict]:
    character_id = character_auth["character_id"]
    response = requests.get(
        f"{ESI_BASE_URL}/characters/{character_id}/planets/",
        headers=get_esi_headers(character_auth["access_token"]),
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def fetch_planet_layout(character_auth: dict, planet_id: int) -> dict:
    character_id = character_auth["character_id"]
    response = requests.get(
        f"{ESI_BASE_URL}/characters/{character_id}/planets/{planet_id}/",
        headers=get_esi_headers(character_auth["access_token"]),
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def fetch_solar_system(system_id: int) -> dict:
    response = requests.get(
        f"{ESI_BASE_URL}/universe/systems/{system_id}/",
        headers=get_esi_headers(),
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def get_first_present(mapping: dict, *keys):
    for key in keys:
        if mapping.get(key) is not None:
            return mapping.get(key)
    return None


def build_pi_summary(character_auth: dict, colonies: list[dict]) -> dict:
    system_cache: dict[int, dict] = {}
    colony_cards = []
    extractors_expiring_soon = 0
    next_expiry = None
    active_extractors = 0
    now = datetime.now(timezone.utc)

    for colony in colonies:
        system_id = colony["solar_system_id"]
        if system_id not in system_cache:
            system_cache[system_id] = fetch_solar_system(system_id)
        system = system_cache[system_id]

        layout = fetch_planet_layout(character_auth, colony["planet_id"])
        pins = layout.get("pins", [])

        extractor_pins = []
        for pin in pins:
            extractor_details = pin.get("extractor_details")
            expiry_time = get_first_present(pin, "expiry_time", "expiryTime")
            install_time = get_first_present(pin, "install_time", "installTime")

            if extractor_details:
                expiry_time = expiry_time or get_first_present(extractor_details, "expiry_time", "expiryTime")
                install_time = install_time or get_first_present(extractor_details, "install_time", "installTime")

            if not extractor_details and not expiry_time:
                continue
            if not expiry_time:
                continue
            extractor_pins.append(
                {
                    "expiry_time": expiry_time,
                    "product_type_id": get_first_present(
                        extractor_details or {},
                        "product_type_id",
                        "productTypeId",
                    ),
                    "qty_per_cycle": get_first_present(
                        extractor_details or {},
                        "qty_per_cycle",
                        "qtyPerCycle",
                    ),
                    "install_time": install_time,
                }
            )

        active_extractors += len(extractor_pins)

        expiry_datetimes = [
            datetime.fromisoformat(extractor["expiry_time"].replace("Z", "+00:00"))
            for extractor in extractor_pins
        ]
        soonest_colony_expiry = min(expiry_datetimes) if expiry_datetimes else None

        if soonest_colony_expiry:
            if soonest_colony_expiry <= now:
                extractors_expiring_soon += 1
            elif (soonest_colony_expiry - now).total_seconds() <= PI_ATTENTION_WINDOW_HOURS * 3600:
                extractors_expiring_soon += 1

            if next_expiry is None or soonest_colony_expiry < next_expiry:
                next_expiry = soonest_colony_expiry

        colony_cards.append(
            {
                "planet_id": colony["planet_id"],
                "planet_type": colony["planet_type"].title(),
                "system_name": system["name"],
                "last_update": colony.get("last_update"),
                "num_pins": colony.get("num_pins"),
                "upgrade_level": colony.get("upgrade_level"),
                "extractor_count": len(extractor_pins),
                "next_expiry": soonest_colony_expiry.isoformat().replace("+00:00", "Z") if soonest_colony_expiry else None,
            }
        )

    colony_cards.sort(key=lambda colony: colony["next_expiry"] or "9999")

    return {
        "colony_count": len(colonies),
        "active_extractors": active_extractors,
        "extractors_expiring_soon": extractors_expiring_soon,
        "next_expiry": next_expiry.isoformat().replace("+00:00", "Z") if next_expiry else None,
        "colonies": colony_cards,
    }


def build_location_summary(character_auth: dict) -> dict:
    character_id = character_auth["character_id"]
    location = fetch_character_location(character_auth)
    character = fetch_character_profile(character_id)
    ship = fetch_current_ship(character_auth)
    wallet_balance = fetch_wallet_balance(character_auth)
    journal_entries = fetch_wallet_journal(character_auth, limit=5)
    colonies = fetch_planetary_colonies(character_auth)

    ship_name = "Unknown"
    ship_type_id = ship.get("ship_type_id")
    if ship_type_id:
        names = fetch_universe_names([ship_type_id])
        if names:
            ship_name = names[0]["name"]

    summary = {
        "character_id": character_id,
        "character_name": character["name"],
        "location": location,
        "ship_name": ship_name,
        "wallet_balance": wallet_balance,
        "journal_entries": journal_entries,
        "pi": build_pi_summary(character_auth, colonies),
    }

    solar_system_id = location.get("solar_system_id")
    if solar_system_id:
        solar_system = fetch_solar_system(solar_system_id)
        security_status = solar_system.get("security_status")
        summary["solar_system"] = {
            "name": solar_system["name"],
            "security_status": math.floor(security_status * 10) / 10 if security_status is not None else None,
        }

    return summary


def refresh_dashboard_cache_for_character(character_id: int) -> None:
    character_auth = get_character_auth(character_id)
    if not character_auth:
        return
    character_auth = refresh_access_token_if_needed_for_worker(character_auth)
    if not character_auth:
        return
    summary = build_location_summary(character_auth)
    save_cached_dashboard(character_id, summary)


def get_characters_needing_refresh() -> list[int]:
    now = int(time.time())
    rows = get_db().execute(
        """
        SELECT c.character_id
        FROM characters c
        LEFT JOIN dashboard_cache dc ON dc.character_id = c.character_id
        WHERE dc.character_id IS NULL
           OR dc.fetched_at < ?
           OR (dc.refresh_requested_at IS NOT NULL AND dc.refresh_requested_at <= ?)
        ORDER BY c.character_name COLLATE NOCASE
        """,
        (now - CACHE_TTL_SECONDS, now),
    ).fetchall()
    return [row["character_id"] for row in rows]


def finalize_manual_pull_if_complete() -> None:
    if not is_manual_pull_in_progress():
        return
    if get_characters_needing_refresh():
        return
    set_app_state("manual_pull_in_progress", "0")
    set_app_state("last_manual_pull_completed_at", int(time.time()))


def background_refresh_loop():
    while True:
        try:
            with app.app_context():
                init_db()
                for character_id in get_characters_needing_refresh():
                    try:
                        refresh_dashboard_cache_for_character(character_id)
                    except Exception:
                        continue
                finalize_manual_pull_if_complete()
        except Exception:
            pass
        time.sleep(BACKGROUND_REFRESH_INTERVAL_SECONDS)


def start_background_refresher() -> None:
    global REFRESHER_STARTED
    with REFRESHER_LOCK:
        if REFRESHER_STARTED:
            return
        thread = threading.Thread(target=background_refresh_loop, daemon=True)
        thread.start()
        REFRESHER_STARTED = True


@app.before_request
def ensure_background_refresher():
    start_background_refresher()


@app.route("/location")
@login_required
def location():
    active_character = get_active_character_auth()
    if not active_character:
        return redirect(url_for("index"))
    cached_summary = get_cached_dashboard(active_character["character_id"])
    if cached_summary and cached_summary.get("wallet_balance") is not None:
        return attach_cache_metadata(cached_summary)
    return {"message": "No cached dashboard data yet. Please wait for next pull."}


@app.route("/characters/<int:character_id>/switch")
def switch_character(character_id: int):
    if not get_character_auth(character_id):
        return redirect(url_for("index", error="Character not found."))
    session["active_character_id"] = character_id
    return redirect(url_for("index"))


@app.route("/overview")
def switch_overview():
    session["active_character_id"] = "overview"
    return redirect(url_for("index"))


@app.route("/pull")
def manual_pull():
    if not can_manual_pull():
        return redirect(url_for("index", error="Manual pull is on cooldown. Please wait a moment."))

    clear_dashboard_cache()
    for character in get_saved_characters():
        request_dashboard_refresh(character["character_id"])

    set_app_state("manual_pull_in_progress", "1")
    set_app_state("last_manual_pull_completed_at", None)
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    get_db().execute("DELETE FROM characters")
    get_db().commit()
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
