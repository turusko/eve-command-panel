import base64
import hmac
import json
import logging
import math
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv
from flask import Flask, g, redirect, render_template, request, session, url_for


load_dotenv()


SSO_METADATA_URL = "https://login.eveonline.com/.well-known/oauth-authorization-server"
ESI_BASE_URL = "https://esi.evetech.net/latest"
EVE_IMAGE_BASE_URL = "https://images.evetech.net"
ESI_COMPATIBILITY_DATE = "2026-04-02"
APP_VERSION = "0.2.0"
PI_ATTENTION_WINDOW_HOURS = 6
CACHE_TTL_SECONDS = 15 * 60
BACKGROUND_REFRESH_INTERVAL_SECONDS = 1 * 60
BACKGROUND_REFRESH_LEASE_SECONDS = 3 * BACKGROUND_REFRESH_INTERVAL_SECONDS
MANUAL_PULL_COOLDOWN_SECONDS = 60
SESSION_LIFETIME_DAYS = int(os.getenv("SESSION_LIFETIME_DAYS", "30"))
CSRF_SESSION_KEY = "csrf_token"
REFRESHER_LEASE_KEY = "background_refresher_lease"
EVE_SCOPES = [
    "esi-location.read_location.v1",
    "esi-location.read_ship_type.v1",
    "esi-wallet.read_character_wallet.v1",
    "esi-planets.manage_planets.v1",
]


app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=SESSION_LIFETIME_DAYS)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", Path(__file__).with_name("eve_dashboard.db")))
LOG_PATH = Path(os.getenv("LOG_PATH", DATABASE_PATH.with_name("eve_dashboard.log")))
REFRESHER_LOCK = threading.Lock()
REFRESHER_STARTED = False
REFRESHER_OWNER_ID = f"{os.getpid()}-{secrets.token_hex(8)}"


def env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_csrf_token() -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


@app.context_processor
def inject_template_helpers() -> dict:
    return {"csrf_token": get_csrf_token}


@app.before_request
def protect_post_routes():
    if request.method != "POST":
        return None

    expected_token = session.get(CSRF_SESSION_KEY)
    submitted_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if expected_token and submitted_token and hmac.compare_digest(expected_token, submitted_token):
        return None

    logger.warning("Rejected POST request for %s due to missing or invalid CSRF token", request.path)
    return redirect(url_for("index", error="Your session security token was invalid. Please try again."))


def configure_logging() -> logging.Logger:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("eve_dashboard")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(threadName)s %(message)s")

    file_handler = RotatingFileHandler(LOG_PATH, maxBytes=1_048_576, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    logger.propagate = False
    return logger


logger = configure_logging()


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


def parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


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
        g.db.execute("PRAGMA foreign_keys = ON")
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
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS user_characters (
            instance_id TEXT NOT NULL,
            character_id INTEGER NOT NULL,
            character_name TEXT NOT NULL,
            access_token TEXT NOT NULL,
            refresh_token TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (instance_id, character_id)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS user_dashboard_cache (
            instance_id TEXT NOT NULL,
            character_id INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            fetched_at INTEGER NOT NULL,
            refresh_requested_at INTEGER,
            PRIMARY KEY (instance_id, character_id),
            FOREIGN KEY(instance_id, character_id) REFERENCES user_characters(instance_id, character_id) ON DELETE CASCADE
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS user_app_state (
            instance_id TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT,
            PRIMARY KEY (instance_id, key)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS user_wallet_journal (
            instance_id TEXT NOT NULL,
            character_id INTEGER NOT NULL,
            entry_id INTEGER NOT NULL,
            entry_date TEXT NOT NULL,
            ref_type TEXT,
            amount REAL,
            balance REAL,
            description TEXT,
            raw_json TEXT NOT NULL,
            PRIMARY KEY (instance_id, character_id, entry_id),
            FOREIGN KEY(instance_id, character_id) REFERENCES user_characters(instance_id, character_id) ON DELETE CASCADE
        )
        """
    )
    db.commit()


def get_instance_id(create: bool = False) -> str | None:
    instance_id = session.get("instance_id")
    if instance_id:
        session.permanent = True
        return instance_id
    if not create:
        return None
    session.permanent = True
    instance_id = secrets.token_urlsafe(24)
    session["instance_id"] = instance_id
    return instance_id


def find_instance_id_for_character(character_id: int) -> str | None:
    row = get_db().execute(
        """
        SELECT instance_id
        FROM user_characters
        WHERE character_id = ?
        ORDER BY expires_at DESC
        LIMIT 1
        """,
        (character_id,),
    ).fetchone()
    return row["instance_id"] if row else None


def migrate_legacy_data_for_current_instance() -> None:
    instance_id = get_instance_id()
    if not instance_id:
        return
    db = get_db()
    migration_done = db.execute(
        "SELECT value FROM app_state WHERE key = 'legacy_instance_migration_complete'"
    ).fetchone()
    if migration_done and migration_done["value"] == "1":
        return

    existing = db.execute(
        "SELECT COUNT(*) AS count FROM user_characters WHERE instance_id = ?",
        (instance_id,),
    ).fetchone()["count"]
    if existing:
        return

    legacy = db.execute("SELECT COUNT(*) AS count FROM characters").fetchone()["count"]
    if not legacy:
        return

    for row in db.execute(
        """
        SELECT character_id, character_name, access_token, refresh_token, expires_at
        FROM characters
        """
    ).fetchall():
        db.execute(
            """
            INSERT OR IGNORE INTO user_characters (
                instance_id, character_id, character_name, access_token, refresh_token, expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                instance_id,
                row["character_id"],
                row["character_name"],
                row["access_token"],
                row["refresh_token"],
                row["expires_at"],
            ),
        )

    for row in db.execute(
        """
        SELECT character_id, payload_json, fetched_at, refresh_requested_at
        FROM dashboard_cache
        """
    ).fetchall():
        db.execute(
            """
            INSERT OR IGNORE INTO user_dashboard_cache (
                instance_id, character_id, payload_json, fetched_at, refresh_requested_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                instance_id,
                row["character_id"],
                row["payload_json"],
                row["fetched_at"],
                row["refresh_requested_at"],
            ),
        )

    for row in db.execute("SELECT key, value FROM app_state").fetchall():
        if row["key"] == "legacy_instance_migration_complete":
            continue
        db.execute(
            """
            INSERT OR IGNORE INTO user_app_state (instance_id, key, value)
            VALUES (?, ?, ?)
            """,
            (instance_id, row["key"], row["value"]),
        )

    db.execute(
        """
        INSERT INTO app_state (key, value)
        VALUES ('legacy_instance_migration_complete', '1')
        ON CONFLICT(key) DO UPDATE SET value = '1'
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


def save_character_auth(character_id: int, character_name: str, token_data: dict, instance_id: str | None = None) -> None:
    instance_id = instance_id or get_instance_id(create=True)
    db = get_db()
    db.execute(
        """
        INSERT INTO user_characters (instance_id, character_id, character_name, access_token, refresh_token, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(instance_id, character_id) DO UPDATE SET
            character_name = excluded.character_name,
            access_token = excluded.access_token,
            refresh_token = excluded.refresh_token,
            expires_at = excluded.expires_at
        """,
        (
            instance_id,
            character_id,
            character_name,
            token_data["access_token"],
            token_data["refresh_token"],
            int(time.time()) + int(token_data["expires_in"]),
        ),
    )
    db.commit()


def get_cached_dashboard(character_id: int):
    instance_id = get_instance_id()
    if not instance_id:
        return None
    row = get_db().execute(
        """
        SELECT payload_json, fetched_at, refresh_requested_at
        FROM user_dashboard_cache
        WHERE instance_id = ? AND character_id = ?
        """,
        (instance_id, character_id),
    ).fetchone()
    if not row:
        return None
    payload = json.loads(row["payload_json"])
    journal_entries = get_wallet_journal_entries(character_id, instance_id=instance_id, limit=5)
    if not journal_entries:
        journal_entries = payload.get("journal_entries", [])
        if journal_entries:
            replace_wallet_journal_entries(instance_id, character_id, journal_entries)
    payload["journal_entries"] = journal_entries
    payload.setdefault(
        "journal_status",
        {
            "newest_entry_time": journal_entries[0].get("date") if journal_entries else None,
            "freshness_lag_minutes": None,
            "esi_expires": None,
            "esi_cache_control": None,
            "esi_last_modified": None,
            "esi_etag": None,
            "esi_response_date": None,
        },
    )
    payload["_cached_at"] = row["fetched_at"]
    payload["_refresh_requested_at"] = row["refresh_requested_at"]
    return payload


def save_cached_dashboard(character_id: int, payload: dict) -> None:
    instance_id = get_instance_id()
    if not instance_id:
        return
    replace_wallet_journal_entries(instance_id, character_id, payload.get("journal_entries", []))
    db = get_db()
    db.execute(
        """
        INSERT INTO user_dashboard_cache (instance_id, character_id, payload_json, fetched_at, refresh_requested_at)
        VALUES (?, ?, ?, ?, NULL)
        ON CONFLICT(instance_id, character_id) DO UPDATE SET
            payload_json = excluded.payload_json,
            fetched_at = excluded.fetched_at,
            refresh_requested_at = NULL
        """,
        (instance_id, character_id, json.dumps(payload), int(time.time())),
    )
    db.commit()


def request_dashboard_refresh(character_id: int) -> None:
    instance_id = get_instance_id()
    if not instance_id:
        return
    db = get_db()
    now = int(time.time())
    db.execute(
        """
        INSERT INTO user_dashboard_cache (instance_id, character_id, payload_json, fetched_at, refresh_requested_at)
        VALUES (?, ?, '{}', 0, ?)
        ON CONFLICT(instance_id, character_id) DO UPDATE SET
            refresh_requested_at = excluded.refresh_requested_at
        """,
        (instance_id, character_id, now),
    )
    db.commit()


def clear_dashboard_cache(character_id: int | None = None) -> None:
    instance_id = get_instance_id()
    if not instance_id:
        return
    db = get_db()
    if character_id is None:
        db.execute("DELETE FROM user_dashboard_cache WHERE instance_id = ?", (instance_id,))
    else:
        db.execute(
            "DELETE FROM user_dashboard_cache WHERE instance_id = ? AND character_id = ?",
            (instance_id, character_id),
        )
    db.commit()


def get_app_state(key: str) -> str | None:
    instance_id = get_instance_id()
    if not instance_id:
        return None
    row = get_db().execute(
        "SELECT value FROM user_app_state WHERE instance_id = ? AND key = ?",
        (instance_id, key),
    ).fetchone()
    return row["value"] if row else None


def set_app_state(key: str, value: str | int | None) -> None:
    instance_id = get_instance_id()
    if not instance_id:
        return
    db = get_db()
    if value is None:
        db.execute("DELETE FROM user_app_state WHERE instance_id = ? AND key = ?", (instance_id, key))
    else:
        db.execute(
            """
            INSERT INTO user_app_state (instance_id, key, value)
            VALUES (?, ?, ?)
            ON CONFLICT(instance_id, key) DO UPDATE SET value = excluded.value
            """,
            (instance_id, key, str(value)),
    )
    db.commit()


def try_acquire_refresh_lease() -> bool:
    db = get_db()
    now = int(time.time())
    lease_payload = json.dumps(
        {
            "owner": REFRESHER_OWNER_ID,
            "expires_at": now + BACKGROUND_REFRESH_LEASE_SECONDS,
        }
    )

    db.execute("BEGIN IMMEDIATE")
    try:
        row = db.execute("SELECT value FROM app_state WHERE key = ?", (REFRESHER_LEASE_KEY,)).fetchone()
        lease = json.loads(row["value"]) if row and row["value"] else {}
        lease_owner = lease.get("owner")
        lease_expires_at = int(lease.get("expires_at") or 0)

        if lease_owner and lease_owner != REFRESHER_OWNER_ID and lease_expires_at > now:
            db.rollback()
            return False

        db.execute(
            """
            INSERT INTO app_state (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (REFRESHER_LEASE_KEY, lease_payload),
        )
        db.commit()
        return True
    except Exception:
        db.rollback()
        raise


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
    instance_id = get_instance_id()
    if not instance_id:
        return
    db = get_db()
    db.execute(
        """
        UPDATE user_characters
        SET access_token = ?, refresh_token = ?, expires_at = ?
        WHERE instance_id = ? AND character_id = ?
        """,
        (
            token_data["access_token"],
            token_data["refresh_token"],
            int(time.time()) + int(token_data["expires_in"]),
            instance_id,
            character_id,
        ),
    )
    db.commit()


def get_saved_characters() -> list[dict]:
    instance_id = get_instance_id()
    if not instance_id:
        return []
    rows = get_db().execute(
        """
        SELECT character_id, character_name
        FROM user_characters
        WHERE instance_id = ?
        ORDER BY character_name COLLATE NOCASE
        """,
        (instance_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def get_overview_wallet_total() -> float:
    instance_id = get_instance_id()
    if not instance_id:
        return 0.0
    rows = get_db().execute(
        """
        SELECT payload_json
        FROM user_dashboard_cache
        WHERE instance_id = ? AND payload_json IS NOT NULL AND payload_json != '{}'
        """
        ,
        (instance_id,),
    ).fetchall()
    total = 0.0
    for row in rows:
        payload = json.loads(row["payload_json"])
        total += float(payload.get("wallet_balance") or 0)
    return total


def get_overview_character_summaries() -> list[dict]:
    instance_id = get_instance_id()
    if not instance_id:
        return []
    rows = get_db().execute(
        """
        SELECT c.character_id, c.character_name, dc.payload_json
        FROM user_characters c
        LEFT JOIN user_dashboard_cache dc
            ON dc.instance_id = c.instance_id AND dc.character_id = c.character_id
        WHERE c.instance_id = ?
        ORDER BY c.character_name COLLATE NOCASE
        """
        ,
        (instance_id,),
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
                "portrait_url": f"{EVE_IMAGE_BASE_URL}/characters/{row['character_id']}/portrait?size=128",
                "next_expiry": next_expiry,
            }
        )

    return summaries


def get_character_auth(character_id: int | None):
    if not character_id:
        return None
    instance_id = get_instance_id()
    if not instance_id:
        return None
    row = get_db().execute(
        """
        SELECT character_id, character_name, access_token, refresh_token, expires_at
        FROM user_characters
        WHERE instance_id = ? AND character_id = ?
        """,
        (instance_id, character_id),
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
        app_version=APP_VERSION,
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
    character_id = parse_character_id(token_data["access_token"])
    character = fetch_character_profile(character_id)
    current_instance_id = get_instance_id()
    existing_instance_id = find_instance_id_for_character(character_id)
    current_has_characters = bool(get_saved_characters()) if current_instance_id else False

    if current_has_characters:
        if existing_instance_id and existing_instance_id != current_instance_id:
            session.pop("oauth_state", None)
            return redirect(
                url_for("index", error="That character is already linked to another dashboard.")
            )
        target_instance_id = current_instance_id
    else:
        target_instance_id = existing_instance_id or get_instance_id(create=True)
        session["instance_id"] = target_instance_id

    save_character_auth(character_id, character["name"], token_data, instance_id=target_instance_id)
    if session.get("active_character_id") in (None, "overview"):
        session["active_character_id"] = "overview"
    request_dashboard_refresh(character_id)
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


def fetch_wallet_journal(character_auth: dict, limit: int = 5) -> tuple[list[dict], dict]:
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
    newest_entry_time = entries[0].get("date") if entries else None
    metadata = {
        "esi_expires": response.headers.get("Expires"),
        "esi_cache_control": response.headers.get("Cache-Control"),
        "esi_last_modified": response.headers.get("Last-Modified"),
        "esi_etag": response.headers.get("ETag"),
        "esi_response_date": response.headers.get("Date"),
        "newest_entry_time": newest_entry_time,
    }
    logger.info(
        "Wallet journal fetch for %s: newest=%s expires=%s cache_control=%s last_modified=%s etag=%s",
        character_id,
        metadata["newest_entry_time"],
        metadata["esi_expires"],
        metadata["esi_cache_control"],
        metadata["esi_last_modified"],
        metadata["esi_etag"],
    )
    return entries[:limit], metadata


def build_wallet_journal_status(entries: list[dict], metadata: dict) -> dict:
    newest_entry_time = metadata.get("newest_entry_time") or (entries[0].get("date") if entries else None)
    newest_dt = parse_iso_datetime(newest_entry_time)
    now = datetime.now(timezone.utc)
    freshness_lag_minutes = None
    if newest_dt:
        freshness_lag_minutes = max(0, int((now - newest_dt).total_seconds() // 60))

    expires_text = metadata.get("esi_expires")
    expires_dt = parse_iso_datetime(expires_text)
    if expires_dt is None and expires_text:
        try:
            from email.utils import parsedate_to_datetime

            expires_dt = parsedate_to_datetime(expires_text)
            if expires_dt.tzinfo is None:
                expires_dt = expires_dt.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            expires_dt = None

    return {
        "newest_entry_time": newest_entry_time,
        "freshness_lag_minutes": freshness_lag_minutes,
        "esi_expires": expires_dt.isoformat().replace("+00:00", "Z") if expires_dt else expires_text,
        "esi_cache_control": metadata.get("esi_cache_control"),
        "esi_last_modified": metadata.get("esi_last_modified"),
        "esi_etag": metadata.get("esi_etag"),
        "esi_response_date": metadata.get("esi_response_date"),
    }


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
    journal_entries, journal_metadata = fetch_wallet_journal(character_auth, limit=5)
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
        "portrait_url": f"{EVE_IMAGE_BASE_URL}/characters/{character_id}/portrait?size=256",
        "location": location,
        "ship_name": ship_name,
        "wallet_balance": wallet_balance,
        "journal_entries": journal_entries,
        "journal_status": build_wallet_journal_status(journal_entries, journal_metadata),
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


def get_character_auth_for_instance(instance_id: str, character_id: int):
    row = get_db().execute(
        """
        SELECT character_id, character_name, access_token, refresh_token, expires_at
        FROM user_characters
        WHERE instance_id = ? AND character_id = ?
        """,
        (instance_id, character_id),
    ).fetchone()
    return dict(row) if row else None


def update_character_tokens_for_instance(instance_id: str, character_id: int, token_data: dict) -> None:
    db = get_db()
    db.execute(
        """
        UPDATE user_characters
        SET access_token = ?, refresh_token = ?, expires_at = ?
        WHERE instance_id = ? AND character_id = ?
        """,
        (
            token_data["access_token"],
            token_data["refresh_token"],
            int(time.time()) + int(token_data["expires_in"]),
            instance_id,
            character_id,
        ),
    )
    db.commit()


def refresh_access_token_if_needed_for_worker(instance_id: str, character_auth: dict | None) -> dict | None:
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
    update_character_tokens_for_instance(instance_id, character_auth["character_id"], token_data)
    return get_character_auth_for_instance(instance_id, character_auth["character_id"])


def save_cached_dashboard_for_instance(instance_id: str, character_id: int, payload: dict) -> None:
    replace_wallet_journal_entries(instance_id, character_id, payload.get("journal_entries", []))
    db = get_db()
    db.execute(
        """
        INSERT INTO user_dashboard_cache (instance_id, character_id, payload_json, fetched_at, refresh_requested_at)
        VALUES (?, ?, ?, ?, NULL)
        ON CONFLICT(instance_id, character_id) DO UPDATE SET
            payload_json = excluded.payload_json,
            fetched_at = excluded.fetched_at,
            refresh_requested_at = NULL
        """,
        (instance_id, character_id, json.dumps(payload), int(time.time())),
    )
    db.commit()


def refresh_dashboard_cache_for_character(instance_id: str, character_id: int) -> None:
    character_auth = get_character_auth_for_instance(instance_id, character_id)
    if not character_auth:
        return
    character_auth = refresh_access_token_if_needed_for_worker(instance_id, character_auth)
    if not character_auth:
        return
    summary = build_location_summary(character_auth)
    save_cached_dashboard_for_instance(instance_id, character_id, summary)


def replace_wallet_journal_entries(
    instance_id: str, character_id: int, journal_entries: list[dict]
) -> None:
    db = get_db()
    db.execute(
        "DELETE FROM user_wallet_journal WHERE instance_id = ? AND character_id = ?",
        (instance_id, character_id),
    )
    for entry in journal_entries:
        entry_id = entry.get("id")
        entry_date = entry.get("date")
        if entry_id is None or not entry_date:
            continue
        db.execute(
            """
            INSERT INTO user_wallet_journal (
                instance_id, character_id, entry_id, entry_date, ref_type, amount, balance, description, raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                instance_id,
                character_id,
                int(entry_id),
                entry_date,
                entry.get("ref_type"),
                entry.get("amount"),
                entry.get("balance"),
                entry.get("description"),
                json.dumps(entry),
            ),
        )
    db.commit()


def get_wallet_journal_entries(
    character_id: int, instance_id: str | None = None, limit: int = 5
) -> list[dict]:
    instance_id = instance_id or get_instance_id()
    if not instance_id:
        return []
    rows = get_db().execute(
        """
        SELECT raw_json
        FROM user_wallet_journal
        WHERE instance_id = ? AND character_id = ?
        ORDER BY entry_date DESC, entry_id DESC
        LIMIT ?
        """,
        (instance_id, character_id, limit),
    ).fetchall()
    return [json.loads(row["raw_json"]) for row in rows]


def get_characters_needing_refresh() -> list[tuple[str, int]]:
    now = int(time.time())
    rows = get_db().execute(
        """
        SELECT c.instance_id, c.character_id
        FROM user_characters c
        LEFT JOIN user_dashboard_cache dc
            ON dc.instance_id = c.instance_id AND dc.character_id = c.character_id
        WHERE dc.character_id IS NULL
           OR dc.fetched_at < ?
           OR (dc.refresh_requested_at IS NOT NULL AND dc.refresh_requested_at <= ?)
        ORDER BY c.instance_id, c.character_name COLLATE NOCASE
        """,
        (now - CACHE_TTL_SECONDS, now),
    ).fetchall()
    return [(row["instance_id"], row["character_id"]) for row in rows]


def finalize_manual_pull_if_complete() -> None:
    pending_by_instance = {instance_id for instance_id, _ in get_characters_needing_refresh()}
    rows = get_db().execute(
        """
        SELECT instance_id
        FROM user_app_state
        WHERE key = 'manual_pull_in_progress' AND value = '1'
        """
    ).fetchall()
    for row in rows:
        instance_id = row["instance_id"]
        if instance_id in pending_by_instance:
            continue
        set_app_state_for_instance(instance_id, "manual_pull_in_progress", "0")
        set_app_state_for_instance(instance_id, "last_manual_pull_completed_at", int(time.time()))


def set_app_state_for_instance(instance_id: str, key: str, value: str | int | None) -> None:
    db = get_db()
    if value is None:
        db.execute("DELETE FROM user_app_state WHERE instance_id = ? AND key = ?", (instance_id, key))
    else:
        db.execute(
            """
            INSERT INTO user_app_state (instance_id, key, value)
            VALUES (?, ?, ?)
            ON CONFLICT(instance_id, key) DO UPDATE SET value = excluded.value
            """,
            (instance_id, key, str(value)),
        )
    db.commit()


def background_refresh_loop():
    lease_held = False
    while True:
        should_sleep = True
        try:
            with app.app_context():
                init_db()
                if not try_acquire_refresh_lease():
                    if lease_held:
                        logger.info("Background refresher lease transferred away from %s", REFRESHER_OWNER_ID)
                        lease_held = False
                    continue
                if not lease_held:
                    logger.info("Background refresher lease acquired by %s", REFRESHER_OWNER_ID)
                    lease_held = True
                for instance_id, character_id in get_characters_needing_refresh():
                    try:
                        refresh_dashboard_cache_for_character(instance_id, character_id)
                    except Exception:
                        logger.exception(
                            "Background refresh failed for instance %s character %s",
                            instance_id,
                            character_id,
                        )
                        continue
                finalize_manual_pull_if_complete()
        except Exception:
            logger.exception("Background refresh loop failed")
        if should_sleep:
            time.sleep(BACKGROUND_REFRESH_INTERVAL_SECONDS)


def start_background_refresher() -> None:
    global REFRESHER_STARTED
    if not env_flag("ENABLE_BACKGROUND_REFRESHER", True):
        logger.info("Background refresher disabled by configuration")
        return
    with REFRESHER_LOCK:
        if REFRESHER_STARTED:
            return
        thread = threading.Thread(target=background_refresh_loop, daemon=True)
        thread.start()
        REFRESHER_STARTED = True
        logger.info("Background refresher started with %s second interval", BACKGROUND_REFRESH_INTERVAL_SECONDS)


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


@app.route("/characters/<int:character_id>/switch", methods=["POST"])
def switch_character(character_id: int):
    if not get_character_auth(character_id):
        return redirect(url_for("index", error="Character not found."))
    session["active_character_id"] = character_id
    return redirect(url_for("index"))


@app.route("/overview", methods=["POST"])
def switch_overview():
    session["active_character_id"] = "overview"
    return redirect(url_for("index"))


@app.route("/pull", methods=["POST"])
def manual_pull():
    saved_characters = get_saved_characters()
    if not saved_characters:
        return redirect(url_for("index", error="No linked characters available for this dashboard."))

    if not can_manual_pull():
        return redirect(url_for("index", error="Manual pull is on cooldown. Please wait a moment."))

    for character in saved_characters:
        request_dashboard_refresh(character["character_id"])

    set_app_state("manual_pull_in_progress", "1")
    set_app_state("last_manual_pull_completed_at", None)
    logger.info("Manual ESI pull requested for %s linked characters", len(saved_characters))
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
def logout():
    logger.info("User signed out of current dashboard session")
    session.clear()
    return redirect(url_for("index"))


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=env_flag("DEBUG", False))
