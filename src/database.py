"""SQLite persistence for scan results."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "code",
    "password",
    "passwd",
    "secret",
    "session",
    "signature",
    "sig",
    "token",
}


def _redact_url(url: str) -> str:
    """Keep useful scan history while avoiding persistence of common URL secrets."""
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    if parsed.port is not None:
        hostname = f"{hostname}:{parsed.port}"
    if parsed.username is not None or parsed.password is not None:
        hostname = f"[redacted]@{hostname}"
    query = urlencode(
        [
            (key, "[redacted]" if key.lower() in _SENSITIVE_QUERY_KEYS else value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
    )
    fragment = "[redacted]" if parsed.fragment else ""
    return urlunsplit((parsed.scheme, hostname, parsed.path, query, fragment))


def get_connection(database_path: str | Path) -> sqlite3.Connection:
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database(database_path: str | Path) -> None:
    with get_connection(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                category TEXT NOT NULL,
                reasons TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
            """
        )


def save_scan(database_path: str | Path, result: dict) -> int:
    scanned_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with get_connection(database_path) as connection:
        cursor = connection.execute(
            "INSERT INTO scans (url, risk_score, category, reasons, scanned_at) VALUES (?, ?, ?, ?, ?)",
            (
                _redact_url(result["url"]),
                result["risk_score"],
                result["category"],
                json.dumps(result["reasons"], ensure_ascii=True),
                scanned_at,
            ),
        )
        return int(cursor.lastrowid)


def get_scans(database_path: str | Path, limit: int = 20) -> list[dict]:
    with get_connection(database_path) as connection:
        rows = connection.execute(
            "SELECT id, url, risk_score, category, reasons, scanned_at FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {
            **dict(row),
            "reasons": json.loads(row["reasons"]),
        }
        for row in rows
    ]


def get_statistics(database_path: str | Path) -> dict[str, int]:
    with get_connection(database_path) as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN category = 'High' THEN 1 ELSE 0 END) AS high,
                   SUM(CASE WHEN category = 'Medium' THEN 1 ELSE 0 END) AS medium,
                   SUM(CASE WHEN category = 'Low' THEN 1 ELSE 0 END) AS low
            FROM scans
            """
        ).fetchone()
    return {key: int(row[key] or 0) for key in ("total", "high", "medium", "low")}


def clear_scans(database_path: str | Path) -> None:
    with get_connection(database_path) as connection:
        connection.execute("DELETE FROM scans")
