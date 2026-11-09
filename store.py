"""Ratcatcher storage: catches, strikes, members and the blocklist, in the plugin's own SQLite file."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from typing import Any, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    chat_id TEXT NOT NULL,
    chat_title TEXT,
    message_id TEXT,
    user_id TEXT,
    user_name TEXT,
    text TEXT,
    score REAL,
    category TEXT,
    reasons TEXT,
    action TEXT,
    ai_note TEXT,
    released INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS incidents_ts ON incidents(ts);
CREATE TABLE IF NOT EXISTS strikes (
    chat_id TEXT NOT NULL, user_id TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (chat_id, user_id)
);
CREATE TABLE IF NOT EXISTS members (
    chat_id TEXT NOT NULL, user_id TEXT NOT NULL, joined_ts REAL, msg_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (chat_id, user_id)
);
CREATE TABLE IF NOT EXISTS blocklist (
    kind TEXT NOT NULL, value TEXT NOT NULL, note TEXT, ts REAL,
    PRIMARY KEY (kind, value)
);
"""

MAX_TEXT = 600
MIN_PHRASE_CHARS = 10
MIN_PHRASE_WORDS = 2

# Sites real members link to every day. Blocking one would remove normal chat across the group.
PROTECTED_DOMAINS = {
    "t.me", "telegram.org", "telegram.me", "x.com", "twitter.com", "youtube.com", "youtu.be", "google.com",
    "github.com", "medium.com", "discord.com", "discord.gg", "reddit.com", "instagram.com", "facebook.com",
    "linkedin.com", "tiktok.com", "wikipedia.org", "coingecko.com", "coinmarketcap.com", "dexscreener.com",
    "etherscan.io", "solscan.io", "bscscan.com", "basescan.org", "arbiscan.io", "notion.so", "gitbook.io",
    "docs.google.com", "mirror.xyz", "substack.com", "linktr.ee",
}

COMMON_WORDS = {
    "a", "an", "the", "and", "or", "to", "of", "in", "on", "for", "is", "are", "was", "be", "it", "this", "that",
    "i", "you", "we", "they", "me", "my", "your", "our", "gm", "gn", "hi", "hello", "hey", "ser", "fam", "bro",
    "please", "pls", "thanks", "thank", "yes", "no", "ok", "okay", "lol", "wen", "when", "what", "how", "who",
    "airdrop", "claim", "wallet", "token", "tokens", "price", "dm", "admin", "support", "help", "link", "join",
    "team", "project", "community", "group", "now", "here", "today", "new", "good", "great", "nice", "send",
}


class Store:
    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    @classmethod
    def memory(cls) -> "Store":
        return cls(sqlite3.connect(":memory:", check_same_thread=False))

    # -- incidents -----------------------------------------------------------

    def add_incident(self, *, chat_id: Any, chat_title: str, message_id: Any, user_id: Any, user_name: str,
                     text: str, score: float, category: str, reasons: list[str], action: str,
                     ai_note: str = "") -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO incidents (ts, chat_id, chat_title, message_id, user_id, user_name, text, score,"
                " category, reasons, action, ai_note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (time.time(), str(chat_id), chat_title, str(message_id), str(user_id), user_name,
                 (text or "")[:MAX_TEXT], round(score, 3), category, json.dumps(reasons), action, ai_note))
            self._conn.commit()
            return int(cur.lastrowid)

    def get_incident(self, incident_id: int) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            cols = [d[0] for d in self._conn.execute("SELECT * FROM incidents LIMIT 0").description]
        return self._row(cols, row) if row else None

    def set_incident(self, incident_id: int, **fields: Any) -> None:
        if not fields:
            return
        keys = ", ".join(f"{k}=?" for k in fields)
        with self._lock:
            self._conn.execute(f"UPDATE incidents SET {keys} WHERE id=?", (*fields.values(), incident_id))
            self._conn.commit()

    def recent(self, hours: float = 24, chat_id: Optional[str] = None, limit: int = 20) -> list[dict]:
        since = time.time() - hours * 3600
        sql = "SELECT * FROM incidents WHERE ts>=?"
        args: list[Any] = [since]
        if chat_id:
            sql += " AND chat_id=?"
            args.append(str(chat_id))
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            cur = self._conn.execute(sql, args)
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
        return [self._row(cols, r) for r in rows]

    def summary(self, hours: float = 24, chat_id: Optional[str] = None) -> dict:
        since = time.time() - hours * 3600
        sql = "SELECT category, action, COUNT(*) FROM incidents WHERE ts>=?"
        args: list[Any] = [since]
        if chat_id:
            sql += " AND chat_id=?"
            args.append(str(chat_id))
        sql += " GROUP BY category, action"
        by_cat: dict[str, int] = {}
        by_action: dict[str, int] = {}
        total = 0
        with self._lock:
            for cat, action, n in self._conn.execute(sql, args):
                by_cat[cat] = by_cat.get(cat, 0) + n
                by_action[action] = by_action.get(action, 0) + n
                total += n
        return {"hours": hours, "total": total, "by_category": by_cat, "by_action": by_action}

    @staticmethod
    def _row(cols: list[str], row: tuple) -> dict:
        d = dict(zip(cols, row))
        try:
            d["reasons"] = json.loads(d.get("reasons") or "[]")
        except ValueError:
            d["reasons"] = []
        return d

    # -- strikes -------------------------------------------------------------

    def add_strike(self, chat_id: Any, user_id: Any) -> int:
        with self._lock:
            self._conn.execute(
                "INSERT INTO strikes (chat_id, user_id, count) VALUES (?,?,1) "
                "ON CONFLICT(chat_id, user_id) DO UPDATE SET count=count+1", (str(chat_id), str(user_id)))
            self._conn.commit()
            row = self._conn.execute("SELECT count FROM strikes WHERE chat_id=? AND user_id=?",
                                     (str(chat_id), str(user_id))).fetchone()
        return int(row[0]) if row else 1

    def clear_strikes(self, chat_id: Any, user_id: Any) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM strikes WHERE chat_id=? AND user_id=?", (str(chat_id), str(user_id)))
            self._conn.commit()

    # -- members -------------------------------------------------------------

    def member_joined(self, chat_id: Any, user_id: Any, ts: Optional[float] = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO members (chat_id, user_id, joined_ts, msg_count) VALUES (?,?,?,0) "
                "ON CONFLICT(chat_id, user_id) DO UPDATE SET joined_ts=excluded.joined_ts",
                (str(chat_id), str(user_id), ts or time.time()))
            self._conn.commit()

    def member_seen(self, chat_id: Any, user_id: Any) -> tuple[Optional[float], int]:
        """Return (joined_ts, messages seen before this one) and count this message."""
        with self._lock:
            row = self._conn.execute("SELECT joined_ts, msg_count FROM members WHERE chat_id=? AND user_id=?",
                                     (str(chat_id), str(user_id))).fetchone()
            if row is None:
                # First time we see them talk. We do not know when they joined.
                self._conn.execute("INSERT INTO members (chat_id, user_id, joined_ts, msg_count) VALUES (?,?,NULL,1)",
                                   (str(chat_id), str(user_id)))
                self._conn.commit()
                return None, 0
            self._conn.execute("UPDATE members SET msg_count=msg_count+1 WHERE chat_id=? AND user_id=?",
                               (str(chat_id), str(user_id)))
            self._conn.commit()
            return row[0], int(row[1])

    # -- blocklist -----------------------------------------------------------

    @staticmethod
    def clean_entry(kind: str, value: str) -> tuple[str, str]:
        """Normalise a blocklist entry. Returns (value, "") or ("", reason it was refused).

        One broad entry must not be able to sweep a whole group, so short or generic phrases and
        domains every group links to are refused.
        """
        value = (value or "").strip().lower()
        if kind not in ("domain", "phrase"):
            return "", "kind must be 'domain' or 'phrase'"
        if kind == "domain":
            value = value.replace("https://", "").replace("http://", "").split("/")[0].split("?")[0]
            value = value[4:] if value.startswith("www.") else value
            if "." not in value or len(value) < 5 or not re.fullmatch(r"[a-z0-9.-]+", value):
                return "", "that does not look like a single domain"
            reg = ".".join(value.split(".")[-2:])
            if value in PROTECTED_DOMAINS or reg in PROTECTED_DOMAINS:
                return "", f"{reg} is a common site members link to all the time, so it cannot be blocklisted"
            return value, ""
        words = re.findall(r"[^\W_]+", value)
        if len(value) < MIN_PHRASE_CHARS or len(words) < MIN_PHRASE_WORDS:
            return "", (f"phrases need at least {MIN_PHRASE_WORDS} words and {MIN_PHRASE_CHARS} characters, "
                        "so a short or common word cannot remove normal chat")
        if all(w in COMMON_WORDS for w in words):
            return "", "that phrase is made only of everyday words and would catch normal chat"
        return value, ""

    def block(self, kind: str, value: str, note: str = "") -> bool:
        value, why = self.clean_entry(kind, value)
        if not value:
            return False
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO blocklist (kind, value, note, ts) VALUES (?,?,?,?)",
                               (kind, value, note, time.time()))
            self._conn.commit()
        return True

    def unblock(self, kind: str, value: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM blocklist WHERE kind=? AND value=?", (kind, value.strip().lower()))
            self._conn.commit()
        return cur.rowcount > 0

    def blocklist(self, kind: Optional[str] = None) -> list[dict]:
        sql = "SELECT kind, value, note, ts FROM blocklist"
        args: tuple = ()
        if kind:
            sql += " WHERE kind=?"
            args = (kind,)
        with self._lock:
            rows = self._conn.execute(sql + " ORDER BY ts DESC", args).fetchall()
        return [{"kind": k, "value": v, "note": n, "ts": t} for k, v, n, t in rows]
