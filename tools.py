"""Tools Hermes can call: check a message, read the catch log, edit the blocklist, release a user."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from .detector import Admin, Sender
from .moderator import Moderator

CHECK = {
    "name": "ratcatcher_check",
    "description": (
        "Score any message for crypto scam signals (wallet drainers, fake airdrops, fake support, "
        "investment or doubling scams, admin impersonation, phishing links) using Ratcatcher's rules. "
        "Use this when the user pastes a message or link and asks whether it is a scam. Read-only."),
    "parameters": {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "The message or link to check."},
            "sender_name": {"type": "string", "description": "Display name of the sender, if known."},
            "admin_names": {"type": "array", "items": {"type": "string"},
                            "description": "Names of the real group admins, to spot copycat names."},
        },
        "required": ["text"],
    },
}

REPORT = {
    "name": "ratcatcher_report",
    "description": (
        "Show what Ratcatcher caught in the user's Telegram groups: totals by scam type and action, plus "
        "the latest catches with who sent them, why they were caught and what was done. Use for questions "
        "like 'who did you ban today' or 'any scams in the group this week'. Read-only."),
    "parameters": {
        "type": "object",
        "properties": {
            "hours": {"type": "number", "description": "How far back to look. Default 24."},
            "chat_id": {"type": "string", "description": "Only this Telegram chat id."},
            "limit": {"type": "integer", "description": "Max catches to list. Default 10."},
        },
    },
}

BLOCKLIST = {
    "name": "ratcatcher_blocklist",
    "description": (
        "List, add or remove entries on Ratcatcher's blocklist. A blocked domain or phrase gets any group "
        "message containing it removed immediately. Use when the user says to block a scam site or phrase, "
        "or to unblock one."),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["list", "add", "remove"]},
            "kind": {"type": "string", "enum": ["domain", "phrase"]},
            "value": {"type": "string", "description": "Domain (e.g. claim-airdrop.xyz) or exact phrase."},
            "note": {"type": "string", "description": "Why it was added."},
        },
        "required": ["action"],
    },
}

RELEASE = {
    "name": "ratcatcher_release",
    "description": (
        "Undo a Ratcatcher catch that was a false alarm: unmute or unban the sender and clear their strikes. "
        "Takes the catch number shown in reports. Only use when the user asks to release someone."),
    "parameters": {
        "type": "object",
        "properties": {"incident_id": {"type": "integer", "description": "Catch number, e.g. 12."}},
        "required": ["incident_id"],
    },
}


def _ago(ts: float) -> str:
    secs = max(0, time.time() - ts)
    if secs < 90:
        return "just now"
    if secs < 5400:
        return f"{int(secs // 60)} min ago"
    if secs < 172800:
        return f"{int(secs // 3600)} h ago"
    return f"{int(secs // 86400)} days ago"


def build(mod: Moderator) -> dict[str, Any]:
    def check(args: dict, **kwargs: Any) -> str:
        try:
            text = str(args.get("text") or "").strip()
            if not text:
                return json.dumps({"error": "Give me the message text to check."})
            admins = [Admin(-(i + 1), n, "") for i, n in enumerate(args.get("admin_names") or [])]
            v = mod.detector().check(text, Sender(user_id=0, full_name=str(args.get("sender_name") or "")), admins)
            s = mod.settings
            verdict = ("would be removed" if v.score >= s.block_threshold
                       else "would get a second look" if v.score >= s.review_threshold else "looks clean")
            return json.dumps({**v.as_dict(), "verdict": verdict,
                               "thresholds": {"block": s.block_threshold, "review": s.review_threshold}})
        except Exception as exc:
            return json.dumps({"error": f"check failed: {exc}"})

    def report(args: dict, **kwargs: Any) -> str:
        try:
            hours = float(args.get("hours") or 24)
            chat = args.get("chat_id") or None
            limit = max(1, min(int(args.get("limit") or 10), 50))
            rows = mod.store.recent(hours, chat, limit)
            return json.dumps({
                "summary": mod.store.summary(hours, chat),
                "mode": mod.settings.mode,
                "connected_to_telegram": mod.bot is not None,
                "catches": [{
                    "id": r["id"], "when": _ago(r["ts"]), "group": r["chat_title"] or r["chat_id"],
                    "sender": r["user_name"], "type": r["category"], "score": r["score"],
                    "action": r["action"], "released": bool(r["released"]),
                    "reasons": r["reasons"][:3], "ai_note": r["ai_note"] or None,
                    "message": (r["text"] or "")[:200]} for r in rows],
            })
        except Exception as exc:
            return json.dumps({"error": f"report failed: {exc}"})

    def blocklist(args: dict, **kwargs: Any) -> str:
        try:
            action = args.get("action") or "list"
            kind = args.get("kind") or "domain"
            value = str(args.get("value") or "")
            if action == "list":
                return json.dumps({"blocklist": mod.store.blocklist(args.get("kind"))})
            if not value.strip():
                return json.dumps({"error": "Give the domain or phrase."})
            if action == "add":
                ok = mod.store.block(kind, value, str(args.get("note") or ""))
                return json.dumps({"ok": ok, "added": {"kind": kind, "value": value.strip().lower()}})
            if action == "remove":
                return json.dumps({"ok": mod.store.unblock(kind, value), "removed": value.strip().lower()})
            return json.dumps({"error": f"unknown action {action}"})
        except Exception as exc:
            return json.dumps({"error": f"blocklist failed: {exc}"})

    def release(args: dict, **kwargs: Any) -> str:
        try:
            inc = mod.store.get_incident(int(args.get("incident_id")))
        except (TypeError, ValueError):
            return json.dumps({"error": "incident_id must be a number"})
        if not inc:
            return json.dumps({"error": "No catch with that number."})
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is not None and running is mod.loop:
            return json.dumps({"error": "Use the Release button on the report instead."})
        try:
            result = mod.run_on_bot_loop(lambda bot: mod.release(bot, inc["chat_id"], inc["user_id"]))
        except Exception as exc:
            return json.dumps({"error": str(exc)})
        ok = result != "failed"
        if ok:
            mod.store.set_incident(inc["id"], released=1)
        return json.dumps({"ok": ok, "result": result, "released": inc["user_name"], "group": inc["chat_title"],
                           "note": "Banned accounts are unbanned and can rejoin with the group link."
                           if result == "unbanned" else ""})

    return {"ratcatcher_check": (CHECK, check), "ratcatcher_report": (REPORT, report),
            "ratcatcher_blocklist": (BLOCKLIST, blocklist), "ratcatcher_release": (RELEASE, release)}
