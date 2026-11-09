"""Ratcatcher: a scam bouncer for the Telegram groups your Hermes bot runs in."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from .moderator import Moderator, Settings, make_factory
from .store import Store
from . import tools as _tools

logger = logging.getLogger(__name__)

PLUGIN_ID = "ratcatcher"
_HERE = Path(__file__).parent


def _open_store() -> Store:
    try:
        from plugins.plugin_storage import plugin_db
        return Store(plugin_db(PLUGIN_ID))
    except Exception:
        logger.warning("ratcatcher: plugin storage unavailable, keeping catches in memory", exc_info=True)
        return Store.memory()


def _status_text(mod: Moderator) -> str:
    s = mod.settings
    day = mod.store.summary(24)
    cats = ", ".join(f"{k} {v}" for k, v in sorted(day["by_category"].items(), key=lambda kv: -kv[1])) or "none"
    chats = ", ".join(s.protected_chats) or "every group the bot is in"
    return (f"🐀 Ratcatcher is {'connected to Telegram' if mod.bot else 'waiting for the Telegram gateway'}\n"
            f"Mode: {s.mode} | guarding: {chats}\n"
            f"Last 24h: {day['total']} caught ({cats})\n"
            f"Thresholds: remove at {s.block_threshold}, second look at {s.review_threshold}, "
            f"AI review {'on' if s.ai_review else 'off'}\n"
            f"Blocklist: {len(mod.store.blocklist())} entries")


GATED_TOOLS = ("ratcatcher_blocklist", "ratcatcher_release")


def approval_gate(mod: Moderator):
    """pre_tool_call hook: blocklist changes and releases need a human to confirm.

    A blocklist entry decides who gets removed from the group, and a release lets someone back in.
    A scam message in a group could try to talk the model into either one, so Hermes's own approval
    prompt has to be answered by a person before these run. Reading the blocklist stays free.
    """
    def guard(tool_name: str = "", args: dict | None = None, **kw: object):
        if tool_name not in GATED_TOOLS:
            return None
        try:
            return _decide(tool_name, args)
        except Exception:  # never let an error here skip the approval: fail closed
            logger.warning("ratcatcher: approval gate error, asking for approval anyway", exc_info=True)
            return {"action": "approve", "message": f"Ratcatcher: allow {tool_name} with {args!r}?"}

    def _decide(tool_name: str, args: dict | None):
        args = args if isinstance(args, dict) else {}
        if tool_name == "ratcatcher_blocklist":
            action = str(args.get("action") or "list")
            if action == "list":
                return None
            kind = str(args.get("kind") or "domain")
            value = str(args.get("value") or "").strip()
            if action == "add":
                clean, why = mod.store.clean_entry(kind, value)
                if not clean:
                    return None  # the tool itself refuses it; nothing would change
                msg = (f"Ratcatcher: add the {kind} '{clean}' to the blocklist? Any member who posts it will "
                       f"have the message removed and get a strike (muted, banned after repeat strikes).")
            else:
                msg = f"Ratcatcher: remove the {kind} '{value.lower()}' from the blocklist?"
            return {"action": "approve", "message": msg,
                    "rule_key": f"ratcatcher:blocklist:{action}:{kind}:{value.lower()}"}
        try:
            inc = mod.store.get_incident(int(args.get("incident_id")))
        except (TypeError, ValueError):
            inc = None
        who = f"{inc['user_name']} in {inc['chat_title'] or inc['chat_id']}" if inc else "this catch"
        return {"action": "approve",
                "message": f"Ratcatcher: release catch #{args.get('incident_id')} ({who})? "
                           "This unbans or unmutes them and clears their strikes.",
                "rule_key": f"ratcatcher:release:{args.get('incident_id')}"}
    return guard


def register(ctx) -> None:
    store = _open_store()
    llm = None
    try:
        llm = ctx.llm
    except Exception:
        logger.info("ratcatcher: no LLM access, AI second look disabled")
    mod = Moderator(store, lambda: Settings.load(ctx.get_config), llm=llm)

    for name, (schema, handler) in _tools.build(mod).items():
        ctx.register_tool(name=name, toolset="ratcatcher", schema=schema, handler=handler)

    def _command(raw: str = "", **kwargs) -> str:
        arg = (raw or "").strip().lower()
        if arg.startswith("check "):
            out = json.loads(_tools.build(mod)["ratcatcher_check"][1]({"text": raw.strip()[6:]}))
            if "error" in out:
                return out["error"]
            why = "\n".join(f"• {r}" for r in out["reasons"][:4]) or "• nothing suspicious"
            return f"{out['label'].title()} (score {out['score']}), {out['verdict']}\n{why}"
        return _status_text(mod)

    ctx.register_command("ratcatcher", _command, description="Ratcatcher status, or /ratcatcher check <text>",
                         args_hint="[check <text>]")

    ctx.register_hook("pre_tool_call", approval_gate(mod))
    ctx.register_telegram_handler(make_factory(mod))

    skill = _HERE / "skills" / "ratcatcher" / "SKILL.md"
    if skill.exists():
        ctx.register_skill("ratcatcher", skill)
