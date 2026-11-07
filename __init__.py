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

    ctx.register_telegram_handler(make_factory(mod))

    skill = _HERE / "skills" / "ratcatcher" / "SKILL.md"
    if skill.exists():
        ctx.register_skill("ratcatcher", skill)
