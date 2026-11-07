"""Ratcatcher tests: detector rules, storage, decisions and the live Telegram handler path.

Run with:  python -m pytest tests  (from the plugin folder, with python-telegram-bot installed)
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ratcatcher.detector import Admin, Detector, Sender  # noqa: E402
from ratcatcher.moderator import HANDLER_GROUP, Moderator, Settings, make_factory  # noqa: E402
from ratcatcher.store import Store  # noqa: E402
from ratcatcher import tools as rc_tools  # noqa: E402

ADMINS = [Admin(1, "Truth", "heistruthx"), Admin(2, "Sign Nigeria Mod", "signng_mod")]

SCAMS = [
    "🎉 $SIGN airdrop is LIVE! Claim now before it ends: https://sign-claim.xyz/connect",
    "Having issues? DM me, I'm from support. Or message @SignSupportDeskBot",
    "Please validate your wallet here to receive your allocation metamask-verify.com",
    "I made $40k with my account manager Mrs Linda, she doubles your money. Inbox me",
    "Ѕеnd 0.5 ETH to 0x1234567890abcdef1234567890abcdef12345678 and get 1 ETH back",
    "Wallet not syncing? Rectify your wallet at https://dapp-rectify.online/sync",
    "Type your 12 word recovery phrase in the form to restore access",
    "Official giveaway is open, first 100 users get 500 USDT, claim here bit.ly/xyz123",
]

CLEAN = [
    "Hi I'm new here, when is the next AMA?",
    "gm everyone, check the docs at https://docs.sign.global",
    "never share your seed phrase with anyone guys",
    "what's the uniswap link? I use app.uniswap.org",
    "Is the airdrop snapshot done or still coming?",
    "Price is pumping today, nice",
    "Admins will never DM you first, report anyone who does",
]


@pytest.mark.parametrize("text", SCAMS)
def test_scams_are_caught(text):
    v = Detector().check(text, Sender(99, "Random", "random99"), ADMINS)
    assert v.score >= 0.7, (text, v.as_dict())


@pytest.mark.parametrize("text", CLEAN)
def test_normal_chat_is_left_alone(text):
    v = Detector().check(text, Sender(98, "Member", "member98"), ADMINS)
    assert v.score < 0.45, (text, v.as_dict())


def test_admins_are_never_touched():
    v = Detector().check(SCAMS[0], Sender(1, "Truth", "heistruthx", is_admin=True), ADMINS)
    assert v.score == 0


def test_admin_copycat_name():
    v = Detector().check("hello fam, check your DMs", Sender(77, "Truth", "heistruthx_"), ADMINS)
    assert v.category in ("impersonation", "fake_support")
    assert any("copies the admin" in r for r in v.reasons)


def test_hidden_link_behind_text():
    v = Detector().check("Read the announcement here", Sender(5, "x", "x"), ADMINS,
                         hidden_urls=["https://phantom-wallet-claim.click/connect"])
    assert v.score >= 0.8


def test_blocklist_and_allowlist():
    d = Detector(blocked_domains=["evil.example"], allowed_domains=["sign-claim.xyz"])
    assert d.check("see https://evil.example/a", Sender(5)).category == "blocklisted"
    # allowed domain removes link signals, but the airdrop wording still counts
    assert d.check("docs: https://sign-claim.xyz/faq", Sender(5)).score == 0


def test_store_roundtrip():
    s = Store.memory()
    i = s.add_incident(chat_id=-100, chat_title="G", message_id=5, user_id=9, user_name="Mike", text="t",
                       score=0.9, category="fake_airdrop", reasons=["r"], action="deleted")
    assert s.get_incident(i)["reasons"] == ["r"]
    assert s.summary(1)["total"] == 1
    assert s.add_strike(-100, 9) == 1 and s.add_strike(-100, 9) == 2
    assert s.block("domain", "https://www.Evil.xyz/path")
    assert s.blocklist()[0]["value"] == "evil.xyz"


def _mod(**overrides):
    st = Settings()
    for k, v in overrides.items():
        setattr(st, k, v)
    return Moderator(Store.memory(), lambda: st)


def test_ai_second_look_blocks_borderline():
    llm = MagicMock()
    llm.acomplete_structured = AsyncMock(return_value=SimpleNamespace(
        parsed={"is_scam": True, "confidence": 0.9, "category": "fake_support", "reason": "DM bait"}))
    mod = _mod()
    mod.llm = llm
    v, decision, note = asyncio.run(mod.judge("support team here, inbox me for help", Sender(4, "a", "a"),
                                              ADMINS, [], False))
    assert decision == "block" and "AI" in note


def test_borderline_without_ai_is_flagged_not_removed():
    mod = _mod(ai_review=False)
    _, decision, _ = asyncio.run(mod.judge("support team here, inbox me for help", Sender(4, "a", "a"),
                                           ADMINS, [], False))
    assert decision == "flag"


def test_tools_check_and_blocklist():
    mod = _mod()
    t = rc_tools.build(mod)
    out = json.loads(t["ratcatcher_check"][1]({"text": SCAMS[0]}))
    assert out["verdict"] == "would be removed"
    json.loads(t["ratcatcher_blocklist"][1]({"action": "add", "kind": "domain", "value": "drain.top"}))
    lst = json.loads(t["ratcatcher_blocklist"][1]({"action": "list"}))["blocklist"]
    assert lst[0]["value"] == "drain.top"
    rep = json.loads(t["ratcatcher_report"][1]({}))
    assert rep["summary"]["total"] == 0 and rep["connected_to_telegram"] is False


# ---------------------------------------------------------------------------
# Live handler path with real python-telegram-bot objects and a fake Bot API
# ---------------------------------------------------------------------------

telegram = pytest.importorskip("telegram")
from telegram import Update  # noqa: E402
from telegram.ext import ApplicationHandlerStop  # noqa: E402


class FakeApp:
    def __init__(self, bot):
        self.bot = bot
        self.handlers = []

    def add_handler(self, handler, group=0):
        self.handlers.append((handler, group))


def _fake_bot():
    bot = MagicMock()
    bot.id = 4242
    bot.defaults = None
    bot.get_chat_administrators = AsyncMock(return_value=[
        SimpleNamespace(user=SimpleNamespace(id=1, full_name="Truth", username="heistruthx"))])
    bot.delete_message = AsyncMock(return_value=True)
    bot.restrict_chat_member = AsyncMock(return_value=True)
    bot.ban_chat_member = AsyncMock(return_value=True)
    bot.send_message = AsyncMock(return_value=MagicMock(delete=AsyncMock()))
    return bot


def _update(bot, text, user_id=9, first="Mike", username="mike22", entities=None):
    data = {"update_id": 1, "message": {
        "message_id": 77, "date": 1730000000, "text": text,
        "chat": {"id": -1001, "type": "supergroup", "title": "Test Group"},
        "from": {"id": user_id, "is_bot": False, "first_name": first, "username": username}}}
    if entities:
        data["message"]["entities"] = entities
    return Update.de_json(data, bot)


def _wire(mod):
    bot = _fake_bot()
    app = FakeApp(bot)
    make_factory(mod)(app, None)
    groups = {g for _, g in app.handlers}
    assert groups == {HANDLER_GROUP}
    on_message = app.handlers[0][0].callback
    return bot, on_message


def test_handler_removes_scam_and_stops_hermes():
    mod = _mod(warning_ttl_seconds=0)
    bot, on_message = _wire(mod)
    upd = _update(bot, SCAMS[0])
    ctx = SimpleNamespace(bot=bot)
    with pytest.raises(ApplicationHandlerStop):
        asyncio.run(on_message(upd, ctx))
    bot.delete_message.assert_awaited_with(-1001, 77)
    bot.restrict_chat_member.assert_awaited()
    bot.send_message.assert_awaited()          # group warning
    caught = mod.store.recent(1)
    assert caught and caught[0]["action"].startswith("deleted")


def test_handler_lets_clean_messages_through():
    mod = _mod()
    bot, on_message = _wire(mod)
    upd = _update(bot, "gm, when is the next AMA?")
    asyncio.run(on_message(upd, SimpleNamespace(bot=bot)))   # no stop raised
    bot.restrict_chat_member.assert_not_awaited()
    assert mod.store.recent(1) == []


def test_watch_mode_only_logs():
    mod = _mod(mode="watch")
    bot, on_message = _wire(mod)
    upd = _update(bot, SCAMS[1])
    asyncio.run(on_message(upd, SimpleNamespace(bot=bot)))
    bot.delete_message.assert_not_awaited()
    assert mod.store.recent(1)[0]["action"] == "watched"


def test_ban_after_strikes():
    mod = _mod(ban_after=2, warn_in_group=False)
    bot, on_message = _wire(mod)
    for _ in range(2):
        upd = _update(bot, SCAMS[0])
        with pytest.raises(ApplicationHandlerStop):
            asyncio.run(on_message(upd, SimpleNamespace(bot=bot)))
    bot.ban_chat_member.assert_awaited_once()


def test_hidden_text_link_entity_is_read():
    mod = _mod(warning_ttl_seconds=0)
    bot, on_message = _wire(mod)
    upd = _update(bot, "Official announcement", entities=[
        {"type": "text_link", "offset": 0, "length": 8, "url": "https://metamask-sync.click/connect"}])
    with pytest.raises(ApplicationHandlerStop):
        asyncio.run(on_message(upd, SimpleNamespace(bot=bot)))
