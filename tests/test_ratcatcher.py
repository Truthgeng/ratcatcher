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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from corpus import CLEAN as CORPUS_CLEAN, FRESH_CLEAN, FRESH_SCAMS, SCAMS as CORPUS_SCAMS  # noqa: E402

_CORPUS = [(fam, t) for fam, lines in CORPUS_SCAMS.items() for t in lines]


@pytest.mark.parametrize("family,text", _CORPUS)
def test_corpus_scams_are_removed(family, text):
    v = Detector().check(text, Sender(99, "Random", "random99"), ADMINS)
    assert v.score >= 0.8, (family, text, v.as_dict())


@pytest.mark.parametrize("text", FRESH_SCAMS)
def test_fresh_scams_reach_at_least_ai_review(text):
    v = Detector().check(text, Sender(99, "Random", "random99"), ADMINS)
    assert v.score >= Settings().review_threshold, (text, v.as_dict())


@pytest.mark.parametrize("text", CORPUS_CLEAN + FRESH_CLEAN)
def test_corpus_clean_chat_is_never_removed(text):
    v = Detector().check(text, Sender(98, "Member", "member98"), ADMINS)
    assert v.score < 0.45, (text, v.as_dict())


@pytest.mark.parametrize("text", [
    "Type your 12 word recovery phrase in the form to restore access",
    "Send 1 ETH get 2 ETH back, Vitalik giveaway is live",
    "Need to recover stolen crypto? Our ethical hacker team can trace and retrieve lost funds",
])
def test_near_certain_scams_are_marked_for_ban_on_sight(text):
    assert Detector().check(text, Sender(9, "x", "x"), ADMINS).certain


def test_safety_warning_is_not_certain():
    assert not Detector().check("never share your seed phrase", Sender(9, "x", "x"), ADMINS).certain

SCAMS = [
    "🎉 $SIGN airdrop is LIVE! Claim now before it ends: https://sign-claim.xyz/connect",
    "Having issues? DM me, I'm from support. Or message @SignSupportDeskBot",
    "Please validate your wallet here to receive your allocation metamask-verify.com",
    "I made $40k with my account manager Mrs Linda, she doubles your money. Inbox me",
    "Ѕеnd 0.5 ETH to 0x1234567890abcdef1234567890abcdef12345678 and get 1 ETH back",
    "Wallet not syncing? Rectify your wallet at https://dapp-rectify.online/sync",
    "Type your 12 word recovery phrase in the form to restore access",
    "Official giveaway is open, first 100 users get 500 USDT, claim here bit.ly/xyz123",
    "Having issues with your wallet? DM me, I'm from support",
    "Having issues with your wallet? DM me, I’m from support",
    "Hello, I am from the support team. Anyone with pending withdrawals inbox me",
    "Is your transaction stuck? Message me, I can help you fix it",
    "We are the official team, contact us for your missing tokens",
]

CLEAN = [
    "Hi I'm new here, when is the next AMA?",
    "gm everyone, check the docs at https://docs.sign.global",
    "never share your seed phrase with anyone guys",
    "what's the uniswap link? I use app.uniswap.org",
    "Is the airdrop snapshot done or still coming?",
    "Price is pumping today, nice",
    "Admins will never DM you first, report anyone who does",
    "dm me if you want to collab on the thread",
    "having issues with my wallet, anyone know why?",
    "I'm from Lagos, gm fam",
    "the team said the update is coming soon",
    "If anyone says I'm from support and asks you to DM them, it is a scam",
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
    assert any("admin Truth" in r for r in v.reasons) and v.certain


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
    v, decision, note = asyncio.run(mod.judge("dm me for help", Sender(4, "a", "a"),
                                              ADMINS, [], False))
    assert decision == "block" and "AI" in note


def test_borderline_without_ai_is_flagged_not_removed():
    mod = _mod(ai_review=False)
    _, decision, _ = asyncio.run(mod.judge("dm me for help", Sender(4, "a", "a"),
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


def test_ban_on_sight_bans_first_time():
    mod = _mod(warn_in_group=False)
    bot, on_message = _wire(mod)
    upd = _update(bot, "Pls paste your 12 word phrase here so the system can restore your funds")
    with pytest.raises(ApplicationHandlerStop):
        asyncio.run(on_message(upd, SimpleNamespace(bot=bot)))
    bot.ban_chat_member.assert_awaited_once()


def test_ban_on_sight_off_only_mutes():
    mod = _mod(warn_in_group=False, ban_on_sight=False)
    bot, on_message = _wire(mod)
    upd = _update(bot, "Pls paste your 12 word phrase here so the system can restore your funds")
    with pytest.raises(ApplicationHandlerStop):
        asyncio.run(on_message(upd, SimpleNamespace(bot=bot)))
    bot.ban_chat_member.assert_not_awaited()
    bot.restrict_chat_member.assert_awaited()


# ---------------------------------------------------------------------------
# Admin and owner clones
# ---------------------------------------------------------------------------

CLONE_ADMINS = [Admin(1, "Truth", "heistruthx"), Admin(2, "Ada Okeke", "ada_okeke"),
                Admin(3, "Sign Nigeria Mod", "signng_mod")]


@pytest.mark.parametrize("name,username,expected", [
    ("Truth", "heistruthx_", "strong"),          # copied name and look-alike username
    ("Truth | Admin", "truth_help", "strong"),   # name plus staff title
    ("Truth Support", "randomguy", "strong"),
    ("Τruth", "heistruthx", "strong"),           # Greek T
    ("heistruthx", "bob22", "strong"),           # admin's username used as display name
    ("Ada Okeke", "scammer777", "strong"),       # exact copy of a distinctive full name
    ("Ada Okeke 🛡", "", "strong"),
    ("Sign Nigeria", "signngofficial", "strong"),
    ("Truth", "", "weak"),                       # short single name, could be a real member
    ("Truth", "kelvin_22", "weak"),
    ("Truthh", "xyz999", "weak"),
    ("Truth Okafor", "truthokafor", None),       # real person who shares a first name
    ("Ada", "ada_b", None),
    ("Kay", "kay", None),
])
def test_clone_levels(name, username, expected):
    c = Detector().clone_check(Sender(50, name, username), CLONE_ADMINS)
    assert (c.strength if c else None) == expected, (name, username, c)


def test_real_admin_is_never_a_clone():
    assert Detector().clone_check(Sender(1, "Truth", "heistruthx", is_admin=True), CLONE_ADMINS) is None


def _clone_bot():
    bot = _fake_bot()
    bot.get_chat_administrators = AsyncMock(return_value=[
        SimpleNamespace(user=SimpleNamespace(id=1, full_name="Truth", username="heistruthx"))])
    return bot


def _wire_with(mod, bot):
    app = FakeApp(bot)
    make_factory(mod)(app, None)
    return [h.callback for h, _ in app.handlers]


def test_strong_clone_is_banned_even_for_a_photo():
    mod = _mod(warning_ttl_seconds=0)
    bot = _clone_bot()
    on_message, _, _ = _wire_with(mod, bot)
    data = {"update_id": 5, "message": {
        "message_id": 90, "date": 1730000000, "photo": [{"file_id": "x", "file_unique_id": "y", "width": 1,
                                                         "height": 1}],
        "chat": {"id": -1001, "type": "supergroup", "title": "Test Group"},
        "from": {"id": 66, "is_bot": False, "first_name": "Truth", "username": "heistruthx_"}}}
    upd = Update.de_json(data, bot)
    with pytest.raises(ApplicationHandlerStop):
        asyncio.run(on_message(upd, SimpleNamespace(bot=bot)))
    bot.ban_chat_member.assert_awaited_once_with(-1001, 66)
    bot.delete_message.assert_awaited_with(-1001, 90)
    assert "banned" in mod.store.recent(1)[0]["action"]


def test_weak_clone_is_muted_not_banned():
    mod = _mod(warning_ttl_seconds=0)
    bot = _clone_bot()
    on_message, _, _ = _wire_with(mod, bot)
    upd = _update(bot, "hello everyone", user_id=67, first="Truth", username="kelvin_22")
    with pytest.raises(ApplicationHandlerStop):
        asyncio.run(on_message(upd, SimpleNamespace(bot=bot)))
    bot.ban_chat_member.assert_not_awaited()
    bot.restrict_chat_member.assert_awaited()
    bot.delete_message.assert_not_awaited()


def test_clone_banned_on_join():
    mod = _mod(warning_ttl_seconds=0)
    bot = _clone_bot()
    _, on_join, _ = _wire_with(mod, bot)
    data = {"update_id": 6, "message": {
        "message_id": 91, "date": 1730000000,
        "chat": {"id": -1001, "type": "supergroup", "title": "Test Group"},
        "from": {"id": 68, "is_bot": False, "first_name": "Truth Admin"},
        "new_chat_members": [{"id": 68, "is_bot": False, "first_name": "Truth Admin"}]}}
    asyncio.run(on_join(Update.de_json(data, bot), SimpleNamespace(bot=bot)))
    bot.ban_chat_member.assert_awaited_once_with(-1001, 68)


def test_ban_clones_off_only_mutes():
    mod = _mod(warning_ttl_seconds=0, ban_clones=False)
    bot = _clone_bot()
    on_message, _, _ = _wire_with(mod, bot)
    upd = _update(bot, "hi", user_id=69, first="Truth", username="heistruthx_")
    with pytest.raises(ApplicationHandlerStop):
        asyncio.run(on_message(upd, SimpleNamespace(bot=bot)))
    bot.ban_chat_member.assert_not_awaited()
    bot.restrict_chat_member.assert_awaited()


# ---------------------------------------------------------------------------
# Release and Ban buttons on admin reports
# ---------------------------------------------------------------------------

def _button_update(bot, data, presser=1):
    return Update.de_json({"update_id": 9, "callback_query": {
        "id": "cb1", "chat_instance": "ci", "data": data,
        "from": {"id": presser, "is_bot": False, "first_name": "Truth"},
        "message": {"message_id": 500, "date": 1730000000, "text": "Caught #1",
                    "chat": {"id": 1, "type": "private", "first_name": "Truth"}}}}, bot)


def _button_setup(status):
    mod = _mod(warning_ttl_seconds=0)
    bot = _clone_bot()
    bot.get_chat_member = AsyncMock(return_value=SimpleNamespace(status=status))
    bot.unban_chat_member = AsyncMock(return_value=True)
    bot.answer_callback_query = AsyncMock(return_value=True)
    bot.edit_message_text = AsyncMock(return_value=True)
    bot.create_chat_invite_link = AsyncMock(return_value=SimpleNamespace(invite_link="https://t.me/+abc123"))
    inc = mod.store.add_incident(chat_id=-1001, chat_title="G", message_id=1, user_id=66, user_name="Clone",
                                 text="hi", score=1.0, category="impersonation", reasons=["r"], action="banned")
    _, _, on_button = _wire_with(mod, bot)
    return mod, bot, inc, on_button


def test_release_button_unbans_a_banned_account():
    mod, bot, inc, on_button = _button_setup("kicked")
    with pytest.raises(ApplicationHandlerStop):
        asyncio.run(on_button(_button_update(bot, f"rcatch:release:{inc}"), SimpleNamespace(bot=bot)))
    bot.unban_chat_member.assert_awaited_once()
    bot.restrict_chat_member.assert_not_awaited()
    bot.create_chat_invite_link.assert_awaited_once()
    assert mod.store.get_incident(inc)["released"] == 1


def test_release_button_unmutes_a_muted_account():
    mod, bot, inc, on_button = _button_setup("restricted")
    with pytest.raises(ApplicationHandlerStop):
        asyncio.run(on_button(_button_update(bot, f"rcatch:release:{inc}"), SimpleNamespace(bot=bot)))
    bot.restrict_chat_member.assert_awaited_once()
    assert mod.store.get_incident(inc)["released"] == 1


def test_only_admins_can_press_buttons():
    mod, bot, inc, on_button = _button_setup("kicked")
    asyncio.run(on_button(_button_update(bot, f"rcatch:release:{inc}", presser=777), SimpleNamespace(bot=bot)))
    bot.unban_chat_member.assert_not_awaited()


def test_basic_group_does_not_try_to_mute():
    mod = _mod(warning_ttl_seconds=0)
    bot, on_message = _wire(mod)
    data = {"update_id": 11, "message": {
        "message_id": 78, "date": 1730000000, "text": SCAMS[1],
        "chat": {"id": -555, "type": "group", "title": "Basic Group"},
        "from": {"id": 9, "is_bot": False, "first_name": "Mike", "username": "mike22"}}}
    with pytest.raises(ApplicationHandlerStop):
        asyncio.run(on_message(Update.de_json(data, bot), SimpleNamespace(bot=bot)))
    bot.delete_message.assert_awaited()
    bot.restrict_chat_member.assert_not_awaited()
    assert "mute_needs_supergroup" in mod.store.recent(1)[0]["action"]


def test_release_dms_the_link_when_possible():
    mod, bot, inc, on_button = _button_setup("kicked")
    with pytest.raises(ApplicationHandlerStop):
        asyncio.run(on_button(_button_update(bot, f"rcatch:release:{inc}"), SimpleNamespace(bot=bot)))
    dm = [c for c in bot.send_message.await_args_list if c.args and c.args[0] == 66]
    assert dm and "t.me/+abc123" in dm[0].args[1]
    call = bot.edit_message_text.await_args
    assert "sent to them in DM" in str(call.args) + str(call.kwargs)


def test_release_falls_back_when_dm_is_blocked():
    mod, bot, inc, on_button = _button_setup("kicked")
    async def _send(chat_id, *a, **k):
        if chat_id == 66:
            raise RuntimeError("Forbidden: bot can't initiate conversation with a user")
        return MagicMock()
    bot.send_message = AsyncMock(side_effect=_send)
    with pytest.raises(ApplicationHandlerStop):
        asyncio.run(on_button(_button_update(bot, f"rcatch:release:{inc}"), SimpleNamespace(bot=bot)))
    call = bot.edit_message_text.await_args
    assert "Forward them this one-time link" in str(call.args) + str(call.kwargs)


def _channel_update(bot, auto_forward, channel_id):
    data = {"update_id": 12, "message": {
        "message_id": 95, "date": 1730000000, "text": SCAMS[0],
        "chat": {"id": -1001, "type": "supergroup", "title": "Test Group"},
        "from": {"id": 136817688, "is_bot": True, "first_name": "Channel", "username": "Channel_Bot"},
        "sender_chat": {"id": channel_id, "type": "channel", "title": "Announcements"}}}
    if auto_forward:
        data["message"]["is_automatic_forward"] = True
    return Update.de_json(data, bot)


def test_linked_channel_announcement_is_not_touched():
    mod = _mod()
    bot, on_message = _wire(mod)
    bot.get_chat = AsyncMock(return_value=SimpleNamespace(linked_chat_id=-100777))
    asyncio.run(on_message(_channel_update(bot, True, -100777), SimpleNamespace(bot=bot)))
    bot.delete_message.assert_not_awaited()


def test_unrelated_channel_posting_scams_is_removed():
    mod = _mod(warning_ttl_seconds=0)
    bot, on_message = _wire(mod)
    bot.get_chat = AsyncMock(return_value=SimpleNamespace(linked_chat_id=-100777))
    with pytest.raises(ApplicationHandlerStop):
        asyncio.run(on_message(_channel_update(bot, False, -100555), SimpleNamespace(bot=bot)))
    bot.delete_message.assert_awaited()
