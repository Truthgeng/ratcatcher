---
name: ratcatcher
description: Run and tune Ratcatcher, the Telegram group scam bouncer. Use when the user asks about scams in their groups, wants a message checked, wants to block a site or phrase, or wants someone released.
---

# Ratcatcher

Ratcatcher guards the Telegram groups this Hermes bot is in. It removes scam messages before you see them, so a removed message never reaches you as a turn.

## Tools

- `ratcatcher_check`: score a pasted message or link. Use it whenever the user asks "is this a scam?". Explain the reasons in plain words.
- `ratcatcher_report`: what was caught, by type and action, plus the latest catches with their numbers. Use for "who got banned today", "any scams this week".
- `ratcatcher_blocklist`: list, add or remove a domain or phrase. Add the bare domain (`claim-sign.xyz`), not a full URL.
- `ratcatcher_release`: undo a false alarm by catch number. Only when the user asks.

## Setup checklist (when the user is setting it up)

1. Add the bot to the group and make it admin with "Delete messages" and "Ban users".
2. In BotFather, turn privacy mode off (`/setprivacy` → Disable) if the bot is not admin, or it only sees commands.
3. Set `report_chat_id` to the user's own Telegram id so reports with Release and Ban buttons arrive in DM. The user must have started a chat with the bot.
4. Add the project's real domains to `allowed_domains`.
5. Suggest `mode: watch` for the first day in a busy group, then switch to `enforce`.

## How it decides

Pattern rules score each message from 0 to 1. At or above the remove score (default 0.8) it acts. Between the second-look score (0.45) and the remove score, the current model reviews it once. Admins are never touched. Safety warnings like "never share your seed phrase" are scored down.

## When answering

- Lead with the result, then the reasons.
- Never repeat a scam link as a clickable link. Write the domain in backticks.
- If a catch looks wrong, offer to release it and to add the domain to `allowed_domains`.
