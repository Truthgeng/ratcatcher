"""Ratcatcher detection engine.

Pure Python, no network, no Hermes imports, so it is fast enough to run on every
group message and easy to test. It turns a message into a Verdict: a 0..1 score,
a category, and the plain-English reasons behind it.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Iterable, Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Normalisation: scammers dodge filters with look-alike letters and hidden chars
# ---------------------------------------------------------------------------

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e"), None)

# Cyrillic / Greek letters that render like Latin ones.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u", "ν": "v", "ο": "o",
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "τ": "t", "ρ": "p", "Α": "a", "Ε": "e", "Ο": "o",
    "Р": "p", "С": "c", "Т": "t", "Х": "x", "М": "m", "Н": "h", "К": "k", "В": "b",
})

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def normalise(text: str) -> str:
    """Lowercase, strip invisible characters and fold look-alike letters."""
    text = unicodedata.normalize("NFKC", text or "").translate(_ZERO_WIDTH)
    return text.lower().translate(_HOMOGLYPHS)


def _deleet(text: str) -> str:
    return text.translate(_LEET)


# ---------------------------------------------------------------------------
# Rule tables
# ---------------------------------------------------------------------------

# (pattern, weight, category, reason). Weights add up; the score is capped at 1.0.
PHRASE_RULES: list[tuple[str, float, str, str]] = [
    # Wallet drainers dressed up as "fixes"
    (r"\b(validate|sync|rectify|restore|unlock|migrate|verify)\b.{0,25}\bwallets?\b", 0.45, "drainer",
     "asks people to 'validate' or 'sync' their wallet, a common drainer line"),
    (r"\bconnect (your )?wallet\b", 0.30, "drainer", "tells people to connect their wallet"),
    (r"\b(enter|type|submit|share|send|input|paste|provide|import)\b.{0,30}\b(seed|recovery|secret|mnemonic) (phrase|words?)\b",
     0.6, "drainer", "asks people to enter or share their seed phrase"),
    (r"\b(seed|recovery|secret|mnemonic) (phrase|words?)\b", 0.25, "drainer",
     "mentions a seed or recovery phrase"),
    (r"\bprivate key\b", 0.45, "drainer", "mentions a private key"),
    # Fake airdrops and giveaways
    (r"\b(airdrop|giveaway|reward|allocation|whitelist|presale)\b.{0,40}\b(live|claim|now|ends?|eligible|open)\b",
     0.35, "fake_airdrop", "pushes an airdrop or reward claim"),
    (r"\bclaim (your|now|here|free)\b", 0.30, "fake_airdrop", "urges people to claim something"),
    (r"\b(first|only) \d+ (users|people|wallets|members)\b|\blimited (slots|spots)\b", 0.20, "fake_airdrop",
     "creates false urgency with limited slots"),
    # Fake support / DM bait
    (r"\b(dm|inbox|pm|message|text|contact) (me|us|admin|support|the admin)\b", 0.35, "fake_support",
     "pulls people into DMs, real admins never ask first"),
    (r"\b(support|help ?desk|customer care|technical team)\b.{0,30}\b(dm|inbox|contact|bot|link|ticket)\b",
     0.35, "fake_support", "pretends to be a support desk"),
    (r"\bopen a (support )?ticket\b", 0.30, "fake_support", "asks people to open a 'ticket' outside the group"),
    (r"\b(i'?m|i am|we'?re|we are|this is)\s+(from\s+)?(the\s+|an?\s+|your\s+)?(official\s+)?(support|admin|"
     r"moderator|mod|help ?desk|customer care|team|dev team|technical team)\b", 0.40, "fake_support",
     "claims to be support or staff without being an admin"),
    (r"\b(issues?|problems?|trouble|stuck|errors?|difficult(y|ies)|delayed|pending|missing)\b.{0,30}"
     r"\b(wallet|transaction|withdrawals?|deposits?|funds|tokens|account|claim|bridge|swap)\b|"
     r"\b(wallet|transaction|withdrawal|deposit|funds|tokens|claim|bridge|swap)s?\b.{0,12}"
     r"\b(stuck|pending|delayed|missing|failed|not (showing|working|syncing))\b", 0.20,
     "fake_support", "fishes for people with wallet or transaction problems"),
    (r"\b(dm|inbox|pm|message|text|contact|reach out to)\b.{0,15}\b(me|us)\b.{0,25}\b(help|fix|resolve|"
     r"assist|solution|sort)\b|\bi can help\b.{0,25}\b(dm|inbox|pm)\b", 0.25, "fake_support",
     "offers private help in DMs"),
    # Investment bait
    (r"\b(doubl(e|es|ing)|tripl(e|es|ing)|2x|3x|10x) (your|ur)\b|\bsend\b.{0,80}\b(get|receive)\b.{0,20}\bback\b", 0.50, "investment_scam",
     "promises to multiply money sent"),
    (r"\bguaranteed (profit|returns?|income)\b|\b(daily|weekly) (profit|returns?) of\b", 0.45, "investment_scam",
     "promises guaranteed profit"),
    (r"\b(account|investment|trading|forex) manager\b|\bi made \$?\d[\d,]*k? (with|from|using)\b", 0.35,
     "investment_scam", "classic 'account manager' or testimonial bait"),
    (r"\bmining (pool|contract|plan)\b|\bcloud mining\b", 0.30, "investment_scam", "cloud mining pitch"),
]

URL_RE = re.compile(r"(?i)\b((?:https?://|www\.)[^\s<>\"']+|(?:[a-z0-9-]+\.)+(?:[a-z]{2,24})/[^\s<>\"']*)")
BARE_DOMAIN_RE = re.compile(r"(?i)\b((?:[a-z0-9-]+\.)+(?:xyz|top|click|live|site|online|app|io|org|com|net|info|"
                            r"pro|link|claims?|gift|finance|network|vip|one|store|cc|me|co|ru|tk|ml|ga|cf|gq))\b")
TG_HANDLE_RE = re.compile(r"(?<![\w.])@([a-z0-9_]{4,32})", re.I)
EVM_ADDR_RE = re.compile(r"\b0x[a-f0-9]{40}\b", re.I)
SOL_ADDR_RE = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "tiny.cc", "ow.ly",
              "rebrand.ly", "s.id", "goo.su", "clck.ru", "v.gd"}
RISKY_TLDS = {"xyz", "top", "click", "live", "site", "online", "link", "claim", "claims", "gift", "vip", "tk",
              "ml", "ga", "cf", "gq", "icu", "buzz", "rest", "fit", "cfd", "sbs", "lol"}
LURE_PATH_WORDS = ("claim", "airdrop", "connect", "wallet", "reward", "drop", "mint", "verify", "validate",
                   "sync", "rectify", "bonus", "gift", "free")

# Brands scammers copy, with their real domains. Anything that wears the brand name
# on another domain is a look-alike.
BRANDS: dict[str, set[str]] = {
    "metamask": {"metamask.io"},
    "phantom": {"phantom.app", "phantom.com"},
    "uniswap": {"uniswap.org", "app.uniswap.org"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "trustwallet": {"trustwallet.com"},
    "opensea": {"opensea.io"},
    "jupiter": {"jup.ag"},
    "pancakeswap": {"pancakeswap.finance"},
    "arbitrum": {"arbitrum.io", "arbitrum.foundation"},
    "optimism": {"optimism.io"},
    "layerzero": {"layerzero.network"},
    "ledger": {"ledger.com"},
    "bybit": {"bybit.com"},
    "okx": {"okx.com"},
    "hyperliquid": {"hyperliquid.xyz", "app.hyperliquid.xyz"},
    "solana": {"solana.com"},
    "ethereum": {"ethereum.org"},
    "telegram": {"telegram.org", "t.me"},
}

PROTECTIVE_RE = re.compile(r"\b(never|don'?t|do not|beware|watch out|be careful|stay safe|warning|report)\b"
                           r".{0,40}\b(share|send|give|click|trust|dm|scam|fake|phrase|key)\b|\bis a scam\b|"
                           r"\badmins? (will )?never\b", re.I)

IMPERSONATION_WORDS = re.compile(r"\b(admin|administrator|support|moderator|mod|official|team|helpdesk|"
                                 r"customer ?care|ceo|founder|dev)\b", re.I)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class Sender:
    user_id: int = 0
    full_name: str = ""
    username: str = ""
    is_admin: bool = False
    joined_seconds_ago: Optional[float] = None   # None = unknown
    prior_messages: Optional[int] = None         # messages Ratcatcher has seen from them


@dataclass
class Admin:
    user_id: int
    full_name: str = ""
    username: str = ""


@dataclass
class Verdict:
    score: float
    category: str
    reasons: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return CATEGORY_LABELS.get(self.category, "suspicious message")

    def as_dict(self) -> dict:
        return {"score": round(self.score, 2), "category": self.category, "label": self.label,
                "reasons": self.reasons, "urls": self.urls}


CATEGORY_LABELS = {
    "clean": "clean",
    "drainer": "wallet drainer",
    "fake_airdrop": "fake airdrop",
    "fake_support": "fake support",
    "investment_scam": "investment scam",
    "impersonation": "admin impersonation",
    "phishing_link": "phishing link",
    "blocklisted": "blocklisted link or phrase",
    "suspicious": "suspicious message",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def extract_urls(text: str, hidden_urls: Iterable[str] = ()) -> list[str]:
    """Visible URLs plus any URLs hidden behind link text (Telegram text_link entities)."""
    found: list[str] = []
    for m in URL_RE.finditer(text or ""):
        found.append(m.group(1).rstrip(").,!?]"))
    for m in BARE_DOMAIN_RE.finditer(text or ""):
        dom = m.group(1)
        if not any(dom in u for u in found):
            found.append(dom)
    for u in hidden_urls:
        if u and u not in found:
            found.append(u)
    return found


def host_of(url: str) -> str:
    u = url if "://" in url else "http://" + url
    try:
        host = (urlparse(u).hostname or "").lower()
    except ValueError:
        host = ""
    return host[4:] if host.startswith("www.") else host


def _registrable(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _similar(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def _name_tokens(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", _deleet(normalise(name)))


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------

class Detector:
    def __init__(self, blocked_domains: Iterable[str] = (), blocked_phrases: Iterable[str] = (),
                 allowed_domains: Iterable[str] = (), new_member_window: float = 24 * 3600):
        self.blocked_domains = {d.lower().strip() for d in blocked_domains if d.strip()}
        self.blocked_phrases = [normalise(p) for p in blocked_phrases if p.strip()]
        self.allowed_domains = {d.lower().strip() for d in allowed_domains if d.strip()}
        self.new_member_window = new_member_window
        self._phrase_rules = [(re.compile(p, re.I | re.S), w, c, r) for p, w, c, r in PHRASE_RULES]

    # -- link checks ---------------------------------------------------------

    def _check_url(self, url: str) -> list[tuple[float, str, str]]:
        hits: list[tuple[float, str, str]] = []
        host = host_of(url)
        if not host:
            return hits
        reg = _registrable(host)
        if host in self.allowed_domains or reg in self.allowed_domains:
            return hits
        if host in self.blocked_domains or reg in self.blocked_domains:
            hits.append((1.0, "blocklisted", f"links to {reg}, which is on the blocklist"))
            return hits
        if host.startswith("xn--") or ".xn--" in host:
            hits.append((0.6, "phishing_link", f"uses a disguised (punycode) domain: {host}"))
        if reg in SHORTENERS:
            hits.append((0.25, "phishing_link", f"hides the real destination behind a link shortener ({reg})"))
        tld = reg.rsplit(".", 1)[-1]
        if tld in RISKY_TLDS:
            hits.append((0.2, "phishing_link", f"uses a domain ending often used in scams (.{tld})"))
        flat = re.sub(r"[^a-z0-9]", "", _deleet(host))
        for brand, real in BRANDS.items():
            if host in real or reg in real:
                break
            label = re.sub(r"[^a-z0-9]", "", reg.rsplit(".", 1)[0])
            if brand in flat or (len(label) >= 5 and _similar(label, brand) >= 0.8):
                hits.append((0.6, "phishing_link",
                             f"looks like {brand.title()} but is not its real site ({reg})"))
                break
        path = url.lower()
        if any(w in path.split(host, 1)[-1] or w in host for w in LURE_PATH_WORDS):
            hits.append((0.2, "phishing_link", "link points to a claim, connect or verify page"))
        return hits

    # -- impersonation -------------------------------------------------------

    def _check_impersonation(self, sender: Sender, admins: Iterable[Admin]) -> list[tuple[float, str, str]]:
        hits: list[tuple[float, str, str]] = []
        if sender.is_admin:
            return hits
        name = sender.full_name or ""
        uname = sender.username or ""
        me = _name_tokens(name + uname)
        for adm in admins:
            if adm.user_id == sender.user_id:
                continue
            for theirs in (_name_tokens(adm.full_name), _name_tokens(adm.username)):
                if len(theirs) >= 4 and len(me) >= 4:
                    a, b = _name_tokens(name) or me, theirs
                    u = _name_tokens(uname)
                    if max(_similar(a, b), _similar(u, b) if u else 0) >= 0.85 or (b in me and len(b) >= 5):
                        who = adm.full_name or ("@" + adm.username)
                        hits.append((0.7, "impersonation", f"name copies the admin {who} but is a different account"))
                        return hits
        if IMPERSONATION_WORDS.search(normalise(name + " " + uname)):
            hits.append((0.3, "impersonation", "calls itself admin, support or official but is not an admin"))
        return hits

    # -- main entry ----------------------------------------------------------

    def check(self, text: str, sender: Optional[Sender] = None, admins: Iterable[Admin] = (),
              hidden_urls: Iterable[str] = (), is_forward: bool = False) -> Verdict:
        sender = sender or Sender()
        admins = list(admins)
        raw = text or ""
        norm = normalise(raw)
        flat = _deleet(norm)
        hits: list[tuple[float, str, str]] = []

        if sender.is_admin:
            return Verdict(0.0, "clean", ["sender is a group admin"])

        for phrase in self.blocked_phrases:
            if phrase and phrase in norm:
                hits.append((1.0, "blocklisted", f"contains the blocked phrase '{phrase}'"))

        for rx, weight, cat, reason in self._phrase_rules:
            if rx.search(norm) or rx.search(flat):
                hits.append((weight, cat, reason))

        urls = extract_urls(raw, hidden_urls)
        for url in urls:
            hits.extend(self._check_url(url))
        hidden = [u for u in hidden_urls if u]
        if hidden:
            hits.append((0.15, "phishing_link", "hides a link behind normal-looking text"))

        for handle in TG_HANDLE_RE.findall(norm):
            h = handle.lower()
            if h.endswith("bot") and any(k in h for k in ("support", "help", "claim", "airdrop", "verify", "admin")):
                hits.append((0.45, "fake_support", f"sends people to a lookalike support bot (@{handle})"))
            elif any(k in h for k in ("support", "helpdesk", "admin", "official")):
                if not any(_name_tokens(a.username) == _name_tokens(h) for a in admins if a.username):
                    hits.append((0.35, "fake_support", f"points to @{handle}, which is not a real admin"))

        if EVM_ADDR_RE.search(raw) or (SOL_ADDR_RE.search(raw) and re.search(r"\b(send|deposit|transfer)\b", norm)):
            if re.search(r"\b(send|deposit|transfer|pay|fee|gas)\b", norm):
                hits.append((0.25, "investment_scam", "asks people to send funds to a wallet address"))

        hits.extend(self._check_impersonation(sender, admins))

        # Context boosts only count when something else is already off.
        if hits:
            if sender.joined_seconds_ago is not None and sender.joined_seconds_ago < self.new_member_window:
                mins = int(sender.joined_seconds_ago // 60)
                hits.append((0.15, "", f"sender joined only {mins} min ago" if mins < 120
                             else "sender is a new member"))
            if sender.prior_messages == 0 and urls:
                hits.append((0.1, "", "first message in the group and it carries a link"))
            if is_forward and urls:
                hits.append((0.1, "", "forwarded message carrying a link"))

        if not hits:
            return Verdict(0.0, "clean", [], urls)

        # Warnings like "never share your seed phrase" use the same words as scams.
        # Without a link or a handle to send people to, treat them as safety advice.
        if PROTECTIVE_RE.search(norm) and not urls and not TG_HANDLE_RE.search(norm):
            hits = [(w * 0.3, c, r) for w, c, r in hits]

        score = min(1.0, sum(w for w, _, _ in hits))
        by_cat: dict[str, float] = {}
        for w, c, _ in hits:
            if c:
                by_cat[c] = by_cat.get(c, 0.0) + w
        category = max(by_cat, key=by_cat.get) if by_cat else "suspicious"
        reasons: list[str] = []
        for _, _, r in sorted(hits, key=lambda h: -h[0]):
            if r not in reasons:
                reasons.append(r)
        return Verdict(score, category, reasons, urls)
