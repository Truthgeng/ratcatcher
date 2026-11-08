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

# Phones and Macs type curly quotes and fancy dashes; fold them to plain ones.
_PUNCT = str.maketrans({"\u2018": "'", "\u2019": "'", "\u02bc": "'", "\u2032": "'", "`": "'", "\u00b4": "'",
                        "\u201c": '"', "\u201d": '"', "\u2013": "-", "\u2014": "-", "\u2212": "-",
                        "\u00a0": " ", "\u2009": " ", "\u202f": " "})

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
    text = unicodedata.normalize("NFKC", text or "").translate(_ZERO_WIDTH).translate(_PUNCT)
    return text.lower().translate(_HOMOGLYPHS)


def _deleet(text: str) -> str:
    return text.translate(_LEET)


# ---------------------------------------------------------------------------
# Rule tables
# ---------------------------------------------------------------------------

# (pattern, weight, category, reason). Weights add up; the score is capped at 1.0.
#
# How weights are set:
#   0.90  near-certain on its own (asks for a seed phrase, "send 1 get 2 back"). Counts for ban on sight.
#   0.40-0.60  strong signal, needs one more thing to be removed.
#   0.10-0.35  weak on its own. Everyday words live here, so one of them never removes a message.
PHRASE_RULES: list[tuple[str, float, str, str]] = [
    # ---- Seed phrase and private key phishing --------------------------------------------------
    (r"\b(enter|type|submit|share|send|input|paste|provide|import|drop|fill( in)?|give( me)?|write)\b.{0,35}"
     r"(\b(seed|recovery|secret|mnemonic|backup|pass|wallet) ?(phrase|words?|keys?)\b|\b(12|24|twelve|twenty[- ]four)"
     r"[- ]?words?\b|\b(your|ur|the) phrase\b)",
     0.90, "drainer", "asks people to enter or share their seed phrase"),
    (r"\b(send|share|give|enter|paste|provide|drop)\b.{0,25}\b(private ?keys?|keystore|key ?file|json file)\b",
     0.90, "drainer", "asks people to share a private key or keystore"),
    (r"\b(seed|recovery|secret|mnemonic) (phrase|words?)\b|\b(12|24)[- ]?words?\b", 0.25, "drainer",
     "mentions a seed or recovery phrase"),
    (r"\bprivate ?keys?\b", 0.30, "drainer", "mentions a private key"),
    (r"\bimport (your )?wallet\b|\bmanual(ly)? (connect|import)\b", 0.40, "drainer",
     "asks people to import their wallet somewhere"),

    # ---- Wallet drainers dressed up as fixes --------------------------------------------------
    (r"\b(validate|sync|synchroni[sz]e|rectify|restore|unlock|migrate|verify|reactivate|recti?fy|unfreeze|"
     r"whitelist|revalidate|upgrade|initiali[sz]e|authenticate|debug)\b.{0,25}\b(your )?(wallets?|dapps?|tokens?|"
     r"assets?|funds|address(es)?|account)\b", 0.45, "drainer",
     "asks people to 'validate' or 'sync' their wallet, a common drainer line"),
    (r"\bconnect (your |ur )?wallets?\b|\bwallet ?connect\b", 0.30, "drainer", "tells people to connect their wallet"),
    (r"\b(decentrali[sz]ed|dapp|defi) (platform|protocol|site|website|tool|portal|node)\b.{0,40}"
     r"\b(fix|resolve|rectify|solve|sync|validate|claim)\b", 0.50, "drainer",
     "points to a 'decentralized platform' to fix a problem"),
    (r"\b(gas|fee|tax) (refund|rebate|reimbursement)s?\b|\bclaim (your )?(gas|refund|compensation)\b", 0.45,
     "drainer", "offers a fake gas refund or compensation claim"),
    (r"\b(revoke|approve|sign) (the |this )?(transaction|contract|approval|permit)\b.{0,30}\b(to (get|receive|claim|"
     r"unlock|fix)|now|here)\b", 0.40, "drainer", "pushes people to sign or approve a transaction"),
    (r"\b(compromised|hacked|flagged|suspended|blacklisted|frozen|restricted)\b.{0,25}\b(wallets?|accounts?|address)"
     r"\b|\b(wallets?|accounts?)\b.{0,15}\b(compromised|flagged|suspended|blacklisted|frozen|restricted)\b", 0.30,
     "drainer", "scares people that their wallet is compromised or frozen"),
    (r"\b(rpc|node) (error|issue|sync|failure)\b|\bwrong (rpc|node|network)\b", 0.25, "drainer",
     "uses fake RPC or node errors as a hook"),

    # ---- Fake airdrops, presales, mints and giveaways -----------------------------------------
    (r"\b(airdrop|giveaway|reward|allocation|whitelist|presale|pre-sale|mint|tge|retro ?drop|refund|"
     r"distribution|bonus|drop)s?\b.{0,40}\b(is |are )?(live|claimable|now open|open now|started|ends?|ending|"
     r"eligible|unclaimed|ready|available)\b", 0.35, "fake_airdrop", "pushes an airdrop or reward claim"),
    (r"\bclaim (your|now|here|free|it|them|today|before|fast|immediately)\b|\bclaim (page|portal|link|site)\b",
     0.30, "fake_airdrop", "urges people to claim something"),
    (r"\b(check|confirm|verify) (your |if you are |if your wallet is )?(eligib|allocation|airdrop|snapshot)", 0.35,
     "fake_airdrop", "sends people to check 'eligibility'"),
    (r"\bfree (mints?|tokens?|nfts?|crypto|usdt|eth|sol|btc|bnb|money|airdrops?|claims?|giveaways?)\b", 0.35, "fake_airdrop",
     "offers free crypto"),
    (r"\b(stealth|fair) launch\b.{0,40}\b(now|live|link|join|buy)\b|\b(presale|pre-sale) (link|is live|now)\b",
     0.25, "fake_airdrop", "shills a sudden launch or presale link"),
    (r"\b(first|only|next) \d+ (users|people|wallets|members|participants|persons)\b|\blimited (slots|spots|"
     r"supply|time|offer)\b", 0.20, "fake_airdrop", "creates false urgency with limited slots"),
    (r"\b(winners?|you (have )?(been )?selected|congratulations?|congrats)\b.{0,40}\b(claim|reward|prize|won|win|"
     r"airdrop|giveaway|usdt|eth)\b", 0.35, "fake_airdrop", "tells people they won something"),

    # ---- Urgency (only adds weight, never removes on its own) ---------------------------------
    (r"\b(hurry|act fast|act now|last chance|don'?t miss|before it'?s too late|ends? (in|soon|today|tonight)|"
     r"expires? (in|soon|today)|only \d+ (hours?|hrs?|minutes?|mins?) left|asap|(claim|buy|join|grab) (it )?fast)\b", 0.15, "",
     "pushes people to act fast"),

    # ---- Fake support and DM bait --------------------------------------------------------------
    (r"\b(dm|inbox|pm|message|text|contact|write( to)?|reach( out to)?|chat( with)?)\s+(me|us|admin|support|"
     r"the admin|an admin|the team|customer care)\b", 0.35, "fake_support",
     "pulls people into DMs, real admins never ask first"),
    (r"\b(support|help ?desk|customer (care|service)|technical team|tech team|live (chat|agent))\b.{0,30}"
     r"\b(dm|inbox|contact|bot|link|ticket|whatsapp|telegram|form)\b", 0.35, "fake_support",
     "pretends to be a support desk"),
    (r"\b(open|create|submit|raise|file) a (support |help )?(ticket|request|complaint)\b", 0.30, "fake_support",
     "asks people to open a 'ticket' outside the group"),
    (r"\b(i'?m|i am|we'?re|we are|this is|am)\s+(from\s+)?(the\s+|an?\s+|your\s+)?(official\s+)?(support|admin|"
     r"administrator|moderator|mod|help ?desk|customer care|team|dev(eloper)? team|developer|technical team|"
     r"community manager)\b|\b(one of the|part of the|from the) (devs?|developers|team|admins?|mods?|"
     r"moderators|support( team)?|core team)\b", 0.40, "fake_support",
     "claims to be support or staff without being an admin"),
    (r"\b(issues?|problems?|trouble|stuck|errors?|difficult(y|ies)|delayed|pending|missing|complaints?)\b.{0,30}"
     r"\b(wallet|transaction|withdrawals?|deposits?|funds|tokens|account|claim|bridge|swap|staking)\b|"
     r"\b(wallet|transaction|withdrawal|deposit|funds|tokens|claim|bridge|swap)s?\b.{0,12}"
     r"\b(stuck|pending|delayed|missing|failed|issues?|problems?|errors?|not (showing|working|syncing|reflecting))\b",
     0.20,
     "fake_support", "fishes for people with wallet or transaction problems"),
    (r"\b(dm|inbox|pm|message|text|contact|reach out to)\b.{0,15}\b(me|us)\b.{0,25}\b(help|fix|resolve|"
     r"assist|solution|sort|guide)\b|\bi can (help|assist|fix|guide)\b.{0,25}\b(dm|inbox|pm|message)\b",
     0.25, "fake_support", "offers private help in DMs"),
    (r"\b(drop|send|tell|share|explain) (me )?(your |ur )?(issue|complaint|problem|request|challenge)s?\b|"
     r"\bcheck (your |ur )?(dm|inbox|pm)s?\b", 0.30, "fake_support", "asks people to send problems to a private chat"),
    (r"\b(whatsapp|wa\.me|signal)\b.{0,20}\+?\d[\d\s-]{7,}", 0.40, "fake_support",
     "moves people to a WhatsApp or Signal number"),

    # ---- Fake recovery experts (a scam aimed at people already scammed) -------------------------
    (r"\b(recover|retrieve|get back|restore|trace)\b.{0,25}\b(lost|stolen|scammed|hacked|missing)\b.{0,20}"
     r"\b(funds|crypto|coins|money|btc|eth|usdt|assets|wallet)\b", 0.55, "investment_scam",
     "offers to recover lost or stolen crypto, a common follow-up scam"),
    (r"\b(recovery|hack(er)?|ethical hacker|blockchain) (expert|specialist|agent|company|team|service)\b|"
     r"\b(hacker|expert)\b.{0,25}\b(helped me|recovered|got (my|back))\b", 0.90, "investment_scam",
     "advertises a 'recovery expert' or hacker"),

    # ---- Investment, doubling and signal scams ------------------------------------------------
    (r"\b(doubl(e|es|ing)|tripl(e|es|ing)|multiply|2x|3x|5x|10x) (your|ur|ya)\b|\bsend\b.{0,80}\b(get|receive)\b"
     r".{0,20}\bback\b|\bsend \d+(\.\d+)?\s?\w+ (and |to )?(get|receive) \d+", 0.90, "investment_scam",
     "promises to multiply money sent"),
    (r"\bguaranteed\b.{0,15}\b(profits?|returns?|income|roi|earnings|gains?|payouts?)\b|\b(risk[- ]free|no risk)\b"
     r".{0,20}\b(profits?|returns?|income|trading|investment)\b|\b(daily|weekly|monthly) (profit|returns?|roi|"
     r"income) of\b", 0.45, "investment_scam", "promises guaranteed or risk-free profit"),
    (r"\b(earn|make|making|made|get)\b.{0,10}\$?\d[\d,.]*\s?(k|usd|usdt|dollars|\$)?.{0,15}\b(daily|weekly|"
     r"per (day|week|hour)|a day|a week|every (day|week)|in \d+ (hours|days))\b", 0.35, "investment_scam",
     "promises fixed earnings per day or week"),
    (r"\b(account|investment|trading|forex|portfolio|crypto|fund) (manager|expert|mentor|coach)\b|\b(mrs?|ms|miss|"
     r"sir|madam)\.? \w+ (helped|changed|made|has been)\b|\bi (made|earned|got)\b.{0,10}\$?\d[\d,]*k?.{0,15}\b(with|"
     r"from|using|thanks to)\b", 0.35, "investment_scam", "classic 'account manager' or testimonial bait"),
    (r"\b(cloud|bitcoin|btc) mining\b|\bmining (pool|contract|plan|investment)\b|\b(binary options?|forex trading "
     r"platform|investment (plan|platform|package)s?)\b", 0.30, "investment_scam",
     "mining or investment-plan pitch"),
    (r"\b(vip|premium|paid|private)\s+(signals?|group|channel|calls?)\b|\b(pump|insider) (group|signals?|calls?)\b|"
     r"\b100x (gem|coin|token)\b", 0.35, "investment_scam", "sells VIP signals or pump groups"),
    (r"\b(giving away|give ?away of|distributing)\b.{0,10}\$?\d[\d,.]*\s?k?\s?(btc|eth|usdt|sol|bnb|usd|dollars|"
     r"coins|tokens)\b", 0.35, "investment_scam", "announces a huge crypto giveaway"),
    (r"\b(elon|musk|cz|saylor|vitalik|binance|coinbase|tesla)\b.{0,40}\b(giveaway|is giving|celebrat|doubl|"
     r"send)\b", 0.50, "investment_scam", "fake celebrity or exchange giveaway"),

    # ---- Job, task and earn-money spam ---------------------------------------------------------
    (r"\b(work from home|part[- ]time (job|work)|remote (job|work)|online (job|task)s?|hiring now|we are "
     r"hiring)\b.{0,50}\b(earn|pay|paid|\$|usdt|daily|per day)\b", 0.40, "investment_scam",
     "offers a too-good job or paid tasks"),
    (r"\b(like|follow|review|rate|watch)\b.{0,20}\b(videos?|posts?|products?|apps?)\b.{0,20}\b(and |to )?(get "
     r"paid|earn|make money)\b", 0.40, "investment_scam", "classic paid-tasks scam"),

    # ---- Promo spam and channel bait -----------------------------------------------------------
    (r"\b(check|see|visit|look at) (my |the )?(bio|profile|pinned|channel)\b|\blink in (my )?bio\b", 0.35,
     "phishing_link", "sends people to a link in a profile or bio"),
    (r"\bjoin (my|our|this) (channel|group|vip|community)\b|\bt\.me/(\+|joinchat/)", 0.30, "phishing_link",
     "pushes an outside Telegram group or private invite"),
    (r"\b(trending|volume bot|cmc|coingecko|dexscreener) (service|listing|boost|promotion)s?\b|\b(promote|boost|"
     r"pump) your (project|token|coin)\b|\bshill(ing)? service\b", 0.30, "phishing_link",
     "promotion or 'trending' service spam"),

    # ---- Added after testing on fresh scams ---------------------------------------------------
    (r"\b(not|isn'?t|is not|un)[- ]?(verified|synced|synchroni[sz]ed|validated|activated|whitelisted|authenticated)\b",
     0.30, "drainer", "claims your wallet or account is 'not verified' to push a fix"),
    (r"\bor (you )?(will )?(lose|forfeit|miss)\b.{0,20}\b(them|it|tokens?|funds|assets|allocation|rewards?)\b|"
     r"\bwill (lose|forfeit) (their|your|all)\b|\b(lose|lost) (your|ur) (bag|tokens|funds|allocation)\b", 0.25, "drainer", "threatens that you will lose your tokens"),
    (r"\b(fill|submit|complete) (the|this|a|our) (form|google form|survey)\b.{0,40}\b(wallet|address|details|"
     r"phrase|keys?)\b|\b(wallet|account|card|bank|login) (details|info|information|credentials)\b", 0.40,
     "drainer", "asks for wallet or account details in a form"),
    (r"\b(dm|message|contact|text|reach|write to|ping|chat)\s+@\w{4,}", 0.30, "fake_support",
     "points people to a private handle for help"),
    (r"\b(contact|text|message|reach|dm|whatsapp)\s+(him|her|them)\b", 0.30, "investment_scam",
     "refers people to a third person to contact"),
    (r"\b(with|via|through|thanks to)\s+(mrs?|ms|miss|sir|madam|dr|prof)\.?\s+[a-z]+\b", 0.30, "investment_scam",
     "credits a named 'mentor' for profits, testimonial bait"),
    (r"\binvested\b.{0,15}\$?\d[\d,.]*\s?k?\b.{0,30}\b(got|made|earned|received|returned|now have)\b.{0,10}"
     r"\$?\d", 0.40, "investment_scam", "testimonial about turning a small amount into a big one"),
    (r"\b(register|sign up|signup|create an account) (on|at|with) (our|my|this) (platform|site|website|app|"
     r"exchange)\b", 0.30, "investment_scam", "pushes sign-up on an outside platform"),
    (r"\b\d+\s?(usdt|usd|\$|eth|sol|bnb|trx)\s+(free|bonus|reward)\b|\bfree (bonus|signup bonus|welcome bonus)\b",
     0.35, "fake_airdrop", "offers a free crypto bonus"),

    (r"\b(exclusive|private|early) (whitelist|presale|pre-sale|access|allocation|round)\b|\bonly \d+ "
     r"(spots?|slots?|places?|seats?)? ?(left|remaining)\b", 0.25, "fake_airdrop", "exclusive spots with a countdown"),
    (r"\b(recovered|got back|retrieved|restored)\b.{0,10}\b(my|all my|his|her)\b.{0,10}\b(usdt|btc|eth|funds|"
     r"crypto|money|coins|wallet|assets)\b|\b(i know|i found) (a guy|someone|a hacker|an expert)\b", 0.50,
     "investment_scam", "recovery testimonial pointing to 'a guy'"),
    (r"\bmy (mentor|coach|manager|broker|trader|account manager)\b|\bno experience (needed|required)\b", 0.25,
     "investment_scam", "mentor or no-experience-needed money pitch"),
    (r"\b(migration|swap|upgrade|migrate|transition) (to v\d|is mandatory|is required|is compulsory)\b|"
     r"\b(mandatory|compulsory) (migration|swap|upgrade|claim)\b", 0.35, "drainer",
     "says a token migration or swap is mandatory"),
    (r"\b(profits?|returns?|roi|income)\b.{0,15}\bguaranteed\b|\b\d+(\.\d+)?\s?% (daily|weekly|monthly|"
     r"per (day|week|month)|a day|every day)\b", 0.40, "investment_scam", "promises a fixed percentage return"),
    (r"\bfree \$?\d[\d,.]*\s?k?\s?\$?\w+\b", 0.30, "fake_airdrop", "offers free tokens"),
    (r"\bwallets? (that|who) (connect|claim|register|join)\b|\bwho (connect|link)s? (their )?wallets?\b", 0.30,
     "drainer", "rewards people for connecting their wallet"),
    (r"\b(dapp|site|portal|link|website|platform|page)\b.{0,10}\bto (resolve|fix|rectify|sync|validate|claim|"
     r"unlock|recover|restore)\b", 0.35, "drainer", "sends people to a site to 'fix' or 'claim'"),
    # ---- Impersonation wording -----------------------------------------------------------------
    (r"\b(official|urgent|important) (announcement|notice|update|message)\b.{0,60}\b(claim|connect|verify|"
     r"validate|migrate|click|link|dm)\b", 0.35, "impersonation", "fake 'official announcement' with an action"),
    (r"\b(admin|team|mod(erator)?s?) (here|speaking)\b|\bmessage from the (team|admins?|devs?)\b", 0.35,
     "impersonation", "speaks as the team or admins"),
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

PROTECTIVE_RE = re.compile(r"\b(never|don'?t|do not|beware|watch out|be careful|stay safe|warning|report|ignore)\b"
                           r".{0,40}\b(share|send|give|click|trust|dm|scam\w*|fake|phrase|key|them|it)\b|"
                           r"\b(is|are|it'?s) (a |all )?scams?\b|\bscammers? (will|would|may|might|always|often)\b|"
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
class CloneMatch:
    strength: str          # "strong" (ban) or "weak" (mute and report)
    admin: Admin
    reason: str


STAFF_TOKENS = {"admin", "admins", "administrator", "support", "supports", "mod", "mods", "moderator", "official",
                "team", "ceo", "founder", "cofounder", "dev", "devs", "help", "helpdesk", "owner", "care", "real",
                "the", "official1", "staff", "manager", "cm", "service", "desk", "bot"}


def _is_staffed_copy(mine: str, theirs: str) -> bool:
    """mine is theirs plus only staff words, digits or one or two stray letters ("truthadmin", "truth_1", "truthx")."""
    if not theirs or len(theirs) < 4 or theirs not in mine or mine == theirs:
        return False
    rest = mine.replace(theirs, "", 1)
    if rest.isdigit():
        return True
    for _ in range(3):  # peel up to three staff words
        for w in sorted(STAFF_TOKENS, key=len, reverse=True):
            if rest.startswith(w):
                rest = rest[len(w):]
                break
            if rest.endswith(w):
                rest = rest[: -len(w)]
                break
        else:
            break
        if not rest or rest.isdigit():
            return True
    return False


def _core(tok: str) -> str:
    """Strip staff words from both ends: "signngmod" -> "signng", "officialtruthteam" -> "truth"."""
    for _ in range(4):
        before = tok
        for w in sorted(STAFF_TOKENS, key=len, reverse=True):
            if len(tok) - len(w) >= 4:
                if tok.endswith(w):
                    tok = tok[: -len(w)]
                    break
                if tok.startswith(w):
                    tok = tok[len(w):]
                    break
        tok = tok.rstrip("0123456789") if len(tok.rstrip("0123456789")) >= 4 else tok
        if tok == before:
            break
    return tok


@dataclass
class Verdict:
    score: float
    category: str
    reasons: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    certain: bool = False   # at least one near-certain signal: eligible for ban on sight

    @property
    def label(self) -> str:
        return CATEGORY_LABELS.get(self.category, "suspicious message")

    def as_dict(self) -> dict:
        return {"score": round(self.score, 2), "category": self.category, "label": self.label,
                "reasons": self.reasons, "urls": self.urls, "certain": self.certain}


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

    def clone_check(self, sender: Sender, admins: Iterable[Admin]) -> Optional[CloneMatch]:
        """Is this account dressed up as one of the group's admins or its owner?

        strong: an exact copy of the admin's full name, the name plus a staff word ("Truth Admin",
                "Truth | Support"), or a copied name together with a look-alike username. Banned at once.
        weak:   the name is close but a real member could share it ("Truth" vs "Truth Okafor" is not
                even weak; "Truthh" with an unrelated username is). Muted and reported to admins.
        """
        if sender.is_admin:
            return None
        my_name = _name_tokens(sender.full_name)
        my_user = _name_tokens(sender.username)
        best: Optional[CloneMatch] = None
        for adm in admins:
            if adm.user_id == sender.user_id:
                continue
            their_name = _name_tokens(adm.full_name)
            their_user = _name_tokens(adm.username)
            who = adm.full_name or ("@" + adm.username)

            name_exact = bool(their_name) and my_name == their_name
            name_staffed = bool(their_name) and _is_staffed_copy(my_name, their_name)
            name_close = bool(their_name) and len(their_name) >= 4 and (
                _similar(my_name, their_name) >= 0.85 or name_staffed
                or (len(_core(their_name)) >= 5 and _core(my_name) == _core(their_name)))
            # The display name copies the admin's username, e.g. name "heistruthx".
            name_is_their_user = bool(their_user) and len(their_user) >= 5 and (
                my_name == their_user or _is_staffed_copy(my_name, their_user))
            user_close = bool(their_user) and bool(my_user) and len(their_user) >= 4 and (
                _similar(my_user, their_user) >= 0.85 or _is_staffed_copy(my_user, their_user)
                or (len(_core(their_user)) >= 4 and _core(my_user) == _core(their_user)))
            user_has_name = bool(my_user) and len(their_name) >= 5 and _is_staffed_copy(my_user, their_name)
            distinctive = len(their_name) >= 6 or len((adm.full_name or "").split()) >= 2

            strength = ""
            if name_staffed and not name_exact:
                strength = "strong"
                reason = f"copies the admin {who}'s name and adds a staff title"
            elif (name_exact or name_close or name_is_their_user) and (user_close or user_has_name):
                strength = "strong"
                reason = f"copies both the name and the username of the admin {who}"
            elif name_exact and distinctive:
                strength = "strong"
                reason = f"uses the exact name of the admin {who}"
            elif name_is_their_user:
                strength = "strong"
                reason = f"uses the admin {who}'s username as its display name"
            elif name_exact or name_close or user_close:
                strength = "weak"
                reason = f"name looks like the admin {who} but is a different account"
            if strength and (best is None or (strength == "strong" and best.strength != "strong")):
                best = CloneMatch(strength, adm, reason)
                if strength == "strong":
                    break
        return best

    def _check_impersonation(self, sender: Sender, admins: Iterable[Admin]) -> list[tuple[float, str, str]]:
        hits: list[tuple[float, str, str]] = []
        if sender.is_admin:
            return hits
        clone = self.clone_check(sender, admins)
        if clone:
            hits.append((1.0 if clone.strength == "strong" else 0.7, "impersonation", clone.reason))
            return hits
        if IMPERSONATION_WORDS.search(normalise((sender.full_name or "") + " " + (sender.username or ""))):
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

        # Several independent scam signals in one message is itself a strong sign.
        strong = {r for w, c, r in hits if c and w >= 0.3}
        flagged = {r for w, c, r in hits if c and w >= 0.2}
        if len(strong) >= 2 or len(flagged) >= 3:
            hits.append((0.15, "", "several scam signals appear together"))

        score = round(min(1.0, sum(w for w, _, _ in hits)), 3)
        by_cat: dict[str, float] = {}
        for w, c, _ in hits:
            if c:
                by_cat[c] = by_cat.get(c, 0.0) + w
        category = max(by_cat, key=by_cat.get) if by_cat else "suspicious"
        reasons: list[str] = []
        for _, _, r in sorted(hits, key=lambda h: -h[0]):
            if r not in reasons:
                reasons.append(r)
        certain = any(w >= 0.9 for w, _, _ in hits)
        return Verdict(score, category, reasons, urls, certain)
