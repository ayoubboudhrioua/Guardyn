"""Canonical closure: every way a string could be hiding inside another string.

Injections and exfiltrated secrets do not have to appear verbatim. We expand every
observation and every action payload into the set of decodings an attacker could
plausibly use, then compare in a normalised space. This is what lets the same
matcher catch a plain-text instruction and a base64 one without a special case.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import math
import re
from urllib.parse import unquote

_NON_ALNUM = re.compile(r"[^a-z0-9]")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
MAX_SCAN = 200_000


def squash(text: str) -> str:
    """Whitespace-insensitive lowercase form."""
    return " ".join(text.split()).lower()


def normalize(text: str) -> str:
    """Strip everything that is not a letter or digit. Defeats spacing tricks."""
    return _NON_ALNUM.sub("", text.lower())


def _b64(text: str) -> str:
    out = []
    for tok in _B64.findall(text):
        try:
            out.append(base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True).decode("utf-8", "ignore"))
        except (binascii.Error, ValueError):
            continue
    return "\n".join(out)


def _hex(text: str) -> str:
    out = []
    for tok in _HEX.findall(text):
        try:
            out.append(bytes.fromhex(tok).decode("utf-8", "ignore"))
        except ValueError:
            continue
    return "\n".join(out)


def variants(text: str) -> list[tuple[str, str]]:
    """(encoding-name, decoded-text) for every transform we understand."""
    text = text[:MAX_SCAN]
    return [
        ("plain", text),
        ("url", unquote(text)),
        ("base64", _b64(text)),
        ("hex", _hex(text)),
        ("rot13", codecs.decode(text, "rot13")),
        ("reversed", text[::-1]),
    ]


def closure(text: str) -> str:
    """All decodings concatenated. Search this, not the raw text."""
    return "\n".join(v for _, v in variants(text) if v)


_COMMON = {
    "the", "and", "with", "then", "call", "this", "that", "for", "you", "your", "from",
    "please", "send", "has", "was", "are", "not", "our", "all", "use", "will", "have",
}


def encodings_present(text: str) -> list[str]:
    """Which non-plain decodings produced text that is genuinely different and readable.

    Guards against rot13/reversal reporting themselves on ordinary prose.
    """
    plain = normalize(text)
    found = []
    for name, decoded in variants(text):
        if name == "plain" or not decoded.strip():
            continue
        if normalize(decoded) == plain:
            continue
        words = {w for w in re.findall(r"[a-z]{2,}", decoded.lower())}
        if len(words & _COMMON) >= 2:
            found.append(name)
    return found


def entropy(token: str) -> float:
    if not token:
        return 0.0
    counts = {c: token.count(c) for c in set(token)}
    n = len(token)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def opaque_tokens(text: str, min_len: int = 14, min_entropy: float = 3.2) -> list[str]:
    """High-entropy blobs: credential-shaped material regardless of what it is."""
    out = []
    for tok in re.findall(r"[A-Za-z0-9_+/=-]{%d,}" % min_len, text):
        if entropy(tok) >= min_entropy and any(c.isdigit() for c in tok):
            out.append(tok)
    return out
