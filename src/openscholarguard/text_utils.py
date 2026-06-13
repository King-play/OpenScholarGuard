"""Shared text normalization helpers."""

from __future__ import annotations

import re
import unicodedata

ZERO_WIDTH_CODEPOINTS = {
    "\u200b",
    "\u200c",
    "\u200d",
    "\u2060",
    "\ufeff",
}

BIDI_CONTROL_CODEPOINTS = {
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}

ALLOWED_CONTROL_CHARS = {"\n", "\r", "\t"}


def compact_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def snippet(text: str, *, limit: int = 220) -> str:
    clean = compact_whitespace(text)
    if len(clean) <= limit:
        return clean
    return f"{clean[: limit - 3]}..."


def strip_invisible_controls(text: str) -> str:
    return "".join(
        char
        for char in text
        if char not in ZERO_WIDTH_CODEPOINTS
        and char not in BIDI_CONTROL_CODEPOINTS
        and (unicodedata.category(char)[0] != "C" or char in ALLOWED_CONTROL_CHARS)
    )


def find_invisible_controls(text: str) -> list[tuple[int, str, str]]:
    matches: list[tuple[int, str, str]] = []
    for index, char in enumerate(text):
        category = unicodedata.category(char)
        if (
            char in ZERO_WIDTH_CODEPOINTS
            or char in BIDI_CONTROL_CODEPOINTS
            or (category[0] == "C" and char not in ALLOWED_CONTROL_CHARS)
        ):
            name = unicodedata.name(char, f"U+{ord(char):04X}")
            matches.append((index, char, name))
    return matches


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for char in text if char.isprintable() or char in ALLOWED_CONTROL_CHARS)
    return printable / len(text)
