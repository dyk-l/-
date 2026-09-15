"""文本归一化：NFKC、全角转半角、去空白与特殊符号，供 PII 检测使用。"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter

_LATIN_ALNUM_RE = re.compile(r"[0-9A-Za-z]+")


def fullwidth_to_halfwidth(text: str) -> str:
    chars: list[str] = []
    for char in text:
        code = ord(char)
        if code == 0x3000:
            chars.append(" ")
        elif 0xFF01 <= code <= 0xFF5E:
            chars.append(chr(code - 0xFEE0))
        else:
            chars.append(char)
    return "".join(chars)


def nfkc(text: str) -> str:
    return unicodedata.normalize("NFKC", text or "")


def is_ignored_separator(char: str) -> bool:
    category = unicodedata.category(char)
    return category[0] in {"C", "P", "S", "Z"}


def normalize_for_match(text: str) -> str:
    """去空白、去特殊符号后的紧凑串，用于词表匹配。"""
    folded = fullwidth_to_halfwidth(nfkc(text)).casefold()
    return "".join(char for char in folded if not is_ignored_separator(char))


def longest_digit_run(text: str, *, min_len: int = 11) -> str:
    """忽略空白/标点/符号后，返回最长连续数字串；不足 min_len 则空。"""
    folded = fullwidth_to_halfwidth(nfkc(text))
    run: list[str] = []
    best = ""
    for char in folded:
        if char.isdigit():
            run.append(char)
            if len(run) > len(best):
                best = "".join(run)
            continue
        if is_ignored_separator(char):
            continue
        run = []
    return best if len(best) >= min_len else ""


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def high_entropy_tokens(text: str, *, min_len: int = 20, min_bits: float = 3.8) -> list[str]:
    """宽泛熵：归一化后的拉丁字母数字长串，熵高则视为编码/哈希载荷。"""
    folded = fullwidth_to_halfwidth(nfkc(text))
    compact = "".join(char if char.isalnum() and char.isascii() else " " for char in folded)
    hits: list[str] = []
    for token in _LATIN_ALNUM_RE.findall(compact):
        if len(token) >= min_len and shannon_entropy(token) >= min_bits:
            hits.append(token)
    return hits
