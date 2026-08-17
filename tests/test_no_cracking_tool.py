"""Guardrail: the repository ships no wordlist, no general-purpose brute-force tool, and no
PRNG state-recovery code. The one enumeration is a fixed, bounded structural window."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

# Names that would indicate a shipped wordlist or dictionary.
WORDLIST_MARKERS = ("wordlist", "rockyou", "passwords.txt", ".dict")

# Tokens that would indicate cracking or PRNG state recovery, matched in attacker source.
BANNED_TOKENS = (
    "getrandbits",
    "setstate",
    "getstate",
    "mersenne",
    "untwister",
    "itertools.product",
    "itertools.permutations",
    "hashcat",
    "rockyou",
)


def test_no_wordlist_files_are_shipped() -> None:
    for path in ROOT.rglob("*"):
        if path.is_file() and ".git" not in path.parts:
            lowered = path.name.lower()
            assert not any(marker in lowered for marker in WORDLIST_MARKERS), path


def test_attacker_uses_no_cracking_or_prng_recovery() -> None:
    for path in (SRC / "keyjack" / "attacker").rglob("*.py"):
        text = path.read_text().lower()
        for token in BANNED_TOKENS:
            assert token not in text, f"{path} contains banned token {token!r}"


def test_enumeration_is_a_fixed_bounded_window() -> None:
    cli = (SRC / "keyjack" / "attacker" / "cli.py").read_text()
    # The window is a fixed <=1000-candidate range derived structurally, not a search tool.
    assert "bound: int = 1000" in cli
    assert "range(bound)" in cli
