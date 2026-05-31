"""
Password Security Analyzer — core analysis engine.

Evaluates password strength using length, character diversity, pattern checks,
and comparisons against known weak passwords and patterns.
"""

from __future__ import annotations

import re
import string
from pathlib import Path
from typing import NamedTuple


# Weak substrings often found in compromised or predictable passwords.
WEAK_PATTERNS: tuple[str, ...] = (
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "password",
    "passw0rd",
    "qwerty",
    "qwertyuiop",
    "abc123",
    "letmein",
    "welcome",
    "admin",
    "iloveyou",
    "monkey",
    "dragon",
    "master",
    "sunshine",
    "princess",
    "football",
    "shadow",
    "baseball",
    "trustno1",
)

# Minimum length recommended by NIST-aligned guidance for user-chosen passwords.
MIN_RECOMMENDED_LENGTH = 12

# Path to the bundled common-password list (one password per line).
COMMON_PASSWORDS_FILE = Path(__file__).resolve().parent / "common_passwords.txt"


class PasswordAnalysis(NamedTuple):
    """Structured result of a full password analysis."""

    password_length: int
    has_uppercase: bool
    has_lowercase: bool
    has_numbers: bool
    has_special: bool
    has_repeated_chars: bool
    is_common_password: bool
    weak_patterns_found: list[str]
    score: int
    classification: str
    recommendations: list[str]


def _load_common_passwords() -> set[str]:
    """Load lowercase common passwords from the data file."""
    if not COMMON_PASSWORDS_FILE.is_file():
        return set()

    with COMMON_PASSWORDS_FILE.open(encoding="utf-8") as handle:
        return {line.strip().lower() for line in handle if line.strip()}


# Loaded once at import time to avoid re-reading the file on every analysis.
_COMMON_PASSWORDS: set[str] = _load_common_passwords()


def check_length(password: str) -> int:
    """Return the password length."""
    return len(password)


def check_uppercase(password: str) -> bool:
    """Return True if the password contains at least one uppercase letter."""
    return any(char in string.ascii_uppercase for char in password)


def check_lowercase(password: str) -> bool:
    """Return True if the password contains at least one lowercase letter."""
    return any(char in string.ascii_lowercase for char in password)


def check_numbers(password: str) -> bool:
    """Return True if the password contains at least one digit."""
    return any(char.isdigit() for char in password)


def check_special_characters(password: str) -> bool:
    """Return True if the password contains at least one special character."""
    special = set(string.punctuation)
    return any(char in special for char in password)


def detect_repeated_characters(password: str) -> bool:
    """
    Return True if the password has consecutive repeated characters
    (e.g. 'aaa' or '111') or three or more of the same character overall.
    """
    if re.search(r"(.)\1{2,}", password):
        return True

    for char in set(password):
        if password.count(char) >= 3:
            return True

    return False


def detect_common_password(password: str, common_list: set[str] | None = None) -> bool:
    """Return True if the password matches an entry in the common-password list."""
    candidates = common_list if common_list is not None else _COMMON_PASSWORDS
    return password.lower() in candidates


def detect_weak_patterns(password: str) -> list[str]:
    """Return weak substrings found in the password (case-insensitive)."""
    lowered = password.lower()
    return [pattern for pattern in WEAK_PATTERNS if pattern in lowered]


def classify_score(score: int) -> str:
    """Map a numeric score (0–100) to a strength label."""
    if score < 20:
        return "Very Weak"
    if score < 40:
        return "Weak"
    if score < 60:
        return "Medium"
    if score < 80:
        return "Strong"
    return "Very Strong"


def calculate_security_score(
    password: str,
    *,
    length: int,
    has_upper: bool,
    has_lower: bool,
    has_digit: bool,
    has_special: bool,
    repeated: bool,
    common: bool,
    weak_patterns: list[str],
) -> int:
    """
    Compute a security score from 0 to 100.

    Points are awarded for length and character diversity; points are deducted
    for repeated characters, dictionary passwords, and known weak patterns.
    """
    if not password:
        return 0

    score = 0

    # Length contributes up to 30 points.
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 24
    elif length >= 10:
        score += 18
    elif length >= 8:
        score += 12
    elif length >= 6:
        score += 6
    else:
        score += max(0, length)

    # Character classes contribute up to 40 points (10 each).
    score += 10 if has_upper else 0
    score += 10 if has_lower else 0
    score += 10 if has_digit else 0
    score += 10 if has_special else 0

    # Bonus for using four character types together.
    variety_count = sum([has_upper, has_lower, has_digit, has_special])
    if variety_count == 4:
        score += 10

    # Entropy proxy: reward longer unique character sets.
    unique_ratio = len(set(password)) / length if length else 0
    if unique_ratio >= 0.8 and length >= 10:
        score += 10
    elif unique_ratio >= 0.6:
        score += 5

    # Penalties for weak signals.
    if repeated:
        score -= 15
    if common:
        score -= 40
    if weak_patterns:
        score -= min(30, 10 * len(weak_patterns))

    # Sequential keyboard/digit runs (e.g. 'abcd', '7890').
    if re.search(r"(?:0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwert)", password.lower()):
        score -= 10

    return max(0, min(100, score))


def generate_recommendations(
    password: str,
    *,
    length: int,
    has_upper: bool,
    has_lower: bool,
    has_digit: bool,
    has_special: bool,
    repeated: bool,
    common: bool,
    weak_patterns: list[str],
) -> list[str]:
    """Build actionable advice based on failed checks."""
    tips: list[str] = []

    if length < MIN_RECOMMENDED_LENGTH:
        tips.append(
            f"Use at least {MIN_RECOMMENDED_LENGTH} characters "
            f"(current length: {length})."
        )

    if not has_upper:
        tips.append("Add uppercase letters (A–Z).")
    if not has_lower:
        tips.append("Add lowercase letters (a–z).")
    if not has_digit:
        tips.append("Add numbers (0–9).")
    if not has_special:
        tips.append("Add special characters (e.g. ! @ # $ % ^ & *).")

    if repeated:
        tips.append("Avoid repeating the same character multiple times in a row.")

    if common:
        tips.append(
            "This password appears in common breach lists. Choose a unique passphrase."
        )

    if weak_patterns:
        patterns = ", ".join(f"'{p}'" for p in weak_patterns[:3])
        extra = " (and others)" if len(weak_patterns) > 3 else ""
        tips.append(f"Remove predictable patterns such as {patterns}{extra}.")

    if len(set(password)) < len(password) * 0.5 and length > 0:
        tips.append("Increase character variety; avoid reusing the same letters.")

    if not tips:
        tips.append(
            "Password looks solid. Consider a password manager and unique passwords per site."
        )

    return tips


def analyze_password(password: str) -> PasswordAnalysis:
    """
    Run all checks and return a complete PasswordAnalysis result.

    Args:
        password: The raw password string entered by the user.

    Returns:
        PasswordAnalysis with checks, score, classification, and recommendations.
    """
    length = check_length(password)
    has_upper = check_uppercase(password)
    has_lower = check_lowercase(password)
    has_digit = check_numbers(password)
    has_special = check_special_characters(password)
    repeated = detect_repeated_characters(password)
    common = detect_common_password(password)
    weak_patterns = detect_weak_patterns(password)

    score = calculate_security_score(
        password,
        length=length,
        has_upper=has_upper,
        has_lower=has_lower,
        has_digit=has_digit,
        has_special=has_special,
        repeated=repeated,
        common=common,
        weak_patterns=weak_patterns,
    )

    classification = classify_score(score)
    recommendations = generate_recommendations(
        password,
        length=length,
        has_upper=has_upper,
        has_lower=has_lower,
        has_digit=has_digit,
        has_special=has_special,
        repeated=repeated,
        common=common,
        weak_patterns=weak_patterns,
    )

    return PasswordAnalysis(
        password_length=length,
        has_uppercase=has_upper,
        has_lowercase=has_lower,
        has_numbers=has_digit,
        has_special=has_special,
        has_repeated_chars=repeated,
        is_common_password=common,
        weak_patterns_found=weak_patterns,
        score=score,
        classification=classification,
        recommendations=recommendations,
    )
