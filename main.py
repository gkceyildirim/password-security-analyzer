#!/usr/bin/env python3
"""
Password Security Analyzer — command-line interface.

A portfolio cybersecurity tool that evaluates password strength and
provides actionable recommendations.
"""

import getpass
import sys

from analyzer import PasswordAnalysis, analyze_password


def _status(ok: bool) -> str:
    """Format a check result as pass/fail for terminal output."""
    return "✓ Pass" if ok else "✗ Fail"


def _print_header() -> None:
    """Print application banner."""
    print()
    print("=" * 56)
    print("       PASSWORD SECURITY ANALYZER")
    print("       Cybersecurity Portfolio Project")
    print("=" * 56)
    print()


def _print_checks(result: PasswordAnalysis) -> None:
    """Display individual password checks."""
    print("--- Security Checks ---")
    print(f"  Length ({result.password_length} chars)     : ", end="")
    print(_status(result.password_length >= 8))

    print(f"  Uppercase letters          : {_status(result.has_uppercase)}")
    print(f"  Lowercase letters          : {_status(result.has_lowercase)}")
    print(f"  Numbers                    : {_status(result.has_numbers)}")
    print(f"  Special characters         : {_status(result.has_special)}")
    print(f"  No excessive repetition    : {_status(not result.has_repeated_chars)}")
    print(f"  Not a common password      : {_status(not result.is_common_password)}")

    if result.weak_patterns_found:
        patterns = ", ".join(result.weak_patterns_found)
        print(f"  Weak patterns detected     : ✗ Fail ({patterns})")
    else:
        print("  Weak patterns detected     : ✓ Pass")
    print()


def _print_score(result: PasswordAnalysis) -> None:
    """Display score, bar visualization, and classification."""
    bar_width = 40
    filled = int(bar_width * result.score / 100)
    bar = "█" * filled + "░" * (bar_width - filled)

    print("--- Security Score ---")
    print(f"  Score          : {result.score}/100")
    print(f"  [{bar}]")
    print(f"  Classification : {result.classification}")
    print()


def _print_recommendations(result: PasswordAnalysis) -> None:
    """Display improvement suggestions."""
    print("--- Recommendations ---")
    for index, tip in enumerate(result.recommendations, start=1):
        print(f"  {index}. {tip}")
    print()


def get_password_from_user() -> str:
    """
    Prompt for a password. Uses hidden input when available (TTY);
    falls back to visible input in non-interactive environments.
    """
    try:
        password = getpass.getpass("Enter a password to analyze: ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        sys.exit(0)

    if not password and sys.stdin.isatty() is False:
        # Allow piping: echo "test" | python main.py
        password = sys.stdin.read().strip()

    return password


def main() -> None:
    """Entry point for the CLI application."""
    _print_header()

    password = get_password_from_user()

    if not password:
        print("Error: No password provided.")
        sys.exit(1)

    result = analyze_password(password)

    _print_checks(result)
    _print_score(result)
    _print_recommendations(result)

    print("=" * 56)
    print("Analysis complete. Do not share passwords in production logs.")
    print("=" * 56)
    print()


if __name__ == "__main__":
    main()
