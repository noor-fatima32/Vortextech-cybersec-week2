"""
VortexTech Cyber Security Internship - Week 2
Password Strength Evaluator

This script evaluates a password using:
- minimum length (8 characters, with a bonus note at 12+)
- uppercase letters
- lowercase letters
- numbers
- special characters
- common-password detection (exact match AND common word used as a substring)
- predictable-pattern detection (keyboard walks, sequential runs, repeated
  characters) so a password can't score "Strong" just by technically
  containing one of each character type while still being easy to guess

No password is stored, logged, or transmitted anywhere.
"""

from __future__ import annotations

import argparse
import sys

try:
    import getpass
except ImportError:  # pragma: no cover - getpass ships with CPython
    getpass = None  # type: ignore[assignment]

COMMON_PASSWORDS = {
    "123456",
    "password",
    "qwerty",
    "12345678",
    "123456789",
    "admin1234",
    "admin123",
    "00000000",
    "p@ssw0rd",
    "administrator",
    "87654321",
    "abc123",
    "welcome@123",
    "password123",
    "admin",
    "letmein",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
}

# Rows of a standard QWERTY keyboard, used to catch "keyboard walks"
# like 'qwerty', 'asdfgh', or '13579' that pass the character-variety
# checks but are still trivially guessable.
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

MIN_RUN_LENGTH = 4  # how many chars in a row before a pattern counts as risky


def _has_keyboard_walk(password: str, run_length: int = MIN_RUN_LENGTH) -> bool:
    """Detect substrings that walk along a keyboard row, forwards or backwards."""
    p = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - run_length + 1):
            fragment = row[i : i + run_length]
            if fragment in p or fragment[::-1] in p:
                return True
    return False


def _has_sequential_run(password: str, run_length: int = MIN_RUN_LENGTH) -> bool:
    """Detect ascending/descending character sequences like '1234' or 'abcd'."""
    p = password.lower()
    for i in range(len(p) - run_length + 1):
        chunk = p[i : i + run_length]
        codes = [ord(c) for c in chunk]
        ascending = all(codes[j] + 1 == codes[j + 1] for j in range(len(codes) - 1))
        descending = all(codes[j] - 1 == codes[j + 1] for j in range(len(codes) - 1))
        if ascending or descending:
            return True
    return False


def _has_repeated_run(password: str, run_length: int = MIN_RUN_LENGTH) -> bool:
    """Detect a single character repeated several times in a row, like 'aaaa'."""
    for i in range(len(password) - run_length + 1):
        if len(set(password[i : i + run_length])) == 1:
            return True
    return False


def _contains_common_substring(password: str) -> str | None:
    """Return the common password that appears *inside* this password, if any.

    Catches things like 'MyPassword123!' or 'p@ssw0rd2024', which don't
    exactly match an entry in COMMON_PASSWORDS but are still built directly
    from one - a very common real-world habit.
    """
    p = password.lower()
    for common in COMMON_PASSWORDS:
        if len(common) >= 4 and common in p:
            return common
    return None


def evaluate_password(password: str) -> tuple[str, list[str]]:
    """Return a strength rating ('Weak' / 'Medium' / 'Strong') plus a list of
    specific, actionable feedback strings explaining *why* it got that rating
    and what to change.
    """
    lower_pw = password.lower()
    exact_common = lower_pw in {c.lower() for c in COMMON_PASSWORDS}

    checks = {
        "length": len(password) >= 8,
        "uppercase": any(c.isupper() for c in password),
        "lowercase": any(c.islower() for c in password),
        "number": any(c.isdigit() for c in password),
        "special": any(not c.isalnum() for c in password),
    }
    passed = sum(checks.values())

    # --- Character-variety feedback: always computed, even for a password
    # that also happens to be a known common password, so the person gets
    # concrete "add X" guidance rather than just a generic warning. ---
    checklist_feedback = []
    if not checks["length"]:
        checklist_feedback.append("Use at least 8 characters (12+ is even better).")
    if not checks["uppercase"]:
        checklist_feedback.append("Add an uppercase letter (A-Z).")
    if not checks["lowercase"]:
        checklist_feedback.append("Add a lowercase letter (a-z).")
    if not checks["number"]:
        checklist_feedback.append("Add a number (0-9).")
    if not checks["special"]:
        checklist_feedback.append("Add a special character (e.g. ! @ # $ %).")

    # --- Predictable-pattern feedback ---
    substring_hit = None if exact_common else _contains_common_substring(password)
    keyboard_walk = _has_keyboard_walk(password)
    sequential_run = _has_sequential_run(password)
    repeated_run = _has_repeated_run(password)

    pattern_feedback = []
    if exact_common:
        pattern_feedback.append(
            "This exact password appears on common password lists - it's one "
            "of the first things attackers try."
        )
    elif substring_hit:
        pattern_feedback.append(
            f"Contains the common word/password '{substring_hit}' - avoid "
            "building passwords out of dictionary words."
        )
    if keyboard_walk:
        pattern_feedback.append(
            "Avoid keyboard-adjacent sequences like 'qwerty' or 'asdf' - "
            "these are tried early in password-cracking tools."
        )
    if sequential_run:
        pattern_feedback.append(
            "Avoid sequential runs like '1234' or 'abcd' - easy to guess."
        )
    if repeated_run:
        pattern_feedback.append(
            "Avoid repeating the same character several times in a row."
        )

    pattern_triggered = bool(substring_hit or keyboard_walk or sequential_run or repeated_run)
    feedback = pattern_feedback + checklist_feedback

    # --- Rating ---
    # Precedence: an exact common-password match is always Weak, no matter
    # what else is true. Otherwise, a predictable pattern caps the rating at
    # Medium even if all five character-variety checks technically pass -
    # a password shouldn't be able to score "Strong" purely by matching
    # 'qwerty123!' against the length/upper/lower/number/special rules.
    if exact_common:
        rating = "Weak"
    elif passed <= 2:
        rating = "Weak"
    elif pattern_triggered or passed <= 4:
        rating = "Medium"
    else:
        rating = "Strong"

    if rating == "Strong":
        if len(password) < 12:
            feedback.append(
                "Good job! Passes all basic checks. For extra protection, "
                "consider making it 12+ characters."
            )
        else:
            feedback.append(
                "Good job! This password passes all basic checks and has solid length."
            )

    if not feedback:
        feedback.append("Good job! This password passes all basic checks.")

    return rating, feedback


DEMO_PASSWORDS = [
    "123456",
    "password",
    "hello",
    "Password1",
    "Password1!",
    "Qwerty123!",
    "P@ssw0rd2024",
    "Tr0ub4dor&3!!",
    "aaaaaaaa",
    "ADMIN123!",
]


def run_demo() -> None:
    """Run the evaluator against a fixed set of example passwords, non-
    interactively. Useful for grading/testing without typing anything in,
    and for confirming the feedback text actually matches each password.
    """
    print("VortexTech Week 2 - Password Strength Evaluator (demo mode)\n")
    for pw in DEMO_PASSWORDS:
        rating, feedback = evaluate_password(pw)
        print(f"Password: {pw!r}")
        print(f"Strength: {rating}")
        for item in feedback:
            print(f"  - {item}")
        print()


def _read_password(prompt: str) -> str:
    """Read a password without echoing it to the terminal when possible."""
    if getpass is not None and sys.stdin.isatty():
        try:
            return getpass.getpass(prompt)
        except Exception:
            pass  # fall back to plain input() below
    return input(prompt)


def main() -> None:
    parser = argparse.ArgumentParser(description="VortexTech password strength evaluator")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run against a built-in list of example passwords and exit (no typing required).",
    )
    args = parser.parse_args()

    if args.demo:
        run_demo()
        return

    print("VortexTech Week 2 - Password Strength Evaluator")
    print("Type 'quit' to exit.\n")

    while True:
        password = _read_password("Enter a password to evaluate: ")
        if password.lower() == "quit":
            print("Exiting.")
            break

        rating, feedback = evaluate_password(password)
        print(f"Strength: {rating}")
        for item in feedback:
            print(f"- {item}")
        print()


if __name__ == "__main__":
    main()
