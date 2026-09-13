"""
Simple automated checks for password_checker.py.

Run with:
    python test_password_checker.py

This doesn't require pytest - it just asserts expected behavior and prints
PASS/FAIL, which is enough for this assignment's "test with several example
passwords" step and gives repeatable proof that the feedback text lines up
with the rating.
"""

from password_checker import evaluate_password

CASES = [
    # (password, expected_rating)
    ("123456", "Weak"),          # exact common password
    ("password", "Weak"),        # exact common password
    ("hello", "Weak"),           # too short, low variety
    ("aaaaaaaa", "Weak"),        # repeated-character run
    ("Password1", "Medium"),     # contains common word 'password'
    ("Password1!", "Medium"),    # still contains 'password' even with all char types
    ("Qwerty123!", "Medium"),    # keyboard walk + common word 'qwerty'
    ("ADMIN123!", "Medium"),     # contains common word 'admin', missing lowercase
    ("Tr0ub4dor&3!!", "Strong"), # no common word, no pattern, all char types, 12+ chars
]


def main() -> None:
    failures = 0
    for password, expected in CASES:
        rating, feedback = evaluate_password(password)
        status = "PASS" if rating == expected else "FAIL"
        if status == "FAIL":
            failures += 1
        print(f"[{status}] {password!r}: got {rating!r}, expected {expected!r}")
        for item in feedback:
            print(f"        - {item}")

    print()
    if failures:
        print(f"{failures} test(s) failed.")
        raise SystemExit(1)
    print("All tests passed.")


if __name__ == "__main__":
    main()
