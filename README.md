#!/usr/bin/env python3
"""Password Strength Checker

Evaluates a password on length, character variety, and common weaknesses,
then classifies it and gives feedback on how to improve it.
"""

import getpass
import string

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "password1", "111111", "iloveyou", "admin", "welcome", "letmein",
    "monkey", "dragon", "football", "login", "passw0rd", "qwerty123",
}

SEQUENCES = [
    string.ascii_lowercase,
    string.digits,
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]


def has_sequence(password: str, length: int = 4) -> bool:
    """Return True if the password has a run of `length` sequential characters."""
    lowered = password.lower()
    for seq in SEQUENCES:
        for variant in (seq, seq[::-1]):
            for i in range(len(variant) - length + 1):
                if variant[i:i + length] in lowered:
                    return True
    return False


def has_repeats(password: str, count: int = 3) -> bool:
    """Return True if any character repeats `count` or more times in a row."""
    run = 1
    for prev, curr in zip(password, password[1:]):
        run = run + 1 if curr == prev else 1
        if run >= count:
            return True
    return False


def evaluate_password(password: str) -> dict:
    """Score a password (0-100), classify it, and collect feedback."""
    score = 0
    feedback = []

    # --- Length (up to 40 points) ---
    length = len(password)
    if length >= 16:
        score += 40
    elif length >= 12:
        score += 32
    elif length >= 8:
        score += 20
        feedback.append("Use at least 12 characters for better security.")
    else:
        score += max(0, length * 2)
        feedback.append("Password is too short. Use at least 8 characters (12+ recommended).")

    # --- Character variety (15 points each) ---
    checks = [
        (any(c.islower() for c in password), "Add lowercase letters (a-z)."),
        (any(c.isupper() for c in password), "Add uppercase letters (A-Z)."),
        (any(c.isdigit() for c in password), "Add numbers (0-9)."),
        (any(c in string.punctuation for c in password),
         "Add special characters (e.g. !@#$%^&*)."),
    ]
    for passed, message in checks:
        if passed:
            score += 15
        else:
            feedback.append(message)

    # --- Penalties for weak patterns ---
    if password.lower() in COMMON_PASSWORDS:
        score = min(score, 10)
        feedback.append("This is a very common password. Choose something unique.")
    if has_sequence(password):
        score -= 10
        feedback.append("Avoid sequences like 'abcd', '1234', or 'qwerty'.")
    if has_repeats(password):
        score -= 10
        feedback.append("Avoid repeating the same character 3+ times in a row (e.g. 'aaa').")
    if len(set(password)) < len(password) / 2 and length > 0:
        score -= 5
        feedback.append("Use a greater variety of different characters.")

    score = max(0, min(100, score))

    if score < 30:
        label = "Very Weak"
    elif score < 50:
        label = "Weak"
    elif score < 70:
        label = "Moderate"
    elif score < 90:
        label = "Strong"
    else:
        label = "Very Strong"

    if not feedback:
        feedback.append("Great job! Your password looks solid. Never reuse it across sites.")

    return {"score": score, "label": label, "feedback": feedback}


def print_report(result: dict) -> None:
    bar_len = 20
    filled = result["score"] * bar_len // 100
    bar = "#" * filled + "-" * (bar_len - filled)
    print("\n" + "=" * 40)
    print(f"Strength : {result['label']}")
    print(f"Score    : {result['score']}/100  [{bar}]")
    print("-" * 40)
    print("Feedback:")
    for item in result["feedback"]:
        print(f"  - {item}")
    print("=" * 40 + "\n")


def main() -> None:
    print("Password Strength Checker (type 'q' to quit)")
    while True:
        try:
            password = getpass.getpass("\nEnter a password to check: ")
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break
        if password.lower() == "q":
            print("Goodbye!")
            break
        if not password:
            print("Please enter a password.")
            continue
        print_report(evaluate_password(password))


if __name__ == "__main__":
    main()
