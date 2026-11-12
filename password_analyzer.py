#!/usr/bin/env python3
"""
Password Strength Analyzer  -  Thiranex Cyber Security Internship, Task 1
=========================================================================
Features
  1. Checks password length, complexity (character classes) and uniqueness
     (repeats, sequences, keyboard walks, common-password list).
  2. Suggests stronger alternatives (random password + passphrase) using the
     cryptographically secure `secrets` module.
  3. OPTIONAL: SQLite database that remembers salted hashes of previously used
     passwords per user so old passwords cannot be reused.

Only the Python standard library is used - nothing to install.
The password is NEVER printed or stored in plain text.
"""

import getpass
import hashlib
import math
import os
import secrets
import sqlite3
import string
import sys

# ----------------------------------------------------------------------------
# Small built-in list of very common passwords. In real projects you would load
# a bigger list (e.g. top 10,000 from the SecLists project) from a text file.
# ----------------------------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "password1", "111111", "iloveyou", "admin", "welcome", "letmein",
    "monkey", "dragon", "football", "login", "passw0rd", "qwerty123",
    "1q2w3e4r", "admin123", "root", "master", "sunshine", "princess",
    "123123", "000000", "zaq12wsx", "trustno1", "p@ssw0rd", "changeme",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

# Wordlist for passphrase suggestions (small demo list; bigger = stronger).
WORDS = [
    "anchor", "bridge", "candle", "dolphin", "ember", "forest", "glacier",
    "harbor", "island", "jungle", "kettle", "lantern", "meadow", "nebula",
    "orchid", "pepper", "quartz", "river", "saddle", "tundra", "umbrella",
    "valley", "willow", "yonder", "zephyr", "marble", "copper", "falcon",
    "garden", "hammer", "ivory", "jasmine", "koala", "lemon", "mango",
    "ocean", "planet", "rocket", "silver", "thunder", "violet", "winter",
]


# ----------------------------------------------------------------------------
# 1. ANALYSIS
# ----------------------------------------------------------------------------
def char_pool_size(pw: str) -> int:
    """Size of the character set the password draws from."""
    pool = 0
    if any(c.islower() for c in pw):
        pool += 26
    if any(c.isupper() for c in pw):
        pool += 26
    if any(c.isdigit() for c in pw):
        pool += 10
    if any(c in string.punctuation for c in pw):
        pool += len(string.punctuation)  # 32
    if any(c == " " for c in pw):
        pool += 1
    if any(ord(c) > 127 for c in pw):
        pool += 100  # rough allowance for non-ASCII characters
    return pool


def estimate_entropy(pw: str) -> float:
    """Theoretical entropy in bits = length * log2(pool). An UPPER bound:
    real attackers use dictionaries and patterns, so we subtract penalties
    elsewhere."""
    pool = char_pool_size(pw)
    return len(pw) * math.log2(pool) if pool else 0.0


def has_sequence(pw: str, n: int = 3) -> bool:
    """Detects ascending/descending runs like 'abc', '321' or keyboard walks
    such as 'qwe', 'asd'."""
    low = pw.lower()
    for i in range(len(low) - n + 1):
        chunk = low[i:i + n]
        # ascending / descending by character code (abc, cba, 123, 321)
        diffs = {ord(chunk[j + 1]) - ord(chunk[j]) for j in range(n - 1)}
        if diffs == {1} or diffs == {-1}:
            return True
        # keyboard rows (forwards or backwards)
        for row in KEYBOARD_ROWS:
            if chunk in row or chunk in row[::-1]:
                return True
    return False


def has_repeats(pw: str, n: int = 3) -> bool:
    """Detects the same character repeated n times in a row ('aaa')."""
    return any(len(set(pw[i:i + n])) == 1 for i in range(len(pw) - n + 1))


def normalise_leet(pw: str) -> str:
    """Undo common substitutions so 'P@ssw0rd' is recognised as 'password'."""
    table = str.maketrans({"@": "a", "4": "a", "1": "i", "!": "i", "3": "e",
                           "0": "o", "$": "s", "5": "s", "7": "t"})
    return pw.lower().translate(table)


def analyze_password(pw: str) -> dict:
    """Return a dictionary with score (0-100), rating, findings, suggestions."""
    findings, tips = [], []
    score = 0

    # ---- Length (max 40 points) -------------------------------------------
    length = len(pw)
    if length < 8:
        findings.append(f"Too short ({length} characters).")
        tips.append("Use at least 12 characters (14+ is better).")
        score += length * 2
    elif length < 12:
        findings.append(f"Acceptable length ({length}) but not strong.")
        tips.append("Aim for 12 or more characters.")
        score += 20
    elif length < 16:
        findings.append(f"Good length ({length}).")
        score += 32
    else:
        findings.append(f"Excellent length ({length}).")
        score += 40

    # ---- Complexity (max 30 points) ---------------------------------------
    classes = {
        "lowercase letters": any(c.islower() for c in pw),
        "uppercase letters": any(c.isupper() for c in pw),
        "digits": any(c.isdigit() for c in pw),
        "special characters": any(c in string.punctuation for c in pw),
    }
    present = sum(classes.values())
    score += present * 7 + (2 if present == 4 else 0)
    for name, ok in classes.items():
        if not ok:
            tips.append(f"Add {name}.")
    findings.append(f"Uses {present}/4 character types.")

    # ---- Uniqueness (max 30 points, with penalties) -----------------------
    unique_ratio = len(set(pw)) / length if length else 0
    uniq_points = int(unique_ratio * 30)
    if unique_ratio < 0.5 and length:
        findings.append("Many repeated characters.")
        tips.append("Avoid reusing the same characters over and over.")
    score += uniq_points

    penalty = 0
    if pw.lower() in COMMON_PASSWORDS or normalise_leet(pw) in COMMON_PASSWORDS:
        findings.append("This is a very common/leaked-style password!")
        tips.append("Never use common passwords - attackers try them first.")
        penalty += 60
    if has_repeats(pw):
        findings.append("Contains a character repeated 3+ times (e.g. 'aaa').")
        penalty += 10
    if has_sequence(pw):
        findings.append("Contains a sequence or keyboard pattern (abc, 123, qwe).")
        tips.append("Avoid sequences like 'abc', '123' or 'qwerty'.")
        penalty += 15
    if pw.isdigit() or pw.isalpha():
        penalty += 10
    score = max(0, min(100, score - penalty))
    # Length caps: a short password can never be rated higher than its length allows
    if length < 8:
        score = min(score, 35)
    elif length < 12:
        score = min(score, 69)

    # ---- Rating ------------------------------------------------------------
    if score < 30:
        rating = "VERY WEAK"
    elif score < 50:
        rating = "WEAK"
    elif score < 70:
        rating = "MODERATE"
    elif score < 85:
        rating = "STRONG"
    else:
        rating = "VERY STRONG"

    entropy = estimate_entropy(pw)
    return {
        "length": length,
        "score": score,
        "rating": rating,
        "entropy_bits": round(entropy, 1),
        "findings": findings,
        "tips": list(dict.fromkeys(tips)),  # de-duplicate, keep order
    }


# ----------------------------------------------------------------------------
# 2. SUGGESTIONS  (random, so they do NOT depend on the user's password)
# ----------------------------------------------------------------------------
def generate_password(length: int = 16) -> str:
    """Random password guaranteed to contain all 4 character types."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw)
                and any(c in "!@#$%^&*()-_=+" for c in pw)):
            return pw


def generate_passphrase(words: int = 4) -> str:
    """Easy-to-remember passphrase, e.g. 'Falcon-River-Quartz-Lemon-48'."""
    chosen = [secrets.choice(WORDS).capitalize() for _ in range(words)]
    return "-".join(chosen) + f"-{secrets.randbelow(90) + 10}"


def suggest_alternatives(count: int = 3) -> list:
    out = [generate_passphrase() for _ in range(count - 1)]
    out.append(generate_password())
    return out


# ----------------------------------------------------------------------------
# 3. OPTIONAL: PASSWORD-HISTORY DATABASE (prevents reuse of old passwords)
# ----------------------------------------------------------------------------
class PasswordHistory:
    """Stores PBKDF2-HMAC-SHA256 hashes (random salt per entry) in SQLite."""

    ITERATIONS = 200_000

    def __init__(self, db_path: str = "password_history.db"):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS history (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT NOT NULL,
                   salt BLOB NOT NULL,
                   hash BLOB NOT NULL,
                   created TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"""
        )
        self.conn.commit()

    def _hash(self, pw: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, self.ITERATIONS)

    def was_used(self, username: str, pw: str) -> bool:
        # Parameterised query (?) -> safe from SQL injection
        rows = self.conn.execute(
            "SELECT salt, hash FROM history WHERE username = ?", (username,)
        ).fetchall()
        return any(secrets.compare_digest(self._hash(pw, s), h) for s, h in rows)

    def add(self, username: str, pw: str) -> None:
        salt = os.urandom(16)
        self.conn.execute(
            "INSERT INTO history (username, salt, hash) VALUES (?, ?, ?)",
            (username, salt, self._hash(pw, salt)),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


# ----------------------------------------------------------------------------
# COMMAND-LINE INTERFACE
# ----------------------------------------------------------------------------
def print_report(result: dict) -> None:
    bar_len = result["score"] // 5
    print("\n" + "=" * 50)
    print(f" Strength : {result['rating']}  ({result['score']}/100)")
    print(f" Meter    : [{'#' * bar_len}{'.' * (20 - bar_len)}]")
    print(f" Entropy  : ~{result['entropy_bits']} bits (theoretical maximum)")
    print("-" * 50)
    print(" Findings:")
    for f in result["findings"]:
        print(f"   - {f}")
    if result["tips"]:
        print(" How to improve:")
        for t in result["tips"]:
            print(f"   * {t}")
    print("=" * 50)


def main() -> None:
    print("PASSWORD STRENGTH ANALYZER  (type 'quit' as username to exit)")
    history = PasswordHistory()
    try:
        while True:
            username = input("\nUsername (for reuse check): ").strip()
            if username.lower() == "quit":
                break
            if not username:
                continue
            pw = getpass.getpass("Password (hidden): ")
            if not pw:
                print("Empty password - try again.")
                continue

            result = analyze_password(pw)
            print_report(result)

            if history.was_used(username, pw):
                print(" !! REUSE DETECTED: you used this password before. "
                      "Choose a new one.")
                result["score"] = 0
            elif result["score"] >= 70:
                if input(" Save to history so it cannot be reused? (y/n): "
                         ).lower() == "y":
                    history.add(username, pw)
                    print(" Saved (as a salted hash, never plain text).")

            if result["score"] < 70:
                print("\n Suggested stronger alternatives:")
                for s in suggest_alternatives():
                    print(f"   {s}")
    finally:
        history.close()


if __name__ == "__main__":
    sys.exit(main())
