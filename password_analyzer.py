import re
import hashlib
import sqlite3
import random
import string
import os
import sys
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS & CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# Path to the SQLite database that stores hashed password history
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "password_history.db")

# Common/weak passwords that should always be flagged as insecure.
# In a production system this list would be loaded from a large file
# (e.g., the HaveIBeenPwned corpus with 500 million+ entries).
COMMON_PASSWORDS = {
    "123456", "password", "qwerty", "admin", "welcome",
    "abc123", "letmein", "monkey", "dragon", "master",
    "123456789", "iloveyou", "sunshine", "princess", "football",
    "shadow", "superman", "michael", "12345678", "password1",
    "passw0rd", "1234567890", "login", "hello", "qwerty123",
    "111111", "000000", "123123", "test", "1234",
}

# Scoring thresholds map to strength labels
SCORE_LABELS = {
    (0, 3): ("Weak",       "🔴"),
    (4, 5): ("Medium",     "🟡"),
    (6, 7): ("Strong",     "🟢"),
    (8, 8): ("Very Strong","✅"),
}

# Character pools used when generating strong password suggestions
UPPER   = string.ascii_uppercase
LOWER   = string.ascii_lowercase
DIGITS  = string.digits
SPECIAL = "!@#$%^&*()-_=+[]{}|;:,.<>?"


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 1 – DATABASE INITIALISATION (Password Reuse Prevention)
# ─────────────────────────────────────────────────────────────────────────────

def init_database() -> sqlite3.Connection:
    """
    Create (or open) the SQLite database and ensure the password_history
    table exists.

    Security Note:
        We NEVER store plaintext passwords.  Only the SHA-256 hex digest is
        persisted, so even if the database file is exfiltrated an attacker
        cannot recover original passwords from stored values alone.

    Returns:
        sqlite3.Connection – an active database connection.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                hash        TEXT    NOT NULL UNIQUE,
                created_at  TEXT    NOT NULL
            )
        """)
        conn.commit()
        return conn
    except sqlite3.Error as exc:
        print(f"[ERROR] Database initialisation failed: {exc}")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 2 – CRYPTOGRAPHY (SHA-256 Hashing)
# ─────────────────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """
    Compute the SHA-256 hex digest of the given password.

    Why SHA-256?
        • Deterministic  – same input always produces the same 256-bit digest.
        • One-way        – computationally infeasible to reverse the digest.
        • Collision-resistant – negligible probability two inputs share a digest.

    Why NOT use SHA-256 for real authentication?
        SHA-256 alone is fast, which makes brute-force attacks cheap.
        Production systems should use bcrypt / Argon2 / PBKDF2 with a unique
        salt.  For this project SHA-256 fulfils the learning objective of
        'never storing plaintext'.

    Args:
        password: The plaintext password string.

    Returns:
        64-character lowercase hexadecimal string (SHA-256 digest).
    """
    # Encode the string to bytes before hashing (UTF-8 covers all Unicode chars)
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def save_password_hash(conn: sqlite3.Connection, password: str) -> bool:
    """
    Store the SHA-256 hash of a password in the history database.

    Args:
        conn:     Active SQLite connection.
        password: Plaintext password to hash and store.

    Returns:
        True  – hash was stored successfully (new password).
        False – hash already exists (duplicate/reused password) or DB error.
    """
    pw_hash = hash_password(password)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn.execute(
            "INSERT INTO password_history (hash, created_at) VALUES (?, ?)",
            (pw_hash, timestamp)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # UNIQUE constraint violated – password hash already in history
        return False
    except sqlite3.Error as exc:
        print(f"[ERROR] Failed to save hash: {exc}")
        return False


def is_password_reused(conn: sqlite3.Connection, password: str) -> bool:
    """
    Check whether a password has already been used (exists in history).

    The lookup is purely hash-based; the original password is never stored
    and never transmitted to the database layer.

    Args:
        conn:     Active SQLite connection.
        password: Plaintext password to check.

    Returns:
        True  – password hash found in history (reused).
        False – password is new (not found in history).
    """
    pw_hash = hash_password(password)
    cursor = conn.execute(
        "SELECT 1 FROM password_history WHERE hash = ? LIMIT 1",
        (pw_hash,)
    )
    return cursor.fetchone() is not None


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 3 – LENGTH ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

def analyse_length(password: str) -> dict:
    """
    Evaluate password strength purely based on character length.

    NIST SP 800-63B guidance recommends a minimum of 8 characters for
    memorised secrets and encourages longer passphrases.

    Args:
        password: The password string to evaluate.

    Returns:
        dict with keys:
            length (int)   – character count
            rating (str)   – Weak / Medium / Strong / Very Strong
            score  (int)   – partial score contribution (0-2)
    """
    length = len(password)

    if length < 8:
        rating, score = "Weak", 0
    elif length < 12:
        rating, score = "Medium", 1
    elif length <= 15:
        rating, score = "Strong", 2
    else:
        rating, score = "Very Strong", 2   # capped at +2 in scoring model

    return {"length": length, "rating": rating, "score": score}


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 4 – COMPLEXITY ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

def analyse_complexity(password: str) -> dict:
    """
    Inspect the password for the four complexity character classes.

    Uses compiled regex patterns for efficiency and readability.

    Args:
        password: The password string to evaluate.

    Returns:
        dict mapping each criterion to a boolean:
            has_upper   – at least one A-Z
            has_lower   – at least one a-z
            has_digit   – at least one 0-9
            has_special – at least one non-alphanumeric character
    """
    return {
        "has_upper":   bool(re.search(r"[A-Z]", password)),
        "has_lower":   bool(re.search(r"[a-z]", password)),
        "has_digit":   bool(re.search(r"[0-9]", password)),
        "has_special": bool(re.search(r"[^A-Za-z0-9]", password)),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 5 – COMMON PASSWORD DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def is_common_password(password: str) -> bool:
    """
    Check whether the password appears in the list of known weak passwords.

    The check is case-insensitive so that 'Password', 'PASSWORD', and
    'password' are all treated as equally weak.

    Args:
        password: The plaintext password.

    Returns:
        True if the password is in the common list, False otherwise.
    """
    return password.lower() in COMMON_PASSWORDS


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 6 – STRENGTH SCORING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def calculate_score(password: str, complexity: dict, is_common: bool) -> dict:
    """
    Compute a composite security score using the weighted scoring model.

    Scoring Table:
        Criterion                  Points
        ─────────────────────────  ──────
        Length ≥ 12 characters      +2
        Uppercase letter present    +1
        Lowercase letter present    +1
        Digit present               +1
        Special character present   +1
        Not a common password       +2
        ─────────────────────────  ──────
        Maximum possible score       8

    Strength Levels:
        0-3 → Weak
        4-5 → Medium
        6-7 → Strong
          8 → Very Strong

    Args:
        password:   Plaintext password.
        complexity: Output of analyse_complexity().
        is_common:  Output of is_common_password().

    Returns:
        dict with keys:
            score       (int) – total score 0-8
            breakdown   (dict) – per-criterion score contribution
            label       (str) – strength label
            icon        (str) – emoji indicator
    """
    breakdown = {
        "length_bonus":     2 if len(password) >= 12 else 0,
        "uppercase":        1 if complexity["has_upper"]   else 0,
        "lowercase":        1 if complexity["has_lower"]   else 0,
        "digit":            1 if complexity["has_digit"]   else 0,
        "special_char":     1 if complexity["has_special"] else 0,
        "not_common":       2 if not is_common             else 0,
    }

    total = sum(breakdown.values())

    # Map the score to a label
    label, icon = "Weak", "🔴"
    for (low, high), (lbl, icn) in SCORE_LABELS.items():
        if low <= total <= high:
            label, icon = lbl, icn
            break

    return {"score": total, "breakdown": breakdown, "label": label, "icon": icon}


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 7 – STRONG PASSWORD SUGGESTION GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_strong_passwords(count: int = 3, min_length: int = 14) -> list:
    """
    Generate cryptographically diverse password suggestions.

    Strategy:
        1. Guarantee at least one character from each of the four classes.
        2. Fill the remaining length with characters drawn from the combined pool.
        3. Shuffle to remove positional predictability.

    Args:
        count:      Number of suggestions to produce (default 3).
        min_length: Minimum character length per suggestion (default 14).

    Returns:
        List of strong password strings.
    """
    suggestions = []

    for _ in range(count):
        # Guaranteed characters – one from each class ensures all criteria pass
        mandatory = [
            random.choice(UPPER),
            random.choice(LOWER),
            random.choice(DIGITS),
            random.choice(SPECIAL),
        ]

        # Fill remaining length from the combined character pool
        all_chars = UPPER + LOWER + DIGITS + SPECIAL
        filler_length = random.randint(min_length - 4, min_length + 2)
        filler = [random.choice(all_chars) for _ in range(filler_length)]

        # Combine and shuffle to eliminate predictable patterns
        password_chars = mandatory + filler
        random.shuffle(password_chars)
        suggestions.append("".join(password_chars))

    return suggestions


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 8 – DISPLAY / REPORTING LAYER
# ─────────────────────────────────────────────────────────────────────────────

def print_banner():
    """Print the application banner."""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║          🔐  PASSWORD STRENGTH ANALYZER  v1.0                   ║
║          2                      ║
║          SHA-256 Hashing  |  SQLite History  |  NIST Guidelines  ║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_separator(char: str = "─", width: int = 66):
    """Print a horizontal separator line."""
    print(char * width)


def display_results(
    password:   str,
    conn:       sqlite3.Connection,
    show_password: bool = False
):
    """
    Orchestrate the full analysis pipeline and print a formatted report.

    Args:
        password:      Plaintext password to analyse.
        conn:          Active SQLite database connection.
        show_password: Whether to echo the password back (disabled by default
                       to avoid shoulder-surfing; useful for testing).
    """
    print_separator("═")
    label_display = f"  {'[PASSWORD HIDDEN]' if not show_password else password}"
    print(f"  ANALYSIS REPORT{label_display}")
    print_separator("═")

    # ── Reuse check (before any analysis output) ──────────────────────────
    reused = is_password_reused(conn, password)
    if reused:
        print("\n  ⚠️  WARNING: This password has been used before.")
        print("     Please choose a new password to maintain account security.\n")
    else:
        # Only save to history if it's a new password being evaluated
        save_password_hash(conn, password)

    # ── Length analysis ───────────────────────────────────────────────────
    length_info = analyse_length(password)
    print(f"\n  📏  LENGTH ANALYSIS")
    print(f"      Characters : {length_info['length']}")
    print(f"      Rating     : {length_info['rating']}")

    # ── Complexity analysis ───────────────────────────────────────────────
    complexity = analyse_complexity(password)
    print(f"\n  🔍  COMPLEXITY ANALYSIS")
    checks = [
        ("Uppercase letters (A-Z)",  complexity["has_upper"]),
        ("Lowercase letters (a-z)",  complexity["has_lower"]),
        ("Numbers (0-9)",            complexity["has_digit"]),
        ("Special characters",       complexity["has_special"]),
    ]
    for criterion, passed in checks:
        status = "✅  PASS" if passed else "❌  MISSING"
        print(f"      {status:<12}  {criterion}")

    # ── Common password check ─────────────────────────────────────────────
    common = is_common_password(password)
    print(f"\n  🚨  COMMON PASSWORD DETECTION")
    if common:
        print("      ❌  SECURITY WARNING: This is a well-known common password.")
        print("         It appears in public breach databases and will be cracked")
        print("         instantly by any dictionary attack.")
    else:
        print("      ✅  Not found in common password list.")

    # ── Score & strength label ────────────────────────────────────────────
    score_info = calculate_score(password, complexity, common)
    print(f"\n  📊  STRENGTH SCORE")
    print_separator()

    score_breakdown_labels = {
        "length_bonus":  "Length ≥ 12 chars",
        "uppercase":     "Uppercase present",
        "lowercase":     "Lowercase present",
        "digit":         "Number present",
        "special_char":  "Special char present",
        "not_common":    "Not a common password",
    }
    max_scores = {
        "length_bonus": 2, "uppercase": 1, "lowercase": 1,
        "digit": 1, "special_char": 1, "not_common": 2,
    }
    for key, earned in score_info["breakdown"].items():
        bar    = "█" * earned + "░" * (max_scores[key] - earned)
        label  = score_breakdown_labels[key]
        status = "✅" if earned else "❌"
        print(f"  {status}  {label:<26}  [{bar}]  {earned}/{max_scores[key]}")

    print_separator()
    print(f"  TOTAL SCORE : {score_info['score']} / 8")
    print(f"  STRENGTH    : {score_info['icon']}  {score_info['label']}")
    print_separator()

    # ── Detailed explanation ──────────────────────────────────────────────
    explanations = _build_explanation(score_info["label"], length_info, complexity, common)
    print(f"\n  💬  DETAILED FEEDBACK")
    for line in explanations:
        print(f"      {line}")

    # ── Suggestions (only for Weak or Medium) ─────────────────────────────
    if score_info["label"] in ("Weak", "Medium"):
        print(f"\n  💡  STRONG PASSWORD SUGGESTIONS")
        print(f"      (Auto-generated – meets all complexity requirements)\n")
        suggestions = generate_strong_passwords(count=3)
        for i, suggestion in enumerate(suggestions, start=1):
            print(f"      [{i}]  {suggestion}")
        print(f"\n      ⚠️  Note: These are examples only. Use a reputable")
        print(f"          password manager to generate and store your passwords.")

    print_separator("═")
    print()


def _build_explanation(label: str, length_info: dict, complexity: dict, is_common: bool) -> list:
    """
    Construct human-readable feedback lines based on analysis results.

    Args:
        label:       Strength label (Weak / Medium / Strong / Very Strong).
        length_info: Output of analyse_length().
        complexity:  Output of analyse_complexity().
        is_common:   Whether password is in common list.

    Returns:
        List of feedback strings.
    """
    lines = []
    length = length_info["length"]

    if label == "Weak":
        lines.append("Your password is critically weak and should be changed immediately.")
    elif label == "Medium":
        lines.append("Your password provides basic protection but can be improved.")
    elif label == "Strong":
        lines.append("Your password is strong and suitable for most accounts.")
    else:
        lines.append("Excellent! Your password is highly secure.")

    if length < 8:
        lines.append(f"⚠  Length ({length} chars) is far too short. Minimum: 8, Recommended: 14+.")
    elif length < 12:
        lines.append(f"⚠  Length ({length} chars) is acceptable but 12+ is recommended.")

    missing = [k for k, v in complexity.items() if not v]
    missing_map = {
        "has_upper":   "uppercase letters",
        "has_lower":   "lowercase letters",
        "has_digit":   "numbers",
        "has_special": "special characters (!@#$...)",
    }
    if missing:
        missing_names = ", ".join(missing_map[m] for m in missing)
        lines.append(f"⚠  Missing: {missing_names}.")

    if is_common:
        lines.append("⚠  This password exists in known breach databases.")

    return lines


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 9 – COMMAND-LINE INTERFACE
# ─────────────────────────────────────────────────────────────────────────────

def get_password_input() -> str:
    """
    Prompt the user for a password using secure (hidden) input where possible.

    Falls back to visible input if the environment does not support it
    (e.g., some CI/IDE terminals).

    Returns:
        The entered password string.
    """
    try:
        import getpass
        password = getpass.getpass("  Enter password to analyse: ")
    except Exception:
        # Fallback for environments that don't support hidden input
        password = input("  Enter password to analyse: ")
    return password


def run_interactive_loop(conn: sqlite3.Connection):
    """
    Main interactive REPL loop.  Keeps running until the user exits.

    Args:
        conn: Active SQLite database connection.
    """
    print_banner()

    while True:
        print("\n  Options:")
        print("  [1] Analyse a password")
        print("  [2] Generate strong password suggestions")
        print("  [3] View password history (hashes only)")
        print("  [4] Clear password history")
        print("  [0] Exit\n")

        choice = input("  Select option: ").strip()

        if choice == "1":
            password = get_password_input()
            if not password:
                print("\n  ❌  Error: Password cannot be empty.")
                continue
            display_results(password, conn, show_password=False)

        elif choice == "2":
            print("\n  🔐  Generated Strong Passwords:\n")
            for i, pwd in enumerate(generate_strong_passwords(count=5, min_length=16), 1):
                print(f"  [{i}]  {pwd}")
            print()

        elif choice == "3":
            _display_history(conn)

        elif choice == "4":
            _clear_history(conn)

        elif choice == "0":
            print("\n  Goodbye. Stay secure! 🔒\n")
            break

        else:
            print("\n  ❌  Invalid option. Please enter 0-4.")


def _display_history(conn: sqlite3.Connection):
    """Show stored password hashes from the history database."""
    print("\n  📋  PASSWORD HISTORY (SHA-256 hashes only)\n")
    cursor = conn.execute(
        "SELECT id, hash, created_at FROM password_history ORDER BY id DESC"
    )
    rows = cursor.fetchall()
    if not rows:
        print("  No password history found.\n")
        return
    print(f"  {'ID':<4}  {'SHA-256 Hash':<66}  {'Date / Time'}")
    print_separator()
    for row_id, pw_hash, created_at in rows:
        # Show only partial hash to reduce exfiltration risk in demo output
        partial = pw_hash[:16] + "..." + pw_hash[-8:]
        print(f"  {row_id:<4}  {partial:<30}  {created_at}")
    print()


def _clear_history(conn: sqlite3.Connection):
    """Wipe all entries from the password history table."""
    confirm = input("\n  ⚠️  Clear ALL password history? (yes/no): ").strip().lower()
    if confirm == "yes":
        conn.execute("DELETE FROM password_history")
        conn.commit()
        print("  ✅  Password history cleared.\n")
    else:
        print("  Operation cancelled.\n")


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """
    Application entry point.

    1. Initialise the SQLite database.
    2. Launch the interactive CLI loop.
    3. Gracefully handle KeyboardInterrupt (Ctrl+C).
    """
    # Accept an optional command-line password argument for scripting/testing
    conn = init_database()

    if len(sys.argv) == 2:
        # Non-interactive mode: analyse the provided password directly
        password = sys.argv[1]
        print_banner()
        display_results(password, conn, show_password=True)
    else:
        try:
            run_interactive_loop(conn)
        except KeyboardInterrupt:
            print("\n\n  Session interrupted. Goodbye!\n")
        finally:
            conn.close()


if __name__ == "__main__":
    main()
