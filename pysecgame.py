#!/usr/bin/env python3
"""
CyberLearn: terminal-based cybersecurity learning prototype.

Run: python3 cyber-game.py

Levels:
  1) Password Strength
  2) Phishing Detector
  3) Caesar Cipher Puzzle
  4) Log Forensics

Author: ChatGPT (prototype)
"""
import random
import sys
import textwrap
import time
import math
from collections import Counter

# --- Utilities --------------------------------------------------------------

def cls():
    print("\n" * 30)

def slow_print(text, delay=0.01):
    for ch in text:
        print(ch, end='', flush=True)
        time.sleep(delay)
    print()

def prompt_choice(prompt, choices):
    """Prompt user to pick one of choices (list of strings). Returns index."""
    while True:
        choice = input(prompt).strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(choices):
                return idx
        print(f"Please enter a number between 1 and {len(choices)}.")

def wrap(s, width=72):
    return textwrap.fill(s, width=width)

# --- Scoring & Progress -----------------------------------------------------

class GameState:
    def __init__(self):
        self.score = 0
        self.completed = []
    def add_score(self, pts):
        self.score += pts
    def mark_done(self, level_name):
        if level_name not in self.completed:
            self.completed.append(level_name)

G = GameState()

# --- Level 1: Password Strength ---------------------------------------------

def estimate_entropy(password: str) -> float:
    """
    Rough entropy estimate:
      - find character sets used: lowercase, uppercase, digits, symbols
      - assume pool size based on sets and entropy = len * log2(pool_size)
    This is simplified but educational.
    """
    pools = 0
    if any(c.islower() for c in password):
        pools += 26
    if any(c.isupper() for c in password):
        pools += 26
    if any(c.isdigit() for c in password):
        pools += 10
    # printable symbol set (rough)
    if any(not c.isalnum() for c in password):
        pools += 32
    if pools == 0:
        return 0.0
    entropy = len(password) * math.log2(pools)
    return entropy

def password_tips(password: str) -> list:
    tips = []
    if len(password) < 8:
        tips.append("Use at least 8 characters (prefer 12+ for important accounts).")
    if password.islower() or password.isupper():
        tips.append("Mix upper and lower case letters.")
    if not any(c.isdigit() for c in password):
        tips.append("Add digits (0-9).")
    if not any(not c.isalnum() for c in password):
        tips.append("Add symbols like !@#$% to increase complexity.")
    # discourage common patterns
    common = ["password", "1234", "qwerty", "letmein", "admin"]
    if any(c in password.lower() for c in common):
        tips.append("Avoid common words or patterns (e.g., 'password', '1234').")
    if len(tips) == 0:
        tips.append("Looks good! Consider using a password manager to store unique passwords.")
    return tips

def level_password_strength():
    cls()
    title = "Level 1 — Password Strength"
    print("=" * len(title))
    print(title)
    print("=" * len(title))
    slow_print("You're asked to create a master password for a new account.")
    print()
    # Give user two options: create their own or try to guess a strong one
    print("Options:")
    print("  1) Enter a password and get feedback (recommended)")
    print("  2) Have the system propose a strong password (educational)")
    choice = prompt_choice("Choose 1 or 2: ", ["Enter", "Propose"])
    if choice == 0:
        pw = input("Enter your candidate password (input visible): ").strip()
        entropy = estimate_entropy(pw)
        print()
        print(f"Estimated entropy: {entropy:.1f} bits")
        if entropy < 40:
            print("Strength: WEAK")
            pts = 5
        elif entropy < 60:
            print("Strength: MEDIUM")
            pts = 10
        else:
            print("Strength: STRONG")
            pts = 20
        tips = password_tips(pw)
        print("\nTips:")
        for t in tips:
            print(" -", t)
        print()
        slow_print("Explanation: Entropy roughly measures unpredictability. Higher entropy -> harder to guess/ brute-force.")
        G.add_score(pts)
        G.mark_done("Password Strength")
        print(f"\nYou earned {pts} points. Total score: {G.score}")
        input("\nPress Enter to continue...")
    else:
        # propose a password (use a human-friendly passphrase)
        words = ["ocean", "battery", "copper", "flight", "nebula", "garden", "silver", "puzzle", "vector", "maple"]
        pw = "-".join(random.sample(words, 3)) + str(random.randint(10,99))
        print("\nProposed password (example):", pw)
        entropy = estimate_entropy(pw)
        print(f"Estimated entropy: {entropy:.1f} bits")
        slow_print("Tip: Use long passphrases (4+ random words) or a password manager to generate/store complex passwords.")
        pts = 15
        G.add_score(pts)
        G.mark_done("Password Strength")
        print(f"\nYou earned {pts} points. Total score: {G.score}")
        input("\nPress Enter to continue...")

# --- Level 2: Phishing Detector --------------------------------------------

PHISHING_EMAILS = [
    {
        "from": "support@yourbank-secure.com",
        "subject": "URGENT: Verify your account NOW",
        "body": "Dear customer, we detected suspicious activity. Click http://yourbank.verify-account.example/login to verify your account immediately or your access will be suspended."
    },
    {
        "from": "security@github.com",
        "subject": "New sign-in to your account",
        "body": "We detected a new login from a new device. If this was you, ignore. Otherwise click https://github.com/settings/security to review."
    },
    {
        "from": "it-helpdesk@company.local",
        "subject": "Mandatory password reset",
        "body": "All employees must reset their password here: https://company-reset.example/reset. Failure to comply will lock your account."
    },
    {
        "from": "friend@example.com",
        "subject": "Check this photo!",
        "body": "Hey, did you see this? http://tinyurl.com/suspiciousphoto"
    },
]

SAFE_EMAILS = [
    {
        "from": "no-reply@amazon.com",
        "subject": "Your order has shipped",
        "body": "Your order #12345 has shipped. Track it at https://www.amazon.com/track"
    },
    {
        "from": "alerts@google.com",
        "subject": "Security alert",
        "body": "A new sign-in from a recognized device occurred. If this was you, no action required."
    }
]

def present_email(email):
    print(f"From: {email['from']}")
    print(f"Subject: {email['subject']}")
    print()
    print(wrap(email['body']))
    print()

def is_phishy(email):
    # simple heuristics for the game:
    # - if the domain in "from" doesn't match brand or contains hyphen/extra words
    # - suspicious shortened URLs or weird domains in body
    from_addr = email['from']
    body = email['body'].lower()
    suspicious_indicators = [
        "http://", "tinyurl", "verify-account", "reset", "suspend", "click",
        ".example", "-secure", "company-reset"
    ]
    for s in suspicious_indicators:
        if s in from_addr.lower() or s in body:
            return True
    # otherwise treat as safe
    return False

def level_phishing_detector():
    cls()
    title = "Level 2 — Phishing Detector"
    print("=" * len(title))
    print(title)
    print("=" * len(title))
    slow_print("You will be shown several emails. Decide whether each is SAFE or PHISHING.")
    print()
    pool = PHISHING_EMAILS + SAFE_EMAILS
    random.shuffle(pool)
    correct = 0
    for idx, email in enumerate(pool[:4], 1):
        print(f"--- Email #{idx} ---")
        present_email(email)
        print("Choices:")
        print("  1) SAFE (no action needed)")
        print("  2) PHISHING (suspicious — do not click)")
        choice = prompt_choice("Your call (1-2): ", ["Safe", "Phishing"])
        guess_phish = (choice == 1)  # 1 -> phishing? Wait: prompt_choice returns 0-based; careful
        # prompt_choice returned index: 0 for "Safe", 1 for "Phishing" because we passed ["Safe","Phishing"]
        # but we used choices list above incorrectly; fix: re-evaluate
        # Actually: we passed ["Safe","Phishing"], so choice==0 => Safe, choice==1 => Phishing
        guess_phish = (choice == 1)
        real_phish = is_phishy(email)
        if guess_phish == real_phish:
            print("Correct!")
            correct += 1
            G.add_score(5)
        else:
            print("Not quite.")
            # give a hint
            if real_phish:
                print("Hint: look for mismatched domains, urgent language, or odd-looking links.")
            else:
                print("Hint: legitimate communications often have the company's official domain and no urgent threat.")
        print()
        time.sleep(0.7)
    print(f"You identified {correct}/4 correctly.")
    if correct >= 3:
        pts = 20
    elif correct == 2:
        pts = 10
    else:
        pts = 5
    G.add_score(pts)
    G.mark_done("Phishing Detector")
    print("\nShort lesson:")
    slow_print("Phishing relies on urgency or curiosity and fake links. Always hover over links (or inspect URLs) and verify sender addresses. When in doubt, contact the company via a known-good channel.")
    print(f"\nYou earned {pts} points. Total score: {G.score}")
    input("\nPress Enter to continue...")

# --- Level 3: Caesar Cipher Puzzle -----------------------------------------

def caesar_encrypt(s, shift):
    out = []
    for ch in s:
        if 'a' <= ch <= 'z':
            out.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            out.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
        else:
            out.append(ch)
    return ''.join(out)

def caesar_bruteforce(cipher):
    candidates = []
    for k in range(26):
        candidates.append((k, caesar_encrypt(cipher, 26 - k)))
    return candidates

def level_caesar_cipher():
    cls()
    title = "Level 3 — Caesar Cipher Puzzle"
    print("=" * len(title))
    print(title)
    print("=" * len(title))
    slow_print("Decrypt the message. It's encoded with a Caesar shift (a simple substitution).")
    print()
    messages = [
        "Meet at midnight by the old bridge",
        "Backup server compromised change keys",
        "User failed login attempts exceed threshold",
        "Patch the database server tonight"
    ]
    plain = random.choice(messages)
    shift = random.randint(1, 25)
    cipher = caesar_encrypt(plain, shift)
    print("Ciphertext:")
    print(wrap(cipher))
    print()
    print("Options:")
    print("  1) Attempt to guess the plaintext")
    print("  2) Show brute-force candidates (educational)")
    choice = prompt_choice("Choose 1 or 2: ", ["Guess", "Brute-force"])
    pts = 0
    if choice == 0:
        guess = input("Enter your guess for the plaintext (case-insensitive): ").strip().lower()
        if guess == plain.lower():
            slow_print("Correct! You recovered the message.")
            pts = 20
        else:
            slow_print("Not exactly. Try reviewing letter shifts and common words.")
            pts = 5
    else:
        print("\nBrute-force results (shift => plaintext):")
        for k, cand in caesar_bruteforce(cipher):
            print(f"{k:2d}: {cand}")
        print()
        slow_print("Explanation: Caesar cipher shifts letters by a fixed amount. It's trivial to brute-force all 26 shifts.")
        pts = 10
    G.add_score(pts)
    G.mark_done("Caesar Cipher")
    print(f"\nYou earned {pts} points. Total score: {G.score}")
    input("\nPress Enter to continue...")

# --- Level 4: Log Forensics ------------------------------------------------

SAMPLE_LOGS = [
    # time ip user msg
    "2025-09-20 09:01:12 192.168.1.101 alice LOGIN_SUCCESS",
    "2025-09-20 09:01:33 192.168.1.102 bob LOGIN_FAIL",
    "2025-09-20 09:02:01 203.0.113.17 unknown LOGIN_FAIL",
    "2025-09-20 09:02:12 203.0.113.17 unknown LOGIN_FAIL",
    "2025-09-20 09:02:31 203.0.113.17 unknown LOGIN_FAIL",
    "2025-09-20 10:15:02 198.51.100.42 charlie FILE_DOWNLOAD secret.zip",
    "2025-09-20 10:15:16 198.51.100.42 charlie FILE_DELETE secret.zip",
    "2025-09-20 11:45:00 192.168.1.103 dave LOGIN_SUCCESS",
    "2025-09-20 12:00:00 198.51.100.99 unknown PORT_SCAN",
    "2025-09-20 12:00:10 198.51.100.99 unknown PORT_SCAN",
]

def level_log_forensics():
    cls()
    title = "Level 4 — Log Forensics"
    print("=" * len(title))
    print(title)
    print("=" * len(title))
    slow_print("Analyze the log snippet and identify suspicious events. You will be asked a few questions.")
    print()
    # Build a randomized log by injecting some noise
    logs = SAMPLE_LOGS.copy()
    random.shuffle(logs)
    # show logs
    print("Server logs (recent first):\n")
    for line in logs:
        print(line)
    print()
    # Q1: Which IP shows repeated failed logins?
    ip_candidates = [line.split()[2] for line in logs]
    counts = Counter()
    for line in logs:
        parts = line.split()
        if len(parts) >= 4 and parts[3].startswith("LOGIN_FAIL"):
            counts[parts[2]] += 1
    suspicious_ip = None
    if counts:
        suspicious_ip = counts.most_common(1)[0][0]
    q1 = input("Q1: Enter the IP that likely performed repeated failed login attempts: ").strip()
    pts = 0
    if q1 == suspicious_ip:
        print("Correct — repeated failed logins indicate brute-force attempts or credential stuffing.")
        pts += 10
    else:
        print(f"Not quite. A likely candidate was: {suspicious_ip}")
    # Q2: Which IP performed port scanning?
    port_scan_ips = set()
    for line in logs:
        if "PORT_SCAN" in line:
            port_scan_ips.add(line.split()[2])
    q2 = input("Q2: Enter an IP that performed a port scan (or 'none'): ").strip()
    if q2 in port_scan_ips:
        print("Correct — port scanning indicates reconnaissance.")
        pts += 10
    else:
        print(f"Expected one of: {', '.join(port_scan_ips) if port_scan_ips else 'none'}")
    # Q3: Which log entry looks like data exfiltration (file download followed by deletion)?
    suspicious_actions = []
    for line in logs:
        if "FILE_DOWNLOAD" in line or "FILE_DELETE" in line:
            suspicious_actions.append(line)
    print("\nQ3: Which entry (paste full line) looks like possible data exfiltration? (copy-paste)")
    q3 = input("Your answer: ").strip()
    matched = any(q3 == s for s in suspicious_actions)
    if matched:
        print("Good catch — suspicious file activity can indicate data theft or cleanup by an attacker.")
        pts += 10
    else:
        print("That wasn't one of the file activity lines. Example suspicious entries were:")
        for s in suspicious_actions:
            print("  ", s)
    G.add_score(pts)
    G.mark_done("Log Forensics")
    print(f"\nYou earned {pts} points. Total score: {G.score}")
    slow_print("\nLesson: Logs are vital. Look for repeated failures, unusual IP addresses, and file operations outside normal business hours.")
    input("\nPress Enter to continue...")

# --- Game Loop --------------------------------------------------------------

LEVELS = [
    ("Password Strength", level_password_strength),
    ("Phishing Detector", level_phishing_detector),
    ("Caesar Cipher", level_caesar_cipher),
    ("Log Forensics", level_log_forensics),
]

def show_menu():
    cls()
    print("=== CyberLearn — interactive terminal prototype ===")
    print()
    print(f"Score: {G.score}   Completed levels: {len(G.completed)}/{len(LEVELS)}")
    print()
    for i, (name, _) in enumerate(LEVELS, 1):
        status = "✓" if name in G.completed else " "
        print(f" {i}) [{status}] {name}")
    print(" 0) Quit")
    print()

def main():
    slow_print("Welcome to CyberLearn — learn cybersecurity by playing!\n", 0.005)
    while True:
        show_menu()
        choice = input("Select a level number to play (or 0 to quit, or 'r' to randomize): ").strip().lower()
        if choice == "0" or choice == "q":
            print("\nThanks for playing! Final score:", G.score)
            print("Completed:", ", ".join(G.completed) if G.completed else "none")
            break
        if choice == "r":
            # pick a random incomplete level
            incomplete = [lvl for lvl in LEVELS if lvl[0] not in G.completed]
            if not incomplete:
                print("You completed all levels!")
                input("Press Enter to continue...")
                continue
            name, fn = random.choice(incomplete)
            fn()
            continue
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(LEVELS):
                _, fn = LEVELS[idx]
                fn()
            else:
                print("Invalid number.")
        else:
            print("Type a number (e.g., 1) or 0 to quit.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted. Goodbye.")
        sys.exit(0)
