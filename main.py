#!/usr/bin/env python3
"""
password-generator
Advanced Password Generator with strength checker,
bulk generation, history, and password policies.

Author: Sameer Bansal
Reg No: RA2311032010061
College: SRM Institute of Science and Technology
Branch: B.Tech CSE (IoT) | Batch: 2023-2027
"""

import random
import string
import os
import json
import datetime
import re
import math
from typing import Optional

# ── Constants ─────────────────────────────────────────────
HISTORY_FILE = "output/password_history.json"

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"

CHAR_SETS = {
    "uppercase": string.ascii_uppercase,  # A-Z
    "lowercase": string.ascii_lowercase,  # a-z
    "digits": string.digits,  # 0-9
    "symbols": "!@#$%^&*()_+-=[]{}|;:,.<>?",  # Special chars
    "ambiguous": "O0Il1",  # Easily confused chars
}

# Common weak passwords to flag
COMMON_PASSWORDS = {
    "password",
    "123456",
    "password123",
    "admin",
    "letmein",
    "qwerty",
    "abc123",
    "monkey",
    "master",
    "dragon",
    "111111",
    "baseball",
    "iloveyou",
    "sunshine",
    "princess",
}

PRESETS = {
    "1": {
        "name": "PIN (4-digit)",
        "length": 4,
        "upper": False,
        "lower": False,
        "digits": True,
        "symbols": False,
    },
    "2": {
        "name": "Simple (8-char)",
        "length": 8,
        "upper": True,
        "lower": True,
        "digits": True,
        "symbols": False,
    },
    "3": {
        "name": "Strong (12-char)",
        "length": 12,
        "upper": True,
        "lower": True,
        "digits": True,
        "symbols": True,
    },
    "4": {
        "name": "Very Strong (16)",
        "length": 16,
        "upper": True,
        "lower": True,
        "digits": True,
        "symbols": True,
    },
    "5": {
        "name": "Ultra Secure (32)",
        "length": 32,
        "upper": True,
        "lower": True,
        "digits": True,
        "symbols": True,
    },
    "6": {
        "name": "Memorable (words)",
        "length": 0,
        "upper": True,
        "lower": True,
        "digits": True,
        "symbols": False,
    },
    "7": {
        "name": "Custom",
        "length": 0,
        "upper": None,
        "lower": None,
        "digits": None,
        "symbols": None,
    },
}


# ── Strength Checker ──────────────────────────────────────
def check_strength(password: str) -> tuple[int, str, str]:
    """
    Returns (score 0-100, label, color)
    """
    if password.lower() in COMMON_PASSWORDS:
        return 0, "COMPROMISED", RED

    score = 0
    feedback = []

    length = len(password)
    if length >= 8:
        score += 10
    if length >= 12:
        score += 15
    if length >= 16:
        score += 15
    if length >= 24:
        score += 10
    if length < 8:
        feedback.append("Too short (min 8)")

    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    has_ambig = any(c in CHAR_SETS["ambiguous"] for c in password)

    if has_upper:
        score += 10
    else:
        feedback.append("Add uppercase letters")
    if has_lower:
        score += 10
    else:
        feedback.append("Add lowercase letters")
    if has_digit:
        score += 10
    else:
        feedback.append("Add numbers")
    if has_symbol:
        score += 20
    else:
        feedback.append("Add symbols for extra strength")

    # Entropy bonus
    charset_size = 0
    if has_upper:
        charset_size += 26
    if has_lower:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 32
    if charset_size > 0:
        entropy = length * math.log2(charset_size)
        if entropy >= 60:
            score += 10
        if entropy >= 80:
            score += 10

    # Penalty for patterns
    if re.search(r"(.)\1{2,}", password):  # 3+ repeated chars
        score -= 10
        feedback.append("Avoid repeated characters")
    if re.search(r"(012|123|234|345|456|567|678|789|890)", password):
        score -= 10
        feedback.append("Avoid sequential numbers")
    if re.search(r"(abc|bcd|cde|def|efg|fgh|ghi|hij)", password.lower()):
        score -= 10
        feedback.append("Avoid sequential letters")

    score = max(0, min(100, score))

    if score >= 80:
        label, color = "VERY STRONG 🔒", GREEN
    elif score >= 60:
        label, color = "STRONG 🛡️", CYAN
    elif score >= 40:
        label, color = "MODERATE ⚠️", YELLOW
    elif score >= 20:
        label, color = "WEAK ❌", RED
    else:
        label, color = "VERY WEAK 💀", RED

    return score, label, color


def strength_bar(score: int) -> str:
    filled = score // 5
    empty = 20 - filled
    if score >= 80:
        color = GREEN
    elif score >= 60:
        color = CYAN
    elif score >= 40:
        color = YELLOW
    else:
        color = RED
    return f"{color}{'█' * filled}{'░' * empty}{RESET} {score}/100"


def crack_time(password: str) -> str:
    """Estimate time to crack at 1 billion guesses/sec"""
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    charset = 0
    if has_upper:
        charset += 26
    if has_lower:
        charset += 26
    if has_digit:
        charset += 10
    if has_symbol:
        charset += 32

    if charset == 0:
        return "instantly"

    combinations = charset ** len(password)
    guesses_per_sec = 1_000_000_000  # 1 billion/sec

    seconds = combinations / guesses_per_sec
    if seconds < 1:
        return f"{GREEN}instantly{RESET}"
    if seconds < 60:
        return f"{RED}{seconds:.0f} seconds{RESET}"
    if seconds < 3600:
        return f"{RED}{seconds/60:.0f} minutes{RESET}"
    if seconds < 86400:
        return f"{YELLOW}{seconds/3600:.0f} hours{RESET}"
    if seconds < 31536000:
        return f"{YELLOW}{seconds/86400:.0f} days{RESET}"
    if seconds < 3.15e9:
        return f"{CYAN}{seconds/31536000:.0f} years{RESET}"
    if seconds < 3.15e13:
        return f"{GREEN}{seconds/3.15e9:.0f} thousand years{RESET}"
    return f"{GREEN}millions of years 🔒{RESET}"


# ── Password Generator ────────────────────────────────────
def build_charset(
    upper: bool, lower: bool, digits: bool, symbols: bool, no_ambiguous: bool = False
) -> str:
    charset = ""
    if upper:
        charset += CHAR_SETS["uppercase"]
    if lower:
        charset += CHAR_SETS["lowercase"]
    if digits:
        charset += CHAR_SETS["digits"]
    if symbols:
        charset += CHAR_SETS["symbols"]
    if no_ambiguous:
        charset = "".join(c for c in charset if c not in CHAR_SETS["ambiguous"])
    return charset


def generate_password(
    length: int,
    upper: bool,
    lower: bool,
    digits: bool,
    symbols: bool,
    no_ambiguous: bool = False,
) -> Optional[str]:
    charset = build_charset(upper, lower, digits, symbols, no_ambiguous)
    if not charset:
        return None

    # Guarantee at least one char from each selected set
    mandatory: list[str] = []
    if upper:
        src = "".join(
            c
            for c in CHAR_SETS["uppercase"]
            if not no_ambiguous or c not in CHAR_SETS["ambiguous"]
        )
        if src:
            mandatory.append(random.choice(src))
    if lower:
        src = "".join(
            c
            for c in CHAR_SETS["lowercase"]
            if not no_ambiguous or c not in CHAR_SETS["ambiguous"]
        )
        if src:
            mandatory.append(random.choice(src))
    if digits:
        src = "".join(
            c
            for c in CHAR_SETS["digits"]
            if not no_ambiguous or c not in CHAR_SETS["ambiguous"]
        )
        if src:
            mandatory.append(random.choice(src))
    if symbols:
        mandatory.append(random.choice(CHAR_SETS["symbols"]))

    remaining = length - len(mandatory)
    if remaining < 0:
        remaining = 0

    password_chars = mandatory + random.choices(charset, k=remaining)
    random.shuffle(password_chars)
    return "".join(password_chars)


def generate_memorable() -> str:
    """Generate a memorable passphrase: Word+Number+Symbol+Word"""
    words = [
        "Tiger",
        "Mango",
        "Rocket",
        "Ocean",
        "Flame",
        "Storm",
        "Eagle",
        "Pixel",
        "Comet",
        "Blaze",
        "Frost",
        "Solar",
        "Brave",
        "Swift",
        "Ninja",
        "Cyber",
        "Alpha",
        "Delta",
        "Prime",
        "Force",
        "Lunar",
        "Sigma",
        "Titan",
        "Nova",
    ]
    symbols = "!@#$%^&*"
    w1 = random.choice(words)
    w2 = random.choice(words)
    num = random.randint(10, 99)
    sym = random.choice(symbols)
    return f"{w1}{num}{sym}{w2}"


# ── History Manager ───────────────────────────────────────
class HistoryManager:
    def __init__(self) -> None:
        os.makedirs("output", exist_ok=True)
        self.history: list = self._load()

    def _load(self) -> list:
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE) as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _save(self) -> None:
        with open(HISTORY_FILE, "w") as f:
            json.dump(self.history[-50:], f, indent=2)  # Keep last 50

    def add(
        self, password: str, label: str, score: int, preset: str = "Custom"
    ) -> None:
        self.history.append(
            {
                "password": password,
                "strength": label,
                "score": score,
                "preset": preset,
                "length": len(password),
                "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
        self._save()

    def show(self, last: int = 10) -> None:
        recent = self.history[-last:]
        if not recent:
            print(f"  {YELLOW}No history yet.{RESET}")
            return
        print(f"\n  {BOLD}📋 LAST {len(recent)} GENERATED PASSWORDS{RESET}")
        print("  " + "─" * 58)
        print(f"  {'#':<3} {'Password':<34} {'Len':<5} {'Score':<7} Strength")
        print("  " + "─" * 58)
        for i, h in enumerate(reversed(recent), 1):
            _, _, color = check_strength(h["password"])
            print(
                f"  {i:<3} {h['password']:<34} {h['length']:<5} "
                f"{h['score']:<7} {color}{h['strength']}{RESET}"
            )


# ── Display ───────────────────────────────────────────────
def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def display_banner() -> None:
    print("=" * 54)
    print("       🔐 ADVANCED PASSWORD GENERATOR")
    print("       Author : Sameer Bansal | RA2311032010061")
    print("       College: SRMIST Kattankulathur")
    print("=" * 54)


def display_menu() -> None:
    print(f"""
  {BOLD}OPTIONS{RESET}
  [1]  Generate password (preset)
  [2]  Custom password
  [3]  Memorable passphrase
  [4]  Bulk generate (multiple passwords)
  [5]  Check password strength
  [6]  View history
  [7]  Clear history
  [q]  Quit
""")


def display_result(password: str, preset_name: str, hm: HistoryManager) -> None:
    score, label, color = check_strength(password)
    ct = crack_time(password)

    print(f"\n  ┌{'─' * 50}┐")
    print(f"  │  🔑 Generated Password                           │")
    print(f"  │{'─' * 50}│")
    print(f"  │  {BOLD}{CYAN}{password}{RESET}")
    print(f"  │{'─' * 50}│")
    print(f"  │  📏 Length     : {len(password)} characters")
    print(f"  │  💪 Strength   : {color}{BOLD}{label}{RESET}")
    print(f"  │  📊 Score      : {strength_bar(score)}")
    print(f"  │  ⏱️  Crack Time : {ct}")
    print(f"  │  🏷️  Preset     : {preset_name}")
    print(f"  └{'─' * 50}┘")

    hm.add(password, label, score, preset_name)


def check_password_interactive(hm: HistoryManager) -> None:
    password = input("\n  Enter password to check: ").strip()
    if not password:
        return

    score, label, color = check_strength(password)
    ct = crack_time(password)

    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    print(f"\n  {'─' * 48}")
    print(f"  🔍 STRENGTH ANALYSIS")
    print(f"  {'─' * 48}")
    print(f"  Password    : {BOLD}{'*' * len(password)}{RESET} ({len(password)} chars)")
    print(f"  Strength    : {color}{BOLD}{label}{RESET}")
    print(f"  Score       : {strength_bar(score)}")
    print(f"  Crack Time  : {ct}")
    print(f"  {'─' * 48}")
    print(f"  Uppercase   : {'✅' if has_upper  else '❌'}")
    print(f"  Lowercase   : {'✅' if has_lower  else '❌'}")
    print(f"  Numbers     : {'✅' if has_digit  else '❌'}")
    print(f"  Symbols     : {'✅' if has_symbol else '❌'}")
    print(f"  Length ≥ 12 : {'✅' if len(password) >= 12 else '❌'}")
    print(f"  Length ≥ 16 : {'✅' if len(password) >= 16 else '❌'}")

    if password.lower() in COMMON_PASSWORDS:
        print(f"\n  {RED}🚨 WARNING: This is a commonly used password!{RESET}")
        print(f"  {RED}   Change it immediately!{RESET}")


def preset_generate(hm: HistoryManager) -> None:
    print(f"\n  {BOLD}SELECT PRESET{RESET}")
    print("  " + "─" * 42)
    for k, p in PRESETS.items():
        if p["length"] > 0:
            print(f"  [{k}] {p['name']}")
        elif p["name"] == "Memorable (words)":
            print(f"  [{k}] {p['name']}")
        else:
            print(f"  [{k}] {p['name']}")

    choice = input("\n  Choose preset [1-7]: ").strip()
    if choice not in PRESETS:
        print(f"  {YELLOW}⚠️  Invalid. Using Strong (12-char).{RESET}")
        choice = "3"

    p = PRESETS[choice]

    if choice == "6":
        password = generate_memorable()
        display_result(password, p["name"], hm)
        return

    if choice == "7":
        custom_generate(hm)
        return

    no_ambig = (
        input("  Exclude ambiguous chars (O,0,I,l,1)? [y/n]: ").strip().lower() == "y"
    )

    password = generate_password(
        p["length"], p["upper"], p["lower"], p["digits"], p["symbols"], no_ambig
    )
    if password:
        display_result(password, p["name"], hm)
    else:
        print(f"  {RED}❌ Could not generate password.{RESET}")


def custom_generate(hm: HistoryManager) -> None:
    print(f"\n  {BOLD}CUSTOM PASSWORD{RESET}")
    print("  " + "─" * 40)
    try:
        length = int(input("  Length (8-128): ").strip() or "16")
        length = max(4, min(128, length))
        upper = input("  Include UPPERCASE? [y/n]: ").strip().lower() != "n"
        lower = input("  Include lowercase? [y/n]: ").strip().lower() != "n"
        digits = input("  Include numbers?  [y/n]: ").strip().lower() != "n"
        symbols = input("  Include symbols?  [y/n]: ").strip().lower() == "y"
        no_amb = input("  Exclude ambiguous chars? [y/n]: ").strip().lower() == "y"

        password = generate_password(length, upper, lower, digits, symbols, no_amb)
        if password:
            display_result(password, "Custom", hm)
        else:
            print(f"  {RED}❌ Select at least one character set.{RESET}")
    except ValueError:
        print(f"  {RED}❌ Invalid input.{RESET}")


def bulk_generate(hm: HistoryManager) -> None:
    print(f"\n  {BOLD}BULK GENERATE{RESET}")
    print("  " + "─" * 40)
    try:
        count = int(input("  How many passwords? (1-50): ").strip() or "5")
        count = max(1, min(50, count))
        length = int(input("  Length: ").strip() or "16")
        length = max(4, min(128, length))

        print(f"\n  {BOLD}Generated {count} passwords:{RESET}")
        print("  " + "─" * 54)
        print(f"  {'#':<4} {'Password':<36} {'Score':<6} Strength")
        print("  " + "─" * 54)

        for i in range(1, count + 1):
            pwd = generate_password(length, True, True, True, True)
            if pwd:
                score, label, color = check_strength(pwd)
                print(f"  {i:<4} {pwd:<36} {score:<6} {color}{label}{RESET}")
                hm.add(pwd, label, score, "Bulk")

    except ValueError:
        print(f"  {RED}❌ Invalid input.{RESET}")


# ── Main ──────────────────────────────────────────────────
def main() -> None:
    clear()
    display_banner()

    hm = HistoryManager()

    print(f"\n  {GREEN}✅ Password Generator Ready!{RESET}")
    print(f"  📁 History saved to: {HISTORY_FILE}")
    print(f"  📋 Previous sessions: {len(hm.history)} passwords generated")

    display_menu()

    while True:
        try:
            choice = input("\n  Enter option: ").strip().lower()

            if choice == "q":
                print(f"\n  👋 Goodbye! Stay secure, {BOLD}Sameer{RESET}!")
                print(f"  🔐 Remember: Never reuse passwords!")
                break
            elif choice == "1":
                preset_generate(hm)
            elif choice == "2":
                custom_generate(hm)
            elif choice == "3":
                pwd = generate_memorable()
                display_result(pwd, "Memorable", hm)
            elif choice == "4":
                bulk_generate(hm)
            elif choice == "5":
                check_password_interactive(hm)
            elif choice == "6":
                hm.show()
            elif choice == "7":
                confirm = input("  ⚠️  Clear all history? [y/n]: ").strip().lower()
                if confirm == "y":
                    hm.history = []
                    hm._save()
                    print(f"  {GREEN}✅ History cleared.{RESET}")
            elif choice == "menu":
                display_menu()
            else:
                print("  ⚠️  Invalid option. Type 'menu' to see options.")

        except KeyboardInterrupt:
            print("\n\n  👋 Goodbye!")
            break


if __name__ == "__main__":
    main()
