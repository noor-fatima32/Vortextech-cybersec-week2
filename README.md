# VortexTech Cyber Security Internship — Week 2

## Hands-On with Basic Security Tools

This project completes the Week 2 Beginner-Intermediate task from the VortexTech Cyber Security Internship.

### Objective

The assignment requires two practical security exercises:

1. A Python password-strength evaluator.
2. A basic local-network port scan using Nmap.

It also requires documenting the results and explaining the real-world security risks of weak passwords and unnecessary open ports.

## Project Structure

```text
vortextech-cybersec-week2/
├── password_checker.py
├── test_password_checker.py
├── port_scan_results.md
├── reflection.md
└── README.md
```

## Part 1 — Password Strength Evaluator

### Checks performed

The Python script checks:

- Minimum length of 8 characters (with a bonus note at 12+)
- Uppercase letters
- Lowercase letters
- Numbers
- Special characters
- Extremely common passwords such as `123456`, `password`, and `qwerty` - both as an **exact match** and as a **substring** (so `Password1!` is still caught, not just `password`)
- Predictable patterns: keyboard walks (`qwerty`, `asdf`), sequential runs (`1234`, `abcd`), and repeated characters (`aaaa`)

A password that is an exact match for a known common password is always rated **Weak**, no matter what else is true about it. A password that contains a common word or a predictable pattern is capped at **Medium**, even if it technically contains an uppercase letter, lowercase letter, number, and special character - passing the letter of the character-variety rules shouldn't be enough to earn "Strong" if the password is still an easy first guess for an attacker.

Every check (length, uppercase, lowercase, number, special) always reports which specific requirement is missing, so the feedback tells you exactly what to add - this applies even when the password is also flagged as common or predictable.

### Run the program

Python 3.7+ is required (the script uses `from __future__ import annotations`, which lets its modern type hints run on older Python 3 versions; `getpass` itself has been part of the standard library since Python 2).

```bash
python password_checker.py
```

On some systems, use:

```bash
python3 password_checker.py
```

When run in a real terminal, your typed password is hidden (via `getpass`) instead of echoed to the screen. If `getpass` isn't supported by your environment (e.g. some IDE consoles), the script automatically falls back to plain visible input.

To see the evaluator run against a fixed set of example passwords without typing anything (useful for the "test with several example passwords" step, and for grading):

```bash
python password_checker.py --demo
```

To run the automated test suite that asserts the ratings and feedback are correct:

```bash
python test_password_checker.py
```

### Example test cases

| Password | Actual rating | Reason |
|---|---|---|
| `123456` | Weak | Exact common password |
| `password` | Weak | Exact common password |
| `hello` | Weak | Too short and lacks variety |
| `aaaaaaaa` | Weak | Repeated-character run |
| `Password1` | Medium | Contains the common word "password"; also missing a special character |
| `Password1!` | Medium | Still contains the common word "password", even with all five character types present |
| `Qwerty123!` | Medium | Contains "qwerty" and is a keyboard walk, despite passing all five character checks |
| `Tr0ub4dor&3!!` | Strong | No common word, no predictable pattern, all character types, 12+ characters |

> Note: This is an educational, rule-based password checker, not a replacement for modern password-auditing tools. It does not compute true entropy or check against a full breached-password database (e.g. Have I Been Pwned) - it only recognizes a small built-in list of common passwords/patterns.

## Part 2 — Nmap Local Port Scan

### Safety requirement

Only scan systems you own or have explicit permission to test. The Week 2 brief specifically permits scanning your own machine with localhost.

### Install Nmap

Download Nmap from:

https://nmap.org/

Verify installation:

```bash
nmap --version
```

### Scan your own computer

Run:

```bash
nmap localhost
```

or:

```bash
nmap 127.0.0.1
```

Do **not** scan third-party networks.

If you own the entire home network and have permission to test it, the assignment also gives the example:

```bash
nmap 192.168.1.0/24
```

Only use the network-range command when that network belongs to you or you have explicit authorization.

### Documenting results

Copy your actual Nmap output into `port_scan_results.md`.

For every open port, record:

- Port number
- Protocol
- State
- Detected service
- What the service normally does
- Whether the service is expected on your machine

Do not invent scan results. The actual open ports depend on which services are running on the computer at scan time.

## Part 3 — Reflection

See `reflection.md` for the required short reflection connecting weak passwords and open ports to real-world security risk.

## Important

Do not put real passwords, API keys, tokens, private IP information, or other secrets into the public repository.

---

# 👩‍💻 Learning Outcomes

Through this assignment, I practiced:

* Basic password security concepts
* Python conditional logic
* Character and string validation
* Common-password detection
* Network reconnaissance fundamentals
* Nmap command-line usage
* Port and service identification
* Basic attack-surface analysis
* Responsible and authorized security testing

---

## 📌 Disclaimer

This project is created for **educational and cybersecurity training purposes** as part of the VortexTech Cyber Security Internship.

Network scanning should only be performed against systems that you own or have explicit authorization to test.

No unauthorized exploitation or intrusive activity is performed as part of this project.