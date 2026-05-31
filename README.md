# Password Security Analyzer

A command-line cybersecurity portfolio project that evaluates password strength, detects common weaknesses, and provides actionable recommendations to improve security.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## Overview

Weak passwords remain one of the most exploited attack vectors. This tool helps users understand *why* a password is weak and how to strengthen it—without storing or transmitting credentials.

### Features

| Feature | Description |
|---------|-------------|
| **Length check** | Validates minimum and recommended password length |
| **Character diversity** | Detects uppercase, lowercase, digits, and special characters |
| **Repetition detection** | Flags consecutive or excessive repeated characters |
| **Common password list** | Compares against known breached/popular passwords |
| **Weak pattern detection** | Catches predictable strings (`123456`, `qwerty`, `password`, etc.) |
| **Security score** | Numeric rating from 0–100 |
| **Classification** | Labels: Very Weak → Very Strong |
| **Recommendations** | Tailored advice for improvement |

## Project Structure

```
password-security-analyzer/
├── main.py                 # CLI entry point
├── analyzer.py             # Core analysis logic
├── common_passwords.txt    # Dictionary of weak/common passwords
├── README.md
└── requirements.txt
```

## Requirements

- **Python 3.10+** (uses modern type hints)
- No external dependencies (standard library only)

## Installation

```bash
git clone https://github.com/yourusername/password-security-analyzer.git
cd password-security-analyzer
```

Verify Python version:

```bash
python3 --version
```

## Usage

### Interactive mode (hidden input)

```bash
python3 main.py
```

You will be prompted to enter a password. Input is masked for privacy.

### Pipe a password (automation / demos)

```bash
echo "MyS3cure!Pass2024" | python3 main.py
```

### Example output

```
========================================================
       PASSWORD SECURITY ANALYZER
       Cybersecurity Portfolio Project
========================================================

Enter a password to analyze:

--- Security Checks ---
  Length (18 chars)     : ✓ Pass
  Uppercase letters          : ✓ Pass
  Lowercase letters          : ✓ Pass
  Numbers                    : ✓ Pass
  Special characters         : ✓ Pass
  No excessive repetition    : ✓ Pass
  Not a common password      : ✓ Pass
  Weak patterns detected     : ✓ Pass

--- Security Score ---
  Score          : 84/100
  [█████████████████████████████████░░░░░░░]
  Classification : Very Strong

--- Recommendations ---
  1. Password looks solid. Consider a password manager and unique passwords per site.

========================================================
Analysis complete. Do not share passwords in production logs.
========================================================
```

### Weak password example

```bash
echo "password123" | python3 main.py
```

Expected: low score, **Very Weak** or **Weak** classification, failures on common-password and weak-pattern checks, and multiple recommendations.

## Scoring methodology

The security score (0–100) is computed from:

1. **Length** — longer passwords earn more points (12+ and 16+ characters are rewarded).
2. **Character classes** — points for uppercase, lowercase, digits, and symbols.
3. **Variety bonus** — extra points when all four character types are present.
4. **Uniqueness** — bonus for high ratio of unique characters.
5. **Penalties** — deductions for repetition, dictionary passwords, weak substrings, and sequential patterns.

| Score range | Classification |
|-------------|----------------|
| 0–19 | Very Weak |
| 20–39 | Weak |
| 40–59 | Medium |
| 60–79 | Strong |
| 80–100 | Very Strong |

## Security & privacy notes

- Passwords are analyzed **in memory only** and are not logged or saved.
- Use `getpass` for masked input in interactive terminals.
- This tool is for **education and awareness**—not a substitute for enterprise password policies, breach monitoring, or hardware security modules.
- Extend `common_passwords.txt` with your own deny-list as needed; keep lists out of version control if they are sensitive.

## Extending the project

Ideas for portfolio enhancements:

- [ ] Add unit tests with `pytest`
- [ ] Support batch analysis from a file (hashed passwords only)
- [ ] Export JSON report for CI integration
- [ ] Integrate [Have I Been Pwned](https://haveibeenpwned.com/API/v3) k-anonymity API (with API key)
- [ ] Estimate crack time using entropy calculations

## Author

Built as a cybersecurity portfolio demonstration project.

## License

MIT License — feel free to use and modify for learning and portfolio purposes.
