# Authify 🔐

> A **secure, offline, privacy-first TOTP/HOTP authenticator** comparable to Google Authenticator — fully open-source.

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Security](https://img.shields.io/badge/Encryption-AES--256--GCM-critical)
![UI](https://img.shields.io/badge/UI-PyQt6-blueviolet)

---

## ✨ Features

| Feature | Details |
|---------|---------|
| **TOTP / HOTP** | RFC 6238 / RFC 4226 — codes match Google Authenticator exactly |
| **Multiple algorithms** | HMAC-SHA1, HMAC-SHA256, HMAC-SHA512 |
| **6 or 8 digit codes** | Configurable per account |
| **Custom periods** | 30 s default, fully configurable |
| **AES-256-GCM encryption** | Every secret encrypted at rest |
| **PBKDF2 key derivation** | 480 000 iterations, SHA-256 |
| **Master password vault** | Unlock on startup; auto-lock after 5 min inactivity |
| **QR code scanning** | Webcam live scan or load from image file (optional) |
| **otpauth:// URI parsing** | Full RFC-compliant parser |
| **Clipboard auto-clear** | Copied code erased after 15 seconds |
| **Dark / light theme** | Catppuccin-inspired palette |
| **Encrypted backup** | Export / import AES-256-GCM encrypted JSON |
| **No cloud, no telemetry** | 100 % offline, no network calls |
| **Cross-platform** | Windows, macOS, Linux |

---

## 📦 Installation

### Prerequisites

- Python **3.11** or newer
- pip

### 1. Clone

````bash
git clone https://github.com/your-org/authify.git
cd authify
````

### 2. Create a virtual environment (recommended)

````bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
````

### 3. Install dependencies

````bash
pip install -r requirements.txt
````

#### Optional: enable QR code scanning

````bash
pip install opencv-python pyzbar
````

> **Windows note:** `pyzbar` on Windows requires the [ZBar DLL](https://sourceforge.net/projects/zbar/).

---

## 🚀 Running

````bash
python main.py
````

Or, if installed as a package:

````bash
pip install -e .
authify
````

---

## 🗂 Project Structure

````
authify/
│
├── core/
│   ├── totp.py        ← RFC 6238 TOTP engine
│   ├── hotp.py        ← RFC 4226 HOTP engine
│   ├── crypto.py      ← AES-256-GCM + PBKDF2 key derivation
│   └── utils.py       ← Base32 helpers, validation, formatting
│
├── storage/
│   ├── database.py    ← SQLite + field-level AES-256-GCM encryption
│   └── encryption.py  ← FieldEncryptor
│
├── ui/
│   ├── main_window.py     ← Main application window
│   ├── add_account.py     ← Add / edit account dialog
│   ├── unlock_dialog.py   ← Master password prompt
│   ├── qr_scan_dialog.py  ← Live webcam QR scanner dialog
│   └── styles.py          ← Dark & light Qt stylesheets
│
├── qr/
│   ├── scanner.py     ← Webcam / file QR scanning
│   └── parser.py      ← otpauth:// URI parser & builder
│
├── main.py            ← Entry point
├── requirements.txt
├── pyproject.toml
└── README.md
````

---

## 🔐 Security Architecture

Every secret is encrypted at rest with **AES-256-GCM**.  
The master key is derived from your password using **PBKDF2-HMAC-SHA256** (480 000 iterations).  
The database stores only ciphertext — your password is never written to disk.

### Threat model

| Attack | Mitigation |
|--------|-----------|
| Database file stolen | AES-256-GCM — unreadable without master password |
| Brute-force password | PBKDF2 — 480k iterations makes guessing expensive |
| Clipboard snooping | Auto-clear after 15 seconds |
| Inactivity | Auto-lock after 5 minutes |
| Network exfiltration | Zero network code |

---

## 🧪 Running Tests

````bash
pip install pytest pytest-qt
pytest tests/ -v
````

---

## 🛠 Development

````bash
pip install -e ".[dev]"
ruff check authify/
ruff format authify/
````

---

## 📥 Backup & Restore

- **Export** — toolbar → Export → choose password → AES-256-GCM encrypted JSON
- **Import** — toolbar → Import → enter backup password → accounts added to vault

---

## 🤝 Contributing

1. Fork the repo and create a feature branch.
2. Follow PEP 8 and add type hints everywhere.
3. Write tests for new functionality.
4. Open a pull request with a clear description.

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements

- [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) — TOTP specification
- [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) — HOTP specification
- [Catppuccin](https://github.com/catppuccin/catppuccin) — colour palette
- [PyQt6](https://www.riverbankcomputing.com/software/pyqt/) — Qt bindings
- [cryptography](https://cryptography.io/) — AES-GCM & PBKDF2