# 🔐 CipherX Bot

Telegram bot for encryption, decryption, and hashing.

## Features

- **🔐 Encrypt Text** — AES-256, Fernet, Base64, ROT13, Caesar
- **🔓 Decrypt Text** — All supported methods
- **#️⃣ Hash Text** — SHA-256, SHA-512, MD5, SHA-1, SHA3, BLAKE2
- **HMAC** — SHA-256, SHA-512, SHA-1, MD5
- **🔑 Generate Password** — Cryptographically secure, 8-128 chars
- **📁📂 File Encryption/Decryption** — AES-256-GCM, max 20 MB

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[test]"
cp .env.example .env  # Add your BOT_TOKEN
```

## Run

```bash
.venv/bin/python -m cryptobot
```

## Tests

```bash
.venv/bin/pytest tests/ -v
```

## Security

- All processing is server-side and ephemeral
- No text or files are stored after response
- Passwords are never logged
- Uses PBKDF2-SHA256 (600k iterations) for key derivation
- AES-256-GCM for file encryption

## License

MIT
