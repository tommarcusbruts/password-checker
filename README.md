# Password Intelligence Tool

A privacy-first Python Flask application for analyzing password strength, producing multiple hash formats, and checking password exposure against public breaches using the Have I Been Pwned (HIBP) k‑anonymity API.

Purpose: security auditing, demos, and learning. Do not store or log production passwords.

## Features

- Real-time strength guidance (zxcvbn integration recommended)
- Multi-hash generation: MD5, SHA1, SHA256, SHA512, bcrypt, Argon2
- HIBP breach check via k‑anonymity (/range/{prefix}) — only first 5 SHA1 characters sent
- Simple terminal/JSON results for breach detection
- Designed for local use, testing, and integration into tooling

## Tech Stack

- Python 3.11+
- Flask
- Libraries: hashlib, bcrypt, argon2-cffi, requests

## Quickstart

1. Clone repository
   git clone https://github.com/your-username/password-intelligence-tool.git
   cd password-intelligence-tool

2. Install dependencies
   pip install -r requirements.txt
   # or
   pip install flask requests bcrypt argon2-cffi

3. Run app
   python app.py

4. Open
   http://127.0.0.1:5000

## How it works (summary)

1. Password supplied to backend or CLI (do not transmit raw passwords to third parties).
2. Multiple hashes computed locally.
3. SHA1 prefix (first 5 chars) queried against HIBP /range endpoint.
4. Server compares returned suffixes to determine leak count.
5. Structured JSON result returned with status and exposure count.

## Security & Privacy

- k‑anonymity only: only SHA1 prefix (5 chars) is transmitted to HIBP.
- Full passwords are not sent to external services.
- Do not store, log, or transmit raw passwords in production.
- Run behind TLS and enforce rate limits and caching for production use.

## Deployment recommendations

- Use gunicorn behind Nginx
- Enforce HTTPS (Let’s Encrypt, Cloudflare, etc.)
- Add caching (Redis) for HIBP prefix lookups to reduce rate usage

## Development notes

- zxcvbn can be integrated for client-side strength scoring
- Can be extended with CLI, REST API endpoints, or local breach datasets for offline testing

## License

MIT License — free for personal and educational use. Attribution appreciated.

## Author

Tom (tommarcusbrut)