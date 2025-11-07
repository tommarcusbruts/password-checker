from flask import Flask, request, jsonify,render_template
import hashlib
import requests
import bcrypt
from argon2 import PasswordHasher

app = Flask(__name__)

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"
ph = PasswordHasher()


def compute_hashes(password: str):
    """Return common hashes (uppercase hex)."""
    p = password.encode("utf-8")
    return {
        "md5": hashlib.md5(p).hexdigest().upper(),
        "sha1": hashlib.sha1(p).hexdigest().upper(),
        "sha256": hashlib.sha256(p).hexdigest().upper(),
        "sha512": hashlib.sha512(p).hexdigest().upper(),
        # bcrypt and argon2 are salted, so generate new random ones each call
        "bcrypt": bcrypt.hashpw(p, bcrypt.gensalt()).decode(),
        "argon2": ph.hash(password),
    }


def hibp_check_sha1(sha1_hex: str):
    """Check password hash in HIBP."""
    prefix = sha1_hex[:5]
    suffix = sha1_hex[5:]
    headers = {"User-Agent": "PasswordLeakChecker"}
    resp = requests.get(HIBP_RANGE_URL.format(prefix), headers=headers, timeout=10)
    if resp.status_code != 200:
        return {"error": f"HIBP failed: {resp.status_code}"}
    count = 0
    for line in resp.text.splitlines():
        h, c = line.split(":")
        if h.upper() == suffix:
            count = int(c)
            break
    return {"found": count > 0, "count": count}


@app.route("/api/check", methods=["POST"])
def check_password():
    data = request.get_json()
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "Missing password"}), 400

    hashes = compute_hashes(password)
    hibp = hibp_check_sha1(hashes["sha1"])

    return jsonify({"hashes": hashes, "hibp": hibp})


@app.route("/")
def home():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
