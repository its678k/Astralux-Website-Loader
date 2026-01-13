from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
import sqlite3
from datetime import datetime
import os
import secrets
import requests

app = Flask(__name__)
CORS(app)

DATABASE = 'licenses.db'

# ======================
# DISCORD CONFIG
# ======================

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = "http://localhost:5000/api/discord/callback"

DISCORD_GUILD_ID = "YOUR_GUILD_ID"
REQUIRED_ROLE_ID = "YOUR_ROLE_ID"
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")

# ======================
# DATABASE
# ======================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            license_key TEXT PRIMARY KEY,
            hwid TEXT,
            discord_id TEXT,
            revoked INTEGER DEFAULT 0,
            hwid_resets INTEGER DEFAULT 1,
            created_at TEXT,
            activated_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ======================
# UTILS
# ======================

def log_access(license_key, hwid, ip):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO access_logs (license_key, hwid, ip_address, timestamp)
        VALUES (?, ?, ?, ?)
    """, (license_key, hwid, ip, datetime.now().isoformat()))
    conn.commit()
    conn.close()

# ======================
# HEALTH
# ======================

@app.route('/health')
def health():
    return jsonify({"status": "online"})

# ======================
# DISCORD OAUTH
# ======================

@app.route('/api/discord/login')
def discord_login():
    state = secrets.token_urlsafe(16)

    url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        "&response_type=code"
        "&scope=identify"
        f"&redirect_uri={DISCORD_REDIRECT_URI}"
        f"&state={state}"
    )

    return jsonify({"url": url})

@app.route('/api/discord/callback')
def discord_callback():
    code = request.args.get("code")
    if not code:
        return "Missing code", 400

    token = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": DISCORD_REDIRECT_URI
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    ).json()

    access_token = token.get("access_token")
    if not access_token:
        return "OAuth failed", 401

    user = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {access_token}"}
    ).json()

    discord_id = user["id"]

    member = requests.get(
        f"https://discord.com/api/guilds/{DISCORD_GUILD_ID}/members/{discord_id}",
        headers={"Authorization": f"Bot {BOT_TOKEN}"}
    )

    if member.status_code != 200:
        return "Join the Discord server first", 403

    roles = member.json().get("roles", [])
    if REQUIRED_ROLE_ID not in roles:
        return "Missing required role", 403

    return f"""
    <html>
    <body style="font-family:sans-serif;text-align:center">
        <h2>✅ Discord Linked</h2>
        <p>You may return to the launcher.</p>
        <script>
          window.opener.postMessage({{
            discord_id: "{discord_id}"
          }}, "*");
          window.close();
        </script>
    </body>
    </html>
    """

# ======================
# LICENSE VALIDATION
# ======================

@app.route('/api/validate', methods=['POST'])
def validate():
    data = request.json
    license_key = data.get("license_key", "").upper()
    hwid = data.get("hwid", "")
    discord_id = data.get("discord_id", "")
    ip = request.remote_addr

    if not license_key or not hwid or not discord_id:
        return jsonify({"valid": False, "error": "Missing data"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM licenses WHERE license_key=?", (license_key,))
    row = c.fetchone()

    if not row:
        return jsonify({"valid": False, "error": "Invalid license"}), 404

    if row["revoked"]:
        return jsonify({"valid": False, "error": "License revoked"}), 403

    if row["discord_id"] and row["discord_id"] != discord_id:
        return jsonify({"valid": False, "error": "License bound to another Discord"}), 403

    if not row["discord_id"]:
        c.execute(
            "UPDATE licenses SET discord_id=?, activated_at=? WHERE license_key=?",
            (discord_id, datetime.now().isoformat(), license_key)
        )
        conn.commit()

    if not row["hwid"]:
        c.execute("UPDATE licenses SET hwid=? WHERE license_key=?", (hwid, license_key))
        conn.commit()
        return jsonify({"valid": True, "message": "HWID bound"})

    if row["hwid"] != hwid:
        return jsonify({"valid": False, "error": "HWID mismatch"}), 403

    return jsonify({"valid": True, "message": "License valid"})

# ======================
# ADMIN
# ======================

ADMIN_SECRET = os.getenv("ADMIN_SECRET", "CHANGE_ME")

@app.route('/api/generate', methods=['POST'])
def generate():
    data = request.json
    if data.get("admin_secret") != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    key = f"ASTRALUX-{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"

    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO licenses (license_key, created_at) VALUES (?, ?)",
        (key, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

    return jsonify({"license_key": key})

# ======================
# RUN
# ======================

if __name__ == "__main__":
    print("🚀 Astralux API running")
    app.run(host="0.0.0.0", port=5000)
