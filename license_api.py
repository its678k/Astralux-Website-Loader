from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import os
import psycopg2
import psycopg2.extras
import secrets

app = Flask(__name__)
CORS(app)

# ================================
# CONFIG
# ================================

DATABASE_URL = os.getenv("DATABASE_URL")  # Railway Postgres
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "Daniel2011.1")

# ================================
# DATABASE
# ================================

def get_db():
    return psycopg2.connect(DATABASE_URL, sslmode="require")

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        license_key TEXT PRIMARY KEY,
        hwid TEXT,
        discord_id TEXT,
        revoked BOOLEAN DEFAULT FALSE,
        hwid_resets INTEGER DEFAULT 1,
        created_at TIMESTAMP,
        activated_at TIMESTAMP
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS access_logs (
        id SERIAL PRIMARY KEY,
        license_key TEXT,
        hwid TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

init_db()

def log_access(license_key, hwid, ip):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO access_logs (license_key, hwid, ip_address, timestamp)
        VALUES (%s, %s, %s, %s)
    """, (license_key, hwid, ip, datetime.utcnow()))
    conn.commit()
    conn.close()

# ================================
# HEALTH
# ================================

@app.route("/health")
def health():
    return jsonify({"status": "online"}), 200

# ================================
# MC CLIENT — VALIDATE
# ================================

@app.route("/api/validate", methods=["POST"])
def validate():
    data = request.json or {}
    license_key = data.get("license_key", "").upper().strip()
    hwid = data.get("hwid", "").strip()
    ip = request.remote_addr

    if not license_key or not hwid:
        return jsonify({"valid": False, "error": "Missing license_key or hwid"}), 400

    conn = get_db()
    c = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    c.execute("SELECT * FROM licenses WHERE license_key=%s", (license_key,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"valid": False, "error": "License not found"}), 404

    if row["revoked"]:
        conn.close()
        return jsonify({"valid": False, "error": "License revoked"}), 403

    if not row["discord_id"]:
        conn.close()
        return jsonify({"valid": False, "error": "License not redeemed in Discord"}), 403

    if not row["hwid"]:
        c.execute("UPDATE licenses SET hwid=%s, activated_at=%s WHERE license_key=%s",
                  (hwid, datetime.utcnow(), license_key))
        conn.commit()
        log_access(license_key, hwid, ip)
        conn.close()
        return jsonify({"valid": True, "message": "HWID bound"}), 200

    if row["hwid"] == hwid:
        log_access(license_key, hwid, ip)
        conn.close()
        return jsonify({"valid": True, "message": "License valid"}), 200

    log_access(license_key, hwid, ip)
    conn.close()
    return jsonify({"valid": False, "error": "HWID mismatch"}), 403

# ================================
# DISCORD — REDEEM
# ================================

@app.route("/api/redeem", methods=["POST"])
def redeem():
    data = request.json or {}
    license_key = data.get("license_key", "").upper().strip()
    discord_id = data.get("discord_id", "").strip()

    if not license_key or not discord_id:
        return jsonify({"success": False, "error": "Missing data"}), 400

    conn = get_db()
    c = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    c.execute("SELECT * FROM licenses WHERE license_key=%s", (license_key,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"success": False, "error": "License not found"}), 404

    if row["revoked"]:
        conn.close()
        return jsonify({"success": False, "error": "License revoked"}), 403

    if row["discord_id"]:
        conn.close()
        return jsonify({"success": False, "error": "License already redeemed"}), 403

    c.execute("""
        UPDATE licenses
        SET discord_id=%s, activated_at=%s
        WHERE license_key=%s
    """, (discord_id, datetime.utcnow(), license_key))

    conn.commit()
    conn.close()

    return jsonify({"success": True}), 200

# ================================
# ADMIN AUTH
# ================================

def admin_ok(secret):
    return secret == ADMIN_SECRET

# ================================
# ADMIN — GENERATE
# ================================

@app.route("/api/generate", methods=["POST"])
def generate():
    data = request.json or {}
    secret = data.get("admin_secret", "")
    discord_id = data.get("discord_id")

    if not admin_ok(secret):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    license_key = f"ASTRALUX-{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"

    conn = get_db()
    c = conn.cursor()

    c.execute("""
        INSERT INTO licenses (license_key, discord_id, created_at)
        VALUES (%s, %s, %s)
    """, (license_key, discord_id, datetime.utcnow()))

    conn.commit()
    conn.close()

    return jsonify({"success": True, "license_key": license_key}), 200

# ================================
# ADMIN — REVOKE
# ================================

@app.route("/api/revoke", methods=["POST"])
def revoke():
    data = request.json or {}
    secret = data.get("admin_secret", "")
    license_key = data.get("license_key", "").upper()

    if not admin_ok(secret):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE licenses SET revoked=TRUE WHERE license_key=%s", (license_key,))
    conn.commit()
    conn.close()

    return jsonify({"success": True}), 200

# ================================
# ADMIN — HWID RESET
# ================================

@app.route("/api/hwid-reset", methods=["POST"])
def hwid_reset():
    data = request.json or {}
    secret = data.get("admin_secret", "")
    license_key = data.get("license_key", "").upper()

    if not admin_ok(secret):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_db()
    c = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    c.execute("SELECT hwid_resets FROM licenses WHERE license_key=%s", (license_key,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"success": False, "error": "License not found"}), 404

    if row["hwid_resets"] <= 0:
        conn.close()
        return jsonify({"success": False, "error": "No resets left"}), 403

    c.execute("""
        UPDATE licenses SET hwid=NULL, hwid_resets=hwid_resets-1
        WHERE license_key=%s
    """, (license_key,))

    conn.commit()
    conn.close()

    return jsonify({"success": True}), 200

# ================================
# ADMIN — CHECK SHARE
# ================================

@app.route("/api/check-share", methods=["POST"])
def check_share():
    data = request.json or {}
    secret = data.get("admin_secret", "")
    license_key = data.get("license_key", "").upper()

    if not admin_ok(secret):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_db()
    c = conn.cursor()

    c.execute("""
        SELECT DISTINCT hwid FROM access_logs WHERE license_key=%s
    """, (license_key,))
    hwids = [r[0] for r in c.fetchall() if r[0]]

    c.execute("""
        SELECT DISTINCT ip_address FROM access_logs WHERE license_key=%s
    """, (license_key,))
    ips = [r[0] for r in c.fetchall()]

    conn.close()

    return jsonify({
        "success": True,
        "unique_hwids": len(hwids),
        "unique_ips": len(ips),
        "hwids": hwids[:10],
        "status": "🚨 SHARING" if len(hwids) > 1 else "✅ CLEAN"
    }), 200

# ================================
# RUN
# ================================

if __name__ == "__main__":
    print("🚀 Astralux API running (PostgreSQL)")
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
