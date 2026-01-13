# ============================================
# ASTRALUX LICENSE API - PostgreSQL Version
# File: license_api.py
# ============================================

from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)  # Allow MC client requests

# ==============================
# DATABASE CONFIG
# ==============================
DATABASE_URL = os.getenv("DATABASE_URL")  # Must be set in Railway
if not DATABASE_URL:
    raise RuntimeError("🚨 DATABASE_URL not set! Add PostgreSQL plugin in Railway and set DATABASE_URL.")

ADMIN_SECRET = os.getenv('ADMIN_SECRET', 'Daniel2011.1')  # Must match Discord bot

# ==============================
# DATABASE HELPERS
# ==============================

def get_db():
    """Returns a new connection to the Postgres database"""
    return psycopg2.connect(DATABASE_URL, sslmode="require", cursor_factory=RealDictCursor)

def init_db():
    """Create required tables if they don't exist"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            license_key TEXT PRIMARY KEY,
            hwid TEXT,
            discord_id TEXT,
            revoked BOOLEAN DEFAULT FALSE,
            hwid_resets INT DEFAULT 1,
            created_at TIMESTAMP,
            activated_at TIMESTAMP
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS access_logs (
            id SERIAL PRIMARY KEY,
            license_key TEXT REFERENCES licenses(license_key),
            hwid TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP
        );
    """)
    conn.commit()
    cur.close()
    conn.close()
    print("✅ Database initialized")

def log_access(license_key, hwid, ip):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO access_logs (license_key, hwid, ip_address, timestamp) VALUES (%s, %s, %s, %s)",
        (license_key, hwid, ip, datetime.now())
    )
    conn.commit()
    cur.close()
    conn.close()

# ==============================
# PUBLIC ENDPOINTS
# ==============================

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "online"}), 200

@app.route('/api/validate', methods=['POST'])
def validate():
    data = request.json
    license_key = data.get('license_key', '').upper().strip()
    hwid = data.get('hwid', '').strip()
    ip = request.remote_addr

    if not license_key or not hwid:
        return jsonify({"valid": False, "error": "Missing license_key or hwid"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM licenses WHERE license_key = %s", (license_key,))
    row = cur.fetchone()

    if not row:
        cur.close()
        conn.close()
        return jsonify({"valid": False, "error": "License not found"}), 404

    if row['revoked']:
        cur.close()
        conn.close()
        return jsonify({"valid": False, "error": "License revoked"}), 403

    if not row['discord_id']:
        cur.close()
        conn.close()
        return jsonify({"valid": False, "error": "License not activated. Redeem in Discord first."}), 403

    stored_hwid = row['hwid']
    if not stored_hwid:
        # Bind HWID
        cur.execute("UPDATE licenses SET hwid=%s, activated_at=%s WHERE license_key=%s", (hwid, datetime.now(), license_key))
        conn.commit()
        log_access(license_key, hwid, ip)
        cur.close()
        conn.close()
        return jsonify({"valid": True, "message": "HWID bound successfully"}), 200

    elif stored_hwid == hwid:
        log_access(license_key, hwid, ip)
        cur.close()
        conn.close()
        return jsonify({"valid": True, "message": "License valid"}), 200

    else:
        log_access(license_key, hwid, ip)
        cur.close()
        conn.close()
        return jsonify({"valid": False, "error": "HWID mismatch. License bound to another PC."}), 403

# ==============================
# ADMIN ENDPOINTS
# ==============================

def admin_auth(secret):
    return secret == ADMIN_SECRET

@app.route('/api/generate', methods=['POST'])
def generate():
    data = request.json
    secret = data.get('admin_secret', '')
    discord_id = data.get('discord_id', None)

    if not admin_auth(secret):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    import secrets
    license_key = f"ASTRALUX-{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO licenses (license_key, discord_id, created_at) VALUES (%s, %s, %s)",
        (license_key, discord_id, datetime.now())
    )
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"success": True, "license_key": license_key}), 200

@app.route('/api/revoke', methods=['POST'])
def revoke():
    data = request.json
    secret = data.get('admin_secret', '')
    license_key = data.get('license_key', '').upper()

    if not admin_auth(secret):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE licenses SET revoked=TRUE WHERE license_key=%s", (license_key,))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"success": True, "message": "License revoked"}), 200

@app.route('/api/hwid-reset', methods=['POST'])
def hwid_reset():
    data = request.json
    secret = data.get('admin_secret', '')
    license_key = data.get('license_key', '').upper()

    if not admin_auth(secret):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT hwid_resets FROM licenses WHERE license_key=%s", (license_key,))
    row = cur.fetchone()

    if not row:
        cur.close()
        conn.close()
        return jsonify({"success": False, "error": "License not found"}), 404

    if row['hwid_resets'] <= 0:
        cur.close()
        conn.close()
        return jsonify({"success": False, "error": "No HWID resets remaining"}), 403

    cur.execute("UPDATE licenses SET hwid=NULL, hwid_resets=hwid_resets-1 WHERE license_key=%s", (license_key,))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"success": True, "message": "HWID reset successfully"}), 200

# ==============================
# RUN SERVER
# ==============================
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Astralux License API running on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=False)
