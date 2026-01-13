from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)  # Allow MC client requests

DATABASE = 'licenses.db'

# ================================
# DATABASE HELPERS
# ================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS licenses (
                    license_key TEXT PRIMARY KEY,
                    hwid TEXT,
                    discord_id TEXT,
                    revoked INTEGER DEFAULT 0,
                    hwid_resets INTEGER DEFAULT 1,
                    created_at TEXT,
                    activated_at TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS access_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    license_key TEXT,
                    hwid TEXT,
                    ip_address TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (license_key) REFERENCES licenses(license_key)
                )''')
    conn.commit()
    conn.close()

def log_access(license_key, hwid, ip):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO access_logs (license_key, hwid, ip_address, timestamp) VALUES (?, ?, ?, ?)",
              (license_key, hwid, ip, datetime.now().isoformat()))
    conn.commit()
    conn.close()

init_db()

# ================================
# PUBLIC ENDPOINTS (MC CLIENT)
# ================================

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "online"}), 200

@app.route('/api/validate', methods=['POST'])
def validate():
    data = request.json
    license_key = data.get('license_key', '').upper().strip()
    ip = request.remote_addr

    if not license_key:
        return jsonify({"valid": False, "error": "Missing license_key"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"valid": False, "error": "License not found"}), 404

    if row['revoked']:
        conn.close()
        return jsonify({"valid": False, "error": "License revoked"}), 403

    # OPTIONAL: log access without HWID
    c.execute(
        "INSERT INTO access_logs (license_key, hwid, ip_address, timestamp) VALUES (?, ?, ?, ?)",
        (license_key, None, ip, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

    return jsonify({"valid": True, "message": "License valid"}), 200

@app.route('/api/claim', methods=['POST'])
def claim():
    """Claim a license in Discord (without HWID) - NEW ENDPOINT FOR DISCORD BOT"""
    data = request.json
    license_key = data.get('license_key', '').upper().strip()
    discord_id = data.get('discord_id', '').strip()
    
    if not license_key or not discord_id:
        return jsonify({"success": False, "error": "Missing license_key or discord_id"}), 400
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        return jsonify({"success": False, "error": "License not found"}), 404
    
    if row['revoked']:
        conn.close()
        return jsonify({"success": False, "error": "License revoked"}), 403
    
    # Check if already claimed by someone else
    if row['discord_id'] and row['discord_id'] != discord_id:
        conn.close()
        return jsonify({"success": False, "error": "License already claimed by another user"}), 403
    
    # Update discord_id if not set
    if not row['discord_id']:
        c.execute("UPDATE licenses SET discord_id=? WHERE license_key=?", (discord_id, license_key))
        conn.commit()
    
    conn.close()
    return jsonify({"success": True, "message": "License claimed successfully"}), 200

@app.route('/api/redeem', methods=['POST'])
def redeem():
    """Activates a license by binding it to a HWID"""
    data = request.json
    license_key = data.get('license_key', '').upper().strip()
    hwid = data.get('hwid', '').strip()
    ip = request.remote_addr

    if not license_key or not hwid:
        return jsonify({"success": False, "error": "Missing license_key or hwid"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"success": False, "error": "License not found"}), 404

    if row['revoked']:
        conn.close()
        return jsonify({"success": False, "error": "License revoked"}), 403

    # If already bound to a HWID
    if row['hwid']:
        if row['hwid'] == hwid:
            # Same HWID - allow access
            log_access(license_key, hwid, ip)
            conn.close()
            return jsonify({"success": True, "message": "License validated"}), 200
        else:
            # Different HWID - deny
            conn.close()
            return jsonify({"success": False, "error": "HWID mismatch"}), 403

    # First time activation - bind HWID
    c.execute("UPDATE licenses SET hwid=?, activated_at=? WHERE license_key=?",
              (hwid, datetime.now().isoformat(), license_key))
    conn.commit()
    log_access(license_key, hwid, ip)
    conn.close()

    return jsonify({"success": True, "message": "License activated"}), 200

# ================================
# ADMIN ENDPOINTS (Discord Bot Only)
# ================================

ADMIN_SECRET = os.getenv('ADMIN_SECRET', 'Qrynt10')

def admin_auth(secret):
    return secret == ADMIN_SECRET

@app.route('/api/generate', methods=['POST'])
def generate():
    data = request.json
    secret = data.get('admin_secret', '')
    discord_id = data.get('discord_id', '')

    if not admin_auth(secret):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    import secrets
    license_key = f"ASTRALUX-{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"

    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO licenses (license_key, discord_id, created_at) VALUES (?, ?, ?)",
              (license_key, discord_id if discord_id else None, datetime.now().isoformat()))
    conn.commit()
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
    c = conn.cursor()
    c.execute("UPDATE licenses SET revoked=1 WHERE license_key=?", (license_key,))
    conn.commit()
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
    c = conn.cursor()
    c.execute("SELECT hwid_resets FROM licenses WHERE license_key=?", (license_key,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"success": False, "error": "License not found"}), 404

    if row['hwid_resets'] <= 0:
        conn.close()
        return jsonify({"success": False, "error": "No HWID resets remaining"}), 403

    c.execute("UPDATE licenses SET hwid=NULL, hwid_resets=hwid_resets-1 WHERE license_key=?", (license_key,))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "HWID reset successfully"}), 200

@app.route('/api/check-share', methods=['POST'])
def check_share():
    """Check if a license is being shared across multiple devices"""
    data = request.json
    secret = data.get('admin_secret', '')
    license_key = data.get('license_key', '').upper()

    if not admin_auth(secret):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_db()
    c = conn.cursor()
    
    # Get unique HWIDs
    c.execute("SELECT DISTINCT hwid FROM access_logs WHERE license_key=? AND hwid IS NOT NULL", (license_key,))
    hwids = [row['hwid'] for row in c.fetchall()]
    
    # Get unique IPs
    c.execute("SELECT DISTINCT ip_address FROM access_logs WHERE license_key=?", (license_key,))
    ips = [row['ip_address'] for row in c.fetchall()]
    
    conn.close()
    
    hwid_count = len(hwids)
    ip_count = len(ips)
    
    if hwid_count >= 3:
        status = "🚨 High Risk - Likely Shared"
    elif hwid_count >= 2:
        status = "⚠️ Suspicious - Multiple Devices"
    else:
        status = "✅ Normal Usage"
    
    return jsonify({
        "success": True,
        "status": status,
        "unique_hwids": hwid_count,
        "unique_ips": ip_count,
        "hwids": hwids
    }), 200

# ================================
# RUN SERVER
# ================================

if __name__ == '__main__':
    print("🚀 Astralux License API running...")
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
