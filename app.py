# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

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
# PUBLIC ENDPOINTS
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

    c.execute(
        "INSERT INTO access_logs (license_key, hwid, ip_address, timestamp) VALUES (?, ?, ?, ?)",
        (license_key, None, ip, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

    return jsonify({"valid": True, "message": "License valid"}), 200

# ===== ADD THIS NEW ENDPOINT HERE =====
@app.route('/api/claim', methods=['POST'])
def claim():
    """Claim a license in Discord (without HWID) - NEW ENDPOINT"""
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
# ===== END NEW ENDPOINT =====

@app.route('/api/redeem', methods=['POST'])
def redeem():
    """Activates a license by binding it to a HWID (called from MC client)"""
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

    if row['hwid']:
        if row['hwid'] == hwid:
            log_access(license_key, hwid, ip)
            conn.close()
            return jsonify({"success": True, "message": "License validated"}), 200
        else:
            conn.close()
            return jsonify({"success": False, "error": "HWID mismatch"}), 403

    c.execute("UPDATE licenses SET hwid=?, activated_at=? WHERE license_key=?",
              (hwid, datetime.now().isoformat(), license_key))
    conn.commit()
    log_access(license_key, hwid, ip)
    conn.close()

    return jsonify({"success": True, "message": "License activated"}), 200

# ================================
# ADMIN ENDPOINTS
# ================================

ADMIN_SECRET = os.getenv('ADMIN_SECRET', 'Qrynt10')

def admin_auth(secret):
    return secret == ADMIN_SECRET

@app.route('/api/generate', methods=['POST'])
def generate():
    # ... (rest of your admin endpoints)
    pass

# ... (other admin endpoints: /api/revoke, /api/hwid-reset, /api/check-share)

# ================================
# RUN SERVER
# ================================

if __name__ == '__main__':
    print("🚀 Astralux License API running...")
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
