from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)  # Allow requests from Minecraft client

# Database setup
DATABASE = 'licenses.db'

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Licenses table
    c.execute('''CREATE TABLE IF NOT EXISTS licenses
                 (license_key TEXT PRIMARY KEY,
                  hwid TEXT,
                  discord_id TEXT,
                  revoked INTEGER DEFAULT 0,
                  hwid_resets INTEGER DEFAULT 1,
                  created_at TEXT,
                  activated_at TEXT)''')
    
    # Access logs table (for anti-sharing detection)
    c.execute('''CREATE TABLE IF NOT EXISTS access_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  license_key TEXT,
                  hwid TEXT,
                  ip_address TEXT,
                  timestamp TEXT,
                  FOREIGN KEY (license_key) REFERENCES licenses(license_key))''')
    
    conn.commit()
    conn.close()

# Initialize DB on startup
init_db()

# ============================================
# HELPER FUNCTIONS
# ============================================

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def generate_license_key():
    """Generate a license key in format: ASTRALUX-XXXX-XXXX-XXXX"""
    part1 = secrets.token_hex(2).upper()
    part2 = secrets.token_hex(2).upper()
    part3 = secrets.token_hex(2).upper()
    return f"ASTRALUX-{part1}-{part2}-{part3}"

def log_access(license_key, hwid, ip_address):
    """Log access attempt for anti-sharing detection"""
    conn = get_db()
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute("INSERT INTO access_logs (license_key, hwid, ip_address, timestamp) VALUES (?, ?, ?, ?)",
              (license_key, hwid, ip_address, timestamp))
    conn.commit()
    conn.close()

def check_sharing(license_key):
    """Check if license is being shared (multiple HWIDs)"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT DISTINCT hwid FROM access_logs WHERE license_key = ?", (license_key,))
    hwids = c.fetchall()
    conn.close()
    return len(hwids)

# ============================================
# API ENDPOINTS
# ============================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "online", "service": "Astralux License API"}), 200

@app.route('/api/redeem', methods=['POST'])
def redeem_license():
    """
    Redeem a license key (called by Discord bot)
    Expects: {license_key: str, discord_id: str}
    """
    data = request.json
    license_key = data.get('license_key', '').strip().upper()
    discord_id = data.get('discord_id', '').strip()
    
    if not license_key or not discord_id:
        return jsonify({"success": False, "error": "Missing license_key or discord_id"}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    # Check if license exists
    c.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,))
    license_data = c.fetchone()
    
    if license_data:
        # License already exists
        if license_data['discord_id']:
            conn.close()
            return jsonify({"success": False, "error": "License already redeemed"}), 400
        
        # Update with discord_id
        c.execute("UPDATE licenses SET discord_id = ?, activated_at = ? WHERE license_key = ?",
                  (discord_id, datetime.now().isoformat(), license_key))
    else:
        # Create new license (for sell.app generated keys)
        c.execute("INSERT INTO licenses (license_key, discord_id, created_at, activated_at) VALUES (?, ?, ?, ?)",
                  (license_key, discord_id, datetime.now().isoformat(), datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "License redeemed successfully"}), 200

@app.route('/api/validate', methods=['POST'])
def validate_license():
    """
    Validate a license (called by Minecraft client)
    Expects: {license_key: str, hwid: str}
    """
    data = request.json
    license_key = data.get('license_key', '').strip().upper()
    hwid = data.get('hwid', '').strip()
    ip_address = request.remote_addr
    
    if not license_key or not hwid:
        return jsonify({"valid": False, "error": "Missing license_key or hwid"}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    # Get license data
    c.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,))
    license_data = c.fetchone()
    
    if not license_data:
        conn.close()
        return jsonify({"valid": False, "error": "License not found"}), 404
    
    # Check if revoked
    if license_data['revoked'] == 1:
        conn.close()
        return jsonify({"valid": False, "error": "License has been revoked"}), 403
    
    # Check if license is redeemed in Discord
    if not license_data['discord_id']:
        conn.close()
        return jsonify({"valid": False, "error": "License not activated. Redeem in Discord first."}), 403
    
    # HWID binding logic
    stored_hwid = license_data['hwid']
    
    if not stored_hwid:
        # First time binding HWID
        c.execute("UPDATE licenses SET hwid = ? WHERE license_key = ?", (hwid, license_key))
        conn.commit()
        log_access(license_key, hwid, ip_address)
        conn.close()
        return jsonify({"valid": True, "message": "HWID bound successfully"}), 200
    
    elif stored_hwid == hwid:
        # HWID matches - allow access
        log_access(license_key, hwid, ip_address)
        conn.close()
        return jsonify({"valid": True, "message": "License valid"}), 200
    
    else:
        # HWID mismatch - potential sharing
        log_access(license_key, hwid, ip_address)
        conn.close()
        return jsonify({"valid": False, "error": "HWID mismatch. License is bound to another PC."}), 403

@app.route('/api/revoke', methods=['POST'])
def revoke_license():
    """
    Revoke a license (admin only - called by Discord bot)
    Expects: {license_key: str, admin_secret: str}
    """
    data = request.json
    license_key = data.get('license_key', '').strip().upper()
    admin_secret = data.get('admin_secret', '')
    
    ADMIN_SECRET = os.getenv('ADMIN_SECRET', 'Qrynt10')
    
    if admin_secret != ADMIN_SECRET:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    if not license_key:
        return jsonify({"success": False, "error": "Missing license_key"}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    c.execute("UPDATE licenses SET revoked = 1 WHERE license_key = ?", (license_key,))
    
    if c.rowcount == 0:
        conn.close()
        return jsonify({"success": False, "error": "License not found"}), 404
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "License revoked"}), 200

@app.route('/api/hwid-reset', methods=['POST'])
def hwid_reset():
    """
    Reset HWID for a license (admin only)
    Expects: {license_key: str, admin_secret: str}
    """
    data = request.json
    license_key = data.get('license_key', '').strip().upper()
    admin_secret = data.get('admin_secret', '')
    
    ADMIN_SECRET = os.getenv('ADMIN_SECRET', 'Qrynt10')
    
    if admin_secret != ADMIN_SECRET:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    if not license_key:
        return jsonify({"success": False, "error": "Missing license_key"}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    # Check if license exists and has resets available
    c.execute("SELECT hwid_resets FROM licenses WHERE license_key = ?", (license_key,))
    result = c.fetchone()
    
    if not result:
        conn.close()
        return jsonify({"success": False, "error": "License not found"}), 404
    
    if result['hwid_resets'] <= 0:
        conn.close()
        return jsonify({"success": False, "error": "No HWID resets remaining"}), 403
    
    # Reset HWID and decrement reset counter
    c.execute("UPDATE licenses SET hwid = NULL, hwid_resets = hwid_resets - 1 WHERE license_key = ?",
              (license_key,))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "HWID reset successfully"}), 200

@app.route('/api/check-share', methods=['POST'])
def check_share():
    """
    Check if license is being shared (admin only)
    Expects: {license_key: str, admin_secret: str}
    """
    data = request.json
    license_key = data.get('license_key', '').strip().upper()
    admin_secret = data.get('admin_secret', '')
    
    ADMIN_SECRET = os.getenv('ADMIN_SECRET', 'Qrynt10')
    
    if admin_secret != ADMIN_SECRET:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    if not license_key:
        return jsonify({"success": False, "error": "Missing license_key"}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    # Get unique HWIDs
    c.execute("SELECT DISTINCT hwid FROM access_logs WHERE license_key = ?", (license_key,))
    hwids = [row['hwid'] for row in c.fetchall()]
    
    # Get unique IPs
    c.execute("SELECT DISTINCT ip_address FROM access_logs WHERE license_key = ?", (license_key,))
    ips = [row['ip_address'] for row in c.fetchall()]
    
    conn.close()
    
    hwid_count = len(hwids)
    ip_count = len(ips)
    
    status = "OK"
    if hwid_count >= 2:
        status = "⚠️ SHARING DETECTED"
    elif hwid_count >= 3:
        status = "🚨 AUTO-REVOKE RECOMMENDED"
    
    return jsonify({
        "success": True,
        "license_key": license_key,
        "unique_hwids": hwid_count,
        "unique_ips": ip_count,
        "status": status,
        "hwids": hwids,
        "ips": ips
    }), 200
