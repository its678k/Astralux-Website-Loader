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
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "Qrynt10")

# ... (keep your existing Discord OAuth and other code) ...

# ======================
# ADD THIS NEW ENDPOINT
# ======================

@app.route('/api/claim', methods=['POST'])
def claim():
    """Claim a license in Discord (without HWID)"""
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

# ======================
# UPDATE YOUR GENERATE ENDPOINT
# ======================

@app.route('/api/generate', methods=['POST'])
def generate():
    data = request.json
    if data.get("admin_secret") != ADMIN_SECRET:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    discord_id = data.get("discord_id", None)
    
    key = f"ASTRALUX-{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"

    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO licenses (license_key, discord_id, created_at) VALUES (?, ?, ?)",
        (key, discord_id, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

    return jsonify({"success": True, "license_key": key})

# ======================
# ADD REVOKE ENDPOINT
# ======================

@app.route('/api/revoke', methods=['POST'])
def revoke():
    data = request.json
    if data.get("admin_secret") != ADMIN_SECRET:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    license_key = data.get("license_key", "").upper()
    
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE licenses SET revoked=1 WHERE license_key=?", (license_key,))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "License revoked"}), 200

# ======================
# ADD HWID RESET ENDPOINT
# ======================

@app.route('/api/hwid-reset', methods=['POST'])
def hwid_reset():
    data = request.json
    if data.get("admin_secret") != ADMIN_SECRET:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    license_key = data.get("license_key", "").upper()
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM licenses WHERE license_key=?", (license_key,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        return jsonify({"success": False, "error": "License not found"}), 404
    
    if row['hwid_resets'] <= 0:
        conn.close()
        return jsonify({"success": False, "error": "No resets remaining"}), 403
    
    c.execute("UPDATE licenses SET hwid=NULL, hwid_resets=hwid_resets-1 WHERE license_key=?", (license_key,))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "HWID reset"}), 200

# ======================
# UPDATE VALIDATE ENDPOINT
# ======================

@app.route('/api/validate', methods=['POST'])
def validate():
    """Check if license is valid (doesn't bind anything)"""
    data = request.json
    license_key = data.get("license_key", "").upper()
    
    if not license_key:
        return jsonify({"valid": False, "error": "Missing license_key"}), 400
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM licenses WHERE license_key=?", (license_key,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        return jsonify({"valid": False, "error": "License not found"}), 404
    
    if row["revoked"]:
        conn.close()
        return jsonify({"valid": False, "error": "License revoked"}), 403
    
    conn.close()
    return jsonify({"valid": True, "message": "License is valid"}), 200
