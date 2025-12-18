@app.route('/api/reset-hwid', methods=['POST'])
def reset_hwid_flexible():
    """
    Reset HWID for a license (admin only) - accepts multiple identifier types
    Expects: {identifier: str, admin_secret: str}
    identifier can be: license_key or discord_id
    """
    data = request.json
    identifier = data.get('identifier', '').strip()
    admin_secret = data.get('admin_secret', '')
    
    ADMIN_SECRET = os.getenv('ADMIN_SECRET', 'Daniel2011.1')
    
    if admin_secret != ADMIN_SECRET:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    if not identifier:
        return jsonify({"success": False, "error": "Missing identifier"}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    # Try to find license by multiple methods
    identifier_upper = identifier.upper()
    c.execute("""
        SELECT license_key, hwid, discord_id, hwid_resets 
        FROM licenses 
        WHERE license_key = ? OR discord_id = ?
    """, (identifier_upper, identifier))
    
    result = c.fetchone()
    
    if not result:
        conn.close()
        return jsonify({"success": False, "error": "License not found"}), 404
    
    license_key = result['license_key']
    old_hwid = result['hwid']
    discord_id = result['discord_id']
    hwid_resets = result['hwid_resets']
    
    if hwid_resets <= 0:
        conn.close()
        return jsonify({"success": False, "error": "No HWID resets remaining"}), 403
    
    # Reset HWID and decrement reset counter
    c.execute("""
        UPDATE licenses 
        SET hwid = NULL, hwid_resets = hwid_resets - 1 
        WHERE license_key = ?
    """, (license_key,))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        "success": True,
        "license_key": license_key,
        "old_hwid": old_hwid,
        "discord_id": discord_id,
        "resets_remaining": hwid_resets - 1,
        "message": "HWID reset successfully"
    }), 200


@app.route('/api/license-info', methods=['POST'])
def license_info():
    """
    Get license information (admin only)
    Expects: {identifier: str, admin_secret: str}
    identifier can be: license_key or discord_id
    """
    data = request.json
    identifier = data.get('identifier', '').strip()
    admin_secret = data.get('admin_secret', '')
    
    ADMIN_SECRET = os.getenv('ADMIN_SECRET', 'Daniel2011.1')
    
    if admin_secret != ADMIN_SECRET:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    if not identifier:
        return jsonify({"success": False, "error": "Missing identifier"}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    # Find license
    identifier_upper = identifier.upper()
    c.execute("""
        SELECT license_key, hwid, discord_id, revoked, hwid_resets, created_at, activated_at
        FROM licenses 
        WHERE license_key = ? OR discord_id = ?
    """, (identifier_upper, identifier))
    
    result = c.fetchone()
    
    if not result:
        conn.close()
        return jsonify({"success": False, "error": "License not found"}), 404
    
    # Get access log stats
    c.execute("""
        SELECT COUNT(DISTINCT hwid) as unique_hwids, 
               COUNT(DISTINCT ip_address) as unique_ips,
               COUNT(*) as total_accesses
        FROM access_logs 
        WHERE license_key = ?
    """, (result['license_key'],))
    
    stats = c.fetchone()
    conn.close()
    
    return jsonify({
        "success": True,
        "license_key": result['license_key'],
        "hwid": result['hwid'],
        "discord_id": result['discord_id'],
        "revoked": bool(result['revoked']),
        "hwid_resets": result['hwid_resets'],
        "created_at": result['created_at'],
        "activated_at": result['activated_at'],
        "stats": {
            "unique_hwids": stats['unique_hwids'] if stats else 0,
            "unique_ips": stats['unique_ips'] if stats else 0,
            "total_accesses": stats['total_accesses'] if stats else 0
        }
    }), 200
