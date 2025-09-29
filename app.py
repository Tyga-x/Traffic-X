# @fileOverview Check usage stats of X-SL
# @author MasterHide
# @Copyright © 2025 x404 MASTER™
# @license MIT
#
# You may not reproduce or distribute this work, in whole or in part, 
# without the express written consent of the copyright owner.
#
# For more information, visit: https://t.me/Dark_Evi

from flask import Flask, request, render_template, jsonify
import sqlite3
import json
import psutil
import requests
from datetime import datetime

app = Flask(__name__)
db_path = "/etc/x-ui/x-ui.db"  # Adjust path if necessary 

def convert_bytes(byte_size):
    """Convert bytes to a human-readable format (MB, GB, TB)."""
    if byte_size is None:
        return "0 Bytes"
    if byte_size < 1024:
        return f"{byte_size} Bytes"
    elif byte_size < 1024 * 1024:
        return f"{round(byte_size / 1024, 2)} KB"
    elif byte_size < 1024 * 1024 * 1024:
        return f"{round(byte_size / (1024 * 1024), 2)} MB"
    elif byte_size < 1024 * 1024 * 1024 * 1024:
        return f"{round(byte_size / (1024 * 1024 * 1024), 2)} GB"
    else:
        return f"{round(byte_size / (1024 * 1024 * 1024 * 1024), 2)} TB"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/usage', methods=['POST'])
def usage():
    try:
        user_input = request.form.get('user_input')  # Get input from the form
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Query to fetch client data
        query = '''SELECT email, up, down, total, expiry_time, inbound_id FROM client_traffics WHERE email = ? OR id = ?'''
        cursor.execute(query, (user_input, user_input))
        row = cursor.fetchone()
        if row:
            email, up, down, total, expiry_time, inbound_id = row
            # **Fixed expiry time handling**
            expiry_date = "Invalid Date"
            if expiry_time and isinstance(expiry_time, (int, float)):
                expiry_timestamp = expiry_time / 1000 if expiry_time > 9999999999 else expiry_time
                try:
                    expiry_date = datetime.utcfromtimestamp(expiry_timestamp).strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, OSError):
                    expiry_date = "Invalid Date"
            # Query to fetch totalGB and user-specific enable status
            inbound_query = '''SELECT settings FROM inbounds WHERE id = ?'''
            cursor.execute(inbound_query, (inbound_id,))
            inbound_row = cursor.fetchone()
            totalGB = "Not Available"
            user_status = "Disabled"  # Default to "Disabled" if user is not found
            if inbound_row:
                settings = inbound_row[0]
                try:
                    inbound_data = json.loads(settings)
                    for client in inbound_data.get('clients', []):
                        if client.get('email') == email:
                            totalGB = client.get('totalGB', "Not Available")
                            user_status = "Enabled" if client.get('enable', True) else "Disabled"
                            break
                except json.JSONDecodeError:
                    totalGB = "Invalid JSON Data"
            conn.close()
            # Convert to human-readable format
            up = convert_bytes(up)
            down = convert_bytes(down)
            total = convert_bytes(total)
            totalGB = convert_bytes(totalGB) if totalGB != "Not Available" else totalGB
            return render_template(
                'result.html',
                email=email,
                up=up,
                down=down,
                total=total,
                expiry_date=expiry_date,
                totalGB=totalGB,
                user_status=user_status
            )
        else:
            conn.close()
            return "No data found for this user."
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/update-status', methods=['POST'])
def update_status():
    try:
        data = request.get_json()
        new_status = data.get('status')  # True or False
        # Update the status in the database (implement this logic)
        print(f"Updating status to: {new_status}")
        return jsonify({"status": "success", "message": "Status updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/server-status')
def server_status():
    """Returns real-time CPU, RAM, and Disk usage."""
    try:
        status = {
            "cpu": psutil.cpu_percent(interval=1),
            "ram": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage('/').percent
        }
        return jsonify(status)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/server-location')
def server_location():
    """Fetches server location based on public IP."""
    try:
        response = requests.get("http://ip-api.com/json/")
        data = response.json()
        return jsonify({
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "ip": data.get("query", "Unknown")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/ping')
def ping():
    """Endpoint for ping test."""
    return jsonify({"status": "success", "message": "Pong!"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=$PORT, debug=False)
