import os
import sqlite3
import random
import string
from flask import Flask, request, jsonify, render_template, Response, send_file
import io
import csv
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

app = Flask(__name__, template_folder='.')

GOOGLE_CLIENT_ID = "1094968049844-p7g646vkmlccpjlcdnsmaq6hi2jpknd9.apps.googleusercontent.com"
DB_NAME = "daou_portal.db"

# In-memory stores for OTP and SSE telemetry streams
otp_store = {}
sse_listeners = []

def broadcast_telemetry(message):
    print(message)
    for listener in list(sse_listeners):
        try:
            listener.put(message)
        except:
            sse_listeners.remove(listener)

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            matric_no TEXT UNIQUE NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            rating INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    
    # Create default admin if not exists
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        matric_code = "DAOU/ADM/2026/001"
        cursor.execute('''
            INSERT INTO users (username, password, email, full_name, matric_no)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', 'adminpassword123', 'admin@daou.edu.ng', 'System Administrator', matric_code))
    
    conn.commit()
    conn.close()

init_db()

def generate_matric():
    return f"DAOU/UG/2026/{random.randint(1000, 9999)}"

@app.route('/')
def index():
    return render_template('index_4.html')

@app.route('/api/system/mode', methods=['POST'])
def update_system_mode():
    data = request.json or {}
    mode = data.get('mode', 'user')
    broadcast_telemetry(f"[SYSTEM MODE] Switched layout framework to: {mode.upper()}")
    return jsonify({"success": True})

@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    full_name = data.get('full_name')
    
    if not all([username, password, email, full_name]):
        return jsonify({"success": False, "message": "All parameters required for registration profile."}), 400
    
    matric_no = generate_matric()
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password, email, full_name, matric_no)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, password, email, full_name, matric_no))
        conn.commit()
        conn.close()
        
        broadcast_telemetry(f"[REGISTRATION] New user created: {username} ({matric_no})")
        return jsonify({"success": True, "generated_matric": matric_no})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Username or Email address already registered."}), 400

@app.route('/api/admin/inject-user', methods=['POST'])
def admin_inject_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    full_name = data.get('full_name')
    
    if not all([username, password, email, full_name]):
        return jsonify({"success": False, "message": "All injection properties are required."}), 400
        
    matric_no = generate_matric()
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password, email, full_name, matric_no)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, password, email, full_name, matric_no))
        conn.commit()
        conn.close()
        
        broadcast_telemetry(f"[DB INJECTION] Admin manually injected row for user: {username} [{matric_no}]")
        return jsonify({"success": True, "generated_matric": matric_no})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Constraint error: Username or Email conflict."}), 400

@app.route('/api/login', methods=['POST'])
def login_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if username == 'admin' and password == 'adminpassword123':
        broadcast_telemetry("[ADMIN LOGIN SUCCESS] Elevated master dashboard unlocked.")
        return jsonify({"success": True, "is_admin": True})
        
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({"success": False, "message": "Invalid username or password credentials."}), 401
        
    # Generate 6-digit OTP code for 2FA verification flow
    otp_code = "".join(random.choices(string.digits, k=6))
    user_id = user['id']
    email = user['email']
    
    masked_email = email[:2] + "****" + email[email.find('@'):] if '@' in email else "user@daou.edu.ng"
    otp_store[user_id] = otp_code
    
    broadcast_telemetry(f"[2FA GATEWAY] Generated OTP signature [{otp_code}] dispatched for user: {username}")
    
    return jsonify({
        "success": True,
        "is_admin": False,
        "user_id": user_id,
        "masked_email": masked_email,
        "expires_in": 300
    })

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    user_id = data.get('user_id')
    input_otp = data.get('otp_code')
    
    if user_id not in otp_store or otp_store[user_id] != input_otp:
        return jsonify({"success": False, "message": "Invalid or expired security clearance OTP code."}), 400
        
    # Clear verified OTP token
    del otp_store[user_id]
    
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({"success": False, "message": "User session identity record lost."}), 404
        
    broadcast_telemetry(f"[LOGIN COMPLETE] Multi-factor clearance fully validated for: {user['username']}")
    
    return jsonify({
        "success": True,
        "user_id": user['id'],
        "user_info": {
            "username": user['username'],
            "full_name": user['full_name'],
            "matric_no": user['matric_no'],
            "email": user['email']
        }
    })

@app.route('/api/auth/google', methods=['POST'])
def google_auth():
    data = request.json
    token = data.get('id_token')
    
    try:
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        email = idinfo['get']('email') if hasattr(idinfo, 'get') else idinfo.get('email')
        name = idinfo.get('name', 'Google Federated User')
        
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        
        if not user:
            username = email.split('@')[0] + "_" + "".join(random.choices(string.digits, k=3))
            matric_no = generate_matric()
            cursor.execute('''
                INSERT INTO users (username, password, email, full_name, matric_no)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, "GOOGLE_AUTH_SECURED", email, name, matric_no))
            conn.commit()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            
        conn.close()
        broadcast_telemetry(f"[GOOGLE LOGIN] Federated auth token verified successfully for: {email}")
        
        return jsonify({
            "success": True,
            "user_id": user['id'],
            "user_info": {
                "username": user['username'],
                "full_name": user['full_name'],
                "matric_no": user['matric_no'],
                "email": user['email']
            }
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Google identity verification fault: {strStr(e) if 'strStr' in globals() else str(e)}"}), 400

@app.route('/api/ratings', methods=['POST'])
def submit_rating():
    data = request.json
    user_id = data.get('user_id')
    rating = data.get('rating')
    
    if not user_id or not rating:
        return jsonify({"success": False, "message": "Missing required metric parameters."}), 400
        
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO ratings (user_id, rating) VALUES (?, ?)", (user_id, rating))
    conn.commit()
    conn.close()
    
    broadcast_telemetry(f"[RATING RECORDED] Metric value '{rating}/10' logged for user ID: {user_id}")
    return jsonify({"success": True})

@app.route('/api/ratings/export', methods=['GET'])
def export_ratings_csv():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.id, u.username, u.matric_no, r.rating, r.timestamp 
        FROM ratings r JOIN users u ON r.user_id = u.id
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Rating ID', 'Username', 'Matric Number', 'Score Metric', 'Timestamp'])
    for row in rows:
        writer.writerow([row['id'], row['username'], row['matric_no'], row['rating'], row['timestamp']])
        
    output.seek(0)
    broadcast_telemetry("[CSV EXPORT] Ratings performance spreadsheet downloaded successfully.")
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype="text/csv",
        as_attachment=True,
        download_name="daou_portal_ratings_export.csv"
    )

@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, full_name, matric_no, email FROM users")
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({"success": True, "users": users})

@app.route('/api/admin/users/update/<int:user_id>', methods=['PUT'])
def admin_update_user(user_id):
    data = request.json
    full_name = data.get('full_name')
    matric_no = data.get('matric_no')
    email = data.get('email')
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users SET full_name = ?, matric_no = ?, email = ? WHERE id = ?
    ''', (full_name, matric_no, email, user_id))
    conn.commit()
    conn.close()
    
    broadcast_telemetry(f"[ADMIN UPDATE] Modified database profile mapping for record ID: {user_id}")
    return jsonify({"success": True})

@app.route('/api/admin/users/delete/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ratings WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    broadcast_telemetry(f"[ADMIN PURGE] Deleted record profile row ID: {user_id}")
    return jsonify({"success": True})

@app.route('/api/admin/live-stream')
def admin_live_stream():
    import queue
    q = queue.Queue()
    sse_listeners.append(q)
    
    def stream():
        try:
            while True:
                msg = q.get()
                yield f"data: {msg}\n\n"
        except GeneratorExit:
            if q in sse_listeners:
                sse_listeners.remove(q)
                
    return Response(stream(), mimetype="text/event-stream")

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)