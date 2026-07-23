import os
import sqlite3
import random
import time
import smtplib
import csv
import io
import queue
import threading  # Replaced Celery with high-speed async native execution threads
from email.mime.text import MIMEText
from flask import Flask, request, jsonify, render_template, Response, stream_with_context

# Cryptographic Federated Verification Imports
from google.oauth2 import id_token
from google.auth.transport import requests

# Parity import layer supporting production PostgreSQL database engine shifts
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

app = Flask(__name__)

# Environmental Database Router System Layout Setup
DATABASE_URL = os.environ.get('DATABASE_URL', 'database.db')
IS_POSTGRES = DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://")

# System Runtime State Control Flags
CURRENT_SYSTEM_MODE = "user"
ACTIVE_OTP_STORE = {}

# Live Admin Pub/Sub Broadcast Subscriptions Layout Container
LIVE_ADMIN_QUEUES = []

# Elevated Console Authentication Parameters
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "DAOU_admin_2026"

# Automated 2FA SMTP Node Variables Configuration Layout
SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '465'))
SMTP_USER = os.environ.get('GMAIL_USER')            
SMTP_PASS = os.environ.get('GMAIL_APP_PASSWORD')    
SMTP_FROM_NAME = os.environ.get('SMTP_FROM_NAME', 'DAOU University Portal')

# Google OAuth Federation Credentials Mapping Identity Key
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com')


def get_remote_context():
    """Extracts true remote client IP address and device summaries from proxy networks."""
    if not request:
        return "SYSTEM", "INTERNAL"
    
    # Check X-Forwarded-For header array for Render production parity, fallback to default remote address
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    user_agent = request.headers.get('User-Agent', 'Unknown Device')
    
    # Strip down long browser user-agents into a concise footprint summary
    device_summary = user_agent.split(')')[0] + ')' if '(' in user_agent else user_agent[:30]
    return ip_address, device_summary


def broadcast_system_event(msg_text):
    """Pushes runtime authentication event alerts instantly to all open Admin SSE data pipelines."""
    for client_queue in LIVE_ADMIN_QUEUES:
        try:
            client_queue.put(msg_text)
        except Exception:
            pass


def get_db_connection():
    """Generates an adaptive backend connector mapping based on infrastructure vars."""
    if IS_POSTGRES and HAS_POSTGRES:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    else:
        conn = sqlite3.connect('database.db' if IS_POSTGRES else DATABASE_URL)
        conn.row_factory = sqlite3.Row
        return conn


def execute_query(query, params=(), fetch_one=False, fetch_all=False, commit=False):
    """Abstraction layer utility helping query processing parity between SQLite and Postgres."""
    conn = get_db_connection()
    try:
        if IS_POSTGRES and HAS_POSTGRES:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(query, params)
            result = None
            if fetch_one:
                result = cur.fetchone()
            elif fetch_all:
                result = cur.fetchall()
            if commit:
                conn.commit()
            return result
        else:
            cursor = conn.execute(query, params)
            result = None
            if fetch_one:
                result = cursor.fetchone()
            elif fetch_all:
                result = cursor.fetchall()
            if commit:
                conn.commit()
            return result
    finally:
        conn.close()


def init_db():
    """Builds the active table framework mappings cleanly if not pre-configured."""
    if IS_POSTGRES and HAS_POSTGRES:
        create_users_table = '''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) NOT NULL,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                full_name VARCHAR(255) NOT NULL,
                matric_no VARCHAR(100) NOT NULL
            )
        '''
        create_ratings_table = '''
            CREATE TABLE IF NOT EXISTS ratings (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                rating INT NOT NULL,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        '''
    else:
        create_users_table = '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                matric_no TEXT NOT NULL
            )
        '''
        create_ratings_table = '''
            CREATE TABLE IF NOT EXISTS ratings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                rating INTEGER NOT NULL,
                submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        '''
    execute_query(create_users_table, commit=True)
    execute_query(create_ratings_table, commit=True)


def write_auth_log(username, action, status):
    ip, device = get_remote_context()
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] MODE: {CURRENT_SYSTEM_MODE.upper()} "
          f"| IP: {ip} | DEVICE: {device} | USER: {username} | ACTION: {action} | STATUS: {status}")


def send_otp_email_thread(recipient_email, full_name, otp_code):
    """
    High-speed asynchronous worker utility executing out of band.
    Bypasses the web processing engine thread loops completely to ensure rapid client UI responsiveness.
    """
    if not SMTP_USER or not SMTP_PASS:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [ASYNC THREAD] ERROR: SMTP credentials missing!")
        return

    subject = "Your DAOU Portal Security Code"
    body = (
        f"Hi {full_name},\n\n"
        f"Your one-time passcode (OTP) for DAOU University Portal is:\n\n"
        f"    {otp_code}\n\n"
        f"This code expires in 5 minutes.\n\n"
        f"— DAOU University Portal Security"
    )

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = f"{SMTP_FROM_NAME} <{SMTP_USER}>"
    msg['To'] = recipient_email

    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=8) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [recipient_email], msg.as_string())
        print(f"[ASYNC THREAD] Clear verification dispatch completed to: {recipient_email}")
    except Exception as e:
        print(f"[ASYNC THREAD] Primary delivery interface error: {str(e)}. Retrying TLS protocol fallback...")
        try:
            with smtplib.SMTP(SMTP_HOST, 587, timeout=8) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(SMTP_USER, [recipient_email], msg.as_string())
        except Exception as e_tls:
            print(f"[ASYNC THREAD] Critical Delivery failure: {str(e_tls)}")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/system/mode', methods=['GET', 'POST'])
def system_mode_switch():
    global CURRENT_SYSTEM_MODE
    if request.method == 'POST':
        data = request.json or {}
        new_mode = data.get('mode', '').lower().strip()
        if new_mode in ['user', 'admin']:
            CURRENT_SYSTEM_MODE = new_mode
            write_auth_log("SYSTEM", f"Context runtime adjusted state to: {CURRENT_SYSTEM_MODE}", "OK")
            return jsonify({"success": True, "current_mode": CURRENT_SYSTEM_MODE})
        return jsonify({"success": False, "message": "Invalid system parameters execution path."}), 400
    return jsonify({"success": True, "current_mode": CURRENT_SYSTEM_MODE})


@app.route('/api/admin/login', methods=['POST'])
def api_admin_login():
    data = request.json or {}
    ip, device = get_remote_context()
    if data.get('username') == ADMIN_USERNAME and data.get('password') == ADMIN_PASSWORD:
        write_auth_log("ADMIN", "Console Gateway Authentication Check", "SUCCESS")
        broadcast_system_event(f"<span class='term-success'>[ADMIN LOGIN] Elevated console handshake verified.<br>"
                               f"📍 Origin: <code>{ip}</code> | 💻 Device: <em>{device}</em></span>")
        return jsonify({"success": True, "role": "admin"})
    
    broadcast_system_event(f"<span class='term-warn'>[ADMIN FAILED] Unauthorized console access attempt!<br>"
                           f"🚨 Source: <code>{ip}</code></span>")
    return jsonify({"success": False, "message": "Access Denied: Administrative footprint failure."}), 401


@app.route('/api/admin/live-stream', methods=['GET'])
def api_admin_live_stream():
    """Server-Sent Events structural telemetry pipeline feeding real-time console updates."""
    def stream_broker():
        q = queue.Queue()
        LIVE_ADMIN_QUEUES.append(q)
        try:
            while True:
                msg = q.get()
                yield f"data: {msg}\n\n"
        except GeneratorExit:
            LIVE_ADMIN_QUEUES.remove(q)
            
    return Response(stream_with_context(stream_broker()), mimetype="text/event-stream")


@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    email = data.get('email', '').strip()
    full_name = data.get('full_name', '').strip()

    if not all([username, password, email, full_name]):
        return jsonify({"success": False, "message": "All fields are required."}), 400

    placeholder = "%s" if IS_POSTGRES else "?"
    
    existing = execute_query(
        f"SELECT email FROM users WHERE email = {placeholder}",
        (email,), fetch_one=True
    )
    if existing:
        return jsonify({"success": False, "message": "An account matching this email mapping footprint already exists."}), 400

    # Execute dynamic matrix indexing to safely calculate the user's sequential identifier
    if IS_POSTGRES and HAS_POSTGRES:
        insert_query = f"INSERT INTO users (username, password, email, full_name, matric_no) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, 'PENDING') RETURNING id"
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(insert_query, (username, password, email, full_name))
        new_id = cur.fetchone()['id']
        conn.commit()
        conn.close()
    else:
        insert_query = f"INSERT INTO users (username, password, email, full_name, matric_no) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, 'PENDING')"
        conn = get_db_connection()
        cursor = conn.execute(insert_query, (username, password, email, full_name))
        new_id = cursor.lastrowid
        conn.commit()
        conn.close()

    # Generate the structured sequential tracking identification code automatically
    generated_matric = f"DA/2026/{str(new_id).zfill(4)}"
    execute_query(
        f"UPDATE users SET matric_no = {placeholder} WHERE id = {placeholder}",
        (generated_matric, new_id), commit=True
    )

    ip, device = get_remote_context()
    write_auth_log(username, f"Public Registration | Auto Matric: {generated_matric}", "SUCCESS")
    broadcast_system_event(f"<span class='term-success'>[REGISTRATION] Profile entry initialized for user: <strong>{username}</strong> ({generated_matric}).<br>"
                           f"📍 Context: <code>{ip}</code> | 💻 Device: <em>{device}</em></span>")
    return jsonify({"success": True, "generated_matric": generated_matric})


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    ip, device = get_remote_context()
    placeholder = "%s" if IS_POSTGRES else "?"
    user = execute_query(f"SELECT * FROM users WHERE username = {placeholder} AND password = {placeholder}", (username, password), fetch_one=True)
    if user:
        email = user['email']
        parts = email.split('@')
        masked_email = f"{parts[0][0]}{'*' * (len(parts[0]) - 2)}{parts[0][-1]}@{parts[1]}" if len(parts[0]) > 2 else f"**@{parts[1]}"
        generated_otp = str(random.randint(100000, 999999))
        ACTIVE_OTP_STORE[str(user['id'])] = {"otp": generated_otp, "expires_at": time.time() + 300}
        
        # Immediate out-of-band delivery routing using structural threads
        threading.Thread(
            target=send_otp_email_thread,
            args=(email, user['full_name'], generated_otp),
            daemon=True
        ).start()
        
        write_auth_log(username, "Primary Credential Verification -> Offloaded to Thread Loop", "SUCCESS")
        broadcast_system_event(f"<span>[LOGIN ATTEMPT] User <strong>{username}</strong> verified primary credentials.<br>"
                               f"📍 Origin: <code>{ip}</code> | 💻 Device: <em>{device}</em></span>")
        return jsonify({"success": True, "user_id": user['id'], "masked_email": masked_email, "expires_in": 300})
    
    broadcast_system_event(f"<span class='term-warn'>[AUTH FAILED] Rejected login parameters for username: <strong>{username}</strong><br>"
                           f"🚨 Source IP: <code>{ip}</code> | Device: <em>{device}</em></span>")
    return jsonify({"success": False, "message": "Invalid credentials."}), 401


@app.route('/api/verify-otp', methods=['POST'])
def api_verify_otp():
    data = request.json or {}
    user_id = str(data.get('user_id', ''))
    otp_code = data.get('otp_code', '').strip()

    ip, device = get_remote_context()
    if user_id not in ACTIVE_OTP_STORE:
        return jsonify({"success": False, "message": "No active verification handshake found."}), 400

    session = ACTIVE_OTP_STORE[user_id]
    if time.time() > session['expires_at']:
        return jsonify({"success": False, "message": "Verification session footprint has expired."}), 401
        
    if session['otp'] != otp_code:
        broadcast_system_event(f"<span class='term-warn'>[2FA FAILED] Erroneous verification token rejected.<br>"
                               f"🚨 Attempt Origin: <code>{ip}</code></span>")
        return jsonify({"success": False, "message": "Clearance signature verification failed."}), 401

    ACTIVE_OTP_STORE.pop(user_id, None)
    placeholder = "%s" if IS_POSTGRES else "?"
    user = execute_query(f"SELECT * FROM users WHERE id = {placeholder}", (user_id,), fetch_one=True)
    
    write_auth_log(user['username'], "2FA Code Verification", "SUCCESS")
    broadcast_system_event(f"<span class='term-success'>[LOGIN COMPLETE] User <strong>{user['username']}</strong> passed 2FA checks. Session opened.<br>"
                           f"📍 Active Device: <code>{ip}</code> ({device})</span>")
    return jsonify({"success": True, "user_id": user['id'], "user_info": {"full_name": user['full_name'], "matric_no": user['matric_no']}})


@app.route('/api/ratings', methods=['POST'])
def submit_rating():
    try:
        data = request.json or {}
        user_id = data.get('user_id')
        rating = data.get('rating')
        
        if user_id is None or rating is None:
            return jsonify({"success": False, "message": "Missing required data framework parameters."}), 400
            
        try:
            rating_val = int(rating)
            user_id_val = int(user_id)
        except ValueError:
            return jsonify({"success": False, "message": "Parameters must be valid integers."}), 400
            
        if not (1 <= rating_val <= 10):
            return jsonify({"success": False, "message": "Invalid parameters configuration footprint rating must be 1-10."}), 400
            
        placeholder = "%s" if IS_POSTGRES else "?"
        execute_query(
            f"INSERT INTO ratings (user_id, rating) VALUES ({placeholder}, {placeholder})",
            (user_id_val, rating_val), commit=True
        )
        return jsonify({"success": True, "message": "Rating captured cleanly within system runtime infrastructure."})
    except Exception as e:
        write_auth_log("SYSTEM/RATINGS", f"Pipeline Exception occurred: {str(e)}", "ERROR")
        return jsonify({"success": False, "message": "Internal data engine error processing payload submission."}), 500


@app.route('/api/ratings/export', methods=['GET'])
def export_ratings():
    """Restricted Endpoint: Strict infrastructure role assertion checks."""
    global CURRENT_SYSTEM_MODE
    if CURRENT_SYSTEM_MODE != "admin":
        return jsonify({"success": False, "message": "Unauthorized Access: Extraction engine requires administrative runtime signature verification."}), 403
        
    try:
        query = '''
            SELECT r.id, u.full_name, u.email, r.rating, r.submitted_at 
            FROM ratings r
            JOIN users u ON r.user_id = u.id
            ORDER BY r.submitted_at DESC
        '''
        records = execute_query(query, fetch_all=True)
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Rating ID', 'Student Full Name', 'Verified Email Address', 'Portal Metric Rating (1-10)', 'Timestamp'])
        
        for row in records:
            writer.writerow([row['id'], row['full_name'], row['email'], row['rating'], row['submitted_at']])
            
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=daou_portal_ratings_report.csv"}
        )
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/auth/google', methods=['POST'])
def api_google_auth():
    try:
        data = request.json or {}
        token_string = data.get('id_token')
        if not token_string:
            return jsonify({"success": False, "message": "Missing Identity Proof Token Vector."}), 400

        id_info = id_token.verify_oauth2_token(token_string, requests.Request(), GOOGLE_CLIENT_ID)
        user_email = id_info.get('email')
        
        ip, device = get_remote_context()
        placeholder = "%s" if IS_POSTGRES else "?"
        user = execute_query(f"SELECT * FROM users WHERE email = {placeholder}", (user_email,), fetch_one=True)
        if not user:
            broadcast_system_event(f"<span class='term-warn'>[GOOGLE FAILED] SSO map mismatch for [{user_email}].<br>"
                                   f"🚨 Target IP: <code>{ip}</code></span>")
            return jsonify({"success": False, "message": f"Verified address [{user_email}] has no matrix mapping record."}), 404

        write_auth_log(user['username'], "Google Federated SSO Handshake", "SUCCESS")
        broadcast_system_event(f"<span class='term-success'>[GOOGLE LOGIN] User <strong>{user['username']}</strong> signed in via federated OAuth proof token.<br>"
                               f"📍 Origin: <code>{ip}</code> | 💻 Device: <em>{device}</em></span>")
        return jsonify({"success": True, "user_id": user['id'], "user_info": {"full_name": user['full_name'], "matric_no": user['matric_no']}})
    except Exception as e:
        return jsonify({"success": False, "message": f"Federation module exception: {str(e)}", "SUCCESS": False}), 500


@app.route('/api/admin/users', methods=['GET'])
def admin_get_all_users():
    global CURRENT_SYSTEM_MODE
    if CURRENT_SYSTEM_MODE != "admin":
        return jsonify({"success": False, "message": "Unauthorized Access"}), 403
    try:
        users = execute_query("SELECT id, username, email, full_name, matric_no FROM users ORDER BY id ASC", fetch_all=True)
        return jsonify({"success": True, "users": [dict(u) for u in users]})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/admin/users/update/<int:user_id>', methods=['PUT'])
def admin_update_user(user_id):
    global CURRENT_SYSTEM_MODE
    if CURRENT_SYSTEM_MODE != "admin":
        return jsonify({"success": False, "message": "Unauthorized Access"}), 403
    try:
        data = request.json or {}
        full_name, matric_no, email = data.get('full_name', '').strip(), data.get('matric_no', '').strip(), data.get('email', '').strip()
        if not all([full_name, matric_no, email]):
            return jsonify({"success": False, "message": "Properties missing parameters data."}), 400

        placeholder = "%s" if IS_POSTGRES else "?"
        execute_query(f"UPDATE users SET full_name={placeholder}, matric_no={placeholder}, email={placeholder} WHERE id={placeholder}", (full_name, matric_no, email, user_id), commit=True)
        broadcast_system_event(f"<span>[DB PROFILE UPDATE] Row ID {user_id} modified inside administrative directory database.</span>")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/admin/users/delete/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    global CURRENT_SYSTEM_MODE
    if CURRENT_SYSTEM_MODE != "admin":
        return jsonify({"success": False, "message": "Unauthorized Access"}), 403
    try:
        placeholder = "%s" if IS_POSTGRES else "?"
        execute_query(f"DELETE FROM users WHERE id = {placeholder}", (user_id,), commit=True)
        broadcast_system_event(f"<span class='term-warn'>[DB PURGE] Row tracking ID {user_id} dropped from persistent infrastructure.</span>")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))