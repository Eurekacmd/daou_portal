import os
import sqlite3
import random
import time
import smtplib
from email.mime.text import MIMEText
from flask import Flask, request, jsonify, render_template

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
        create_table_query = '''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                full_name VARCHAR(255) NOT NULL,
                matric_no VARCHAR(100) UNIQUE NOT NULL
            )
        '''
    else:
        create_table_query = '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                matric_no TEXT UNIQUE NOT NULL
            )
        '''
    execute_query(create_table_query, commit=True)


def write_auth_log(username, action, status):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] MODE: {CURRENT_SYSTEM_MODE.upper()} | USER: {username} | ACTION: {action} | STATUS: {status}")


def send_otp_email(recipient_email, full_name, otp_code):
    if not SMTP_USER or not SMTP_PASS:
        write_auth_log("SYSTEM", "SMTP credentials not configured", "ERROR")
        return False

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
        with smtplib.SMTP_SSL(SMTP_HOST, 465, timeout=15) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [recipient_email], msg.as_string())
        return True
    except Exception as e_ssl:
        write_auth_log("SYSTEM", f"SMTP SSL send failure: {str(e_ssl)}", "WARN")

    try:
        with smtplib.SMTP(SMTP_HOST, 587, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [recipient_email], msg.as_string())
        return True
    except Exception as e_tls:
        write_auth_log("SYSTEM", f"SMTP TLS send failure: {str(e_tls)}", "ERROR")
        return False


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
    if data.get('username') == ADMIN_USERNAME and data.get('password') == ADMIN_PASSWORD:
        write_auth_log("ADMIN", "Console Gateway Authentication Check", "SUCCESS")
        return jsonify({"success": True, "role": "admin"})
    return jsonify({"success": False, "message": "Access Denied: Administrative footprint failure."}), 401


@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    email = data.get('email', '').strip()
    full_name = data.get('full_name', '').strip()
    matric_no = data.get('matric_no', '').strip()

    if not all([username, password, email, full_name, matric_no]):
        return jsonify({"success": False, "message": "All fields are required."}), 400

    placeholder = "%s" if IS_POSTGRES else "?"
    existing = execute_query(
        f"SELECT username FROM users WHERE username = {placeholder} OR matric_no = {placeholder} OR email = {placeholder}",
        (username, matric_no, email), fetch_one=True
    )
    if existing:
        return jsonify({"success": False, "message": "Identity components collide with pre-existing data values."}), 400

    insert_query = f"INSERT INTO users (username, password, email, full_name, matric_no) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})"
    execute_query(insert_query, (username, password, email, full_name, matric_no), commit=True)
    write_auth_log(username, "Direct DB Injection / Public Registration", "SUCCESS")
    return jsonify({"success": True})


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    placeholder = "%s" if IS_POSTGRES else "?"
    user = execute_query(f"SELECT * FROM users WHERE username = {placeholder} AND password = {placeholder}", (username, password), fetch_one=True)
    if user:
        email = user['email']
        parts = email.split('@')
        masked_email = f"{parts[0][0]}{'*' * (len(parts[0]) - 2)}{parts[0][-1]}@{parts[1]}" if len(parts[0]) > 2 else f"**@{parts[1]}"
        generated_otp = str(random.randint(100000, 999999))
        ACTIVE_OTP_STORE[str(user['id'])] = {"otp": generated_otp, "expires_at": time.time() + 300}
        
        send_otp_email(email, user['full_name'], generated_otp)
        write_auth_log(username, "Primary Credential Verification", "SUCCESS")
        return jsonify({"success": True, "user_id": user['id'], "masked_email": masked_email})
    return jsonify({"success": False, "message": "Invalid credentials."}), 401


@app.route('/api/verify-otp', methods=['POST'])
def api_verify_otp():
    data = request.json or {}
    user_id = str(data.get('user_id', ''))
    otp_code = data.get('otp_code', '').strip()

    if user_id not in ACTIVE_OTP_STORE:
        return jsonify({"success": False, "message": "No active verification handshake found."}), 400

    session = ACTIVE_OTP_STORE[user_id]
    if time.time() > session['expires_at'] or session['otp'] != otp_code:
        return jsonify({"success": False, "message": "Clearance signature verification failed."}), 401

    ACTIVE_OTP_STORE.pop(user_id, None)
    placeholder = "%s" if IS_POSTGRES else "?"
    user = execute_query(f"SELECT * FROM users WHERE id = {placeholder}", (user_id,), fetch_one=True)
    return jsonify({"success": True, "user_id": user['id'], "user_info": {"full_name": user['full_name'], "matric_no": user['matric_no']}})


# --- Cryptographic Google Authentication Hook API Node Layer ---
@app.route('/api/auth/google', methods=['POST'])
def api_google_auth():
    try:
        data = request.json or {}
        token_string = data.get('id_token')
        if not token_string:
            return jsonify({"success": False, "message": "Missing Identity Proof Token Vector."}), 400

        id_info = id_token.verify_oauth2_token(token_string, requests.Request(), GOOGLE_CLIENT_ID)
        user_email = id_info.get('email')
        
        placeholder = "%s" if IS_POSTGRES else "?"
        user = execute_query(f"SELECT * FROM users WHERE email = {placeholder}", (user_email,), fetch_one=True)
        if not user:
            return jsonify({"success": False, "message": f"Verified address [{user_email}] has no matrix mapping record."}), 404

        write_auth_log(user['username'], "Google Federated SSO Handshake", "SUCCESS")
        return jsonify({"success": True, "user_id": user['id'], "user_info": {"full_name": user['full_name'], "matric_no": user['matric_no']}})
    except Exception as e:
        return jsonify({"success": False, "message": f"Federation module exception: {str(e)}"}), 500


# --- Elevated Administrative Oversight Management System Core API Operations ---
@app.route('/api/admin/users', methods=['GET'])
def admin_get_all_users():
    try:
        users = execute_query("SELECT id, username, email, full_name, matric_no FROM users ORDER BY id ASC", fetch_all=True)
        return jsonify({"success": True, "users": [dict(u) for u in users]})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/admin/users/update/<int:user_id>', methods=['PUT'])
def admin_update_user(user_id):
    try:
        data = request.json or {}
        full_name, matric_no, email = data.get('full_name', '').strip(), data.get('matric_no', '').strip(), data.get('email', '').strip()
        if not all([full_name, matric_no, email]):
            return jsonify({"success": False, "message": "Properties missing parameters data."}), 400

        placeholder = "%s" if IS_POSTGRES else "?"
        execute_query(f"UPDATE users SET full_name={placeholder}, matric_no={placeholder}, email={placeholder} WHERE id={placeholder}", (full_name, matric_no, email, user_id), commit=True)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/admin/users/delete/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    try:
        placeholder = "%s" if IS_POSTGRES else "?"
        execute_query(f"DELETE FROM users WHERE id = {placeholder}", (user_id,), commit=True)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))