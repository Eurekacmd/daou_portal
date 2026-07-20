import os
import sqlite3
import random
import time
import smtplib
from email.mime.text import MIMEText
from flask import Flask, request, jsonify, render_template

import webauthn
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
)

# Conditional import helper for deployment targets
try:
    import psycopg2
    from psycopg2.extras import RealDictRow
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

app = Flask(__name__)

# Environmental Database Router Strategy
DATABASE_URL = os.environ.get('DATABASE_URL', 'database.db')
IS_POSTGRES = DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://")

# Operational State Control Variable
CURRENT_SYSTEM_MODE = "user"  # Options: "user" or "admin"

ACTIVE_OTP_STORE = {}
ACTIVE_WEBAUTHN_CHALLENGES = {}

# Hardcoded Admin Credentials for Secure Interface Isolation
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "DAOU_admin_2026"

# ---------------------------------------------------------------------------
# SMTP configuration (Gmail) — set these as real environment variables,
# never hardcode credentials in source. See setup notes at the bottom of
# this file / the accompanying message for how to generate a Gmail App
# Password.
# ---------------------------------------------------------------------------
SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '465'))
SMTP_USER = os.environ.get('GMAIL_USER')            # e.g. your.address@gmail.com
SMTP_PASS = os.environ.get('GMAIL_APP_PASSWORD')    # 16-char Gmail App Password
SMTP_FROM_NAME = os.environ.get('SMTP_FROM_NAME', 'DAOU University Portal')

# ---------------------------------------------------------------------------
# WebAuthn (biometric / passkey) configuration — RP_ID must match the
# domain the app is served from. For local testing this is "localhost".
# If you deploy to a real domain later, update RP_ID and ORIGIN to match
# (e.g. RP_ID="portal.daou.edu.ng", ORIGIN="https://portal.daou.edu.ng").
# ---------------------------------------------------------------------------
RP_ID = os.environ.get('WEBAUTHN_RP_ID', 'localhost')
RP_NAME = "DAOU University Portal"
ORIGIN = os.environ.get('WEBAUTHN_ORIGIN', 'http://localhost:5000')


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
    """Abstraction layout utility helping query processing parity between SQLite and Postgres."""
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
    """Initializes schema targets based on target infrastructure layout rules."""
    if IS_POSTGRES and HAS_POSTGRES:
        create_table_query = '''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                full_name VARCHAR(255) NOT NULL,
                matric_no VARCHAR(100) UNIQUE NOT NULL,
                biometric_enrolled INT DEFAULT 0,
                webauthn_credential_id VARCHAR(512),
                webauthn_public_key TEXT,
                webauthn_sign_count INT DEFAULT 0
            )
        '''
    else:
        create_table_query = '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT NOT NULL,
                full_name TEXT NOT NULL,
                matric_no TEXT UNIQUE NOT NULL,
                biometric_enrolled INTEGER DEFAULT 0,
                webauthn_credential_id TEXT,
                webauthn_public_key TEXT,
                webauthn_sign_count INTEGER DEFAULT 0
            )
        '''

    conn = get_db_connection()
    if IS_POSTGRES and HAS_POSTGRES:
        cur = conn.cursor()
        cur.execute(create_table_query)
        conn.commit()
    else:
        conn.execute(create_table_query)
        conn.commit()

        # Lightweight migration for pre-existing SQLite databases that predate
        # the webauthn_* columns.
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        for col, coltype in [
            ("webauthn_credential_id", "TEXT"),
            ("webauthn_public_key", "TEXT"),
            ("webauthn_sign_count", "INTEGER DEFAULT 0"),
        ]:
            if col not in existing_cols:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {coltype}")
        conn.commit()
    conn.close()


def write_auth_log(username, action, status):
    """Optional logger helper function to print server-side actions."""
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] MODE: {CURRENT_SYSTEM_MODE.upper()} | USER: {username} | ACTION: {action} | STATUS: {status}")


def send_otp_email(recipient_email, full_name, otp_code):
    """Sends the OTP to the user's real inbox over SMTP (Gmail). Returns True/False.
    Tries implicit SSL (465) first, then falls back to STARTTLS (587) — some
    hosting providers throttle or block one of the two."""
    if not SMTP_USER or not SMTP_PASS:
        write_auth_log("SYSTEM", "SMTP credentials not configured (GMAIL_USER / GMAIL_APP_PASSWORD)", "ERROR")
        return False

    subject = "Your DAOU Portal Security Code"
    body = (
        f"Hi {full_name},\n\n"
        f"Your one-time passcode (OTP) for DAOU University Portal is:\n\n"
        f"    {otp_code}\n\n"
        f"This code expires in 5 minutes. If you did not request this, "
        f"you can safely ignore this email.\n\n"
        f"— DAOU University Portal Security"
    )

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = f"{SMTP_FROM_NAME} <{SMTP_USER}>"
    msg['To'] = recipient_email

    # Attempt 1: implicit TLS on 465
    try:
        with smtplib.SMTP_SSL(SMTP_HOST, 465, timeout=15) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [recipient_email], msg.as_string())
        return True
    except Exception as e_ssl:
        write_auth_log("SYSTEM", f"SMTP SSL(465) send failure: {str(e_ssl)}", "WARN")

    # Attempt 2: STARTTLS on 587 (fallback for hosts that block 465 outbound)
    try:
        with smtplib.SMTP(SMTP_HOST, 587, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [recipient_email], msg.as_string())
        return True
    except Exception as e_tls:
        write_auth_log("SYSTEM", f"SMTP STARTTLS(587) send failure: {str(e_tls)}", "ERROR")
        return False


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/system/mode', methods=['GET', 'POST'])
def system_mode_switch():
    """Operational context controller switch node."""
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
    """Explicitly isolated route verifying Admin access to view backend console telemetry."""
    try:
        data = request.json or {}
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            write_auth_log("ADMIN", "Console Gateway Authentication Check", "SUCCESS")
            return jsonify({
                "success": True,
                "role": "admin",
                "message": "Elevated credentials accepted. Initializing backend terminal streaming array."
            })

        write_auth_log(username if username else "UNKNOWN", "Console Gateway Authentication Check", "FAILED")
        return jsonify({
            "success": False,
            "message": "Access Denied: Administrative footprint authorization failure."
        }), 401
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/register', methods=['POST'])
def api_register():
    try:
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
            f"SELECT username, matric_no FROM users WHERE username = {placeholder} OR matric_no = {placeholder}",
            (username, matric_no),
            fetch_one=True
        )

        if existing:
            if existing['username'].lower() == username.lower():
                return jsonify({"success": False, "message": "Username bound to pre-existing records."}), 400
            if existing['matric_no'].lower() == matric_no.lower():
                return jsonify({"success": False, "message": "Matric Number bound to pre-existing records."}), 400

        insert_query = f"INSERT INTO users (username, password, email, full_name, matric_no) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})"
        execute_query(insert_query, (username, password, email, full_name, matric_no), commit=True)

        write_auth_log(username, "Direct DB Injection", "SUCCESS")
        return jsonify({"success": True, "message": "Account injected successfully."})

    except Exception as e:
        write_auth_log("SYSTEM", f"Registration Exception: {str(e)}", "ERROR")
        return jsonify({"success": False, "message": f"Database exception: {str(e)}"}), 500


@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.json or {}
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        placeholder = "%s" if IS_POSTGRES else "?"
        select_query = f"SELECT * FROM users WHERE username = {placeholder} AND password = {placeholder}"
        user = execute_query(select_query, (username, password), fetch_one=True)

        if user:
            email = user['email']
            parts = email.split('@')

            if len(parts[0]) > 2:
                masked_email = f"{parts[0][0]}{'*' * (len(parts[0]) - 2)}{parts[0][-1]}@{parts[1]}"
            else:
                masked_email = f"**@{parts[1]}"

            generated_otp = str(random.randint(100000, 999999))
            expiration_time = time.time() + 300

            email_sent = send_otp_email(email, user['full_name'], generated_otp)
            if not email_sent:
                write_auth_log(username, "OTP Email Dispatch", "FAILED")
                return jsonify({
                    "success": False,
                    "message": "Could not send verification email. Check SMTP configuration and try again."
                }), 502

            ACTIVE_OTP_STORE[str(user['id'])] = {
                "otp": generated_otp,
                "username": username,
                "expires_at": expiration_time
            }

            write_auth_log(username, "Primary Login Credential Check", "SUCCESS")
            write_auth_log(username, "OTP Email Dispatch", "SUCCESS")

            return jsonify({
                "success": True,
                "user_id": user['id'],
                "masked_email": masked_email,
                # NOTE: the OTP itself is intentionally never returned here —
                # it only exists in ACTIVE_OTP_STORE server-side and in the
                # user's real inbox.
                "biometric_enrolled": bool(user['biometric_enrolled']),
                "system_context_mode": CURRENT_SYSTEM_MODE
            })

        write_auth_log(username if username else "UNKNOWN", "Primary Login Credential Check", "FAILED")
        return jsonify({
            "success": False,
            "message": "Access Denied: Invalid identity credentials pattern matching."
        }), 401

    except Exception as e:
        write_auth_log("SYSTEM", f"Login Exception: {str(e)}", "ERROR")
        return jsonify({"success": False, "message": f"Server processing error: {str(e)}"}), 500


@app.route('/api/verify-otp', methods=['POST'])
def api_verify_otp():
    try:
        data = request.json or {}
        user_id = str(data.get('user_id', ''))
        otp_code = data.get('otp_code', '').strip()

        if user_id not in ACTIVE_OTP_STORE:
            return jsonify({"success": False, "message": "No active authentication handshake found for this profile."}), 400

        session = ACTIVE_OTP_STORE[user_id]

        if time.time() > session['expires_at']:
            ACTIVE_OTP_STORE.pop(user_id, None)
            return jsonify({"success": False, "message": "Security clearance token expired. Re-authenticate."}), 400

        if session['otp'] == otp_code:
            ACTIVE_OTP_STORE.pop(user_id, None)

            placeholder = "%s" if IS_POSTGRES else "?"
            select_query = f"SELECT * FROM users WHERE id = {placeholder}"
            user = execute_query(select_query, (user_id,), fetch_one=True)

            if user:
                write_auth_log(user['username'], "MFA Security Validation", "SUCCESS")
                return jsonify({
                    "success": True,
                    "user_id": user['id'],
                    "user_info": {
                        "full_name": user['full_name'],
                        "matric_no": user['matric_no'],
                        "biometric_enrolled": bool(user['biometric_enrolled'])
                    }
                })

        write_auth_log("UNKNOWN", "MFA Security Validation", "FAILED")
        return jsonify({"success": False, "message": "MFA Challenge signature verification failed."}), 401

    except Exception as e:
        return jsonify({"success": False, "message": f"Server processing error: {str(e)}"}), 500


@app.route('/api/check-biometric-enrolled', methods=['POST'])
def api_check_biometric():
    try:
        data = request.json or {}
        username = data.get('username', '').strip()

        placeholder = "%s" if IS_POSTGRES else "?"
        select_query = f"SELECT biometric_enrolled FROM users WHERE username = {placeholder}"
        user = execute_query(select_query, (username,), fetch_one=True)

        if user:
            return jsonify({"success": True, "enrolled": bool(user['biometric_enrolled'])})
        return jsonify({"success": False, "message": "User sequence mismatch."}), 404
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ---------------------------------------------------------------------------
# WebAuthn (real biometric / passkey) — registration ceremony
# ---------------------------------------------------------------------------

@app.route('/api/webauthn/register/begin', methods=['POST'])
def webauthn_register_begin():
    try:
        data = request.json or {}
        user_id = data.get('user_id')

        placeholder = "%s" if IS_POSTGRES else "?"
        user = execute_query(f"SELECT * FROM users WHERE id = {placeholder}", (user_id,), fetch_one=True)
        if not user:
            return jsonify({"success": False, "message": "User not found."}), 404

        options = webauthn.generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=str(user['id']).encode('utf-8'),
            user_name=user['username'],
            user_display_name=user['full_name'],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
        )

        ACTIVE_WEBAUTHN_CHALLENGES[str(user['id'])] = options.challenge

        return webauthn.options_to_json(options), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/webauthn/register/complete', methods=['POST'])
def webauthn_register_complete():
    try:
        data = request.json or {}
        user_id = str(data.get('user_id'))
        credential = data.get('credential')

        expected_challenge = ACTIVE_WEBAUTHN_CHALLENGES.pop(user_id, None)
        if not expected_challenge:
            return jsonify({"success": False, "message": "No pending registration challenge for this profile."}), 400

        verification = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
        )

        placeholder = "%s" if IS_POSTGRES else "?"
        update_query = (
            f"UPDATE users SET biometric_enrolled = 1, "
            f"webauthn_credential_id = {placeholder}, "
            f"webauthn_public_key = {placeholder}, "
            f"webauthn_sign_count = {placeholder} "
            f"WHERE id = {placeholder}"
        )
        execute_query(
            update_query,
            (
                bytes_to_base64url(verification.credential_id),
                bytes_to_base64url(verification.credential_public_key),
                verification.sign_count,
                user_id,
            ),
            commit=True,
        )

        write_auth_log(f"user#{user_id}", "WebAuthn Passkey Enrollment", "SUCCESS")
        return jsonify({"success": True, "message": "Passkey registered successfully."})
    except Exception as e:
        write_auth_log(f"user#{data.get('user_id') if 'data' in locals() else '?'}", f"WebAuthn Enrollment Exception: {str(e)}", "ERROR")
        return jsonify({"success": False, "message": f"Passkey registration failed: {str(e)}"}), 400


# ---------------------------------------------------------------------------
# WebAuthn (real biometric / passkey) — authentication ceremony
# ---------------------------------------------------------------------------

@app.route('/api/webauthn/login/begin', methods=['POST'])
def webauthn_login_begin():
    try:
        data = request.json or {}
        username = data.get('username', '').strip()

        placeholder = "%s" if IS_POSTGRES else "?"
        user = execute_query(
            f"SELECT * FROM users WHERE username = {placeholder} AND biometric_enrolled = 1",
            (username,),
            fetch_one=True,
        )
        if not user or not user['webauthn_credential_id']:
            return jsonify({"success": False, "message": "No passkey registered for this account."}), 404

        allow_credentials = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(user['webauthn_credential_id']))
        ]

        options = webauthn.generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        ACTIVE_WEBAUTHN_CHALLENGES[username] = options.challenge

        return webauthn.options_to_json(options), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/webauthn/login/complete', methods=['POST'])
def webauthn_login_complete():
    try:
        data = request.json or {}
        username = data.get('username', '').strip()
        credential = data.get('credential')

        expected_challenge = ACTIVE_WEBAUTHN_CHALLENGES.pop(username, None)
        if not expected_challenge:
            return jsonify({"success": False, "message": "No pending authentication challenge for this profile."}), 400

        placeholder = "%s" if IS_POSTGRES else "?"
        user = execute_query(
            f"SELECT * FROM users WHERE username = {placeholder}", (username,), fetch_one=True
        )
        if not user or not user['webauthn_public_key']:
            return jsonify({"success": False, "message": "No passkey registered for this account."}), 404

        verification = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=base64url_to_bytes(user['webauthn_public_key']),
            credential_current_sign_count=user['webauthn_sign_count'] or 0,
        )

        execute_query(
            f"UPDATE users SET webauthn_sign_count = {placeholder} WHERE id = {placeholder}",
            (verification.new_sign_count, user['id']),
            commit=True,
        )

        write_auth_log(username, "WebAuthn Passkey Authentication", "SUCCESS")
        return jsonify({
            "success": True,
            "user_id": user['id'],
            "user_info": {
                "full_name": user['full_name'],
                "matric_no": user['matric_no'],
                "biometric_enrolled": True
            }
        })
    except Exception as e:
        write_auth_log(username if 'username' in locals() else 'UNKNOWN', f"WebAuthn Auth Exception: {str(e)}", "ERROR")
        return jsonify({"success": False, "message": f"Passkey verification failed: {str(e)}"}), 401


if __name__ == '__main__':
    init_db()
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
else:
    # Also run migrations when imported by a WSGI server (gunicorn on Render)
    init_db()
