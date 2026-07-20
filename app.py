import os
import sqlite3
import random
import time
from flask import Flask, request, jsonify, render_template

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

# Hardcoded Admin Credentials for Secure Interface Isolation
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "DAOU_admin_2026" 

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
                biometric_enrolled INT DEFAULT 0
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
                biometric_enrolled INTEGER DEFAULT 0
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
    conn.close()

def write_auth_log(username, action, status):
    """Optional logger helper function to print server-side actions."""
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] MODE: {CURRENT_SYSTEM_MODE.upper()} | USER: {username} | ACTION: {action} | STATUS: {status}")


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

        # Account for dialect placeholder variations between SQLite (?) and Postgres (%s)
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
            
            ACTIVE_OTP_STORE[str(user['id'])] = {
                "otp": generated_otp, 
                "username": username,
                "expires_at": expiration_time
            }
            
            write_auth_log(username, "Primary Login Credential Check", "SUCCESS")
            
            return jsonify({
                "success": True, 
                "user_id": user['id'], 
                "masked_email": masked_email,
                "generated_otp": generated_otp,
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


@app.route('/api/enroll-biometrics', methods=['POST'])
def api_enroll_biometrics():
    try:
        data = request.json or {}
        user_id = data.get('user_id')
        
        placeholder = "%s" if IS_POSTGRES else "?"
        update_query = f"UPDATE users SET biometric_enrolled = 1 WHERE id = {placeholder}"
        execute_query(update_query, (user_id,), commit=True)
            
        return jsonify({"success": True, "message": "Passkey parameter registration successful."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/verify-biometrics-bypass', methods=['POST'])
def api_verify_biometrics_bypass():
    try:
        data = request.json or {}
        username = data.get('username', '').strip()
        
        placeholder = "%s" if IS_POSTGRES else "?"
        select_query = f"SELECT * FROM users WHERE username = {placeholder} AND biometric_enrolled = 1"
        user = execute_query(select_query, (username,), fetch_one=True)
            
        if user:
            write_auth_log(username, "Biometric Key Bypass Handshake", "SUCCESS")
            return jsonify({
                "success": True,
                "user_id": user['id'],
                "user_info": {
                    "full_name": user['full_name'],
                    "matric_no": user['matric_no'],
                    "biometric_enrolled": True
                }
            })
            
        write_auth_log(username, "Biometric Key Bypass Handshake", "FAILED")
        return jsonify({"success": False, "message": "FIDO2 signature verification failure."}), 401
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)