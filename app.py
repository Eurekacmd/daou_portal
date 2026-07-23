import os
import random
import time
import csv
import io
import secrets
from datetime import datetime
from flask import Flask, jsonify, request, Response, stream_with_context, render_template, make_response

app = Flask(__name__)

# --- IN-MEMORY DATABASE MATRICES ---
USERS_DB = [
    {
        "id": 1,
        "username": "Enoch",
        "password": "password",
        "full_name": "Enoch Ola",
        "matric_no": "DAOU/CYB/2026/001",
        "email": "enochstudent@daou.edu.ng"
    }
]

PENDING_OTP_VALIDATIONS = {}
PORTAL_RATINGS = []
SYSTEM_RUNTIME_MODE = "user"
TELEMETRY_LISTENERS = []

# In-Memory Active Sessions Table for Multi-Device Tracking
USER_SESSIONS_DB = []

# --- STRUCTURAL ENGINE UTILITIES ---
def generate_matric_number():
    """Generates unique structural matrix identification number matching DAOU format."""
    unique_suffix = random.randint(100, 999)
    return f"DAOU/CYB/2026/{unique_suffix}"

def emit_telemetry(message):
    """Dispatches log strings down the persistent event stream channels."""
    global TELEMETRY_LISTENERS
    payload = f"data: {message}\n\n"
    active_listeners = []
    for listener in TELEMETRY_LISTENERS:
        try:
            listener.put(payload)
            active_listeners.append(listener)
        except Exception:
            pass
    TELEMETRY_LISTENERS = active_listeners

class TelemetryQueue:
    def __init__(self):
        self.messages = []
    def put(self, msg):
        self.messages.append(msg)
    def get(self):
        if self.messages:
            return self.messages.pop(0)
        return None

# --- REQUEST HOOK FOR ACTIVITY TRACKING ---

@app.before_request
def update_user_activity():
    """Updates the last_active timestamp for the current device session token."""
    session_token = request.cookies.get('device_session_token')
    if session_token:
        for session in USER_SESSIONS_DB:
            if session['session_token'] == session_token:
                session['last_active'] = time.time()
                break

# --- FRONTEND TEMPLATE ROUTE ---

@app.route('/')
def serve_portal_gateway():
    """Renders the main frontend interface template."""
    return render_template('index.html')

# --- AUTHENTICATION INTERFACE PIPELINES ---

@app.route('/api/register', methods=['POST'])
def handle_registration():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    email = data.get('email', '').strip()
    full_name = data.get('full_name', '').strip()

    if not all([username, password, email, full_name]):
        return jsonify({"success": False, "message": "Missing required registration framework dimensions."}), 400

    if any(u['username'].lower() == username.lower() for u in USERS_DB):
        return jsonify({"success": False, "message": "Username already claimed within memory database matrix."}), 400
    if any(u['email'].lower() == email.lower() for u in USERS_DB):
        return jsonify({"success": False, "message": "Email mapping signature already linked."}), 400

    assigned_matric = generate_matric_number()
    new_user = {
        "id": len(USERS_DB) + 1,
        "username": username,
        "password": password,
        "full_name": full_name,
        "matric_no": assigned_matric,
        "email": email
    }
    USERS_DB.append(new_user)
    
    emit_telemetry(f"<span class='term-success'>[REGISTRATION] {username} registered. Assigned Matric: {assigned_matric}</span>")
    return jsonify({"success": True, "generated_matric": assigned_matric})

@app.route('/api/login', methods=['POST'])
def handle_login():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    # Intercept Hardcoded Administration Credentials
    if username == "Admin" and password == "Eureka":
        global SYSTEM_RUNTIME_MODE
        SYSTEM_RUNTIME_MODE = "admin"
        emit_telemetry("<span class='term-success'>[ADMIN LOGIN] Administrative dashboard accessed successfully.</span>")
        return jsonify({
            "success": True,
            "is_admin": True,
            "message": "Admin authorization granted."
        })

    user = next((u for u in USERS_DB if u['username'].lower() == username.lower()), None)
    
    if not user or user['password'] != password:
        emit_telemetry(f"<span class='term-warn'>[AUTH FAILURE] Rejected credential assertion match for: {username}</span>")
        return jsonify({"success": False, "message": "Invalid portal credentials footprint."}), 401

    otp = str(random.randint(100000, 999999))
    expiration_window = 300 
    
    PENDING_OTP_VALIDATIONS[user['id']] = {
        "code": otp,
        "expires_at": time.time() + expiration_window
    }

    email_parts = user['email'].split('@')
    masked_email = f"{email_parts[0][:3]}***@{email_parts[1]}"

    emit_telemetry(f"[MFA DISPATCHED] Security OTP code ({otp}) sent down to virtual email spooler for user ID: {user['id']}")
    
    return jsonify({
        "success": True,
        "is_admin": False,
        "user_id": user['id'],
        "masked_email": masked_email,
        "expires_in": expiration_window
    })

@app.route('/api/verify-otp', methods=['POST'])
def handle_otp_verification():
    data = request.json or {}
    user_id = data.get('user_id')
    otp_code = data.get('otp_code', '').strip()

    otp_record = PENDING_OTP_VALIDATIONS.get(user_id)
    
    if not otp_record:
        return jsonify({"success": False, "message": "No validation sequence context running for identity."}), 400

    if time.time() > otp_record['expires_at']:
        del PENDING_OTP_VALIDATIONS[user_id]
        emit_telemetry("<span class='term-warn'>[MFA EXPIRED] OTP signature verification context window closed automatically.</span>")
        return jsonify({"success": False, "message": "Security verification token has expired!"}), 400

    if otp_record['code'] != otp_code:
        emit_telemetry(f"<span class='term-warn'>[MFA BAD CODE] Incorrect token submitted for user mapping reference ID: {user_id}</span>")
        return jsonify({"success": False, "message": "Invalid security authentication code sequence match."}), 400

    del PENDING_OTP_VALIDATIONS[user_id]
    user = next((u for u in USERS_DB if u['id'] == user_id), None)
    
    # --- MULTI-DEVICE SESSION CREATION ---
    session_token = secrets.token_hex(32)
    ip_address = request.remote_addr or "127.0.0.1"
    user_agent = request.headers.get('User-Agent', 'Unknown Browser')
    device_name = "Mobile Device" if "Mobile" in user_agent else "Desktop Browser"

    session_entry = {
        "id": len(USER_SESSIONS_DB) + 1,
        "user_id": user['id'],
        "session_token": session_token,
        "ip_address": ip_address,
        "device_name": device_name,
        "created_at": time.time(),
        "last_active": time.time()
    }
    USER_SESSIONS_DB.append(session_entry)

    emit_telemetry(f"<span class='term-success'>[LOGIN COMPLETE] MFA clearance passed for target {user['username']} from {device_name} ({ip_address}).</span>")
    
    resp_data = {
        "success": True,
        "user_id": user['id'],
        "user_info": {
            "full_name": user['full_name'],
            "matric_no": user['matric_no']
        }
    }
    
    response = make_response(jsonify(resp_data))
    response.set_cookie('device_session_token', session_token, httponly=True, secure=False, samesite='Lax')
    return response

@app.route('/api/auth/google', methods=['POST'])
def handle_google_oauth():
    data = request.json or {}
    id_token = data.get('id_token')
    
    if not id_token:
        return jsonify({"success": False, "message": "Missing structural federation payload token."}), 400

    emit_telemetry("<span class='term-success'>[GOOGLE LOGIN] Parsing inbound federated token payload signatures.</span>")
    
    user = USERS_DB[0] 
    
    # --- MULTI-DEVICE SESSION CREATION FOR GOOGLE OAUTH ---
    session_token = secrets.token_hex(32)
    ip_address = request.remote_addr or "127.0.0.1"
    user_agent = request.headers.get('User-Agent', 'Unknown Browser')
    device_name = "Mobile Device" if "Mobile" in user_agent else "Desktop Browser"

    session_entry = {
        "id": len(USER_SESSIONS_DB) + 1,
        "user_id": user['id'],
        "session_token": session_token,
        "ip_address": ip_address,
        "device_name": device_name,
        "created_at": time.time(),
        "last_active": time.time()
    }
    USER_SESSIONS_DB.append(session_entry)

    resp_data = {
        "success": True,
        "user_id": user['id'],
        "user_info": {
            "full_name": user['full_name'],
            "matric_no": user['matric_no']
        }
    }
    response = make_response(jsonify(resp_data))
    response.set_cookie('device_session_token', session_token, httponly=True, secure=False, samesite='Lax')
    return response

# --- MULTI-DEVICE MONITORING ENDPOINTS ---

@app.route('/api/user/active-devices', methods=['GET'])
def get_active_devices():
    """Retrieves all active device sessions and status metrics for the authenticated user."""
    session_token = request.cookies.get('device_session_token')
    if not session_token:
        return jsonify({"success": False, "message": "Unauthorized session context."}), 401

    current_session = next((s for s in USER_SESSIONS_DB if s['session_token'] == session_token), None)
    if not current_session:
        return jsonify({"success": False, "message": "Session footprint invalid or expired."}), 401

    user_id = current_session['user_id']
    user_sessions = [s for s in USER_SESSIONS_DB if s['user_id'] == user_id]

    device_list = []
    current_time = time.time()

    for s in user_sessions:
        time_diff = current_time - s['last_active']
        is_online = time_diff < 300  # Online if active within the last 5 minutes

        device_list.append({
            "session_id": s['id'],
            "device_name": s['device_name'],
            "ip_address": s['ip_address'],
            "created_at": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(s['created_at'])),
            "last_active": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(s['last_active'])),
            "status": "Online" if is_online else "Away / Offline",
            "is_current_device": s['session_token'] == session_token
        })

    return jsonify({"success": True, "devices": device_list})

@app.route('/api/user/revoke-session/<int:session_id>', methods=['DELETE'])
def revoke_specific_session(session_id):
    """Terminates a specific device session remotely."""
    global USER_SESSIONS_DB
    session_token = request.cookies.get('device_session_token')
    if not session_token:
        return jsonify({"success": False, "message": "Unauthorized."}), 401

    current_session = next((s for s in USER_SESSIONS_DB if s['session_token'] == session_token), None)
    if not current_session:
        return jsonify({"success": False, "message": "Unauthorized."}), 401

    # Ensure target session belongs to the same user
    target_session = next((s for s in USER_SESSIONS_DB if s['id'] == session_id and s['user_id'] == current_session['user_id']), None)
    if not target_session:
        return jsonify({"success": False, "message": "Target session not found."}), 404

    USER_SESSIONS_DB = [s for s in USER_SESSIONS_DB if s['id'] != session_id]
    emit_telemetry(f"<span class='term-warn'>[SESSION REVOKED] Remote termination executed on session ID: {session_id}</span>")
    
    return jsonify({"success": True, "message": "Session terminated successfully."})

# --- USER LAND INTERACTIVE ENDPOINTS ---

@app.route('/api/ratings', methods=['POST'])
def record_portal_rating():
    data = request.json or {}
    user_id = data.get('user_id')
    rating = data.get('rating')

    if not user_id or not rating:
        return jsonify({"success": False, "message": "Incomplete evaluation matrix metrics payload."}), 400

    user = next((u for u in USERS_DB if u['id'] == user_id), None)
    if not user:
        return jsonify({"success": False, "message": "Session footprint identity reference untrusted."}), 403

    rating_entry = {
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
        "username": user['username'],
        "matric_no": user['matric_no'],
        "rating_score": int(rating)
    }
    PORTAL_RATINGS.append(rating_entry)
    
    emit_telemetry(f"[METRIC LOGGED] User {user['username']} pushed score value array: {rating}/10")
    return jsonify({"success": True, "message": "Metric score captured successfully."})

# --- BACKEND SYSTEM ADMINISTRATION PIPELINES ---

@app.route('/api/system/mode', methods=['POST'])
def set_system_mode():
    global SYSTEM_RUNTIME_MODE
    data = request.json or {}
    mode = data.get('mode', 'user')
    SYSTEM_RUNTIME_MODE = mode
    emit_telemetry(f"[MODE SWITCH] Structural layout environment reassigned -> {SYSTEM_RUNTIME_MODE.upper()}_MODE")
    return jsonify({"success": True})

@app.route('/api/admin/users', methods=['GET'])
def get_admin_user_directory():
    if SYSTEM_RUNTIME_MODE != "admin":
        return jsonify({"success": False, "message": "Operation requires structural admin validation context status."}), 403
    return jsonify({"success": True, "users": USERS_DB})

@app.route('/api/admin/users/update/<int:user_id>', methods=['PUT'])
def update_user_profile(user_id):
    if SYSTEM_RUNTIME_MODE != "admin":
        return jsonify({"success": False, "message": "Access restricted."}), 403
        
    data = request.json or {}
    user = next((u for u in USERS_DB if u['id'] == user_id), None)
    
    if not user:
        return jsonify({"success": False, "message": "Target record reference identity not located."}), 404

    user['full_name'] = data.get('full_name', user['full_name'])
    user['matric_no'] = data.get('matric_no', user['matric_no'])
    user['email'] = data.get('email', user['email'])
    
    emit_telemetry(f"<span class='term-success'>[DB ROW UPDATE] Row modification written successfully on identifier ID: {user_id}</span>")
    return jsonify({"success": True})

@app.route('/api/admin/users/delete/<int:user_id>', methods=['DELETE'])
def delete_user_profile(user_id):
    global USERS_DB
    if SYSTEM_RUNTIME_MODE != "admin":
        return jsonify({"success": False, "message": "Access restricted."}), 403

    USERS_DB = [u for u in USERS_DB if u['id'] != user_id]
    emit_telemetry(f"<span class='term-warn'>[DB ROW PURGE] Dropped entry row structural reference index match ID: {user_id}</span>")
    return jsonify({"success": True})

@app.route('/api/ratings/export', methods=['GET'])
def export_ratings_csv():
    if SYSTEM_RUNTIME_MODE != "admin":
        return Response("Unauthorized extraction parameter engine bounds.", status=403)

    dest_output = io.StringIO()
    writer = csv.writer(dest_output)
    writer.writerow(['Timestamp Signature', 'Account Username', 'Matric Number', 'Metric Rating Score'])
    
    for row in PORTAL_RATINGS:
        writer.writerow([row['timestamp'], row['username'], row['matric_no'], row['rating_score']])
        
    response_payload = dest_output.getvalue()
    dest_output.close()
    
    return Response(
        response_payload,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=DAOU_Portal_Ratings_Extract.csv"}
    )

@app.route('/api/admin/live-stream')
def backend_telemetry_stream():
    """Generates continuous text event metrics back into the terminal wrapper layout loop."""
    def event_stream_loop():
        q = TelemetryQueue()
        TELEMETRY_LISTENERS.append(q)
        yield f"data: > System runtime engine connected safely to logging node interface telemetry stream.\n\n"
        
        while True:
            msg = q.get()
            if msg:
                yield msg
            time.sleep(0.2)

    return Response(stream_with_context(event_stream_loop()), mimetype="text/event-stream")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)