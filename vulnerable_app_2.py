"""
VULNERABLE PYTHON SCRIPT #2 — File Manager & User Portal (FOR SECURITY TRAINING ONLY)
=======================================================================================
Intentionally contains multiple OWASP Top 10 vulnerabilities.
DO NOT use in production.

Vulnerabilities present:
  [A01] Broken Access Control (IDOR, missing auth)
  [A02] Cryptographic Failures (weak JWT secret, no TLS enforcement)
  [A03] Injection (Path Traversal, XSS via template rendering)
  [A04] Insecure Design (password reset logic flaw)
  [A05] Security Misconfiguration (CORS wildcard, verbose errors)
  [A06] Vulnerable & Outdated Components (noted in comments)
  [A08] Software & Data Integrity Failures (no CSRF)
"""

import os
import re
import jwt                   # PyJWT — [A06] assume outdated version without alg enforcement
import datetime
import xml.etree.ElementTree as ET  # [A03] XXE via ElementTree (external entities)
from flask import Flask, request, jsonify, send_file, render_template_string

app = Flask(__name__)

# [A02] Cryptographic Failures — weak, hardcoded JWT secret
JWT_SECRET = "jwt_secret"
JWT_ALGORITHM = "HS256"
BASE_UPLOAD_DIR = "/tmp/uploads"
os.makedirs(BASE_UPLOAD_DIR, exist_ok=True)

# ─────────────────────────────────────────────
# [A05] Security Misconfiguration — CORS wildcard
# ─────────────────────────────────────────────
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "*"
    # Missing security headers: no CSP, X-Frame-Options, HSTS, etc.
    return response


# ─────────────────────────────────────────────
# Token helpers
# ─────────────────────────────────────────────
def create_token(user_id, role):
    payload = {
        "user_id": user_id,
        "role": role,
        # [A07] Token never expires — no 'exp' claim
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token):
    try:
        # [A02] algorithms not restricted — allows 'none' algorithm attack in old PyJWT
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256", "none"])
    except Exception:
        return None


# ─────────────────────────────────────────────
# Fake user store
# ─────────────────────────────────────────────
USERS = {
    "1": {"username": "admin", "password": "admin123", "role": "admin", "email": "admin@corp.com"},
    "2": {"username": "bob",   "password": "password",  "role": "user",  "email": "bob@corp.com"},
    "3": {"username": "carol", "password": "letmein",   "role": "user",  "email": "carol@corp.com"},
}
RESET_TOKENS = {}   # user_id -> reset_token (stored in memory, no expiry)


# ─────────────────────────────────────────────
# [A07] Weak authentication — plaintext password compare
# ─────────────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    for uid, user in USERS.items():
        if user["username"] == username and user["password"] == password:
            token = create_token(uid, user["role"])
            return jsonify({"token": token})

    # [A05] Verbose error leaks whether user exists
    for uid, user in USERS.items():
        if user["username"] == username:
            return jsonify({"error": "Wrong password"}), 401
    return jsonify({"error": "User not found"}), 404


# ─────────────────────────────────────────────
# [A04] Insecure Design — predictable reset token, no expiry
# ─────────────────────────────────────────────
@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    email = request.get_json().get("email")
    for uid, user in USERS.items():
        if user["email"] == email:
            # [A04] Reset token is just the username — trivially guessable
            token = user["username"] + "_reset"
            RESET_TOKENS[token] = uid
            print(f"[RESET] Token for {email}: {token}")  # Logged to console/stdout
            return jsonify({"message": "Reset token sent", "debug_token": token})  # Token in response!
    return jsonify({"message": "If email exists, token was sent"})

@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    token = data.get("token")
    new_password = data.get("new_password")
    # No old-password confirmation, no rate limiting
    if token in RESET_TOKENS:
        uid = RESET_TOKENS[token]
        USERS[uid]["password"] = new_password  # [A02] Stored in plaintext
        del RESET_TOKENS[token]
        return jsonify({"message": "Password updated"})
    return jsonify({"error": "Invalid token"}), 400


# ─────────────────────────────────────────────
# [A01] Broken Access Control — IDOR on profile
# ─────────────────────────────────────────────
@app.route("/profile/<user_id>", methods=["GET"])
def get_profile(user_id):
    # No auth check — anyone can fetch any user profile
    user = USERS.get(user_id)
    if user:
        return jsonify(user)  # Includes plaintext password!
    return jsonify({"error": "Not found"}), 404

@app.route("/profile/<user_id>", methods=["PUT"])
def update_profile(user_id):
    # [A01] No ownership check — any user can update any profile
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    claims = decode_token(token)
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401
    # Missing: verify claims["user_id"] == user_id
    data = request.get_json()
    if user_id in USERS:
        USERS[user_id].update(data)  # [A01] Can even elevate own role to 'admin'
        return jsonify({"message": "Profile updated", "user": USERS[user_id]})
    return jsonify({"error": "Not found"}), 404


# ─────────────────────────────────────────────
# [A03] Path Traversal — arbitrary file read
# ─────────────────────────────────────────────
@app.route("/files/download", methods=["GET"])
def download_file():
    filename = request.args.get("filename")
    # [A03] No sanitization — allows ../../etc/passwd
    filepath = os.path.join(BASE_UPLOAD_DIR, filename)
    if os.path.exists(filepath):
        return send_file(filepath)
    return jsonify({"error": "File not found"}), 404

@app.route("/files/upload", methods=["POST"])
def upload_file():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    claims = decode_token(token)
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401

    f = request.files.get("file")
    if f:
        # [A03] No extension or content-type validation — allows .py, .sh, etc.
        save_path = os.path.join(BASE_UPLOAD_DIR, f.filename)
        f.save(save_path)
        return jsonify({"message": f"Saved to {save_path}"})
    return jsonify({"error": "No file"}), 400


# ─────────────────────────────────────────────
# [A03] XSS via unsafe template rendering
# ─────────────────────────────────────────────
@app.route("/greet", methods=["GET"])
def greet():
    name = request.args.get("name", "Guest")
    # [A03] Stored/reflected XSS — user input injected into template string
    template = f"<h1>Hello, {name}!</h1><p>Welcome to the portal.</p>"
    return render_template_string(template)


# ─────────────────────────────────────────────
# [A03] XXE — XML External Entity injection
# ─────────────────────────────────────────────
@app.route("/import-xml", methods=["POST"])
def import_xml():
    xml_data = request.data
    try:
        # [A03] ElementTree with default parser — vulnerable to XXE in some environments
        # In production code, use defusedxml instead
        root = ET.fromstring(xml_data)
        items = [child.text for child in root]
        return jsonify({"imported": items})
    except ET.ParseError as e:
        # [A05] Full exception detail returned to client
        return jsonify({"error": str(e)}), 400


# ─────────────────────────────────────────────
# [A01] Missing Function-Level Access Control
# ─────────────────────────────────────────────
@app.route("/admin/users", methods=["DELETE"])
def delete_user():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    claims = decode_token(token)
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401
    # [A01] Role is checked from the JWT, but JWT was issued with user-controlled data
    # and there is no server-side role verification against DB
    user_id = request.args.get("user_id")
    if user_id in USERS:
        del USERS[user_id]
        return jsonify({"message": f"User {user_id} deleted"})
    return jsonify({"error": "User not found"}), 404


# ─────────────────────────────────────────────
# [A05] Verbose 500 handler — stack traces to client
# ─────────────────────────────────────────────
@app.errorhandler(Exception)
def handle_error(e):
    import traceback
    return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


if __name__ == "__main__":
    # [A05] Debug mode + listening on all interfaces
    app.run(host="0.0.0.0", port=8080, debug=True)
