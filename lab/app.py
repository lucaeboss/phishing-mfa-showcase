"""
MFA Phishing-Resistance Lab  --  ExampleCorp (FICTIONAL TRAINING SERVICE)
=========================================================================

A self-contained teaching lab for a senior security project. It demonstrates,
end to end and entirely on your own machine:

  1. Credential capture via a fake "evil portal" login page.
  2. Why TOTP 2FA stops *basic* credential phishing (the attacker hits a wall).
  3. Why a stolen *session token* bypasses that 2FA (the AiTM insight) -- shown
     in a closed loop against THIS app only (see replay_demo.py).
  4. Why passkeys / WebAuthn (FIDO2) defeat the whole chain, because the
     credential is cryptographically bound to the real origin.

SCOPE / ETHICS
--------------
Everything here targets ONLY this local application ("ExampleCorp", a fictional
service). It does not clone, proxy, or talk to any real website or provider.
Run it on localhost in an isolated lab. See docs/scope-and-ethics.md.
"""

import os
import io
import json
import socket
import secrets
import datetime

from flask import (
    Flask, request, redirect, url_for, make_response, jsonify, render_template
)
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import qrcode.image.svg

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
CAPTURE_LOG = os.path.join(DATA_DIR, "captured.log")

# WebAuthn relying-party identity. Browse to the app via EXACTLY this origin,
# otherwise passkey ceremonies will (correctly) refuse to run.
RP_ID = "localhost"
RP_NAME = "ExampleCorp (TRAINING)"
ORIGIN = "http://localhost:5000"

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# In-memory stores. Sessions are deliberately simple so the "session token = the
# prize" lesson is easy to see and demonstrate.
SESSIONS = {}              # sid            -> {username, authed, created}
PENDING = {}               # pending token  -> {username, created}
WEBAUTHN_CHALLENGES = {}   # username       -> base64url challenge string


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_users(users):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def new_session(username):
    sid = secrets.token_urlsafe(24)
    SESSIONS[sid] = {"username": username, "authed": True, "created": now()}
    return sid


def set_session_cookie(resp, sid):
    # HttpOnly mirrors real apps (blocks JS theft) -- note that it does NOT stop
    # a network/AiTM position from capturing the cookie, which is the point.
    resp.set_cookie("demo_session", sid, httponly=True, samesite="Lax")


def current_user():
    sid = request.cookies.get("demo_session")
    s = SESSIONS.get(sid)
    if s and s.get("authed"):
        return s["username"]
    return None


def make_qr_svg(data):
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode()


# --------------------------------------------------------------------------
# Landing
# --------------------------------------------------------------------------
@app.get("/")
def index():
    return render_template("index.html", user=current_user())


# --------------------------------------------------------------------------
# Account enrollment (password + TOTP)
# --------------------------------------------------------------------------
@app.get("/enroll")
def enroll_page():
    return render_template("enroll.html")


@app.post("/api/enroll")
def api_enroll():
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    if not username or not password:
        return render_template("enroll.html", error="Username and password are required.")
    users = load_users()
    if username in users:
        return render_template("enroll.html", error="That user already exists.")
    secret = pyotp.random_base32()
    users[username] = {
        "password": generate_password_hash(password),
        "totp_secret": secret,
        "webauthn": [],
        "created": now(),
    }
    save_users(users)
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="ExampleCorp TRAINING")
    return render_template(
        "enroll_done.html",
        username=username,
        secret=secret,
        uri=uri,
        qr_svg=make_qr_svg(uri),
    )


# --------------------------------------------------------------------------
# Password + TOTP login (the "phishable" authentication path)
# --------------------------------------------------------------------------
@app.get("/login")
def login_page():
    return render_template("login.html")


@app.post("/api/login")
def api_login():
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    users = load_users()
    user = users.get(username)
    if not user or not check_password_hash(user["password"], password):
        return render_template("login.html", error="Invalid username or password."), 401
    # First factor OK -> issue a short-lived pending token and demand TOTP.
    token = secrets.token_urlsafe(16)
    PENDING[token] = {"username": username, "created": now()}
    resp = make_response(redirect(url_for("totp_page")))
    resp.set_cookie("pending_2fa", token, httponly=True, samesite="Lax")
    return resp


@app.get("/totp")
def totp_page():
    token = request.cookies.get("pending_2fa")
    if not token or token not in PENDING:
        return redirect(url_for("login_page"))
    return render_template("totp.html")


@app.post("/api/totp")
def api_totp():
    token = request.cookies.get("pending_2fa")
    pend = PENDING.get(token)
    if not pend:
        return redirect(url_for("login_page"))
    code = request.form.get("code", "").strip()
    users = load_users()
    user = users.get(pend["username"])
    totp = pyotp.TOTP(user["totp_secret"])
    if not totp.verify(code, valid_window=1):
        return render_template("totp.html", error="Invalid or expired code."), 401
    PENDING.pop(token, None)
    sid = new_session(pend["username"])
    resp = make_response(redirect(url_for("dashboard")))
    set_session_cookie(resp, sid)
    resp.delete_cookie("pending_2fa")
    return resp


# --------------------------------------------------------------------------
# Protected resources (what the session token unlocks)
# --------------------------------------------------------------------------
@app.get("/dashboard")
def dashboard():
    u = current_user()
    if not u:
        return redirect(url_for("login_page"))
    return render_template("dashboard.html", username=u)


@app.get("/api/me")
def api_me():
    """Protected API. Access is granted by the session token ALONE -- no second
    factor is re-checked here. This is what makes a stolen session so valuable."""
    u = current_user()
    if not u:
        return jsonify({"error": "unauthenticated"}), 401
    return jsonify({
        "username": u,
        "email": u,
        "account_balance": "$14,204.55",
        "ssn_last4": "0097",
        "note": "Sensitive data returned on the strength of the session token only.",
    })


@app.post("/api/logout")
def logout():
    sid = request.cookies.get("demo_session")
    SESSIONS.pop(sid, None)
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("demo_session")
    return resp


# --------------------------------------------------------------------------
# The "evil portal" -- a fake login page for the FICTIONAL ExampleCorp service.
# It captures the first factor (username + password) to a local log file.
# --------------------------------------------------------------------------
@app.get("/portal")
def portal():
    return render_template("portal.html")


@app.post("/portal/capture")
def portal_capture():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    line = f"{now()}  CAPTURED  user={username!r}  pass={password!r}  from={request.remote_addr}"
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CAPTURE_LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print("[EVIL PORTAL] " + line)
    return render_template("portal_captured.html", username=username, password=password)


# --------------------------------------------------------------------------
# QR-code phishing ("quishing") demo.
# The QR encodes the LOCAL training portal ONLY. Set the host to this machine's
# LAN IP so a phone on the same network can reach the lab during a controlled,
# in-person demo. It never points at a real site, and the lab is never meant to
# be exposed on the public internet.
# --------------------------------------------------------------------------
def lan_ip():
    """Best-effort LAN IP for the in-person QR demo. No packets are actually sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


@app.get("/qr")
def qr_page():
    host = request.args.get("host", "").strip() or f"{lan_ip()}:5000"
    target = f"http://{host}/portal"
    return render_template("qr.html", host=host, target=target, qr_svg=make_qr_svg(target))


# --------------------------------------------------------------------------
# Passkey / WebAuthn (FIDO2) -- the phishing-resistant authentication path
# --------------------------------------------------------------------------
@app.get("/secure")
def secure_page():
    return render_template("secure.html")


@app.post("/api/webauthn/register/options")
def wa_register_options():
    username = (request.get_json() or {}).get("username", "").strip().lower()
    users = load_users()
    user = users.get(username)
    if not user:
        return jsonify({"error": "Create a password account at /enroll first, then add a passkey."}), 400
    existing = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["id"]))
                for c in user.get("webauthn", [])]
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_name=username,
        user_id=username.encode(),
        exclude_credentials=existing,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    WEBAUTHN_CHALLENGES[username] = bytes_to_base64url(options.challenge)
    return app.response_class(options_to_json(options), mimetype="application/json")


@app.post("/api/webauthn/register/verify")
def wa_register_verify():
    data = request.get_json() or {}
    username = data.get("username", "").strip().lower()
    cred = data.get("credential")
    challenge = base64url_to_bytes(WEBAUTHN_CHALLENGES.get(username, ""))
    try:
        verification = verify_registration_response(
            credential=json.dumps(cred),
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
        )
    except Exception as e:  # noqa: BLE001 -- surface the reason to the lab UI
        return jsonify({"verified": False, "error": str(e)}), 400
    users = load_users()
    users[username].setdefault("webauthn", []).append({
        "id": bytes_to_base64url(verification.credential_id),
        "public_key": bytes_to_base64url(verification.credential_public_key),
        "sign_count": verification.sign_count,
    })
    save_users(users)
    return jsonify({"verified": True})


@app.post("/api/webauthn/login/options")
def wa_login_options():
    username = (request.get_json() or {}).get("username", "").strip().lower()
    users = load_users()
    user = users.get(username)
    allow = []
    if user:
        allow = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["id"]))
                 for c in user.get("webauthn", [])]
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    WEBAUTHN_CHALLENGES[username] = bytes_to_base64url(options.challenge)
    return app.response_class(options_to_json(options), mimetype="application/json")


@app.post("/api/webauthn/login/verify")
def wa_login_verify():
    data = request.get_json() or {}
    username = data.get("username", "").strip().lower()
    cred = data.get("credential") or {}
    users = load_users()
    user = users.get(username)
    if not user:
        return jsonify({"verified": False, "error": "unknown user"}), 400
    stored = next((c for c in user.get("webauthn", []) if c["id"] == cred.get("id")), None)
    if not stored:
        return jsonify({"verified": False, "error": "no matching passkey"}), 400
    try:
        verification = verify_authentication_response(
            credential=json.dumps(cred),
            expected_challenge=base64url_to_bytes(WEBAUTHN_CHALLENGES.get(username, "")),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=base64url_to_bytes(stored["public_key"]),
            credential_current_sign_count=stored["sign_count"],
            require_user_verification=False,
        )
    except Exception as e:  # noqa: BLE001
        return jsonify({"verified": False, "error": str(e)}), 400
    stored["sign_count"] = verification.new_sign_count
    save_users(users)
    sid = new_session(username)
    resp = jsonify({"verified": True})
    set_session_cookie(resp, sid)
    return resp


# --------------------------------------------------------------------------
# First-run seed
# --------------------------------------------------------------------------
def seed():
    users = load_users()
    if "victim@examplecorp.test" not in users:
        secret = pyotp.random_base32()
        users["victim@examplecorp.test"] = {
            "password": generate_password_hash("Password123!"),
            "totp_secret": secret,
            "webauthn": [],
            "created": now(),
        }
        save_users(users)
    users = load_users()
    s = users["victim@examplecorp.test"]["totp_secret"]
    print("=" * 70)
    print("ExampleCorp TRAINING lab running at", ORIGIN)
    print("Seeded demo account:")
    print("   username: victim@examplecorp.test")
    print("   password: Password123!")
    print("   TOTP secret:", s)
    print("   (add that secret to an authenticator app, or run: "
          "python totp_now.py victim@examplecorp.test)")
    print("=" * 70)


if __name__ == "__main__":
    seed()
    # Browse via http://localhost:5000  (NOT 127.0.0.1) so WebAuthn origin matches.
    app.run(host="127.0.0.1", port=5000, debug=False)
