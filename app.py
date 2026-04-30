import streamlit as st
import hashlib
import hmac
import json
import os
import pyotp
import qrcode
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import bcrypt
from datetime import datetime, timedelta
from io import BytesIO
import random
import time

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="IoT 2L-MFA Blockchain",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# CUSTOM CSS
# ============================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Exo 2', sans-serif;
    background-color: #0a0f1e;
    color: #c9d1e8;
}

.stApp {
    background: linear-gradient(135deg, #0a0f1e 0%, #0d1a2e 50%, #0a1628 100%);
}

h1, h2, h3 {
    font-family: 'Share Tech Mono', monospace;
    color: #00e5ff;
    letter-spacing: 2px;
}

.stButton > button {
    background: linear-gradient(90deg, #00e5ff22, #00bcd422);
    border: 1px solid #00e5ff66;
    color: #00e5ff;
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: 1px;
    border-radius: 4px;
    transition: all 0.3s;
}
.stButton > button:hover {
    background: linear-gradient(90deg, #00e5ff44, #00bcd444);
    border-color: #00e5ff;
    box-shadow: 0 0 12px #00e5ff55;
}

.metric-card {
    background: linear-gradient(135deg, #0d1f35, #0a1628);
    border: 1px solid #00e5ff33;
    border-radius: 8px;
    padding: 20px;
    text-align: center;
    box-shadow: 0 0 20px #00e5ff11;
}
.metric-value {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2rem;
    color: #00e5ff;
}
.metric-label {
    font-size: 0.8rem;
    color: #7a8aab;
    letter-spacing: 1px;
    text-transform: uppercase;
}

.block-card {
    background: #0d1f35;
    border: 1px solid #1e3a5f;
    border-left: 3px solid #00e5ff;
    border-radius: 6px;
    padding: 14px 18px;
    margin-bottom: 10px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.78rem;
    color: #8ab4d4;
}
.block-card .block-title {
    color: #00e5ff;
    font-size: 0.95rem;
    margin-bottom: 8px;
}
.hash-text { color: #4fc3f7; word-break: break-all; }
.tampered { border-left-color: #ff4444 !important; }
.valid { border-left-color: #00e5ff; }

.factor-pass { color: #00e676; font-weight: bold; }
.factor-fail { color: #ff4444; font-weight: bold; }

.device-card {
    background: #0d1a2e;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 14px;
    text-align: center;
    margin-bottom: 8px;
}
.status-online { color: #00e676; }
.status-offline { color: #ff9800; }
.status-locked { color: #ff4444; }

.puf-box {
    background: #071020;
    border: 1px solid #00e5ff33;
    border-radius: 6px;
    padding: 12px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.78rem;
    color: #4fc3f7;
    word-break: break-all;
    margin: 8px 0;
}

.progress-container {
    background: #0d1a2e;
    border: 1px solid #1e3a5f;
    border-radius: 20px;
    height: 8px;
    margin: 10px 0 20px 0;
    overflow: hidden;
}
.progress-bar {
    height: 100%;
    border-radius: 20px;
    background: linear-gradient(90deg, #00e5ff, #00bcd4);
    box-shadow: 0 0 8px #00e5ff88;
    transition: width 0.5s ease;
}

.lockout-banner {
    background: #2a0a0a;
    border: 1px solid #ff444466;
    border-radius: 6px;
    padding: 12px;
    color: #ff6666;
    font-family: 'Share Tech Mono', monospace;
    text-align: center;
    margin-bottom: 12px;
}

.section-divider {
    border: none;
    border-top: 1px solid #1e3a5f;
    margin: 24px 0;
}

[data-testid="stSidebar"] {
    background: #060d1a;
    border-right: 1px solid #1e3a5f;
}
[data-testid="stSidebar"] .stRadio label {
    font-family: 'Share Tech Mono', monospace;
    color: #7a8aab;
}
</style>
""", unsafe_allow_html=True)

# ============================================================
# FILE PATHS
# ============================================================
DEVICES_FILE   = "devices.json"
USERS_FILE     = "users.json"
LOGS_FILE      = "logs.json"
BLOCKCHAIN_FILE = "blockchain.json"
LOCKOUT_FILE   = "lockout.json"

# ============================================================
# HELPERS — FILE I/O
# ============================================================
def load_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except:
        return default

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)

# ============================================================
# MERKLE TREE
# ============================================================
def merkle_root(data_list):
    """Calculate Merkle root from a list of strings."""
    if not data_list:
        return hashlib.sha256(b"empty").hexdigest()
    leaves = [hashlib.sha256(str(d).encode()).hexdigest() for d in data_list]
    while len(leaves) > 1:
        if len(leaves) % 2 != 0:
            leaves.append(leaves[-1])
        leaves = [
            hashlib.sha256((leaves[i] + leaves[i+1]).encode()).hexdigest()
            for i in range(0, len(leaves), 2)
        ]
    return leaves[0]

# ============================================================
# BLOCKCHAIN
# ============================================================
class Block:
    def __init__(self, index, timestamp, event_type, device_id,
                 user_id, data_hash, merkle, previous_hash):
        self.index        = index
        self.timestamp    = timestamp
        self.event_type   = event_type
        self.device_id    = device_id
        self.user_id      = user_id
        self.data_hash    = data_hash
        self.merkle_root  = merkle
        self.previous_hash = previous_hash
        self.hash         = self.calculate_hash()

    def calculate_hash(self):
        content = (
            f"{self.index}{self.timestamp}{self.event_type}"
            f"{self.device_id}{self.user_id}{self.data_hash}"
            f"{self.merkle_root}{self.previous_hash}"
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "device_id": self.device_id,
            "user_id": self.user_id,
            "data_hash": self.data_hash,
            "merkle_root": self.merkle_root,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

class Blockchain:
    def __init__(self):
        self.chain = []
        self._load_or_init()

    def _load_or_init(self):
        """Load persisted chain or create genesis block."""
        data = load_json(BLOCKCHAIN_FILE, [])
        if data:
            for b in data:
                block = Block(
                    b["index"], b["timestamp"], b["event_type"],
                    b["device_id"], b["user_id"], b["data_hash"],
                    b["merkle_root"], b["previous_hash"]
                )
                block.hash = b["hash"]  # preserve stored hash
                self.chain.append(block)
        else:
            genesis = Block(0, str(datetime.now()), "GENESIS",
                            "system", "system",
                            hashlib.sha256(b"genesis").hexdigest(),
                            merkle_root(["genesis"]), "0")
            self.chain.append(genesis)
            self._persist()

    def _persist(self):
        save_json(BLOCKCHAIN_FILE, [b.to_dict() for b in self.chain])

    def add_block(self, event_type, device_id, user_id, data_fields):
        """Add a new block with Merkle root from data_fields list."""
        prev  = self.chain[-1]
        dh    = hashlib.sha256(str(data_fields).encode()).hexdigest()
        mr    = merkle_root(data_fields)
        block = Block(
            len(self.chain), str(datetime.now()),
            event_type, device_id, user_id, dh, mr, prev.hash
        )
        self.chain.append(block)
        self._persist()
        return block

    def is_valid(self):
        """Verify chain integrity — returns (bool, broken_index)."""
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i-1]
            if curr.hash != curr.calculate_hash():
                return False, i
            if curr.previous_hash != prev.hash:
                return False, i
        return True, -1

    def tamper_block(self, index):
        """Simulate tampering by modifying a block's data_hash."""
        if 0 < index < len(self.chain):
            self.chain[index].data_hash = "TAMPERED_" + self.chain[index].data_hash[:8]
            self._persist()

# ============================================================
# LOGGING
# ============================================================
def log_event(event, status, device_id="", user_id=""):
    entry = {
        "event": event,
        "status": status,
        "device_id": device_id,
        "user_id": user_id,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "date": datetime.now().strftime("%Y-%m-%d")
    }
    logs = load_json(LOGS_FILE, [])
    logs.append(entry)
    save_json(LOGS_FILE, logs)

# ============================================================
# PUF SIMULATION
# ============================================================
def puf_response(device_id, secret):
    """Deterministic HMAC-SHA256 based PUF simulation."""
    return hmac.new(
        secret.encode(),
        device_id.encode(),
        hashlib.sha256
    ).hexdigest()

# ============================================================
# BIOMETRIC SIMULATION
# ============================================================
def biometric_score(bio_input):
    """Simulate fingerprint matching — returns 0.0–1.0 score."""
    if not bio_input:
        return 0.0
    seed = int(hashlib.sha256(bio_input.encode()).hexdigest(), 16) % 10000
    random.seed(seed)
    score = round(random.uniform(0.55, 1.0), 3)
    random.seed()
    return score

# ============================================================
# LOCKOUT MANAGEMENT
# ============================================================
def get_lockout(device_id):
    locks = load_json(LOCKOUT_FILE, {})
    return locks.get(device_id, {"attempts": 0, "locked_until": None})

def set_lockout(device_id, lock_data):
    locks = load_json(LOCKOUT_FILE, {})
    locks[device_id] = lock_data
    save_json(LOCKOUT_FILE, locks)

def record_failed_attempt(device_id):
    lock = get_lockout(device_id)
    lock["attempts"] = lock.get("attempts", 0) + 1
    if lock["attempts"] >= 3:
        lock["locked_until"] = (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    set_lockout(device_id, lock)
    return lock["attempts"]

def reset_lockout(device_id):
    set_lockout(device_id, {"attempts": 0, "locked_until": None})

def is_locked(device_id):
    lock = get_lockout(device_id)
    if lock.get("locked_until"):
        until = datetime.strptime(lock["locked_until"], "%Y-%m-%d %H:%M:%S")
        if datetime.now() < until:
            remaining = int((until - datetime.now()).total_seconds())
            return True, remaining
        else:
            reset_lockout(device_id)
    return False, 0

# ============================================================
# SESSION TIMEOUT
# ============================================================
def check_session_timeout():
    """Reset to step 1 if idle > 5 minutes."""
    if "last_activity" in st.session_state:
        elapsed = (datetime.now() - st.session_state.last_activity).total_seconds()
        if elapsed > 300 and st.session_state.get("auth_step", 1) > 1:
            st.session_state.auth_step = 1
            st.session_state.pop("auth_device_id", None)
            st.session_state.pop("auth_username", None)
            st.warning("⏱ Session timed out. Please re-authenticate.")
    st.session_state.last_activity = datetime.now()

# ============================================================
# INIT SESSION STATE
# ============================================================
if "blockchain" not in st.session_state:
    st.session_state.blockchain = Blockchain()
if "auth_step" not in st.session_state:
    st.session_state.auth_step = 1
if "last_activity" not in st.session_state:
    st.session_state.last_activity = datetime.now()
if "qr_generated" not in st.session_state:
    st.session_state.qr_generated = False
if "qr_bytes" not in st.session_state:
    st.session_state.qr_bytes = None

check_session_timeout()

# ============================================================
# SIDEBAR NAVIGATION
# ============================================================
st.sidebar.markdown("""
<div style='text-align:center; padding: 10px 0 20px 0;'>
  <div style='font-family: Share Tech Mono, monospace; font-size: 1.1rem; color: #00e5ff;'>
    🔐 IoT 2L-MFA
  </div>
  <div style='font-size: 0.7rem; color: #4a5a7a; letter-spacing: 2px;'>BLOCKCHAIN SECURED</div>
</div>
""", unsafe_allow_html=True)

nav = st.sidebar.radio(
    "NAVIGATION",
    ["🔑 Authenticate", "📡 Register Device", "👤 Register User",
     "📊 Dashboard", "⛓ Blockchain Explorer"],
    label_visibility="visible"
)

# IoT Device Simulation Panel in sidebar
st.sidebar.markdown("<hr style='border-color:#1e3a5f'>", unsafe_allow_html=True)
st.sidebar.markdown("<div style='font-family: Share Tech Mono, monospace; font-size: 0.8rem; color: #00e5ff; margin-bottom:8px;'>📶 LIVE IoT NODES</div>", unsafe_allow_html=True)

sim_devices = [
    {"id": "NODE-A1", "status": "online", "label": "🟢 Online"},
    {"id": "NODE-B2", "status": "offline", "label": "🟡 Standby"},
    {"id": "NODE-C3", "status": "locked", "label": "🔴 Locked"},
]
for dev in sim_devices:
    st.sidebar.markdown(f"""
    <div class='device-card'>
      <div style='font-family: Share Tech Mono, monospace; font-size: 0.75rem; color: #4fc3f7;'>{dev['id']}</div>
      <div style='font-size: 0.8rem; margin-top: 4px;'>{dev['label']}</div>
    </div>
    """, unsafe_allow_html=True)

# ============================================================
# PAGE: REGISTER DEVICE
# ============================================================
if nav == "📡 Register Device":
    st.markdown("## 📡 Device Registration")
    st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)

    with st.form("register_device_form"):
        d_id     = st.text_input("Device ID (e.g. IOT-001)")
        d_secret = st.text_input("Device Secret Key", type="password")
        d_owner  = st.text_input("Owner Name")
        submitted = st.form_submit_button("Register Device")

    if submitted:
        if not d_id or not d_secret or not d_owner:
            st.error("All fields are required.")
        else:
            devices = load_json(DEVICES_FILE, {})
            if d_id in devices:
                st.warning(f"Device `{d_id}` already registered.")
            else:
                devices[d_id] = {
                    "device_secret": d_secret,
                    "owner": d_owner,
                    "registered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                save_json(DEVICES_FILE, devices)
                st.session_state.blockchain.add_block(
                    "DEVICE_REGISTER", d_id, "admin",
                    [d_id, d_owner, "REGISTER"]
                )
                log_event("Device Registration", "Success", d_id, "admin")
                st.success(f"✅ Device `{d_id}` registered successfully.")

    # Show registered devices
    st.markdown("### Registered Devices")
    devices = load_json(DEVICES_FILE, {})
    if devices:
        rows = [{"Device ID": k, "Owner": v["owner"], "Registered At": v["registered_at"]}
                for k, v in devices.items()]
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
    else:
        st.info("No devices registered yet.")

# ============================================================
# PAGE: REGISTER USER
# ============================================================
elif nav == "👤 Register User":
    st.markdown("## 👤 User Registration")
    st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)

    with st.form("register_user_form"):
        username  = st.text_input("Username")
        password  = st.text_input("Password", type="password")
        role      = st.selectbox("Role", ["operator", "admin", "viewer"])
        submitted = st.form_submit_button("Register User")

    if submitted:
        if not username or not password:
            st.error("Username and password are required.")
        else:
            users = load_json(USERS_FILE, {})
            if username in users:
                st.warning(f"User `{username}` already exists.")
            else:
                hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                totp_secret = pyotp.random_base32()
                users[username] = {
                    "hashed_password": hashed,
                    "totp_secret": totp_secret,
                    "role": role,
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                save_json(USERS_FILE, users)
                log_event("User Registration", "Success", "", username)
                st.success(f"✅ User `{username}` registered.")

                # Show TOTP QR code for setup
                totp = pyotp.TOTP(totp_secret)
                uri  = totp.provisioning_uri(name=username, issuer_name="IoT-2LMFA")
                img  = qrcode.make(uri)
                buf  = BytesIO()
                img.save(buf)
                st.markdown("**Scan this QR code with Google Authenticator:**")
                st.image(buf.getvalue(), width=200)
                st.code(f"Manual key: {totp_secret}", language="text")

    # Show registered users (no secrets)
    st.markdown("### Registered Users")
    users = load_json(USERS_FILE, {})
    if users:
        rows = [{"Username": k, "Role": v["role"], "Created": v["created_at"]}
                for k, v in users.items()]
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
    else:
        st.info("No users registered yet.")

# ============================================================
# PAGE: AUTHENTICATE
# ============================================================
elif nav == "🔑 Authenticate":
    st.markdown("## 🔐 Two-Layer Authentication")
    st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)

    # Progress bar
    step = st.session_state.auth_step
    pct  = 50 if step == 1 else (100 if step == 3 else 75)
    st.markdown(f"""
    <div style='margin-bottom:6px; font-family: Share Tech Mono, monospace;
         font-size: 0.8rem; color: #4a6a8a;'>
      AUTHENTICATION PROGRESS — STEP {min(step,2)} OF 2
    </div>
    <div class='progress-container'>
      <div class='progress-bar' style='width:{pct}%'></div>
    </div>
    """, unsafe_allow_html=True)

    # ---- STEP 1: DEVICE AUTH ----
    if step == 1:
        st.markdown("### 📡 Layer 1 — Device Authentication")

        device_id = st.text_input("Enter Device ID")

        # Lockout check
        locked, remaining = is_locked(device_id) if device_id else (False, 0)
        if locked:
            mins, secs = divmod(remaining, 60)
            st.markdown(f"""
            <div class='lockout-banner'>
              🔒 DEVICE LOCKED — Too many failed attempts<br>
              Retry in {mins:02d}:{secs:02d}
            </div>""", unsafe_allow_html=True)
        else:
            if st.button("Verify Device", disabled=not device_id):
                devices = load_json(DEVICES_FILE, {})
                if device_id not in devices:
                    record_failed_attempt(device_id)
                    log_event("Device Auth", "Failed - Not Registered", device_id)
                    st.error("❌ Device not registered. Contact admin.")
                else:
                    dev     = devices[device_id]
                    secret  = dev["device_secret"]
                    puf_r   = puf_response(device_id, secret)
                    proof   = hashlib.sha256(puf_r.encode()).hexdigest()

                    # PUF visual
                    st.markdown("**🔬 PUF Challenge-Response:**")
                    st.markdown(f"""
                    <div class='puf-box'>
                      <div style='color:#7a8aab; margin-bottom:4px;'>CHALLENGE (Device ID)</div>
                      <div>{device_id}</div>
                      <div style='color:#7a8aab; margin:8px 0 4px 0;'>PUF RESPONSE (HMAC-SHA256)</div>
                      <div>{puf_r}</div>
                      <div style='color:#7a8aab; margin:8px 0 4px 0;'>PROOF HASH</div>
                      <div>{proof}</div>
                    </div>
                    """, unsafe_allow_html=True)

                    st.session_state.blockchain.add_block(
                        "DEVICE_AUTH", device_id, "pending",
                        [device_id, puf_r, proof]
                    )
                    reset_lockout(device_id)
                    log_event("Device Authentication", "Success", device_id)
                    st.session_state.auth_device_id = device_id
                    st.session_state.auth_step = 2
                    st.success("✅ Device verified. Proceed to User Authentication.")
                    time.sleep(1)
                    st.rerun()

    # ---- STEP 2: USER MFA ----
    elif step == 2:
        st.markdown(f"### 👤 Layer 2 — User MFA  *(Device: `{st.session_state.get('auth_device_id', '?')}`)*")

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        # QR code generation for TOTP
        col_qr, col_otp = st.columns([1, 2])
        with col_qr:
            if st.button("Show TOTP QR"):
                users = load_json(USERS_FILE, {})
                if username and username in users:
                    totp_secret = users[username]["totp_secret"]
                    totp = pyotp.TOTP(totp_secret)
                    uri  = totp.provisioning_uri(name=username, issuer_name="IoT-2LMFA")
                    img  = qrcode.make(uri)
                    buf  = BytesIO()
                    img.save(buf)
                    st.session_state.qr_bytes = buf.getvalue()
                    st.session_state.qr_generated = True
                else:
                    st.warning("Enter a valid registered username first.")
            if st.session_state.qr_generated and st.session_state.qr_bytes:
                st.image(st.session_state.qr_bytes, width=160)

        with col_otp:
            otp       = st.text_input("TOTP Code (6-digit)")
            biometric = st.text_input("Biometric Token (any passphrase)")

        if st.button("Verify User"):
            users = load_json(USERS_FILE, {})
            if not username or username not in users:
                st.error("User not found.")
            else:
                user_data   = users[username]
                totp        = pyotp.TOTP(user_data["totp_secret"])
                dev_id      = st.session_state.get("auth_device_id", "unknown")

                # Factor evaluations
                f1_pass = totp.verify(otp) if otp else False
                f2_pass = bcrypt.checkpw(password.encode(),
                           user_data["hashed_password"].encode()) if password else False
                bio_sc  = biometric_score(biometric)
                f3_pass = bio_sc >= 0.7

                # Show per-factor results
                st.markdown("#### Factor Results:")
                c1, c2, c3 = st.columns(3)
                c1.markdown(f"**Factor 1 — TOTP**<br><span class='{'factor-pass' if f1_pass else 'factor-fail'}'>{'✅ PASS' if f1_pass else '❌ FAIL'}</span>", unsafe_allow_html=True)
                c2.markdown(f"**Factor 2 — Password**<br><span class='{'factor-pass' if f2_pass else 'factor-fail'}'>{'✅ PASS' if f2_pass else '❌ FAIL'}</span>", unsafe_allow_html=True)
                c3.markdown(f"**Factor 3 — Biometric** (score: {bio_sc})<br><span class='{'factor-pass' if f3_pass else 'factor-fail'}'>{'✅ PASS' if f3_pass else '❌ FAIL'}</span>", unsafe_allow_html=True)

                score = sum([f1_pass, f2_pass, f3_pass])

                if score >= 2:
                    st.session_state.blockchain.add_block(
                        "USER_AUTH", dev_id, username,
                        [username, otp, str(bio_sc), "AUTH_SUCCESS"]
                    )
                    log_event("User Authentication", "Success", dev_id, username)
                    st.session_state.auth_username = username
                    st.session_state.auth_step = 3
                    st.success(f"✅ Access Granted! Welcome, **{username}** ({user_data['role']})")
                    time.sleep(1)
                    st.rerun()
                else:
                    record_failed_attempt(dev_id)
                    log_event("User Authentication", "Failed", dev_id, username)
                    st.error(f"❌ Authentication Failed — {score}/3 factors passed (need ≥2)")

        if st.button("← Back to Device Auth"):
            st.session_state.auth_step = 1
            st.rerun()

    # ---- STEP 3: SUCCESS ----
    elif step == 3:
        dev  = st.session_state.get("auth_device_id", "?")
        user = st.session_state.get("auth_username", "?")
        st.markdown(f"""
        <div style='text-align:center; padding: 40px 20px;'>
          <div style='font-size:3rem;'>✅</div>
          <div style='font-family: Share Tech Mono, monospace; font-size: 1.5rem;
               color: #00e676; margin: 16px 0 8px 0;'>ACCESS GRANTED</div>
          <div style='color: #7a8aab;'>Device: <b>{dev}</b> · User: <b>{user}</b></div>
          <div style='color: #4a6a8a; font-size: 0.8rem; margin-top: 8px;'>
            Session authenticated and recorded on blockchain.
          </div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("🔄 New Authentication Session"):
            st.session_state.auth_step = 1
            st.session_state.qr_generated = False
            st.session_state.qr_bytes = None
            st.rerun()

# ============================================================
# PAGE: DASHBOARD
# ============================================================
elif nav == "📊 Dashboard":
    st.markdown("## 📊 Analytics Dashboard")
    st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)

    logs = load_json(LOGS_FILE, [])
    bc   = st.session_state.blockchain

    if not logs:
        st.info("No authentication events recorded yet.")
    else:
        df = pd.DataFrame(logs)

        total       = len(df)
        successes   = len(df[df["status"] == "Success"])
        failures    = total - successes
        success_pct = round((successes / total) * 100, 1) if total else 0
        devices     = df["device_id"].nunique()

        # Metric cards
        c1, c2, c3, c4 = st.columns(4)
        for col, val, label in [
            (c1, total, "Total Events"),
            (c2, f"{success_pct}%", "Success Rate"),
            (c3, failures, "Failed Attempts"),
            (c4, devices, "Active Devices")
        ]:
            col.markdown(f"""
            <div class='metric-card'>
              <div class='metric-value'>{val}</div>
              <div class='metric-label'>{label}</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Charts row
        col_bar, col_pie = st.columns(2)

        with col_bar:
            daily = df.groupby("date").size().reset_index(name="count")
            fig_bar = px.bar(
                daily, x="date", y="count",
                title="Auth Events by Day",
                color_discrete_sequence=["#00e5ff"]
            )
            fig_bar.update_layout(
                plot_bgcolor="#0d1a2e", paper_bgcolor="#0d1a2e",
                font_color="#7a8aab", title_font_color="#00e5ff"
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        with col_pie:
            pie_data = df["status"].value_counts().reset_index()
            pie_data.columns = ["status", "count"]
            fig_pie = px.pie(
                pie_data, names="status", values="count",
                title="Success vs Failure",
                color_discrete_sequence=["#00e676", "#ff4444"]
            )
            fig_pie.update_layout(
                plot_bgcolor="#0d1a2e", paper_bgcolor="#0d1a2e",
                font_color="#7a8aab", title_font_color="#00e5ff"
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        # Blockchain integrity
        valid, broken_idx = bc.is_valid()
        if valid:
            st.markdown("### ⛓ Blockchain Integrity: <span style='color:#00e676'>✅ VALID CHAIN</span>", unsafe_allow_html=True)
        else:
            st.markdown(f"### ⛓ Blockchain Integrity: <span style='color:#ff4444'>❌ TAMPERED — Block {broken_idx} compromised</span>", unsafe_allow_html=True)

        # Log table with color coding
        st.markdown("### 📋 Authentication Log")
        def color_row(row):
            color = "#0a2a0a" if row["status"] == "Success" else "#2a0a0a"
            return [f"background-color: {color}"] * len(row)
        styled = df[::-1].style.apply(color_row, axis=1)
        st.dataframe(styled, use_container_width=True)

# ============================================================
# PAGE: BLOCKCHAIN EXPLORER
# ============================================================
elif nav == "⛓ Blockchain Explorer":
    st.markdown("## ⛓ Blockchain Explorer")
    st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)

    bc = st.session_state.blockchain
    valid, broken_idx = bc.is_valid()

    status_html = (
        "<span style='color:#00e676'>✅ Valid Chain</span>" if valid
        else f"<span style='color:#ff4444'>❌ Tampered at Block {broken_idx}</span>"
    )
    st.markdown(f"**Chain Status:** {status_html}", unsafe_allow_html=True)
    st.markdown(f"**Total Blocks:** {len(bc.chain)}")

    # Tamper simulation
    with st.expander("⚠️ Tamper Simulation (Demo Only)"):
        st.warning("This modifies a block's data to demonstrate chain validation breaking.")
        tamper_idx = st.number_input(
            "Block index to tamper", min_value=1,
            max_value=max(1, len(bc.chain)-1), step=1, value=1
        )
        if st.button("🔨 Tamper Block"):
            bc.tamper_block(int(tamper_idx))
            st.error(f"Block {tamper_idx} tampered. Re-validate in Dashboard.")
            st.rerun()
        if st.button("🔄 Reload Chain from File"):
            st.session_state.blockchain = Blockchain()
            st.success("Chain reloaded.")
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # Block cards
    for block in reversed(bc.chain):
        is_tampered = block.hash != block.calculate_hash()
        card_class  = "block-card tampered" if is_tampered else "block-card valid"
        badge       = "🔴 TAMPERED" if is_tampered else "🟢 VALID"
        st.markdown(f"""
        <div class='{card_class}'>
          <div class='block-title'>Block #{block.index} &nbsp; {badge}</div>
          <table style='width:100%; border-collapse:collapse; font-size:0.77rem;'>
            <tr><td style='color:#4a6a8a; width:160px;'>Event Type</td><td>{block.event_type}</td></tr>
            <tr><td style='color:#4a6a8a;'>Device ID</td><td>{block.device_id}</td></tr>
            <tr><td style='color:#4a6a8a;'>User ID</td><td>{block.user_id}</td></tr>
            <tr><td style='color:#4a6a8a;'>Timestamp</td><td>{block.timestamp}</td></tr>
            <tr><td style='color:#4a6a8a;'>Merkle Root</td><td class='hash-text'>{block.merkle_root}</td></tr>
            <tr><td style='color:#4a6a8a;'>Block Hash</td><td class='hash-text'>{block.hash}</td></tr>
            <tr><td style='color:#4a6a8a;'>Prev Hash</td><td class='hash-text'>{block.previous_hash}</td></tr>
          </table>
        </div>
        """, unsafe_allow_html=True)
