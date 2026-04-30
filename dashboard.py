import streamlit as st
import pyotp
import qrcode
import json
import os
import pandas as pd
from datetime import datetime
from io import BytesIO

st.set_page_config(page_title="IoT Two-Layer Auth System", layout="wide")
st.title("🔐 IoT Two-Layer Authentication System")

# ---------------- SESSION ----------------
if "step" not in st.session_state:
    st.session_state.step = 1

if "secret" not in st.session_state:
    st.session_state.secret = pyotp.random_base32()

if "qr_img" not in st.session_state:
    st.session_state.qr_img = None

secret = st.session_state.secret
totp = pyotp.TOTP(secret)

# ---------------- LOGGING ----------------
def log_event(event, status):
    log_data = {
        "event": event,
        "status": status,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    try:
        with open("auth_logs.json", "r") as file:
            data = json.load(file)
    except:
        data = []

    data.append(log_data)

    with open("auth_logs.json", "w") as file:
        json.dump(data, file, indent=4)


# ===================================================
# STEP 1 → QR GENERATE
# ===================================================
if st.session_state.step == 1:

    st.subheader("📱 Step 1: Generate QR Code")

    if st.button("Generate QR"):
        uri = totp.provisioning_uri(name="iot_user", issuer_name="IoTAuthSystem")
        img = qrcode.make(uri)

        buf = BytesIO()
        img.save(buf)
        st.session_state.qr_img = buf.getvalue()

    if st.session_state.qr_img:
        st.image(st.session_state.qr_img, width=250)
        st.success("Scan QR in Google Authenticator")

        if st.button("Next ➡ OTP Step"):
            st.session_state.step = 2
            st.rerun()


# ===================================================
# STEP 2 → OTP VERIFY
# ===================================================
elif st.session_state.step == 2:

    st.subheader("🔑 Step 2: Enter OTP")

    user_otp = st.text_input("Enter 6-digit OTP")

    if st.button("Verify OTP"):
        if totp.verify(user_otp):
            st.success("User Authentication Successful ✅")
            log_event("User Authentication", "Success")
            st.session_state.step = 3
            st.rerun()
        else:
            st.error("Wrong OTP ❌")
            log_event("User Authentication", "Failed")


# ===================================================
# STEP 3 → DEVICE VERIFY
# ===================================================
elif st.session_state.step == 3:

    st.subheader("📡 Step 3: Device Authentication")

    device_id = st.text_input("Enter Device ID")

    if st.button("Authenticate Device"):
        if device_id == "DEVICE123":
            st.success("Device Authentication Successful ✅")
            log_event("Device Authentication", "Success")
            st.session_state.step = 4
            st.rerun()
        else:
            st.error("Invalid Device ID ❌")
            log_event("Device Authentication", "Failed")


# ===================================================
# STEP 4 → DASHBOARD
# ===================================================
elif st.session_state.step == 4:

    st.subheader("📊 Authentication Dashboard")

    if os.path.exists("auth_logs.json"):
        with open("auth_logs.json", "r") as file:
            data = json.load(file)
    else:
        data = []

    if data:
        df = pd.DataFrame(data)

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Events", len(df))
        col2.metric("Success Count", len(df[df["status"] == "Success"]))
        col3.metric("Failure Count", len(df[df["status"] == "Failed"]))

        df["numeric_status"] = df["status"].apply(lambda x: 1 if x == "Success" else 0)
        st.line_chart(df["numeric_status"])

        st.dataframe(df[::-1], use_container_width=True)
    else:
        st.info("No logs available yet.")

    if st.button("Logout 🔓"):
        st.session_state.clear()
        st.rerun()
