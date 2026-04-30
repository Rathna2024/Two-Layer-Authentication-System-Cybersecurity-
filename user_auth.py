import pyotp
import qrcode
import json
from datetime import datetime

# Generate secret key
secret = pyotp.random_base32()
print("Your TOTP Secret Key:", secret)

# Generate QR code
totp = pyotp.TOTP(secret)
uri = totp.provisioning_uri(name="iot_user", issuer_name="IoTAuthSystem")

img = qrcode.make(uri)
img.save("totp_qr.png")
print("QR code saved as totp_qr.png")

# Ask user to enter OTP
otp = input("Enter OTP from Google Authenticator: ")

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

if totp.verify(otp):
    print("User Authentication Successful ✅")
    log_event("User Authentication", "Success")
else:
    print("User Authentication Failed ❌")
    log_event("User Authentication", "Failed")
