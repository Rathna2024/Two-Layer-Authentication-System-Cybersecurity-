import json
from datetime import datetime

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



import pyotp
import qrcode

# Step 1: Device registration - set a secret key
def register_device():
    device_secret_key = "mysecurekey123"
    print("=== DEVICE REGISTRATION ===")
    print(f"Set device secret key: {device_secret_key}")

    # Generate device ID (for example, a random string or UUID)
    device_id = "a1db72794cc0...2a7e3f0d1d44"  # This should be dynamically generated in production
    print(f"Device ID: {device_id}")
    print("Geolocation locked to current area")  # In real scenario, use geolocation APIs
    
    return device_secret_key

# Step 2: Device authentication
def authenticate_device(device_secret_key):
    input("Press Enter to authenticate ...\n")
    
    print("=== DEVICE AUTHENTICATION ===")
    entered_key = input("Enter secret key: ")
    
    if entered_key == device_secret_key:
        print("Authentication successful!")
    else:
        print("Authentication failed!")

if __name__ == "__main__":
    secret_key = register_device()
    authenticate_device(secret_key)

