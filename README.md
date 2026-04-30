# 🔐 Two-Layer Authentication System (Cybersecurity)

## 📌 Project Overview
This project implements a secure two-layer authentication system designed for IoT environments.  
It enhances security using Secret Key, Device ID verification, and OTP (One-Time Password).

## 🚀 Features
- 🔑 Secret Key-based Authentication  
- 📱 Device ID Verification  
- 🔐 OTP Generation & Verification using PyOTP  
- 📊 Login Tracking (Success & Failure Count)  
- 📷 QR Code Generation  
- 🔗 Basic Blockchain Concept  

## 🛠 Technologies Used
- Python  
- Streamlit  
- PyOTP  
- QR Code  
- Pillow  
- ECDSA 

## 📂 Project Structure

project-folder/
│── app.py
│── README.md

## ▶️ How to Run

### 1. Create Virtual Environment

py -m venv venv

### 2. Activate Environment

venv\Scripts\activate

### 3. Install Dependencies

pip install streamlit pyotp qrcode pillow ecdsa

### 4. Run Application

streamlit run app.py

## 🔄 Working Flow
1. User enters secret key  
2. Device ID is generated and verified  
3. OTP is generated using PyOTP  
4. User enters OTP  
5. System verifies authentication  
6. Success/Failure count is updated  

## 🎯 Objective
To provide a secure authentication system for IoT environments using multi-factor authentication and device verification.

## 🔮 Future Enhancements
- Full Blockchain Integration  
- Biometric Authentication  
- Cloud Deployment  
