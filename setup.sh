#!/bin/bash

echo "🚀 Starting setup for IoT Streamlit App..."

-------------------------------

1. Update system

-------------------------------

echo "🔄 Updating system..."
sudo apt update -y

-------------------------------

2. Install Python 3.10 if not present

-------------------------------

if ! command -v python3.10 &> /dev/null
then
echo "🐍 Python 3.10 not found. Installing..."

sudo apt install -y build-essential zlib1g-dev libncurses5-dev \
libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev wget

cd /tmp
wget https://www.python.org/ftp/python/3.10.13/Python-3.10.13.tgz
tar -xf Python-3.10.13.tgz
cd Python-3.10.13

./configure --enable-optimizations
make -j$(nproc)
sudo make altinstall

echo "✅ Python 3.10 installed"

else
echo "✅ Python 3.10 already installed"
fi

-------------------------------

3. Create virtual environment

-------------------------------

echo "📦 Creating virtual environment..."
python3.10 -m venv venv

-------------------------------

4. Activate venv

-------------------------------

echo "⚡ Activating virtual environment..."
source venv/bin/activate

-------------------------------

5. Upgrade pip

-------------------------------

echo "⬆️ Upgrading pip..."
python -m pip install --upgrade pip

-------------------------------

6. Install dependencies

-------------------------------

echo "📚 Installing dependencies..."
pip install streamlit pandas plotly bcrypt pyotp qrcode[pil] pillow

-------------------------------

7. Run Streamlit app

-------------------------------

echo "🌐 Running Streamlit app..."
streamlit run app-1.py
