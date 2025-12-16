#!/bin/bash

echo "🌐 Starting setup for AI Website Testing App..."

# 1️⃣ Upgrade pip
python -m pip install --upgrade pip

# 2️⃣ Install Python dependencies
pip install -r requirements.txt

# 3️⃣ Install Playwright browsers
echo "🧩 Installing Playwright browsers..."
playwright install

# 4️⃣ Optional: verify Selenium fallback
echo "🧪 Verifying Selenium ChromeDriver..."
python - <<EOF
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

options = Options()
options.add_argument("--headless=new")
driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
driver.quit()
print("✅ Selenium ChromeDriver verified")
EOF

echo "🎉 Setup complete! You can now run the app:"
echo "streamlit run app.py --server.port \$PORT"
