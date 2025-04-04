# 🔐 Fuzzy Security API

This project is a simple **Fuzzy Logic-Based API Security System** built with Flask. It calculates a risk score by analyzing request frequency, response time, and failed login attempts, and blocks access if the risk is high.

## 🚀 Features

- 🔑 JWT-based user authentication
- 📈 Fuzzy logic risk analysis
- 🧠 Custom fuzzy rules for intrusion detection
- 📊 Real-time risk score visualization with Matplotlib
- 📂 Logging of all access attempts

## ⚙️ Installation

### 1. Install Dependencies

```bash
pip install flask pyjwt numpy scikit-fuzzy matplotlib

2. Run the Application

python app.py

🔐 API Usage
1. Login (Get Token)

curl -X POST http://127.0.0.1:5000/login \
     -H "Content-Type: application/json" \
     -d "{\"username\": \"admin\", \"password\": \"password123\"}"

2. Access Protected Endpoint

curl http://127.0.0.1:5000/data \
     -H "x-access-token: <YOUR_TOKEN_HERE>"
Replace <YOUR_TOKEN_HERE> with the token received from the login response.

📊 Real-Time Risk Score Visualization
A Matplotlib window will open when the app is running to display a live graph of the last 20 requests' risk scores.

📁 Project Structure
fuzzy_api_security/
├── app.py              # Main application script
├── security_logs.log   # Access logs
└── README.md           # Project description

👨‍💻 Developer
Oğuz Aydın

GitHub: @OguzAyd1n

📜 License
This project is licensed under the MIT License.

