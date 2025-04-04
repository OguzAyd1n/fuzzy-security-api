from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps
import random
import numpy as np
import skfuzzy as fuzz
import skfuzzy.control as ctrl
import logging
import matplotlib.pyplot as plt
import threading
import time
import os


app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({'message': 'Fuzzy Logic API Security System is Running!'})

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecretkey')  # Güvenlik için değiştirin

# Kullanıcı veritabanı (Basit simülasyon)
users = {
    "admin": "password123"
}

# Loglama ayarları
logging.basicConfig(filename='security_logs.log', level=logging.INFO, 
                    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
log_data = []  # Görselleştirme için verileri saklama

# Fuzzy Logic Değişkenleri
request_freq = ctrl.Antecedent(np.arange(0, 101, 1), 'request_freq')  # 0-100 istek/dakika
response_time = ctrl.Antecedent(np.arange(0, 1001, 1), 'response_time')  # 0-1000 ms
failed_attempts = ctrl.Antecedent(np.arange(0, 11, 1), 'failed_attempts')  # 0-10 başarısız giriş
risk_score = ctrl.Consequent(np.arange(0, 101, 1), 'risk_score')  # 0-100 risk skoru

# Üyelik Fonksiyonları (Manuel Tanımlama)
request_freq['low'] = fuzz.trimf(request_freq.universe, [0, 0, 50])
request_freq['medium'] = fuzz.trimf(request_freq.universe, [25, 50, 75])
request_freq['high'] = fuzz.trimf(request_freq.universe, [50, 100, 100])

response_time['fast'] = fuzz.trimf(response_time.universe, [0, 0, 500])
response_time['normal'] = fuzz.trimf(response_time.universe, [250, 500, 750])
response_time['slow'] = fuzz.trimf(response_time.universe, [500, 1000, 1000])

failed_attempts['low'] = fuzz.trimf(failed_attempts.universe, [0, 0, 5])
failed_attempts['medium'] = fuzz.trimf(failed_attempts.universe, [2, 5, 8])
failed_attempts['high'] = fuzz.trimf(failed_attempts.universe, [5, 10, 10])

risk_score['low'] = fuzz.trimf(risk_score.universe, [0, 25, 50])
risk_score['medium'] = fuzz.trimf(risk_score.universe, [25, 50, 75])
risk_score['high'] = fuzz.trimf(risk_score.universe, [50, 75, 100])

# Kurallar
rule1 = ctrl.Rule(request_freq['high'] & response_time['slow'] & failed_attempts['high'], risk_score['high'])
rule2 = ctrl.Rule(request_freq['medium'] & response_time['normal'] & failed_attempts['medium'], risk_score['medium'])
rule3 = ctrl.Rule(request_freq['low'] & response_time['fast'] & failed_attempts['low'], risk_score['low'])

# Fuzzy Kontrol Sistemi
risk_ctrl = ctrl.ControlSystem([rule1, rule2, rule3])
risk_eval = ctrl.ControlSystemSimulation(risk_ctrl)

def evaluate_risk(req_freq, resp_time, fail_attempts):
    risk_eval = ctrl.ControlSystemSimulation(risk_ctrl)  # HER SEFERİNDE YENİDEN OLUŞTUR
    risk_eval.input['request_freq'] = req_freq
    risk_eval.input['response_time'] = resp_time
    risk_eval.input['failed_attempts'] = fail_attempts
    risk_eval.compute()
    return risk_eval.output['risk_score']


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token missing!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'message': 'Invalid token!'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login():
    auth = request.json
    username = auth.get('username')
    password = auth.get('password')
    
    if username in users and users[username] == password:
        token = jwt.encode({'user': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, 
                           app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/data', methods=['GET'])
@token_required
def protected_data():
    req_freq = random.randint(1, 100)
    resp_time = random.randint(100, 1000)
    fail_attempts = random.randint(0, 10)

    try:  # Buradaki boşluk hatalıydı, düzelttik.
        risk = evaluate_risk(req_freq, resp_time, fail_attempts)
        if risk is None:
            raise ValueError("Risk score computation failed.")
    except KeyError:
        return jsonify({'error': 'risk_score key is missing'}), 400
    except ValueError as e:
        return jsonify({'error': str(e)}), 500


    log_entry = f"Request: {req_freq}, Response Time: {resp_time}, Failed Attempts: {fail_attempts}, Risk: {risk}"
    logging.info(log_entry)
    log_data.append(risk)
    
    if risk > 70:
        return jsonify({'message': 'Access denied! High risk detected.', 'risk_score': risk}), 403
    return jsonify({'message': 'Success! You accessed protected data', 'risk_score': risk})

# Canlı Risk Skoru Görselleştirme

def live_plot():
    plt.ion()
    fig, ax = plt.subplots()
    while True:
        if log_data:
            ax.clear()
            ax.plot(log_data[-20:], marker='o', linestyle='-')
            ax.set_title('Real-time Risk Score Monitoring')
            ax.set_xlabel('Request Count')
            ax.set_ylabel('Risk Score')
            ax.set_ylim(0, 100)
            plt.pause(1)
        time.sleep(1)

if __name__ == '__main__':
    threading.Thread(target=live_plot, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=True)
