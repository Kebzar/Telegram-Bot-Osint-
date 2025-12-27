# File: keep_alive.py
from flask import Flask
import threading
import os

app = Flask(__name__)

@app.route('/')
def home():
    return 'Bot attivo ✅', 200

@app.route('/ping')
def ping():
    return 'PONG', 200

def run_flask():
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

# Avvia Flask in thread separato
flask_thread = threading.Thread(target=run_flask, daemon=True)
flask_thread.start()
