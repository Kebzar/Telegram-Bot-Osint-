# File: keep_alive.py
from flask import Flask, request, jsonify
import threading
import os
import asyncio
from telegram import Update
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Variabile globale per l'applicazione bot
bot_instance = None

@app.route('/')
def home():
    return 'Bot attivo ✅', 200

@app.route('/ping')
def ping():
    return 'PONG', 200

@app.route('/webhook/<token>', methods=['POST'])
def webhook(token):
    """Endpoint webhook per Telegram"""
    try:
        # Verifica che il token sia corretto
        expected_token = os.environ.get('TELEGRAM_BOT_TOKEN')
        if token != expected_token:
            logging.warning(f"Token non valido: {token}")
            return 'Token non valido', 403
        
        if bot_instance is None:
            logging.error("Bot non inizializzato")
            return 'Bot non inizializzato', 500
        
        # Processa l'aggiornamento
        update_data = request.get_json(force=True)
        logging.info(f"📥 Update ricevuto: {update_data.get('update_id')}")
        
        # Crea l'oggetto Update
        update = Update.de_json(update_data, bot_instance.bot)
        
        # Processa l'aggiornamento
        bot_instance.update_queue.put_nowait(update)
        
        return 'OK', 200
        
    except Exception as e:
        logging.error(f"❌ Errore webhook: {e}")
        return 'Errore interno', 500

def set_bot_instance(bot_app):
    """Imposta l'istanza del bot"""
    global bot_instance
    bot_instance = bot_app
    logging.info("✅ Bot instance impostata in Flask")

# RIMUOVI QUESTA PARTE:
# def run_flask():
#     """Avvia Flask"""
#     port = int(os.environ.get('PORT', 10000))
#     logging.info(f"🚀 Avvio Flask su porta {port}")
#     app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

# # Avvia Flask in thread separato
# flask_thread = threading.Thread(target=run_flask, daemon=True)
# flask_thread.start()
