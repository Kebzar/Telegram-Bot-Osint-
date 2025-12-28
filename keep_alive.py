# File: keep_alive.py
from flask import Flask, request, jsonify
import threading
import os
import asyncio
import sys

app = Flask(__name__)

# Memorizza l'applicazione del bot
bot_instance = None
bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')

@app.route('/')
def home():
    return 'Bot attivo ✅', 200

@app.route('/ping')
def ping():
    return 'PONG', 200

# ENDPOINT WEBHOOK DINAMICO basato sul token
@app.route(f'/<path:token_path>', methods=['POST'])
def webhook(token_path):
    """Endpoint dinamico per il webhook di Telegram"""
    try:
        print(f"📥 Ricevuta richiesta webhook per: {token_path}")
        
        # Verifica che sia il token corretto
        if token_path != bot_token and not token_path.endswith(bot_token):
            print(f"❌ Token non valido: {token_path} (atteso: {bot_token})")
            return 'Token non valido', 403
        
        if bot_instance is None:
            print("❌ Bot non inizializzato")
            return 'Bot non inizializzato', 500
        
        # Processa l'aggiornamento
        update_json = request.get_json(force=True)
        print(f"📊 Update ricevuto: {update_json.get('update_id')}")
        
        # Usa asyncio per processare
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Importa qui per evitare import circolari
        from telegram import Update
        from telegram.ext import Application
        
        update = Update.de_json(update_json, bot_instance.bot)
        loop.run_until_complete(bot_instance.process_update(update))
        
        return 'OK', 200
        
    except Exception as e:
        print(f"❌ Errore webhook: {e}")
        import traceback
        traceback.print_exc()
        return 'Errore interno', 500

def set_bot_instance(bot_app):
    """Imposta l'istanza del bot"""
    global bot_instance
    bot_instance = bot_app
    print(f"✅ Bot instance settata: {bot_instance}")

def run_flask():
    """Avvia Flask"""
    port = int(os.environ.get('PORT', 10000))
    print(f"🚀 Avvio Flask su porta {port}")
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

# Avvia Flask in thread separato
flask_thread = threading.Thread(target=run_flask, daemon=True)
flask_thread.start()
