from flask import Flask, request, jsonify
import threading
import os
from telegram import Update
from telegram.ext import Application, MessageHandler, filters, CommandHandler, CallbackQueryHandler
import asyncio
import logging

app = Flask(__name__)

# Inizializza il bot in modo globale
bot_app = None

@app.route('/')
def home():
    return 'Bot attivo ✅', 200

@app.route('/ping')
def ping():
    return 'PONG', 200

@app.route(f'/{os.environ.get("TELEGRAM_BOT_TOKEN")}', methods=['POST'])
def webhook():
    """Endpoint del webhook Telegram"""
    try:
        if bot_app is None:
            return 'Bot non inizializzato', 500
        
        # Ottieni l'aggiornamento dalla richiesta
        update_json = request.get_json(force=True)
        
        # Crea un oggetto Update
        update = Update.de_json(update_json, bot_app.bot)
        
        # Usa una nuova event loop per processare l'update
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Processa l'update
        loop.run_until_complete(bot_app.process_update(update))
        
        return 'OK', 200
    except Exception as e:
        logging.error(f"Webhook error: {e}")
        return 'Error', 500

def run_flask(application):
    """Avvia Flask con il bot applicazione"""
    global bot_app
    bot_app = application
    
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

# Rimuovi l'avvio automatico di Flask qui
# Flask verrà avviato dopo che il bot è inizializzato
