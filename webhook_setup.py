# File: webhook_setup.py
import os
import asyncio
import sys
from telegram import Bot

async def setup_webhook():
    BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
    WEBHOOK_URL = os.environ.get('WEBHOOK_URL')
    
    if not BOT_TOKEN or not WEBHOOK_URL:
        print("❌ Variabili d'ambiente mancanti!")
        print(f"BOT_TOKEN: {'Set' if BOT_TOKEN else 'Mancante'}")
        print(f"WEBHOOK_URL: {'Set' if WEBHOOK_URL else 'Mancante'}")
        return
    
    print(f"🤖 Token: {BOT_TOKEN[:10]}...")
    print(f"🌐 URL: {WEBHOOK_URL}")
    
    bot = Bot(token=BOT_TOKEN)
    
    # Cancella webhook precedente
    print("🗑️  Cancello webhook precedente...")
    try:
        await bot.delete_webhook()
        print("✅ Webhook cancellato")
    except Exception as e:
        print(f"⚠️  Errore cancellazione webhook: {e}")
    
    # Imposta nuovo webhook
    webhook_full_url = f"{WEBHOOK_URL.rstrip('/')}/webhook/{BOT_TOKEN}"
    print(f"🔗 Imposto webhook: {webhook_full_url}")
    
    try:
        result = await bot.set_webhook(
            url=webhook_full_url,
            max_connections=40,
            allowed_updates=['message', 'callback_query']
        )
        print(f"✅ Webhook impostato: {result}")
        
        # Verifica
        webhook_info = await bot.get_webhook_info()
        print(f"📊 Info webhook:")
        print(f"   URL: {webhook_info.url}")
        print(f"   Pending updates: {webhook_info.pending_update_count}")
        print(f"   Last error: {webhook_info.last_error_message}")
        
    except Exception as e:
        print(f"❌ Errore impostazione webhook: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    asyncio.run(setup_webhook())
