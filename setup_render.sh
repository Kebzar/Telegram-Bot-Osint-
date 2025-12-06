#!/bin/bash
echo "🚀 Setup per Render..."

# Crea il file di configurazione
cat > render.yaml << EOF
services:
  - type: web
    name: leakosint-bot
    env: python
    plan: free
    buildCommand: pip install -r requirements.txt
    startCommand: python bot.py
    envVars:
      - key: TELEGRAM_BOT_TOKEN
        sync: false
      - key: WEBHOOK_URL
        sync: false
      - key: RENDER
        value: true
    healthCheckPath: /health
EOF

echo "✅ File creati:"
echo "   - requirements.txt"
echo "   - runtime.txt"
echo "   - render.yaml"
echo "   - Procfile"
echo "   - .env.example"
echo ""
echo "📋 Passi successivi:"
echo "1. Crea un bot su @BotFather e ottieni il token"
echo "2. Crea un nuovo Web Service su Render.com"
echo "3. Collega il tuo repository GitHub"
echo "4. Imposta le variabili d'ambiente:"
echo "   - TELEGRAM_BOT_TOKEN: il tuo token"
echo "   - WEBHOOK_URL: https://tuo-bot.onrender.com"
echo "5. Avvia il deploy!"
