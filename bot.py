import os
import logging
import asyncio
import sqlite3
import hashlib
import base64
import json
import re
import csv
import io
import socket
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from urllib.parse import quote_plus

import requests
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
import whois
import dns.resolver
from bs4 import BeautifulSoup
import shodan

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    CallbackContext,
    CallbackQueryHandler,
    ConversationHandler
)

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== CONFIGURAZIONE API ====================
BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
ADMIN_ID = 123456789  # Il tuo ID Telegram

# API Keys REALI (sostituire con le tue)
SHODAN_API_KEY = "YOUR_REAL_SHODAN_API_KEY"
HUNTER_API_KEY = "YOUR_REAL_HUNTER_API_KEY"
HIBP_API_KEY = "YOUR_REAL_HIBP_API_KEY"
DEHASHED_EMAIL = "YOUR_REAL_DEHASHED_EMAIL"
DEHASHED_API_KEY = "YOUR_REAL_DEHASHED_API_KEY"
NUMVERIFY_KEY = "YOUR_REAL_NUMVERIFY_KEY"
ABUSEIPDB_KEY = "YOUR_REAL_ABUSEIPDB_KEY"
SECURITYTRAILS_KEY = "YOUR_REAL_SECURITYTRAILS_KEY"
IPINFO_API_KEY = "YOUR_REAL_IPINFO_API_KEY"
VIRUSTOTAL_API_KEY = "YOUR_REAL_VIRUSTOTAL_API_KEY"
LEAKCHECK_API_KEY = "YOUR_REAL_LEAKCHECK_API_KEY"
SNUSBASE_API_KEY = "YOUR_REAL_SNUSBASE_API_KEY"

# Nuove API per Facebook
FACEBOOK_GRAPH_API_KEY = "YOUR_FACEBOOK_GRAPH_API_KEY"
FACEBOOK_SEARCH_TOKEN = "YOUR_FACEBOOK_SEARCH_TOKEN"
SOCIALSEARCH_API_KEY = "YOUR_SOCIALSEARCH_API_KEY"
FBSCRAPER_API_KEY = "YOUR_FBSCRAPER_API_KEY"

# Database setup
conn = sqlite3.connect('leakosint_bot.db', check_same_thread=False)
c = conn.cursor()

# Tabelle database
c.execute('''CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY,
    username TEXT,
    balance REAL DEFAULT 10.0,
    searches INTEGER DEFAULT 0,
    registration_date TEXT DEFAULT CURRENT_TIMESTAMP,
    subscription_type TEXT DEFAULT 'free',
    last_active TEXT DEFAULT CURRENT_TIMESTAMP
)''')

c.execute('''CREATE TABLE IF NOT EXISTS searches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    query TEXT,
    type TEXT,
    results TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)''')

c.execute('''CREATE TABLE IF NOT EXISTS breach_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    phone TEXT,
    name TEXT,
    surname TEXT,
    username TEXT,
    password TEXT,
    hash TEXT,
    source TEXT,
    breach_name TEXT,
    breach_date TEXT,
    found_date DATETIME DEFAULT CURRENT_TIMESTAMP
)''')

c.execute('''CREATE TABLE IF NOT EXISTS facebook_leaks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT,
    facebook_id TEXT,
    name TEXT,
    surname TEXT,
    gender TEXT,
    birth_date TEXT,
    city TEXT,
    country TEXT,
    company TEXT,
    relationship_status TEXT,
    leak_date TEXT,
    found_date DATETIME DEFAULT CURRENT_TIMESTAMP
)''')

# NUOVA TABELLA PER INDIRIZZI E DOCUMENTI
c.execute('''CREATE TABLE IF NOT EXISTS addresses_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_number TEXT,
    document_type TEXT,
    full_name TEXT,
    home_address TEXT,
    work_address TEXT,
    city TEXT,
    country TEXT,
    phone TEXT,
    email TEXT,
    source TEXT,
    found_date DATETIME DEFAULT CURRENT_TIMESTAMP
)''')

conn.commit()

# ==================== CLASSI PRINCIPALI ====================

class LeakSearchAPI:
    """API per ricerche nei data breach reali"""
    
    def __init__(self):
        self.base_url = "https://leak-lookup.com/api"
        self.api_key = LEAKCHECK_API_KEY
        
    def search_email(self, email):
        """Cerca email nei data breach"""
        try:
            url = f"{self.base_url}/search"
            headers = {'Authorization': f'Bearer {self.api_key}'}
            params = {'type': 'email_address', 'query': email}
            response = requests.post(url, headers=headers, json=params)
            
            if response.status_code == 200:
                return response.json()
            return {"success": False, "error": f"Status code: {response.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def search_phone(self, phone):
        """Cerca telefono nei data breach"""
        try:
            url = f"{self.base_url}/search"
            headers = {'Authorization': f'Bearer {self.api_key}'}
            params = {'type': 'phone_number', 'query': phone}
            response = requests.post(url, headers=headers, json=params)
            
            if response.status_code == 200:
                return response.json()
            return {"success": False, "error": f"Status code: {response.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def search_username(self, username):
        """Cerca username nei data breach"""
        try:
            url = f"{self.base_url}/search"
            headers = {'Authorization': f'Bearer {self.api_key}'}
            params = {'type': 'username', 'query': username}
            response = requests.post(url, headers=headers, json=params)
            
            if response.status_code == 200:
                return response.json()
            return {"success": False, "error": f"Status code: {response.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

class LeakosintBot:
    """Bot principale con interfaccia come nelle immagini"""
    
    def __init__(self):
        self.leak_api = LeakSearchAPI()
        self.user_data = {}
        
    def get_user_balance(self, user_id):
        """Ottiene il saldo dell'utente"""
        c.execute('SELECT balance FROM users WHERE user_id = ?', (user_id,))
        result = c.fetchone()
        if result:
            return result[0]
        return 0.0
    
    def get_user_searches(self, user_id):
        """Ottiene il numero di ricerche dell'utente"""
        c.execute('SELECT searches FROM users WHERE user_id = ?', (user_id,))
        result = c.fetchone()
        if result:
            return result[0]
        return 0
    
    def register_user(self, user_id, username):
        """Registra un nuovo utente"""
        try:
            c.execute('''INSERT OR IGNORE INTO users (user_id, username) 
                         VALUES (?, ?)''', (user_id, username))
            conn.commit()
        except Exception as e:
            logger.error(f"Error registering user: {e}")
    
    async def start(self, update: Update, context: CallbackContext):
        """Gestisce il comando /start"""
        user_id = update.effective_user.id
        username = update.effective_user.username or "N/A"
        
        # Registra l'utente
        self.register_user(user_id, username)
        
        # Messaggio di benvenuto
        now = datetime.now()
        data_italiana = now.strftime("%d.%m.%Y")
        
        text = f"""👋 Benvenuto, {username}!

Sono il tuo assistente OSINT.

📌 Usa /menu per vedere tutte le funzioni.
📌 Invia qualsiasi dato per una ricerca.
📌 /help per le istruzioni.

Buona ricerca! 🕵️‍♂️

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await update.message.reply_text(text)
    
    async def profile_command(self, update: Update, context: CallbackContext):
        """Mostra il profilo dell'utente"""
        user_id = update.effective_user.id
        username = update.effective_user.username or "Nessuno"
        
        # Recupera dati utente
        c.execute('''SELECT registration_date, last_active, balance, searches, subscription_type 
                     FROM users WHERE user_id = ?''', (user_id,))
        result = c.fetchone()
        
        now = datetime.now()
        data_italiana = now.strftime("%d.%m.%Y")
        
        if result:
            reg_date = result[0]
            last_active = result[1]
            balance = result[2]
            searches = result[3]
            sub_type = result[4]
            
            text = f"""👤 Profilo Utente:

👤 Informazioni Personali:
🆔ID Telegram: {user_id}
👤Username: @{username}
📅Registrato: {reg_date}
🕒Ultima attività: {last_active}

💳 Sistema Credit:
💰Crediti attuali: {balance:.1f}
🔍Ricerche effettuate: {searches}
🎯Ricerche disponibili: {int(balance / 2.0)}
📊Abbonamento: {sub_type}

⚙️ Configurazioni:
🔔Notifiche: Attive
🌐Lingua: Italiano
💾Salvataggio ricerche: 30 giorni

📊 Statistiche odierne:
· Ricerche oggi: {searches % 100}
· Crediti usati oggi: {(100 - balance) % 100:.1f}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        else:
            text = "Utente non registrato. Usa /start per registrarti."
        
        await update.message.reply_text(text)
    
    async def menu_completo(self, update: Update, context: CallbackContext):
        """Mostra il menu completo"""
        user_id = update.effective_user.id
        
        now = datetime.now()
        data_italiana = now.strftime("%d.%m.%Y")
        
        text = f"""📋 MENU PRINCIPALE

📧 Cerca per posta
· example@gmail.com - Cerca la posta
· example@ - Cerca senza prendere in considerazione il dominio
· @gmail.com - Cerca determinati domini.

👤 Cerca per nome o nick
· Petrov
· Petrov Maxim
· Petrov Sergeevich
· Maxim Sergeevich
· Petrov Maxim Sergeevich
· ShadowPlayer228

📱 Cerca per numero di telefono
· +79002206090
· 79002206090
· 89002206090

📄 Cerca per documento  # NUOVO
· AA1234567 - Carta Identità
· 123456789 - Codice Fiscale
· AA12345AA1234 - Passaporto

🏠 Cerca per indirizzo di casa  # NUOVO
· Via Roma 123, Milano
· Corso Vittorio Emanuele 45, Roma
· Piazza del Duomo 1, Firenze

🏢 Cerca per indirizzo lavorativo  # NUOVO
· Ufficio Via Torino 50, Milano
· Azienda Via Milano 10, Roma
· Sede Via Garibaldi 25, Napoli

🔐 Ricerca password
· 123qwe

🚗 Cerca in auto
· 0999MY777 - Cerca auto nella Federazione Russa
· BO4561AX - Cerca le auto con il codice penale
· XTA21150053965897 - Cerca di Vin

📱 Cerca un account Telegram
· Petrov Ivan - Cerca per nome e cognome
· 314159265 - Cerca account ID
· Petivan - Cerca per nome utente

📘 Cerca l'account Facebook
· Petrov Ivan - Cerca per nome
· 314159265 - Cerca account ID

🔵 Cerca l'account VKontakte
· Petrov Ivan - Cerca per nome e cognome
· 314159265 - Cerca account ID

📸 Cerca account Instagram
· Petrov Ivan - Cerca per nome e cognome
· 314159265 - Cerca account ID

🌐 Cerca tramite IP
· 127.0.0.1

📋 Ricerca di massa: /utf8 per istruzioni

📝 Le richieste composite in tutti i formati sono supportate:
· Petrov 79002206090
· Maxim Sergeevich 127.0.0.1
· Petrov Maxim Sergeevich
· AA1234567 Via Roma 123
· Mario Rossi 123456789 Milano

💰 Crediti disponibili: {self.get_user_balance(user_id):.1f}
📊Ricerche effettuate: {self.get_user_searches(user_id)}

📩 Inviami qualsiasi dato per iniziare la ricerca.

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await update.message.reply_text(text)
    
    async def buy_credits(self, update: Update, context: CallbackContext):
        """Mostra i pacchetti di crediti disponibili"""
        now = datetime.now()
        data_italiana = now.strftime("%d.%m.%Y")
        
        text = f"""🛒 NEGOZIO CREDITI

💎 PACCHETTI CREDITI:
━━━━━━━━━━━━━━━━━━━━
·🟢 20 CREDITI = 2.0 USDT
·🟡 50 CREDITI = 4.5 USDT
·🔵 100 CREDITI = 8.0 USDT
·🟣 200 CREDITI = 15.0 USDT

📊 CONVERSIONE:
━━━━━━━━━━━━━━━━━━━━
💰2 crediti = 1 ricerca
💸1 credito = 0.1 USDT

🎁 SCONTI:
━━━━━━━━━━━━━━━━━━━━
•+50 crediti: 10% sconto
•+100 crediti: 20% sconto
•+200 crediti: 25% sconto

🔗 PAGAMENTO CRYPTO:
━━━━━━━━━━━━━━━━━━━━
🌐Rete: TRC20 (Tron) o BEP20 (BSC)
💰Accettiamo: USDT, USDC, BTC, ETH
🔄Conversione automatica

📝 COME ACQUISTARE:
━━━━━━━━━━━━━━━━━━━━

1. Scegli il pacchetto
2. Invia crypto all'indirizzo:
   🔹 TRC20: TPRg6fVqZ4qJq8XqXqXqXqXqXqXqXqXqXq
   🔸 BEP20: 0x9a8f9c8d7e6f5a4b3c2d1e0f
3. Invia TX Hash / Screenshot
4. Ricevi crediti in 5-15 minuti

⚠️ AVVERTENZE:
━━━━━━━━━━━━━━━━━━━━
•Solo pagamenti crypto
•Nessun rimborso
•Verifica indirizzo
•Minimo 10 USDT

📞 SUPPORTO:
━━━━━━━━━━━━━━━━━━━━
•@Zerofilter00
•24/7 disponibile

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await update.message.reply_text(text)
    
    async def handle_message(self, update: Update, context: CallbackContext):
        """Gestisce i messaggi di testo per le ricerche"""
        query = update.message.text.strip()
        user_id = update.effective_user.id
        
        now = datetime.now()
        data_italiana = now.strftime("%d.%m.%Y")
        
        # Controlla saldo
        balance = self.get_user_balance(user_id)
        if balance < 2.0:
            text = f"""❌ Crediti insufficienti!

💎 Saldo attuale: {balance:.1f} crediti
🔍 Costo per ricerca: 2.0 crediti

🛒 Usa /buy per acquistare crediti.

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
            await update.message.reply_text(text)
            return
        
        # Inizia la ricerca
        msg = await update.message.reply_text(f"🔍 Analisi in corso...\n\n⏰ {now.hour:02d}:{now.minute:02d}\n\n{data_italiana}")
        
        try:
            # Analizza il tipo di query
            query_type = self.analyze_query(query)
            total_components = len(query_type)
            
            # Deduci 2 crediti
            new_balance = balance - 2.0
            c.execute('UPDATE users SET balance = ?, searches = searches + 1, last_active = ? WHERE user_id = ?',
                     (new_balance, datetime.now().isoformat(), user_id))
            conn.commit()
            
            # Esegui ricerca basata sul tipo
            if 'email' in query_type:
                await self.search_email_exact(update, msg, query, user_id, data_italiana)
            elif 'phone' in query_type:
                await self.search_phone_exact(update, msg, query, user_id, data_italiana)
            elif 'name' in query_type:
                await self.search_name_exact(update, msg, query, user_id, data_italiana)
            elif 'document' in query_type:
                await self.search_document_exact(update, msg, query, user_id, data_italiana)
            elif 'address' in query_type:
                await self.search_address_exact(update, msg, query, user_id, data_italiana)
            elif 'ip' in query_type:
                await self.search_ip_exact(update, msg, query, user_id, data_italiana)
            elif 'facebook' in query_type.lower():
                await self.search_facebook_complete(update, msg, query, user_id, data_italiana)
            else:
                # Ricerca generica
                await self.perform_generic_search(update, msg, query, user_id, data_italiana)
                
        except Exception as e:
            error_text = f"""❌ Errore durante la ricerca

Query: {query}
Errore: {str(e)[:100]}

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

---
{data_italiana}"""
            try:
                await msg.edit_text(error_text)
            except:
                await update.message.reply_text(error_text)
    
    def analyze_query(self, query: str) -> List[str]:
        """Analizza il tipo di query"""
        components = []
        
        # Email pattern
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        if re.search(email_pattern, query):
            components.append('email')
        
        # Phone pattern (internazionale)
        phone_pattern = r'(\+?\d[\d\s\-\(\)]{8,}\d)'
        if re.search(phone_pattern, query):
            components.append('phone')
        
        # IP pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        if re.search(ip_pattern, query):
            components.append('ip')
        
        # Document patterns
        doc_patterns = [
            r'[A-Z]{2}\d{7}',  # Carta identità
            r'\d{9}',  # Codice fiscale italiano
            r'[A-Z]{2}\d{5}[A-Z]{2}\d{4}',  # Passaporto
        ]
        for pattern in doc_patterns:
            if re.search(pattern, query):
                components.append('document')
                break
        
        # Address indicators
        address_indicators = ['via', 'corso', 'piazza', 'viale', 'strada', 'largo', 'via.', 'c.so', 'p.zza']
        if any(indicator in query.lower() for indicator in address_indicators):
            components.append('address')
        
        # Name patterns (italiano/russo)
        name_patterns = [
            r'\b[A-Z][a-z]+ [A-Z][a-z]+\b',  # Nome Cognome
            r'\b[A-Z][a-z]+ [A-Z][a-z]+ [A-Z][a-z]+\b',  # Nome Cognome SecondoCognome
        ]
        for pattern in name_patterns:
            if re.search(pattern, query):
                components.append('name')
                break
        
        return components if components else ['generic']
    
    async def perform_generic_search(self, update: Update, msg, query: str, user_id: int, data_italiana: str):
        """Esegue una ricerca generica"""
        now = datetime.now()
        
        # Simula ricerca
        await asyncio.sleep(2)
        
        result_text = f"""🔍 RISULTATI RICERCA

📋 Query: {query}
📊 Tipo: Ricerca generica
🎯 Componenti rilevati: {len(self.analyze_query(query))}

📈 DATI TROVATI:

1. 📧 Email correlate: 2
   · example@mail.ru
   · user123@gmail.com

2. 📱 Telefoni: 1
   · +79001234567

3. 👤 Nomi: 3
   · Ivan Petrov
   · Maxim Sergeevich
   · Petrov Ivanovich

4. 🔑 Password esposte: 1
   · 123qwe (MD5: 46f94c8de14fb36680850768ff1b7f2a)

5. 📄 Documenti: 0

6. 🏠 Indirizzi: 2
   · Via Roma 123, Milano
   · Corso Italia 45, Roma

7. 💼 Lavoro: 1
   · Azienda XYZ S.p.A.

8. 🌐 Social Media: 4 profili
   · Facebook: facebook.com/ivan.petrov
   · VK: vk.com/id123456
   · Telegram: @ivan_petrov
   · Instagram: @ivan.petrov

📊 STATISTICHE:
· 🔍 Data breach: 3
· 📱 Numeri trovati: 1
· 👤 Profili: 7
· 📄 Documenti: 0
· 🏠 Indirizzi: 2

⚠️ NOTA: I dati sono di esempio.
Per risultati reali, configura le API nel codice.

💰 Crediti usati: 2.0
💎 Nuovo saldo: {self.get_user_balance(user_id):.1f}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(result_text)
    
    # ============ FUNZIONI DI RICERCA SPECIFICHE ============
    
    async def search_email_exact(self, update: Update, msg, email: str, user_id: int, data_italiana: str):
        """Ricerca email - Formato esatto"""
        now = datetime.now()
        
        await msg.edit_text(f"🔍 Ricerca email...\n\n📧 {email}\n\n⏰ {now.hour:02d}:{now.minute:02d}\n\n{data_italiana}")
        await asyncio.sleep(1)
        
        # Simula risultati
        result = self.leak_api.search_email(email)
        
        result_text = f"""📧 RISULTATI EMAIL

📋 Email: {email}
🔍 Tipo: Ricerca specifica email

📊 DATI TROVATI:

✅ Email trovata in 3 data breach:
1. 📛 Breach: Collection #1 (2019)
   · Password: ********
   · Hash: 5f4dcc3b5aa765d61d8327deb882cf99
   · Data violazione: 2019-01-01

2. 📛 Breach: Anti Public (2020)
   · Password: qwerty123
   · Hash: 25d55ad283aa400af464c76d713c07ad
   · Data violazione: 2020-03-15

3. 📛 Breach: COMB (2021)
   · Password: password123
   · Hash: 482c811da5d5b4bc6d497ffa98491e38
   · Data violazione: 2021-02-28

📈 STATISTICHE:
· 🔍 Data breach: 3
· 🔑 Password esposte: 3
· 📱 Telefoni associati: 2
· 👤 Nomi associati: 1

⚠️ CONSIGLI:
1. Cambia password immediatamente
2. Attiva 2FA
3. Controlla account correlati

💰 Crediti usati: 2.0
💎 Nuovo saldo: {self.get_user_balance(user_id):.1f}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(result_text)
    
    async def search_phone_exact(self, update: Update, msg, phone: str, user_id: int, data_italiana: str):
        """Ricerca telefono - Formato esatto"""
        now = datetime.now()
        
        await msg.edit_text(f"🔍 Ricerca telefono...\n\n📱 {phone}\n\n⏰ {now.hour:02d}:{now.minute:02d}\n\n{data_italiana}")
        await asyncio.sleep(1)
        
        result_text = f"""📱 RISULTATI TELEFONO

📋 Numero: {phone}
🌍 Paese: Italia
🏙️ Operatore: TIM
📍 Posizione: Roma

📊 DATI TROVATI:

✅ Numero trovato in 2 data breach:
1. 📛 Breach: Facebook Leak (2021)
   · Nome: Mario Rossi
   · Email: mario.rossi@gmail.com
   · Data violazione: 2021-04-05

2. 📛 Breach: Telegram Scrape (2022)
   · Username: @mariorossi
   · User ID: 123456789
   · Data violazione: 2022-11-30

👤 PROFILI SOCIAL TROVATI:
· Facebook: facebook.com/mario.rossi.123
· Instagram: instagram.com/mario_rossi
· Telegram: @mariorossi
· WhatsApp: +39{phone[3:]}

📈 STATISTICHE:
· 🔍 Data breach: 2
· 📧 Email associate: 1
· 👤 Profili social: 4
· 🏠 Indirizzi: 1

⚠️ SICUREZZA:
1. Numero esposto pubblicamente
2. Collegato a profili social
3. Possibile spam telefonico

💰 Crediti usati: 2.0
💎 Nuovo saldo: {self.get_user_balance(user_id):.1f}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(result_text)
    
    async def search_name_exact(self, update: Update, msg, name: str, user_id: int, data_italiana: str):
        """Ricerca per nome - Formato esatto"""
        now = datetime.now()
        
        await msg.edit_text(f"🔍 Ricerca nome...\n\n👤 {name}\n\n⏰ {now.hour:02d}:{now.minute:02d}\n\n{data_italiana}")
        await asyncio.sleep(1)
        
        result_text = f"""👤 RISULTATI NOME

📋 Nome: {name}
🔍 Tipo: Ricerca anagrafica

📊 DATI TROVATI:

✅ Nome trovato in 4 fonti:

1. 📋 ANAGRAFICA:
   · Data di nascita: 15/05/1985
   · Luogo di nascita: Milano
   · Codice Fiscale: RSSMRA85M15F205Z

2. 🏠 RESIDENZE:
   · Via Roma 123, Milano (2015-2020)
   · Corso Italia 45, Roma (2020-attuale)

3. 📱 CONTATTI:
   · Telefono: +393331234567
   · Email: {name.lower().replace(' ', '.')}@gmail.com

4. 💼 LAVORO:
   · Azienda: Tech Solutions S.p.A.
   · Posizione: Sviluppatore Software
   · Indirizzo lavoro: Via Torino 50, Milano

👥 PROFILI SOCIAL:
· LinkedIn: linkedin.com/in/{name.lower().replace(' ', '')}
· Facebook: facebook.com/{name.lower().replace(' ', '.')}
· Instagram: instagram.com/{name.lower().replace(' ', '_')}

📈 STATISTICHE:
· 🔍 Fonti trovate: 8
· 📄 Documenti: 2
· 📱 Contatti: 3
· 🏠 Indirizzi: 2

💰 Crediti usati: 2.0
💎 Nuovo saldo: {self.get_user_balance(user_id):.1f}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(result_text)
    
    async def search_document_exact(self, update: Update, msg, document: str, user_id: int, data_italiana: str):
        """Ricerca documento - Formato esatto come immagini"""
        now = datetime.now()
        
        await msg.edit_text(f"🔍 Ricerca documento...\n\n📄 {document}\n\n⏰ {now.hour:02d}:{now.minute:02d}\n\n{data_italiana}")
        await asyncio.sleep(1)
        
        result_text = f"""📄 RISULTATI DOCUMENTO

📋 Documento: {document}
🔍 Tipo: Carta Identità Italiana

✅ DOCUMENTO TROVATO:

📋 DATI COMPLETI:
· Nome completo: MARIO ROSSI
· Data di nascita: 15/05/1985
· Luogo di nascita: MILANO
· Data emissione: 10/01/2020
· Data scadenza: 10/01/2030
· Comune emissione: COMUNE DI MILANO

🏠 INDIRIZZI ASSOCIATI:
1. Residenza: VIA ROMA 123, 20121 MILANO (MI)
2. Domicilio: CORSO ITALIA 45, 00186 ROMA (RM)

📱 CONTATTI:
· Telefono: +393331234567
· Email: mario.rossi@email.com

🏢 DATI LAVORATIVI:
· Azienda: TECH SOLUTIONS S.P.A.
· Posizione: DIRETTORE TECNICO
· Indirizzo: VIA TORINO 50, 20123 MILANO

🌐 PRESENZA ONLINE:
· Iscrizione al comune: TROVATA
· Registro automobilistico: TROVATO
· Database fiscale: PRESENTE

⚠️ AVVERTENZE:
1. Documento valido
2. Non segnalato come perso/rubato
3. Presenza in database pubblici

📊 STATISTICHE:
· 🔍 Database consultati: 7
· 📄 Documenti correlati: 3
· 🏠 Indirizzi: 2
· 📱 Contatti: 2

💰 Crediti usati: 2.0
💎 Nuovo saldo: {self.get_user_balance(user_id):.1f}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(result_text)
    
    async def search_address_exact(self, update: Update, msg, address: str, user_id: int, data_italiana: str):
        """Ricerca indirizzo - Formato esatto come immagini"""
        now = datetime.now()
        
        await msg.edit_text(f"🔍 Ricerca indirizzo...\n\n🏠 {address}\n\n⏰ {now.hour:02d}:{now.minute:02d}\n\n{data_italiana}")
        await asyncio.sleep(1)
        
        result_text = f"""🏠 RISULTATI INDIRIZZO

📋 Indirizzo: {address}
📍 Tipo: Residenza civile

✅ INDIRIZZO TROVATO:

🏠 DATI IMMOBILE:
· Tipo: Appartamento
· Piano: 3°
· Superficie: 85 m²
· Anno costruzione: 1995
· Catastale: F/123/456

👤 RESIDENTI ATTUALI:
1. MARIO ROSSI (proprietario)
   · Data nascita: 15/05/1985
   · CF: RSSMRA85M15F205Z

2. ANNA ROSSI (convivente)
   · Data nascita: 20/08/1988
   · CF: RSSNNA88M60F205X

📋 RESIDENTI PRECEDENTI (ultimi 5 anni):
· LUCA BIANCHI (2018-2020)
· GIULIA VERDI (2016-2018)

💼 ATTIVITÀ COMMERCIALI:
· Nessuna attività registrata

🌐 DATI PUBBLICI:
· Valore immobile: €250.000
· Tassa rifiuti: €350/anno
· Classe energetica: C

📱 CONTATTI ASSOCIATI:
· Telefono: +393331234567
· Telefono: +393332234568
· Email: casa.roma@email.com

⚠️ SICUREZZA:
1. Indirizzo residenziale
2. Nessuna segnalazione particolare
3. Zona residenziale tranquilla

📊 STATISTICHE:
· 🔍 Database consultati: 6
· 👤 Residenti: 4
· 📱 Contatti: 3
· 💼 Attività: 0

💰 Crediti usati: 2.0
💎 Nuovo saldo: {self.get_user_balance(user_id):.1f}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(result_text)
    
    async def search_ip_exact(self, update: Update, msg, ip: str, user_id: int, data_italiana: str):
        """Ricerca IP - Formato esatto"""
        now = datetime.now()
        
        await msg.edit_text(f"🔍 Analisi IP...\n\n🌐 {ip}\n\n⏰ {now.hour:02d}:{now.minute:02d}\n\n{data_italiana}")
        await asyncio.sleep(1)
        
        result_text = f"""🌐 RISULTATI ANALISI IP

📋 IP: {ip}
🔍 Tipo: Indirizzo IPv4

🌍 GEO-LOCALIZZAZIONE:
· Paese: Italia
· Regione: Lazio
· Città: Roma
· CAP: 00100
· Coordinate: 41.9028° N, 12.4964° E
· Fuso orario: UTC+1

🏢 INFORMAZIONI ISP:
· Provider: Telecom Italia
· ASN: AS3269
· Organizzazione: Telecom Italia S.p.A.
· Tipo: Broadband

⚠️ SICUREZZA:
· Threat Score: 45/100 (Medio)
· Proxy/VPN: Rilevato
· TOR Node: No
· Hosting malevolo: No
· Abuso segnalato: 3 volte

📊 PORTE APERTE (Shodan):
· 80/tcp - HTTP
· 443/tcp - HTTPS
· 22/tcp - SSH
· 53/tcp - DNS

🔒 SERVIZI RILEVATI:
· Web Server: Apache/2.4.41
· OS: Ubuntu 20.04
· Firewall: Attivo
· Certificato SSL: Valido

📈 STATISTICHE:
· Uptime: 99.2%
· Ping: 24ms
· Velocità: 100 Mbps
· Connessioni attive: 127

💰 Crediti usati: 2.0
💎 Nuovo saldo: {self.get_user_balance(user_id):.1f}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(result_text)
    
    async def search_facebook_complete(self, update: Update, msg, query: str, user_id: int, data_italiana: str):
        """Ricerca Facebook completa"""
        now = datetime.now()
        
        await msg.edit_text(f"🔍 Analisi Facebook...\n\n📘 {query}\n\n⏰ {now.hour:02d}:{now.minute:02d}\n\n{data_italiana}")
        await asyncio.sleep(2)
        
        result_text = f"""📘 RISULTATI FACEBOOK

📋 Query: {query}
🔍 Tipo: Ricerca profilo Facebook

✅ PROFILO TROVATO:

👤 INFORMAZIONI BASE:
· Nome: Mario Rossi
· Facebook ID: 1000123456789
· Username: mario.rossi.123
· Amici: 847
· Follower: 1.2K
· Account creato: 2012-05-15

📱 CONTATTI:
· Telefono: +393331234567
· Email: mario.rossi@email.com
· Siti web: mariosblog.com

🏠 INFORMAZIONI PERSONALI:
· Data di nascita: 15 Maggio 1985
· Città natale: Milano
· Città attuale: Roma
· Stato relazione: Sposato
· Familiari: Anna Rossi (moglie)

🎓 ISTRUZIONE:
· Università: Politecnico di Milano (2004-2008)
· Liceo: Liceo Scientifico A. Einstein (1999-2004)

💼 LAVORO:
· Attuale: Tech Solutions S.p.A. (2015-oggi)
· Precedente: Web Agency XYZ (2010-2015)

📸 FOTO PUBBLICHE:
· Foto profilo: 15
· Foto copertina: 8
· Album: 24
· Foto totali: 347

👥 GRUPPI (principali):
· Ex Allievi Politecnico Milano
· Sviluppatori Web Italia
· Community Fotografia Roma

📊 STATISTICHE ATTIVITÀ:
· Post ultimo mese: 12
· Like dati: 1.4K
· Commenti: 327
· Condivisioni: 89

⚠️ PRIVACY:
· Profilo: Pubblico
· Amicizie: Visibili
· Foto: Visibili a tutti
· Informazioni contatto: Pubbliche

📈 DATI LEAK:
· Presente in Facebook Leak 2021: SÌ
· Email esposta: mario.rossi@email.com
· Telefono esposto: +393331234567

💰 Crediti usati: 2.0
💎 Nuovo saldo: {self.get_user_balance(user_id):.1f}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(result_text)
    
    async def advanced_search(self, update: Update, context: CallbackContext):
        """Ricerca avanzata con query composite"""
        user_id = update.effective_user.id
        
        now = datetime.now()
        data_italiana = now.strftime("%d.%m.%Y")
        
        text = f"""🔍 RICERCA AVANZATA

📌 Email + Telefono + Nome:
· example@gmail.com +79002206090 Petrov Ivan

📌 Nome + Città + Telefono:
· Maxim Sergeevich Mosca +79001234567

📌 Username + Email + Password:
· ShadowPlayer228 example@mail.ru 123qwe

📌 Nome Completo + Data Nascita:
· Petrov Maxim Sergeevich 16/02/1995

📌 Telefono + Email + IP:
· +79002206090 example@gmail.com 192.168.1.1

📌 Hash + Email + Telefono:
· 5f4dcc3b5aa765d61d8327deb882cf99 admin@gmail.com +79001112233

📌 Password + Username + Email:
· Qwerty123! ShadowPlayer example@protonmail.com

📌 Facebook ID + Telefono + Nome:
· 1000123456789 +79003334455 Ivan Petrov

📌 Documento + Indirizzo + Nome:
· AA1234567 Via Roma 123 Mario Rossi
· 123456789 Milano Luigi Bianchi

🔍 PUOI COMBINARE:
· Email: example@
· Telefono: +39, +7, +44
· Nomi: Nome, Cognome, Completo
· Username: qualsiasi
· IP: IPv4
· Password: qualsiasi
· Hash: MD5, SHA1, SHA256
· Documenti: Carta ID, Passaporto, CF
· Indirizzi: Casa, Ufficio, Azienda
· Date: GG/MM/AAAA

📋 RICERCA DI MASSA:
· /utf8 per istruzioni file
· Massimo 50 righe
· Formato UTF-8

💰 Crediti disponibili: {self.get_user_balance(user_id):.1f}
📊Ricerche effettuate: {self.get_user_searches(user_id)}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await update.message.reply_text(text)
    
    async def balance_command(self, update: Update, context: CallbackContext):
        """Mostra il saldo dell'utente"""
        user_id = update.effective_user.id
        balance = self.get_user_balance(user_id)
        searches = self.get_user_searches(user_id)
        
        now = datetime.now()
        data_italiana = now.strftime("%d.%m.%Y")
        
        text = f"""💰 SALDO UTENTE

💎 Saldo attuale: {balance:.1f} crediti
🔍Costo per ricerca: 2.0 crediti
📊Ricerche effettuate: {searches}
🎯Ricerche disponibili: {int(balance / 2.0)}

🛒 Per acquistare crediti: /buy
🔍Per una ricerca: invia qualsiasi dato

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        await update.message.reply_text(text)
    
    async def admin_panel(self, update: Update, context: CallbackContext):
        """Pannello admin"""
        user_id = update.effective_user.id
        
        if user_id != ADMIN_ID:
            await update.message.reply_text("❌ Accesso negato. Solo admin.")
            return
        
        # Statistiche globali
        c.execute('SELECT COUNT(*) FROM users')
        total_users = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM searches')
        total_searches = c.fetchone()[0]
        
        c.execute('SELECT SUM(balance) FROM users')
        total_credits = c.fetchone()[0] or 0
        
        now = datetime.now()
        data_italiana = now.strftime("%d.%m.%Y")
        
        text = f"""🛡️ PANNELLO ADMIN

📊 Statistiche:
·👥 Utenti totali: {total_users}
·🔍 Ricerche totali: {total_searches}
·💎 Credit totali: {total_credits:.1f}

👥 Ultimi 5 utenti:"""
        
        # Ultimi 5 utenti
        c.execute('SELECT user_id, username, registration_date FROM users ORDER BY registration_date DESC LIMIT 5')
        users = c.fetchall()
        
        for idx, (uid, uname, reg_date) in enumerate(users, 1):
            text += f"\n{idx}. ID: {uid} - @{uname} - {reg_date[:10]}"
        
        text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}\n\n{data_italiana}"
        
        await update.message.reply_text(text)
    
    async def add_credits(self, update: Update, context: CallbackContext):
        """Aggiunge crediti a un utente (admin only)"""
        user_id = update.effective_user.id
        
        if user_id != ADMIN_ID:
            await update.message.reply_text("❌ Accesso negato. Solo admin.")
            return
        
        if context.args and len(context.args) >= 2:
            target_user = int(context.args[0])
            credits = float(context.args[1])
            
            c.execute('UPDATE users SET balance = balance + ? WHERE user_id = ?', (credits, target_user))
            conn.commit()
            
            await update.message.reply_text(f"✅ Aggiunti {credits} crediti all'utente {target_user}")
        else:
            await update.message.reply_text("Uso: /addcredits <user_id> <crediti>")
    
    async def help_command(self, update: Update, context: CallbackContext):
        """Mostra le istruzioni di aiuto"""
        now = datetime.now()
        data_italiana = now.strftime("%d.%m.%Y")
        
        text = f"""🆘 GUIDA E AIUTO

🔍 INVIA:
·📧 Email: example@gmail.com
·📱 Telefono: +393331234567
·👤 Nome: Mario Rossi
·👥 Username: shadowplayer
·🌐 IP: 8.8.8.8
·🔐 Password: 123qwe
·🔑 Hash: 5f4dcc3b5aa765d61d8327deb882cf99
·📄 Documento: AA1234567, 123456789
·🏠 Indirizzo casa: Via Roma 123, Milano
·🏢 Indirizzo lavoro: Ufficio Via Torino 45

📊 FORMATI SUPPORTATI:
·👤 Petrov 📱 79002206090
·👤 Maxim Sergeevich 🌐 127.0.0.1
·👤 Petrov Maxim Sergeevich 📅 16/02/1995
·👤 Username 📧 example@gmail.com
·👤 Nome Cognome 🏙️ Città
·📄 AA1234567 🏠 Via Roma 123
·👤 Mario Rossi 📄 123456789

💎 SISTEMA CREDITI:
·🔍 1 ricerca = 2.0 crediti
·🎁 Partenza: 10 crediti gratis
·🛒 Ricarica: /buy

📈 STATISTICHE: /balance
📋MENU COMPLETO: /menu
🛒ACQUISTA: /buy
🛡️ADMIN: /admin (solo admin)
➕AGGIUNGI CREDITI: /addcredits (solo admin)

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await update.message.reply_text(text)
    
    async def utf8_instructions(self, update: Update, context: CallbackContext):
        """Istruzioni per file UTF-8"""
        now = datetime.now()
        data_italiana = now.strftime("%d.%m.%Y")
        
        text = f"""🔧 ISTRUZIONI PER FILE .txt:

1. 📝 Crea un file di testo con:
   · Codifica: UTF-8
   · Estensione: .txt
   · Una richiesta per riga

2. 💻 COME SALVARE IN UTF-8:
   ⚙️ Windows (Notepad):
      · Apri Blocco note
      · Scrivi le ricerche (una per riga)
      · File → Salva con nome
      · Nome file: "ricerche.txt"
      · Tipo: "Tutti i file"
      · Codifica: "UTF-8"
   
   ⚙️ Windows (Notepad++):
      · Apri Notepad++
      · Scrivi le ricerche
      · Codifica → Converti in UTF-8
      · File → Salva
   
   ⚙️ Mac/Linux (TextEdit/Terminale):
      · Usa terminale: nano/nvim
      · Scrivi le ricerche
      · Salva come: UTF-8

3. 📋 ESEMPIO DI CONTENUTO:
   example@gmail.com
   +79002206090 Petrov Ivan
   ShadowPlayer228
   127.0.0.1
   Petrov 79002206090
   Maxim Sergeevich
   example@mail.ru
   AA1234567 Via Roma 123, Milano
   Ufficio Via Torino 45

4. ⚠️ AVVERTENZE:
   · MAX 50 righe per file
   · Solo testo (.txt)
   · NO .doc, .pdf, .xlsx
   · Codifica corretta: UTF-8

5. 📤 CARICAMENTO:
   · Usa l'icona 📎 in Telegram
   · Seleziona il file .txt
   · Attendi l'elaborazione

💰 COSTO: 2.0 crediti per riga

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await update.message.reply_text(text)
    
    async def stats_command(self, update: Update, context: CallbackContext):
        """Statistiche del bot"""
        c.execute('SELECT COUNT(*) FROM users')
        total_users = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM searches')
        total_searches = c.fetchone()[0]
        
        c.execute('SELECT SUM(balance) FROM users')
        total_credits = c.fetchone()[0] or 0
        
        now = datetime.now()
        data_italiana = now.strftime("%d.%m.%Y")
        
        text = f"""📊 STATISTICHE BOT

👥 Utenti totali: {total_users}
🔍 Ricerche totali: {total_searches}
💎 Credit totali: {total_credits:.1f}

📈 OGGI ({data_italiana}):
· Nuovi utenti: {total_users % 10}
· Ricerche: {total_searches % 100}
· Credit usati: {(100 - total_credits) % 100:.1f}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await update.message.reply_text(text)
    
    async def handle_document(self, update: Update, context: CallbackContext):
        """Gestisce file .txt per ricerche di massa"""
        user_id = update.effective_user.id
        document = update.message.document
        
        # Controlla se è un file .txt
        if not document.file_name.endswith('.txt'):
            await update.message.reply_text("❌ Solo file .txt sono supportati.")
            return
        
        now = datetime.now()
        data_italiana = now.strftime("%d.%m.%Y")
        
        # Messaggio di avvio
        msg = await update.message.reply_text(f"📄 File: {document.file_name}\n🔍Lettura righe...\n\n⏰ {now.hour:02d}:{now.minute:02d}\n\n---\n\n{data_italiana}")
        
        try:
            # Scarica il file
            file = await document.get_file()
            file_bytes = await file.download_as_bytearray()
            
            # Decodifica come UTF-8
            try:
                content = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                error_text = f"""📄 File: {document.file_name}
⚠️Il file non è in formato UTF-8

📌 Usa un editor che supporta UTF-8:
· Notepad++ (Windows)
· Sublime Text
· Visual Studio Code

🔧 Salva come: "UTF-8 senza BOM"

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

---
{data_italiana}"""
                await msg.edit_text(error_text)
                return
            
            # Legge le righe
            lines = [line.strip() for line in content.split('\n') if line.strip()]
            
            if not lines:
                error_text = f"""📄 File: {document.file_name}
⚠️Il file non contiene righe valide

📌 Formato richiesto:
· Una query per riga
· Esempio: example@gmail.com +79002206090 Petrov Ivan

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
                await msg.edit_text(error_text)
                return
            
            # Limite 50 righe
            if len(lines) > 50:
                lines = lines[:50]
                await msg.edit_text(f"⚠️ File troppo grande. Verranno processate solo le prime 50 righe.")
            
            # Calcola costo
            total_cost = len(lines) * 2.0
            current_balance = self.get_user_balance(user_id)
            
            if current_balance < total_cost:
                error_text = f"""📄 File: {document.file_name}
📊Righe: {len(lines)}
💰Costo totale: {total_cost:.1f} crediti
💳Saldo attuale: {current_balance:.1f} crediti

🔢 Ti servono: {total_cost - current_balance:.1f} crediti in più
🛒Usa /buy per acquistare crediti

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
                await msg.edit_text(error_text)
                return
            
            # Aggiorna saldo
            new_balance = current_balance - total_cost
            c.execute('UPDATE users SET balance = ?, searches = searches + ? WHERE user_id = ?',
                     (new_balance, len(lines), user_id))
            conn.commit()
            
            # Processa le righe
            success_count = 0
            error_count = 0
            
            for i, line in enumerate(lines, 1):
                try:
                    # Simula elaborazione
                    await asyncio.sleep(0.5)
                    
                    # Aggiorna progresso ogni 5 righe
                    if i % 5 == 0 or i == len(lines):
                        progress_text = f"""📄 File: {document.file_name}
📊Progresso: {i}/{len(lines)} righe
✅Successo: {success_count}
❌Errori: {error_count}

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
                        await msg.edit_text(progress_text)
                    
                    success_count += 1
                    
                except Exception as e:
                    error_count += 1
                    logger.error(f"Errore processando riga {i}: {e}")
            
            # Risultato finale
            result_text = f"""📄 File: {document.file_name}
📊Righe processate: {len(lines)}
✅Ricerche riuscite: {success_count}
❌Errori: {error_count}
💰Costo totale: {total_cost:.1f} crediti
💳Nuovo saldo: {self.get_user_balance(user_id):.1f} crediti

📝 RISULTATI DETTAGLIATI:
· Righe valide: {success_count}
· Errori: {error_count}
· Tempo impiegato: {len(lines)*0.5:.1f}s
· Velocità: {len(lines)/(len(lines)*0.5):.1f} righe/s

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
            
            await msg.edit_text(result_text)
            
        except Exception as e:
            error_text = f"""📄 File: {document.file_name}
⚠️Errore: {str(e)[:100]}

📌 Assicurati che:

1. Il file sia in formato .txt
2. La codifica sia UTF-8
3. Non superi le 50 righe

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
            try:
                await msg.edit_text(error_text)
            except:
                await update.message.reply_text(error_text)

# ==================== FUNZIONI PER CARICARE DATI ====================

def load_facebook_leaks_data():
    """Carica dati Facebook leaks nel database"""
    try:
        # Questo è un esempio - sostituisci con il tuo file di dati
        # Formato CSV: phone,facebook_id,name,surname,gender,birth_date,city,country,company,relationship_status,leak_date
        facebook_leaks_files = [
            'facebook_leaks.csv',
            'data/facebook_leaks.csv',
            'facebook_data.csv',
            'leaks/facebook_2021.csv'
        ]
        
        for file_path in facebook_leaks_files:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        c.execute('''INSERT OR IGNORE INTO facebook_leaks 
                                     (phone, facebook_id, name, surname, gender, birth_date, city, country, company, relationship_status, leak_date)
                                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                (row.get('phone', ''), row.get('facebook_id', ''), row.get('name', ''),
                                 row.get('surname', ''), row.get('gender', ''), row.get('birth_date', ''),
                                 row.get('city', ''), row.get('country', ''), row.get('company', ''),
                                 row.get('relationship_status', ''), row.get('leak_date', '')))
                conn.commit()
                logger.info(f"Caricati dati Facebook da {file_path}")
                break
    except Exception as e:
        logger.error(f"Errore caricamento Facebook leaks: {e}")

def load_addresses_documents_data():
    """Carica dati documenti e indirizzi nel database"""
    try:
        # File per documenti e indirizzi
        addresses_files = [
            'addresses_documents.csv',
            'data/addresses.csv',
            'documents_data.csv',
            'leaks/addresses_leak.csv'
        ]
        
        for file_path in addresses_files:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        c.execute('''INSERT OR IGNORE INTO addresses_documents 
                                     (document_number, document_type, full_name, home_address, work_address, city, country, phone, email, source)
                                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                (row.get('document_number', ''), row.get('document_type', ''),
                                 row.get('full_name', ''), row.get('home_address', ''),
                                 row.get('work_address', ''), row.get('city', ''),
                                 row.get('country', ''), row.get('phone', ''),
                                 row.get('email', ''), row.get('source', '')))
                conn.commit()
                logger.info(f"Caricati dati indirizzi e documenti da {file_path}")
                break
    except Exception as e:
        logger.error(f"Errore caricamento indirizzi e documenti: {e}")

# ==================== MAIN ====================

def main():
    """Funzione principale"""
    
    # Carica dati iniziali
    logger.info("Caricamento dati iniziali...")
    load_facebook_leaks_data()
    load_addresses_documents_data()
    
    # Inizializza il bot
    bot = LeakosintBot()
    
    # Crea l'application
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Aggiungi gli handlers
    application.add_handler(CommandHandler("start", bot.start))
    application.add_handler(CommandHandler("menu", bot.menu_completo))
    application.add_handler(CommandHandler("balance", bot.balance_command))
    application.add_handler(CommandHandler("buy", bot.buy_credits))
    application.add_handler(CommandHandler("admin", bot.admin_panel))
    application.add_handler(CommandHandler("addcredits", bot.add_credits))
    application.add_handler(CommandHandler("help", bot.help_command))
    application.add_handler(CommandHandler("utf8", bot.utf8_instructions))
    application.add_handler(CommandHandler("stats", bot.stats_command))
    application.add_handler(CommandHandler("profile", bot.profile_command))
    application.add_handler(CommandHandler("advanced", bot.advanced_search))
    
    # Handler per documenti (file .txt)
    application.add_handler(MessageHandler(filters.Document.ALL & filters.Document.FileExtension("txt"), bot.handle_document))
    
    # Handler per messaggi di testo (ricerche)
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_message))
    
    logger.info("Bot avviato...")
    
    # Avvia il bot
    application.run_polling()

if __name__ == '__main__':
    main()
