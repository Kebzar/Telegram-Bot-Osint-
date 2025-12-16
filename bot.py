import os
import logging
import asyncio
import hashlib
import base64
import json
import re
import csv
import io
import socket
import sys
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
from flask import Flask, request

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, filters,
    CallbackContext, CallbackQueryHandler, ConversationHandler
)

# Import per Turso/libSQL
try:
    import libsql_client
    from libsql_client import Client
    TURSO_ENABLED = True
except ImportError:
    # Fallback per sviluppo locale
    TURSO_ENABLED = False
    import sqlite3

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== CONFIGURAZIONE API ====================

BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
if not BOT_TOKEN:
    logger.error("❌ BOT_TOKEN non configurato! Configura la variabile d'ambiente TELEGRAM_BOT_TOKEN")
    sys.exit(1)

ADMIN_ID = int(os.environ.get('ADMIN_ID', 0))

# Configurazione Turso Database
TURSO_DB_URL = os.environ.get('TURSO_DB_URL')
TURSO_DB_AUTH_TOKEN = os.environ.get('TURSO_DB_AUTH_TOKEN')

# API Keys REALI (sostituire con le tue)
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')
HUNTER_API_KEY = os.environ.get('HUNTER_API_KEY', '')
HIBP_API_KEY = os.environ.get('HIBP_API_KEY', '')
DEHASHED_EMAIL = os.environ.get('DEHASHED_EMAIL', '')
DEHASHED_API_KEY = os.environ.get('DEHASHED_API_KEY', '')
NUMVERIFY_KEY = os.environ.get('NUMVERIFY_KEY', '')
ABUSEIPDB_KEY = os.environ.get('ABUSEIPDB_KEY', '')
SECURITYTRAILS_KEY = os.environ.get('SECURITYTRAILS_KEY', '')
IPINFO_API_KEY = os.environ.get('IPINFO_API_KEY', '')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
LEAKCHECK_API_KEY = os.environ.get('LEAKCHECK_API_KEY', '')
SNUSBASE_API_KEY = os.environ.get('SNUSBASE_API_KEY', '')

# Nuove API per Facebook
FACEBOOK_GRAPH_API_KEY = os.environ.get('FACEBOOK_GRAPH_API_KEY', '')
FACEBOOK_SEARCH_TOKEN = os.environ.get('FACEBOOK_SEARCH_TOKEN', '')
SOCIALSEARCH_API_KEY = os.environ.get('SOCIALSEARCH_API_KEY', '')
FBSCRAPER_API_KEY = os.environ.get('FBSCRAPER_API_KEY', '')

# ==================== API OSINT POTENZIATE ====================

WHATSMYNAME_API_URL = "https://api.whatsmyname.app/v0"
INSTANTUSERNAME_API = "https://api.instantusername.com/v1"
NAMEAPI_KEY = os.environ.get('NAMEAPI_KEY', '')
SOCIAL_SEARCHER_KEY = os.environ.get('SOCIAL_SEARCHER_KEY', '')

# ==================== SISTEMA LINGUE ====================

translations = {
    'it': {
        'language': 'Italiano 🇮🇹',
        'main_menu': '# Posso cercare tutto. Inviami la tua richiesta.🔍\n\nTrova ciò che nascondono🕵🏻‍♂️\n\n•🔍 Ricerca\n\n•shop💸\n\n•⚙️ Impostazioni\n\n•📋 Menu\n\n•help❓',
        'search': '🔍 Ricerca',
        'shop': 'shop💸',
        'settings': '⚙️ Impostazioni',
        'menu': '📋 Menu',
        'help': 'help❓',
        'language_btn': '🌐 Lingua',
        'back': '🔙 Indietro',
        'buy_20': '💳 Acquista 20 crediti',
        'buy_50': '💳 Acquista 50 crediti',
        'buy_100': '💳 Acquista 100 crediti',
        'buy_200': '💳 Acquista 200 crediti',
        'buy_500': '💳 Acquista 500 crediti',
        'buy_1000': '💳 Acquista 1000 crediti',
    }
}

# ==================== DATABASE MANAGER PER TURSO ====================

class DatabaseManager:
    """Gestione database per Turso/libSQL"""
    
    def __init__(self):
        self.client = None
        self.local_conn = None
        
    async def initialize(self):
        """Inizializza la connessione al database"""
        try:
            if TURSO_ENABLED and TURSO_DB_URL and TURSO_DB_AUTH_TOKEN:
                self.client = Client(
                    url=TURSO_DB_URL,
                    auth_token=TURSO_DB_AUTH_TOKEN
                )
                logger.info("✅ Connesso a Turso Database")
            else:
                # Usa SQLite locale
                self.local_conn = sqlite3.connect('leakosint.db', check_same_thread=False)
                self.local_conn.row_factory = sqlite3.Row
                logger.info("✅ Database locale inizializzato")
        except Exception as e:
            logger.error(f"❌ Errore inizializzazione database: {e}")
            
    async def execute(self, query, params=None):
        """Esegue una query"""
        try:
            if self.client:
                result = await self.client.execute(query, params or [])
                return result
            else:
                cursor = self.local_conn.cursor()
                cursor.execute(query, params or [])
                self.local_conn.commit()
                return cursor
        except Exception as e:
            logger.error(f"❌ Errore esecuzione query: {e} - Query: {query}")
            raise
            
    async def fetch_all(self, query, params=None):
        """Esegue query e ritorna tutti i risultati"""
        try:
            if self.client:
                result = await self.client.execute(query, params or [])
                return result.rows
            else:
                cursor = self.local_conn.cursor()
                cursor.execute(query, params or [])
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"❌ Errore fetch_all: {e}")
            return []
            
    async def fetch_one(self, query, params=None):
        """Esegue query e ritorna un risultato"""
        try:
            if self.client:
                result = await self.client.execute(query, params or [])
                return result.rows[0] if result.rows else None
            else:
                cursor = self.local_conn.cursor()
                cursor.execute(query, params or [])
                return cursor.fetchone()
        except Exception as e:
            logger.error(f"❌ Errore fetch_one: {e}")
            return None

# Istanza globale del database manager
db = DatabaseManager()

# ==================== CLASSI PRINCIPALI ====================

class LeakSearchAPI:
    """API per ricerche nei data breach reali"""
    
    def __init__(self):
        self.api_keys = {
            'dehashed': (DEHASHED_EMAIL, DEHASHED_API_KEY),
            'hibp': HIBP_API_KEY,
            'leakcheck': LEAKCHECK_API_KEY,
            'snusbase': SNUSBASE_API_KEY
        }
        
    async def search_email(self, email):
        """Ricerca email in breach databases"""
        results = []
        
        # Try Dehashed API
        if DEHASHED_EMAIL and DEHASHED_API_KEY:
            try:
                auth = f"{DEHASHED_EMAIL}:{DEHASHED_API_KEY}"
                encoded_auth = base64.b64encode(auth.encode()).decode()
                headers = {
                    'Authorization': f'Basic {encoded_auth}',
                    'Accept': 'application/json'
                }
                
                response = requests.get(
                    f'https://api.dehashed.com/search?query=email:"{email}"',
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if 'entries' in data:
                        for entry in data['entries']:
                            results.append({
                                'source': 'Dehashed',
                                'email': entry.get('email', ''),
                                'password': entry.get('password', ''),
                                'hash': entry.get('hashed_password', ''),
                                'breach': entry.get('database_name', '')
                            })
            except Exception as e:
                logger.error(f"Errore Dehashed API: {e}")
        
        # Try HaveIBeenPwned API
        if HIBP_API_KEY:
            try:
                headers = {'hibp-api-key': HIBP_API_KEY}
                response = requests.get(
                    f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    breaches = response.json()
                    for breach in breaches:
                        results.append({
                            'source': 'HaveIBeenPwned',
                            'email': email,
                            'breach': breach.get('Name', ''),
                            'date': breach.get('BreachDate', ''),
                            'description': breach.get('Description', '')
                        })
            except Exception as e:
                logger.error(f"Errore HIBP API: {e}")
        
        return results
        
    async def search_phone(self, phone):
        """Ricerca numero di telefono in database"""
        results = []
        
        # Normalize phone number
        phone_clean = re.sub(r'[^0-9+]', '', phone)
        
        # Search in Facebook leaks
        try:
            fb_results = await db.fetch_all(
                "SELECT * FROM facebook_leaks WHERE phone = ? LIMIT 10",
                [phone_clean]
            )
            for row in fb_results:
                results.append({
                    'source': 'Facebook Leak',
                    'phone': row[1] if isinstance(row, tuple) else row['phone'],
                    'name': row[3] if isinstance(row, tuple) else row['name'],
                    'surname': row[4] if isinstance(row, tuple) else row['surname'],
                    'city': row[8] if isinstance(row, tuple) else row['city'],
                    'leak_date': row[12] if isinstance(row, tuple) else row['leak_date']
                })
        except Exception as e:
            logger.error(f"Errore ricerca telefono in DB: {e}")
            
        return results
        
    async def search_name(self, name):
        """Ricerca per nome"""
        results = []
        
        try:
            # Search in addresses_documents table
            doc_results = await db.fetch_all(
                "SELECT * FROM addresses_documents WHERE full_name LIKE ? LIMIT 10",
                [f'%{name}%']
            )
            
            for row in doc_results:
                if isinstance(row, tuple):
                    results.append({
                        'source': 'Documents Database',
                        'name': row[3],
                        'document': row[1],
                        'address': row[4] or row[5],
                        'city': row[6],
                        'phone': row[8]
                    })
                else:
                    results.append({
                        'source': 'Documents Database',
                        'name': row['full_name'],
                        'document': row['document_number'],
                        'address': row['home_address'] or row['work_address'],
                        'city': row['city'],
                        'phone': row['phone']
                    })
                    
        except Exception as e:
            logger.error(f"Errore ricerca nome in DB: {e}")
            
        return results
        
    async def search_username(self, username):
        """Ricerca username su piattaforme social"""
        results = []
        
        # WhatsMyName API
        try:
            response = requests.get(
                f"{WHATSMYNAME_API_URL}/username/{username}",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if 'sites' in data:
                    for site in data['sites']:
                        if site.get('status') == 'claimed':
                            results.append({
                                'platform': site.get('name', ''),
                                'url': site.get('uri_check', '').replace('{account}', username),
                                'status': 'Found'
                            })
        except Exception as e:
            logger.error(f"Errore WhatsMyName API: {e}")
            
        # InstantUsername API
        try:
            response = requests.get(
                f"{INSTANTUSERNAME_API}/check/{username}",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                for platform, info in data.items():
                    if isinstance(info, dict) and info.get('available') == False:
                        results.append({
                            'platform': platform,
                            'url': info.get('url', ''),
                            'status': 'Found'
                        })
        except Exception as e:
            logger.error(f"Errore InstantUsername API: {e}")
            
        return results
        
    async def search_username_advanced(self, username):
        """Ricerca avanzata username"""
        results = []
        
        platforms = [
            ('GitHub', f'https://github.com/{username}'),
            ('Twitter', f'https://twitter.com/{username}'),
            ('Instagram', f'https://instagram.com/{username}'),
            ('Facebook', f'https://facebook.com/{username}'),
            ('LinkedIn', f'https://linkedin.com/in/{username}'),
            ('Reddit', f'https://reddit.com/user/{username}'),
            ('TikTok', f'https://tiktok.com/@{username}'),
            ('YouTube', f'https://youtube.com/@{username}'),
            ('Telegram', f'https://t.me/{username}'),
            ('VK', f'https://vk.com/{username}')
        ]
        
        for platform, url in platforms:
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                if response.status_code < 400:
                    results.append({
                        'platform': platform,
                        'url': url,
                        'status': 'Found'
                    })
            except:
                continue
                
        return results
        
    async def search_ip(self, ip):
        """Ricerca informazioni IP"""
        results = []
        
        # IPInfo API
        if IPINFO_API_KEY:
            try:
                response = requests.get(
                    f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}",
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        'source': 'IPInfo',
                        'ip': ip,
                        'city': data.get('city', ''),
                        'region': data.get('region', ''),
                        'country': data.get('country', ''),
                        'org': data.get('org', ''),
                        'loc': data.get('loc', '')
                    })
            except Exception as e:
                logger.error(f"Errore IPInfo API: {e}")
                
        # AbuseIPDB
        if ABUSEIPDB_KEY:
            try:
                headers = {
                    'Key': ABUSEIPDB_KEY,
                    'Accept': 'application/json'
                }
                response = requests.get(
                    f"https://api.abuseipdb.com/api/v2/check",
                    headers=headers,
                    params={'ipAddress': ip, 'maxAgeInDays': 90},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    if 'data' in data:
                        results.append({
                            'source': 'AbuseIPDB',
                            'abuse_score': data['data'].get('abuseConfidenceScore', 0),
                            'country': data['data'].get('countryCode', ''),
                            'isp': data['data'].get('isp', ''),
                            'total_reports': data['data'].get('totalReports', 0)
                        })
            except Exception as e:
                logger.error(f"Errore AbuseIPDB API: {e}")
                
        return results
        
    async def search_password(self, password):
        """Ricerca password in breach databases"""
        results = []
        
        # Cerca hash MD5
        md5_hash = hashlib.md5(password.encode()).hexdigest()
        
        if LEAKCHECK_API_KEY:
            try:
                headers = {'API-Key': LEAKCHECK_API_KEY}
                response = requests.get(
                    f"https://leakcheck.io/api/public?check={md5_hash}",
                    headers=headers,
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    if 'success' in data and data['success']:
                        for result in data.get('result', []):
                            results.append({
                                'source': 'LeakCheck',
                                'hash': md5_hash,
                                'password': password,
                                'found_in': result.get('source', ''),
                                'count': result.get('count', 0)
                            })
            except Exception as e:
                logger.error(f"Errore LeakCheck API: {e}")
                
        return results
        
    async def search_hash(self, hash_str):
        """Ricerca hash in database"""
        results = []
        
        if LEAKCHECK_API_KEY:
            try:
                headers = {'API-Key': LEAKCHECK_API_KEY}
                response = requests.get(
                    f"https://leakcheck.io/api/public?check={hash_str}",
                    headers=headers,
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    if 'success' in data and data['success']:
                        for result in data.get('result', []):
                            results.append({
                                'source': 'LeakCheck',
                                'hash': hash_str,
                                'found_in': result.get('source', ''),
                                'count': result.get('count', 0)
                            })
            except Exception as e:
                logger.error(f"Errore LeakCheck API: {e}")
                
        return results
        
    async def search_document(self, document):
        """Ricerca documento"""
        results = []
        
        try:
            # Search in addresses_documents table
            doc_results = await db.fetch_all(
                "SELECT * FROM addresses_documents WHERE document_number = ? LIMIT 10",
                [document]
            )
            
            for row in doc_results:
                if isinstance(row, tuple):
                    results.append({
                        'source': 'Documents Database',
                        'document': row[1],
                        'type': row[2],
                        'name': row[3],
                        'home_address': row[4],
                        'work_address': row[5],
                        'city': row[6],
                        'phone': row[8],
                        'email': row[9]
                    })
                else:
                    results.append({
                        'source': 'Documents Database',
                        'document': row['document_number'],
                        'type': row['document_type'],
                        'name': row['full_name'],
                        'home_address': row['home_address'],
                        'work_address': row['work_address'],
                        'city': row['city'],
                        'phone': row['phone'],
                        'email': row['email']
                    })
                    
        except Exception as e:
            logger.error(f"Errore ricerca documento in DB: {e}")
            
        return results
        
    async def search_address(self, address, is_work=False):
        """Ricerca indirizzo"""
        results = []
        
        try:
            if is_work:
                query = "SELECT * FROM addresses_documents WHERE work_address LIKE ? LIMIT 10"
            else:
                query = "SELECT * FROM addresses_documents WHERE home_address LIKE ? LIMIT 10"
                
            doc_results = await db.fetch_all(query, [f'%{address}%'])
            
            for row in doc_results:
                if isinstance(row, tuple):
                    results.append({
                        'source': 'Documents Database',
                        'name': row[3],
                        'document': row[1],
                        'address': row[5] if is_work else row[4],
                        'city': row[6],
                        'phone': row[8],
                        'email': row[9]
                    })
                else:
                    results.append({
                        'source': 'Documents Database',
                        'name': row['full_name'],
                        'document': row['document_number'],
                        'address': row['work_address'] if is_work else row['home_address'],
                        'city': row['city'],
                        'phone': row['phone'],
                        'email': row['email']
                    })
                    
        except Exception as e:
            logger.error(f"Errore ricerca indirizzo in DB: {e}")
            
        return results

class LeakosintBot:
    """Bot principale con interfaccia come nelle immagini"""
    
    def __init__(self):
        self.api = LeakSearchAPI()
        
    async def start(self, update: Update, context: CallbackContext):
        """Comando /start"""
        user_id = update.effective_user.id
        username = update.effective_user.username or "N/A"
        
        # Registra o aggiorna utente
        await self.register_user(user_id, username)
        
        # Invia menu principale
        await self.show_main_menu(update, context)
        
    async def register_user(self, user_id: int, username: str):
        """Registra o aggiorna utente nel database"""
        try:
            user = await db.fetch_one(
                "SELECT * FROM users WHERE user_id = ?",
                [user_id]
            )
            
            if not user:
                await db.execute(
                    """INSERT INTO users (user_id, username, balance, searches, 
                    registration_date, last_active) 
                    VALUES (?, ?, 4, 0, datetime('now'), datetime('now'))""",
                    [user_id, username]
                )
                logger.info(f"👤 Nuovo utente registrato: {user_id} (@{username})")
            else:
                await db.execute(
                    "UPDATE users SET last_active = datetime('now') WHERE user_id = ?",
                    [user_id]
                )
                
        except Exception as e:
            logger.error(f"❌ Errore registrazione utente: {e}")
            
    async def get_user_balance(self, user_id: int) -> int:
        """Ottiene il saldo dell'utente"""
        try:
            user = await db.fetch_one(
                "SELECT balance FROM users WHERE user_id = ?",
                [user_id]
            )
            if user:
                if isinstance(user, tuple):
                    return user[0]
                return user['balance']
            return 4  # Default
        except Exception as e:
            logger.error(f"❌ Errore ottenimento saldo: {e}")
            return 4
            
    async def get_user_searches(self, user_id: int) -> int:
        """Ottiene il numero di ricerche dell'utente"""
        try:
            user = await db.fetch_one(
                "SELECT searches FROM users WHERE user_id = ?",
                [user_id]
            )
            if user:
                if isinstance(user, tuple):
                    return user[0]
                return user['searches']
            return 0
        except Exception as e:
            logger.error(f"❌ Errore ottenimento ricerche: {e}")
            return 0
            
    async def update_user_balance(self, user_id: int, amount: int):
        """Aggiorna il saldo dell'utente"""
        try:
            await db.execute(
                "UPDATE users SET balance = balance + ? WHERE user_id = ?",
                [amount, user_id]
            )
            return True
        except Exception as e:
            logger.error(f"❌ Errore aggiornamento saldo: {e}")
            return False
            
    async def increment_user_searches(self, user_id: int):
        """Incrementa il contatore ricerche"""
        try:
            await db.execute(
                "UPDATE users SET searches = searches + 1 WHERE user_id = ?",
                [user_id]
            )
            return True
        except Exception as e:
            logger.error(f"❌ Errore incremento ricerche: {e}")
            return False
            
    async def get_user_language(self, user_id: int) -> str:
        """Ottiene la lingua dell'utente"""
        try:
            user = await db.fetch_one(
                "SELECT language FROM users WHERE user_id = ?",
                [user_id]
            )
            if user:
                if isinstance(user, tuple):
                    return user[0] or 'en'
                return user.get('language', 'en')
            return 'en'
        except Exception as e:
            logger.error(f"❌ Errore ottenimento lingua: {e}")
            return 'en'
            
    async def set_user_language(self, user_id: int, language: str):
        """Imposta la lingua dell'utente"""
        try:
            await db.execute(
                "UPDATE users SET language = ? WHERE user_id = ?",
                [language, user_id]
            )
            return True
        except Exception as e:
            logger.error(f"❌ Errore impostazione lingua: {e}")
            return False
            
    async def show_main_menu(self, update: Update, context: CallbackContext):
        """Mostra il menu principale"""
        user_id = update.effective_user.id
        user_lang = await self.get_user_language(user_id)
        
        if user_lang == 'it':
            text = """# Posso cercare tutto. Inviami la tua richiesta.🔍

Trova ciò che nascondono🕵🏻‍♂️

•🔍 Ricerca
•shop💸
•⚙️ Impostazioni
•📋 Menu
•help❓"""
        else:
            text = """# I can search for everything. Send me your request.🔍

Find what they hide🕵🏻‍♂️

•🔍 Search
•shop💸
•⚙️ Settings
•📋 Menu
•help❓"""
            
        keyboard = [
            [InlineKeyboardButton("🔍 Ricerca" if user_lang == 'it' else "🔍 Search", 
                                 callback_data='search')],
            [InlineKeyboardButton("shop💸", callback_data='shop')],
            [InlineKeyboardButton("⚙️ Impostazioni" if user_lang == 'it' else "⚙️ Settings", 
                                 callback_data='settings')],
            [InlineKeyboardButton("📋 Menu", callback_data='menu')],
            [InlineKeyboardButton("help❓", callback_data='help')]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if update.callback_query:
            await update.callback_query.edit_message_text(
                text, 
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
        else:
            await update.message.reply_text(
                text, 
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
            
    async def show_profile(self, update: Update, context: CallbackContext):
        """Mostra il profilo utente"""
        user_id = update.effective_user.id
        username = update.effective_user.username or "N/A"
        user_lang = await self.get_user_language(user_id)
        
        # Ottieni dati utente
        user = await db.fetch_one(
            "SELECT * FROM users WHERE user_id = ?",
            [user_id]
        )
        
        if user:
            if isinstance(user, tuple):
                balance = user[2]
                searches = user[3]
                reg_date = user[4]
                sub_type = user[5]
                last_active = user[6]
            else:
                balance = user['balance']
                searches = user['searches']
                reg_date = user['registration_date']
                sub_type = user['subscription_type']
                last_active = user['last_active']
        else:
            balance = 4
            searches = 0
            reg_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            sub_type = 'free'
            last_active = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        now = datetime.now()
        data_italiana = now.strftime("%d/%m/%Y")
        
        if user_lang == 'it':
            text = f"""👤 Informazioni Personali:
🆔ID Telegram: {user_id}
👤Username: @{username}
📅Registrato: {reg_date}
🕒Ultima attività: {last_active}

💳 Sistema Credit:
💰Crediti attuali: {balance}
🔍Ricerche effettuate: {searches}
🎯Ricerche disponibili: {int(balance / 2)}
📊Abbonamento: {sub_type}

⚙️ Configurazioni:
🔔Notifiche: Attive
🌐Lingua: {translations.get(user_lang, {}).get('language', 'English')}
💾Salvataggio ricerche: 30 giorni

📊 Statistiche odierne:

· Ricerche oggi: {searches % 100}
·Crediti usati oggi: {(100 - balance) % 100}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        else:
            text = f"""👤 Personal Information:
🆔Telegram ID: {user_id}
👤Username: @{username}
📅Registered: {reg_date}
🕒Last active: {last_active}

💳 Credit System:
💰Current credits: {balance}
🔍Searches performed: {searches}
🎯Available searches: {int(balance / 2)}
📊Subscription: {sub_type}

⚙️ Configurations:
🔔Notifications: Active
🌐Language: {translations.get(user_lang, {}).get('language', 'English')}
💾Search saving: 30 days

📊 Today's statistics:

· Searches today: {searches % 100}
·Credits used today: {(100 - balance) % 100}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
            
        keyboard = [[InlineKeyboardButton("🔙 Indietro" if user_lang == 'it' else "🔙 Back", 
                                        callback_data='back_to_main')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if update.callback_query:
            await update.callback_query.edit_message_text(
                text, 
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
        else:
            await update.message.reply_text(
                text, 
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
            
    async def show_language_menu(self, update: Update, context: CallbackContext):
        """Mostra menu selezione lingua"""
        user_id = update.effective_user.id
        current_lang = await self.get_user_language(user_id)
        
        text = f"""🌐 **Selezione Lingua / Language Selection**

Lingua attuale: {translations.get(current_lang, {}).get('language', 'English')}

Seleziona una lingua:
🇮🇹Italiano - Lingua italiana
🇬🇧English - English language

Il cambio lingua influenzerà:
•Testi dei menu
•Messaggi del bot
•Istruzioni"""
        
        keyboard = [
            [InlineKeyboardButton("🇮🇹 Italiano", callback_data='lang_it')],
            [InlineKeyboardButton("🇬🇧 English", callback_data='lang_en')],
            [InlineKeyboardButton("🔙 Indietro", callback_data='settings')]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if update.callback_query:
            await update.callback_query.edit_message_text(
                text, 
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
        else:
            await update.message.reply_text(
                text, 
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
            
    async def change_language(self, update: Update, context: CallbackContext, language: str):
        """Cambia lingua utente"""
        user_id = update.effective_user.id
        await self.set_user_language(user_id, language)
        
        if language == 'it':
            text = "✅ Lingua cambiata in Italiano!"
        else:
            text = "✅ Language changed to English!"
            
        await update.callback_query.answer(text)
        await self.show_settings(update, context)
        
    async def show_settings(self, update: Update, context: CallbackContext):
        """Mostra impostazioni"""
        user_id = update.effective_user.id
        user_lang = await self.get_user_language(user_id)
        
        if user_lang == 'it':
            text = "⚙️ **Impostazioni**"
        else:
            text = "⚙️ **Settings**"
            
        keyboard = [
            [InlineKeyboardButton("🌐 Lingua" if user_lang == 'it' else "🌐 Language", 
                                 callback_data='language')],
            [InlineKeyboardButton("👤 Profilo", callback_data='profile')],
            [InlineKeyboardButton("🔙 Indietro" if user_lang == 'it' else "🔙 Back", 
                                 callback_data='back_to_main')]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if update.callback_query:
            await update.callback_query.edit_message_text(
                text, 
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
        else:
            await update.message.reply_text(
                text, 
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
            
    async def show_search_menu(self, update: Update, context: CallbackContext):
        """Mostra menu di ricerca"""
        user_id = update.effective_user.id
        user_lang = await self.get_user_language(user_id)
        
        now = datetime.now()
        data_italiana = now.strftime("%d/%m/%Y")
        
        if user_lang == 'it':
            text = f"""🔍 **Menu di Ricerca**

📧 Cerca per posta

· example@gmail.com - Cerca la posta
·example@ - Cerca senza prendere in considerazione il dominio
·@gmail.com - Cerca determinati domini.

👤 Cerca per nome o nick

· Petrov
·Petrov Maxim
·Petrov Sergeevich
·Maxim Sergeevich
·Petrov Maxim Sergeevich
·ShadowPlayer228

📱 Cerca per numero di telefono

· +79002206090
·79002206090
·89002206090

📄 Cerca per documento

· AA1234567 - Carta Identità
·123456789 - Codice Fiscale
·AA12345AA1234 - Passaporto

🏠 Cerca per indirizzo di casa

· Via Roma 123, Milano
·Corso Vittorio Emanuele 45, Roma
·Piazza del Duomo 1, Firenze

🏢 Cerca per indirizzo lavorativo

· Ufficio Via Torino 50, Milano
·Azienda Via Milano 10, Roma
·Sede Via Garibaldi 25, Napoli

🔐 Ricerca password

· 123qwe

🚗 Cerca in auto

· 0999MY777 - Cerca auto nella Federazione Russa
·BO4561AX - Cerca le auto con il codice penale
·XTA21150053965897 - Cerca di Vin

📱 Cerca un account Telegram

· Petrov Ivan - Cerca per nome e cognome
·314159265 - Cerca account ID
·Petivan - Cerca per nome utente

📘 Cerca l'account Facebook

· Petrov Ivan - Cerca per nome
·314159265 - Cerca account ID

🔵 Cerca l'account VKontakte

· Petrov Ivan - Cerca per nome e cognome
·314159265 - Cerca account ID

📸 Cerca account Instagram

· Petrov Ivan - Cerca per nome e cognome
·314159265 - Cerca account ID

🌐 Cerca tramite IP

· 127.0.0.1

📋 Ricerca di massa: /utf8 per istruzioni

📝 Le richieste composite in tutti i formati sono supportate:

· Petrov 79002206090
·Maxim Sergeevich 127.0.0.1
·Petrov Maxim Sergeevich
·AA1234567 Via Roma 123
·Mario Rossi 123456789 Milano

💰 Crediti disponibili: {await self.get_user_balance(user_id)}
📊Ricerche effettuate: {await self.get_user_searches(user_id)}

📩 Inviami qualsiasi dato per iniziare la ricerca.

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        else:
            text = f"""🔍 **Search Menu**

📧 Search by email

· example@gmail.com - Search email
·example@ - Search without domain consideration
·@gmail.com - Search specific domains

👤 Search by name or nickname

· Petrov
·Petrov Maxim
·Petrov Sergeevich
·Maxim Sergeevich
·Petrov Maxim Sergeevich
·ShadowPlayer228

📱 Search by phone number

· +79002206090
·79002206090
·89002206090

📄 Search by document

· AA1234567 - Identity Card
·123456789 - Tax Code
·AA12345AA1234 - Passport

🏠 Search by home address

· Via Roma 123, Milano
·Corso Vittorio Emanuele 45, Roma
·Piazza del Duomo 1, Firenze

🏢 Search by work address

· Office Via Torino 50, Milano
·Company Via Milano 10, Roma
·Headquarters Via Garibaldi 25, Napoli

🔐 Password search

· 123qwe

🚗 Search vehicles

· 0999MY777 - Search vehicles in Russia
·BO4561AX - Search vehicles with penal code
·XTA21150053965897 - Search by VIN

📱 Search Telegram account

· Petrov Ivan - Search by name and surname
·314159265 - Search by account ID
·Petivan - Search by username

📘 Search Facebook account

· Petrov Ivan - Search by name
·314159265 - Search by account ID

🔵 Search VKontakte account

· Petrov Ivan - Search by name and surname
·314159265 - Search by account ID

📸 Search Instagram account

· Petrov Ivan - Search by name and surname
·314159265 - Search by account ID

🌐 Search by IP

· 127.0.0.1

📋 Mass search: /utf8 for instructions

📝 Composite requests in all formats are supported:

· Petrov 79002206090
·Maxim Sergeevich 127.0.0.1
·Petrov Maxim Sergeevich
·AA1234567 Via Roma 123
·Mario Rossi 123456789 Milano

💰 Available credits: {await self.get_user_balance(user_id)}
📊Searches performed: {await self.get_user_searches(user_id)}

📩 Send me any data to start searching.

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
            
        keyboard = [[InlineKeyboardButton("🔙 Indietro" if user_lang == 'it' else "🔙 Back", 
                                        callback_data='back_to_main')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if update.callback_query:
            await update.callback_query.edit_message_text(
                text, 
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
        else:
            await update.message.reply_text(
                text, 
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
            
    async def show_shop(self, update: Update, context: CallbackContext):
        """Mostra shop"""
        user_id = update.effective_user.id
        user_lang = await self.get_user_language(user_id)
        
        now = datetime.now()
        data_italiana = now.strftime("%d/%m/%Y")
        
        # Prezzi in EUR e USD
        eur_20, usd_20 = 5, 5.5
        eur_50, usd_50 = 10, 11
        eur_100, usd_100 = 18, 20
        eur_200, usd_200 = 30, 33
        eur_500, usd_500 = 65, 71
        eur_1000, usd_1000 = 120, 132
        
        if user_lang == 'it':
            text = f"""🛒 **Negozio Credit**

{translations[user_lang]['credit_packages']}
━━━━━━━━━━━━━━━━━━━━
·🟢 20 CREDITI = {eur_20}€ / {usd_20}$
·🟡 50 CREDITI = {eur_50}€ / {usd_50}$
·🔵 100 CREDITI = {eur_100}€ / {usd_100}$
·🟣 200 CREDITI = {eur_200}€ / {usd_200}$
·🔴 500 CREDITI = {eur_500}€ / {usd_500}$
·🟤 1000 CREDITI = {eur_1000}€ / {usd_1000}$

{translations[user_lang]['payment_addresses']}
━━━━━━━━━━━━━━━━━━━━
Ⓜ️XRM (Monero):

459uXRXZknoRy3eq9TfZxKZ85jKWCZniBEh2U5GEg9VCYjT6f5U57cNjerJcpw2eF7jSmQwzh6sgmAQEL79HhM3NRmSu6ZT

₿ BTC (Bitcoin):

19rgimxDy1FKW5RvXWPQN4u9eevKySmJTu

Ξ ETH (Ethereum):

0x2e7edD5154Be461bae0BD9F79473FC54B0eeEE59

💳 PayPal (EUR/USD):

https://www.paypal.me/BotAi36

📊 CONVERSIONE:
━━━━━━━━━━━━━━━━━━━━
💰2 crediti = 1 ricerca

🎁 SCONTI:
━━━━━━━━━━━━━━━━━━━━
•200 crediti: 10% sconto
•500 crediti: 15% sconto
•1000 crediti: 20% sconto

📝 COME ACQUISTARE:
━━━━━━━━━━━━━━━━━━━━

1. Scegli il pacchetto
2. Invia l'importo corrispondente in crypto (copia e incolla indirizzi) o PayPal
3. Invia ID Profilo / Screenshot a @Zerofilter00 (o su messaggi PayPal)
4. Ricevi crediti in 5-15 minuti

⚠️ AVVERTENZE:
━━━━━━━━━━━━━━━━━━━━
•Invia l'importo esatto in €/$ o equivalente crypto
•Nessun rimborso
•Verifica indirizzo prima di inviare

📞 SUPPORTO:
━━━━━━━━━━━━━━━━━━━━
•@Zerofilter00
•24/7 disponibile

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        else:
            text = f"""🛒 **Credit Shop**

{translations[user_lang]['credit_packages']}
━━━━━━━━━━━━━━━━━━━━
·🟢 20 CREDITS = {eur_20}€ / {usd_20}$
·🟡 50 CREDITS = {eur_50}€ / {usd_50}$
·🔵 100 CREDITS = {eur_100}€ / {usd_100}$
·🟣 200 CREDITS = {eur_200}€ / {usd_200}$
·🔴 500 CREDITS = {eur_500}€ / {usd_500}$
·🟤 1000 CREDITS = {eur_1000}€ / {usd_1000}$

{translations[user_lang]['payment_addresses']}
━━━━━━━━━━━━━━━━━━━━
Ⓜ️XRM (Monero):

459uXRXZknoRy3eq9TfZxKZ85jKWCZniBEh2U5GEg9VCYjT6f5U57cNjerJcpw2eF7jSmQwzh6sgmAQEL79HhM3NRmSu6ZT

₿ BTC (Bitcoin):

19rgimxDy1FKW5RvXWPQN4u9eevKySmJTu

Ξ ETH (Ethereum):

0x2e7edD5154Be461bae0BD9F79473FC54B0eeEE59

💳 PayPal (EUR/USD):

https://www.paypal.me/BotAi36

📊 CONVERSION:
━━━━━━━━━━━━━━━━━━━━
💰2 credits = 1 search

🎁 DISCOUNTS:
━━━━━━━━━━━━━━━━━━━━
•200 credits: 10% discount
•500 credits: 15% discount
•1000 credits: 20% discount

📝 HOW TO BUY:
━━━━━━━━━━━━━━━━━━━━

1. Choose the package
2. Send the corresponding amount in crypto (copy and paste) or PayPal
3. Send ID Profile / Screenshot to @Zerofilter00 (or on PayPal messages)
4. Receive credits in 5-15 minutes

⚠️ WARNINGS:
━━━━━━━━━━━━━━━━━━━━
•Send the exact amount in €/$ or crypto equivalent
•No refunds
•Verify address before sending

📞 SUPPORT:
━━━━━━━━━━━━━━━━━━━━
•@Zerofilter00
•24/7 available

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
            
        keyboard = [[InlineKeyboardButton("🔙 Indietro" if user_lang == 'it' else "🔙 Back", 
                                        callback_data='back_to_main')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if update.callback_query:
            await update.callback_query.edit_message_text(
                text, 
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
        else:
            await update.message.reply_text(
                text, 
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
            
    async def show_help(self, update: Update, context: CallbackContext):
        """Mostra help"""
        user_id = update.effective_user.id
        user_lang = await self.get_user_language(user_id)
        
        now = datetime.now()
        data_italiana = now.strftime("%d/%m/%Y")
        
        if user_lang == 'it':
            text = f"""❓ **Guida e Supporto**

📌 **COME FUNZIONA:**
1. Invia dati (email, telefono, nome, etc.)
2. Il bot cerca in database e fonti OSINT
3. Ricevi risultati dettagliati

🔍 **COSA PUOI CERCARE:**
· Email: example@gmail.com
· Telefono: +393331234567
· Nome: Mario Rossi
· Username: shadowplayer
· IP: 8.8.8.8
· Password: 123qwe
· Hash: 5f4dcc3b5aa765d61d8327deb882cf99
· Documenti: AA1234567, 123456789
· Indirizzi: Via Roma 123, Milano

💰 **SISTEMA CREDITI:**
· 1 ricerca = 2 crediti
· Partenza: 4 crediti gratis
· Ricarica: /buy

📊 **COMANDI:**
/start - Avvia il bot
/menu - Menu completo
/balance - Mostra saldo
/buy - Acquista crediti
/help - Questo messaggio
/utf8 - Istruzioni file massivo

📞 **SUPPORTO:**
· @Zerofilter00
· 24/7 disponibile

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        else:
            text = f"""❓ **Help and Support**

📌 **HOW IT WORKS:**
1. Send data (email, phone, name, etc.)
2. Bot searches in databases and OSINT sources
3. Receive detailed results

🔍 **WHAT YOU CAN SEARCH:**
· Email: example@gmail.com
· Phone: +393331234567
· Name: Mario Rossi
· Username: shadowplayer
· IP: 8.8.8.8
· Password: 123qwe
· Hash: 5f4dcc3b5aa765d61d8327deb882cf99
· Documents: AA1234567, 123456789
· Addresses: Via Roma 123, Milano

💰 **CREDIT SYSTEM:**
· 1 search = 2 credits
· Start: 4 free credits
· Recharge: /buy

📊 **COMMANDS:**
/start - Start bot
/menu - Complete menu
/balance - Show balance
/buy - Buy credits
/help - This message
/utf8 - Mass file instructions

📞 **SUPPORT:**
· @Zerofilter00
· 24/7 available

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
            
        keyboard = [[InlineKeyboardButton("🔙 Indietro" if user_lang == 'it' else "🔙 Back", 
                                        callback_data='back_to_main')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if update.callback_query:
            await update.callback_query.edit_message_text(
                text, 
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
        else:
            await update.message.reply_text(
                text, 
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
            
    async def handle_message(self, update: Update, context: CallbackContext):
        """Gestisce i messaggi di testo per le ricerche"""
        query = update.message.text.strip()
        user_id = update.effective_user.id
        user_lang = await self.get_user_language(user_id)
        
        # Verifica saldo
        balance = await self.get_user_balance(user_id)
        if balance < 2:
            if user_lang == 'it':
                text = "❌ Credit insufficienti. Usa /buy per acquistare crediti."
            else:
                text = "❌ Insufficient credits. Use /buy to purchase credits."
            await update.message.reply_text(text)
            return
            
        # Inizia ricerca
        await self.process_search(update, context, query)
        
    async def process_search(self, update: Update, context: CallbackContext, query: str):
        """Processa una ricerca"""
        user_id = update.effective_user.id
        user_lang = await self.get_user_language(user_id)
        
        now = datetime.now()
        data_italiana = now.strftime("%d/%m/%Y")
        
        # Invia messaggio di attesa
        if user_lang == 'it':
            wait_text = f"""🔍 **Analisi in corso...**

Query: {query}

📊 Verifica pattern...
🌐 Connessione database...
🔎 Ricerca fonti...

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        else:
            wait_text = f"""🔍 **Analysis in progress...**

Query: {query}

📊 Checking patterns...
🌐 Connecting to database...
🔎 Searching sources...

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
            
        msg = await update.message.reply_text(wait_text, parse_mode='HTML')
        
        try:
            # Analizza la query per determinare il tipo
            search_type = await self.analyze_query(query)
            
            # Esegue ricerca in base al tipo
            if search_type == 'email':
                await self.search_email_exact(update, msg, query, user_id, data_italiana)
            elif search_type == 'phone':
                await self.search_phone_exact(update, msg, query, user_id, data_italiana)
            elif search_type == 'name':
                await self.search_name_exact(update, msg, query, user_id, data_italiana)
            elif search_type == 'username':
                await self.search_social_exact(update, msg, query, user_id, data_italiana)
            elif search_type == 'ip':
                await self.search_ip_exact(update, msg, query, user_id, data_italiana)
            elif search_type == 'password':
                await self.search_password_exact(update, msg, query, user_id, data_italiana)
            elif search_type == 'hash':
                await self.search_hash_exact(update, msg, query, user_id, data_italiana)
            elif search_type == 'document':
                await self.search_document_exact(update, msg, query, user_id, data_italiana)
            elif search_type == 'address':
                await self.search_address_exact(update, msg, query, user_id, data_italiana)
            elif search_type == 'facebook':
                await self.search_facebook_complete(update, msg, query, user_id, data_italiana)
            else:
                # Ricerca composita
                await self.search_composite(update, msg, query, user_id, data_italiana)
                
            # Aggiorna saldo e contatore ricerche
            await self.update_user_balance(user_id, -2)
            await self.increment_user_searches(user_id)
            
            # Salva ricerca nel database
            await db.execute(
                """INSERT INTO searches (user_id, query, type, results, timestamp)
                VALUES (?, ?, ?, ?, datetime('now'))""",
                [user_id, query, search_type, 'completed']
            )
            
        except Exception as e:
            logger.error(f"❌ Errore ricerca: {e}")
            
            if user_lang == 'it':
                error_text = f"""❌ **Errore durante la ricerca**

Query: {query}
Errore:{str(e)[:100]}

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
            else:
                error_text = f"""❌ **Error during search**

Query: {query}
Error:{str(e)[:100]}

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
            try:
                await msg.edit_text(error_text)
            except:
                await update.message.reply_text(error_text)
                
    async def analyze_query(self, query: str) -> str:
        """Analizza la query per determinare il tipo"""
        query_lower = query.lower()
        
        # Email pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if re.search(email_pattern, query):
            return 'email'
            
        # Phone pattern
        phone_pattern = r'(\+?\d{1,3}[-.\s]?)?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}'
        if re.search(r'\d{7,15}', query) and len(re.findall(r'\d', query)) >= 7:
            return 'phone'
            
        # IP pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        if re.match(ip_pattern, query):
            return 'ip'
            
        # Document pattern (Italian documents)
        doc_patterns = [
            r'^[A-Z]{2}\d{5,7}$',  # Carta Identità
            r'^\d{9}$',  # Codice Fiscale
            r'^[A-Z]{2}\d{5,7}[A-Z]{2}\d{4}$',  # Passaporto
        ]
        for pattern in doc_patterns:
            if re.match(pattern, query.upper()):
                return 'document'
                
        # Address indicators
        address_indicators = ['via', 'corso', 'piazza', 'viale', 'largo', 'street', 'avenue', 'road']
        if any(indicator in query_lower for indicator in address_indicators):
            return 'address'
            
        # Facebook indicators
        fb_indicators = ['facebook', 'fb', 'face', 'zuckerberg']
        if any(indicator in query_lower for indicator in fb_indicators):
            return 'facebook'
            
        # Username/social pattern
        if re.match(r'^[a-zA-Z0-9_.]{3,}$', query) and ' ' not in query:
            return 'username'
            
        # Name pattern (contains spaces or is a single word that looks like a name)
        if ' ' in query or query[0].isupper():
            return 'name'
            
        # Password/hash pattern
        if len(query) <= 50 and (' ' not in query):
            if len(query) == 32 or len(query) == 40 or len(query) == 64:
                return 'hash'
            else:
                return 'password'
                
        return 'composite'
        
    async def search_composite(self, update: Update, msg, query: str, user_id: int, data_italiana: str):
        """Ricerca composita"""
        user_lang = await self.get_user_language(user_id)
        
        # Analizza componenti
        components = {
            'emails': re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', query),
            'phones': re.findall(r'(\+?\d{1,3}[-.\s]?)?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}', query),
            'ips': re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', query),
            'words': re.findall(r'\b[A-Za-zÀ-ÿ]{2,}\b', query)
        }
        
        now = datetime.now()
        
        if user_lang == 'it':
            results_text = f"""✅ **Ricerca completata**

📋 Query: {query}

📊 Componenti rilevati:
"""
        else:
            results_text = f"""✅ **Search completed**

📋 Query: {query}

📊 Detected components:
"""
            
        if components['emails']:
            results_text += f"📧 Email: {', '.join(components['emails'])}\n"
        if components['phones']:
            results_text += f"📱 Telefono: {', '.join(components['phones'])}\n"
        if components['ips']:
            results_text += f"🌐 IP: {', '.join(components['ips'])}\n"
        if components['words']:
            results_text += f"👤 Parole: {', '.join(components['words'][:5])}\n"
            
        # Esegue ricerche per ogni componente
        all_results = []
        
        for email in components['emails'][:2]:  # Limita a 2 email
            email_results = await self.api.search_email(email)
            all_results.extend(email_results)
            
        for phone in components['phones'][:2]:  # Limita a 2 telefoni
            phone_results = await self.api.search_phone(phone)
            all_results.extend(phone_results)
            
        # Cerca per nomi
        name_words = [w for w in components['words'] if w[0].isupper()]
        if name_words:
            name_query = ' '.join(name_words[:3])
            name_results = await self.api.search_name(name_query)
            all_results.extend(name_results)
            
        # Limita risultati
        all_results = all_results[:20]
        
        if all_results:
            results_text += f"\n🔍 **Risultati trovati ({len(all_results)}):**\n\n" if user_lang == 'it' else f"\n🔍 **Results found ({len(all_results)}):**\n\n"
            
            for i, result in enumerate(all_results[:10], 1):
                source = result.get('source', 'Unknown')
                if 'email' in result:
                    results_text += f"{i}. 📧 {result['email']} ({source})\n"
                elif 'phone' in result:
                    results_text += f"{i}. 📱 {result['phone']} - {result.get('name', 'N/A')} ({source})\n"
                elif 'name' in result:
                    results_text += f"{i}. 👤 {result['name']} - {result.get('document', 'N/A')} ({source})\n"
                elif 'platform' in result:
                    results_text += f"{i}. 🌐 {result['platform']}: {result.get('url', 'N/A')}\n"
                    
            if len(all_results) > 10:
                results_text += f"\n... e altri {len(all_results) - 10} risultati\n"
        else:
            results_text += "\n❌ **Nessun risultato trovato**\n" if user_lang == 'it' else "\n❌ **No results found**\n"
            
        results_text += f"""\n💰 Costo: 2 crediti
📊 Nuovo saldo: {await self.get_user_balance(user_id)} crediti

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(results_text, parse_mode='HTML')
        
    async def search_email_exact(self, update: Update, msg, email: str, user_id: int, data_italiana: str):
        """Ricerca email - Formato esatto"""
        user_lang = await self.get_user_language(user_id)
        search_results = await self.api.search_email(email)
        
        now = datetime.now()
        
        if user_lang == 'it':
            results_text = f"""✅ **Ricerca email completata**

📧 Email: {email}

"""
        else:
            results_text = f"""✅ **Email search completed**

📧 Email: {email}

"""
            
        if search_results:
            results_text += f"🔍 **Risultati trovati ({len(search_results)}):**\n\n" if user_lang == 'it' else f"🔍 **Results found ({len(search_results)}):**\n\n"
            
            for i, result in enumerate(search_results[:10], 1):
                source = result.get('source', 'Unknown')
                password = result.get('password', '')
                breach = result.get('breach', '')
                
                if password:
                    results_text += f"{i}. 🔓 Password: {password} ({source})\n"
                elif breach:
                    results_text += f"{i}. 🚨 Breach: {breach} ({source})\n"
                else:
                    results_text += f"{i}. 📁 {source}\n"
                    
            if len(search_results) > 10:
                results_text += f"\n... e altri {len(search_results) - 10} risultati\n"
        else:
            results_text += "❌ **Nessun risultato trovato**\n" if user_lang == 'it' else "❌ **No results found**\n"
            
        results_text += f"""\n💰 Costo: 2 crediti
📊 Nuovo saldo: {await self.get_user_balance(user_id)} crediti

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(results_text, parse_mode='HTML')
        
    async def search_phone_exact(self, update: Update, msg, phone: str, user_id: int, data_italiana: str):
        """Ricerca telefono - Formato esatto"""
        user_lang = await self.get_user_language(user_id)
        phone_info = {}
        
        try:
            parsed = phonenumbers.parse(phone, None)
            phone_info = {
                'valid': phonenumbers.is_valid_number(parsed),
                'country': geocoder.description_for_number(parsed, "it"),
                'carrier': carrier.name_for_number(parsed, "it"),
                'national': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
            }
        except:
            pass
            
        search_results = await self.api.search_phone(phone)
        
        now = datetime.now()
        
        if user_lang == 'it':
            results_text = f"""✅ **Ricerca telefono completata**

📱 Telefono: {phone}

"""
        else:
            results_text = f"""✅ **Phone search completed**

📱 Phone: {phone}

"""
            
        if phone_info.get('valid'):
            results_text += f"""📊 Informazioni numero:
📍 Paese: {phone_info.get('country', 'N/A')}
🏢 Operatore: {phone_info.get('carrier', 'N/A')}
📞 Formato nazionale: {phone_info.get('national', 'N/A')}

"""
            
        if search_results:
            results_text += f"🔍 **Risultati trovati ({len(search_results)}):**\n\n" if user_lang == 'it' else f"🔍 **Results found ({len(search_results)}):**\n\n"
            
            for i, result in enumerate(search_results[:10], 1):
                name = result.get('name', 'N/A')
                surname = result.get('surname', '')
                city = result.get('city', '')
                source = result.get('source', 'Unknown')
                
                full_name = f"{name} {surname}".strip()
                location = f" - {city}" if city else ""
                
                results_text += f"{i}. 👤 {full_name}{location} ({source})\n"
                
            if len(search_results) > 10:
                results_text += f"\n... e altri {len(search_results) - 10} risultati\n"
        else:
            results_text += "❌ **Nessun risultato trovato**\n" if user_lang == 'it' else "❌ **No results found**\n"
            
        results_text += f"""\n💰 Costo: 2 crediti
📊 Nuovo saldo: {await self.get_user_balance(user_id)} crediti

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(results_text, parse_mode='HTML')
        
    async def search_name_exact(self, update: Update, msg, name: str, user_id: int, data_italiana: str):
        """Ricerca per nome - Formato esatto"""
        user_lang = await self.get_user_language(user_id)
        search_results = await self.api.search_name(name)
        username = name.split()[0] if ' ' in name else name
        social_results = await self.api.search_username(username)
        
        now = datetime.now()
        
        if user_lang == 'it':
            results_text = f"""✅ **Ricerca nome completata**

👤 Nome: {name}

"""
        else:
            results_text = f"""✅ **Name search completed**

👤 Name: {name}

"""
            
        if search_results:
            results_text += f"📄 **Documenti/Indirizzi trovati ({len(search_results)}):**\n\n" if user_lang == 'it' else f"📄 **Documents/Addresses found ({len(search_results)}):**\n\n"
            
            for i, result in enumerate(search_results[:5], 1):
                doc = result.get('document', 'N/A')
                address = result.get('address', 'N/A')
                city = result.get('city', '')
                phone = result.get('phone', '')
                
                location = f" - {city}" if city else ""
                contact = f" | 📱{phone}" if phone else ""
                
                results_text += f"{i}. 🆔 {doc}{location}{contact}\n"
                
        if social_results:
            results_text += f"\n🌐 **Account social trovati ({len(social_results)}):**\n\n" if user_lang == 'it' else f"\n🌐 **Social accounts found ({len(social_results)}):**\n\n"
            
            for i, result in enumerate(social_results[:5], 1):
                platform = result.get('platform', 'N/A')
                url = result.get('url', 'N/A')
                results_text += f"{i}. {platform}: {url}\n"
                
        if not search_results and not social_results:
            results_text += "❌ **Nessun risultato trovato**\n" if user_lang == 'it' else "❌ **No results found**\n"
            
        results_text += f"""\n💰 Costo: 2 crediti
📊 Nuovo saldo: {await self.get_user_balance(user_id)} crediti

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(results_text, parse_mode='HTML')
        
    async def search_social_exact(self, update: Update, msg, username: str, user_id: int, data_italiana: str):
        """Ricerca username - Formato esatto con API potenziate"""
        user_lang = await self.get_user_language(user_id)
        # PRIMA usa le nuove API
        search_results = await self.api.search_username(username)
        # POI ricerca avanzata
        advanced_results = await self.api.search_username_advanced(username)
        
        # Combina risultati, rimuovi duplicati
        all_results = search_results + advanced_results
        unique_results = []
        seen_urls = set()
        
        for result in all_results:
            url = result.get('url', '')
            if url not in seen_urls:
                seen_urls.add(url)
                unique_results.append(result)
                
        now = datetime.now()
        
        if user_lang == 'it':
            results_text = f"""✅ **Ricerca username completata**

👤 Username: {username}

"""
        else:
            results_text = f"""✅ **Username search completed**

👤 Username: {username}

"""
            
        if unique_results:
            results_text += f"🌐 **Account trovati ({len(unique_results)}):**\n\n" if user_lang == 'it' else f"🌐 **Accounts found ({len(unique_results)}):**\n\n"
            
            for i, result in enumerate(unique_results[:15], 1):
                platform = result.get('platform', 'N/A')
                url = result.get('url', 'N/A')
                status = result.get('status', 'Found')
                
                results_text += f"{i}. {platform}: {url}\n"
                
            if len(unique_results) > 15:
                results_text += f"\n... e altri {len(unique_results) - 15} account\n"
        else:
            results_text += "❌ **Nessun account trovato**\n" if user_lang == 'it' else "❌ **No accounts found**\n"
            
        results_text += f"""\n💰 Costo: 2 crediti
📊 Nuovo saldo: {await self.get_user_balance(user_id)} crediti

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(results_text, parse_mode='HTML')
        
    async def search_ip_exact(self, update: Update, msg, ip: str, user_id: int, data_italiana: str):
        """Ricerca IP - Formato esatto"""
        user_lang = await self.get_user_language(user_id)
        search_results = await self.api.search_ip(ip)
        
        now = datetime.now()
        
        if user_lang == 'it':
            results_text = f"""✅ **Ricerca IP completata**

🌐 IP: {ip}

"""
        else:
            results_text = f"""✅ **IP search completed**

🌐 IP: {ip}

"""
            
        if search_results:
            results_text += "📊 **Informazioni IP:**\n\n" if user_lang == 'it' else "📊 **IP Information:**\n\n"
            
            for i, result in enumerate(search_results, 1):
                source = result.get('source', 'Unknown')
                
                if source == 'IPInfo':
                    results_text += f"""📍 Località: {result.get('city', 'N/A')}, {result.get('region', 'N/A')}, {result.get('country', 'N/A')}
🏢 Organizzazione: {result.get('org', 'N/A')}
📌 Coordinate: {result.get('loc', 'N/A')}

"""
                elif source == 'AbuseIPDB':
                    score = result.get('abuse_score', 0)
                    reports = result.get('total_reports', 0)
                    isp = result.get('isp', 'N/A')
                    
                    if score > 50:
                        risk = "🚨 ALTO RISCHIO"
                    elif score > 20:
                        risk = "⚠️ MEDIO RISCHIO"
                    else:
                        risk = "✅ BASSO RISCHIO"
                        
                    results_text += f"""🚨 Abuse Score: {score}/100 {risk}
📊 Report totali: {reports}
🏢 ISP: {isp}

"""
        else:
            results_text += "❌ **Nessuna informazione trovata**\n" if user_lang == 'it' else "❌ **No information found**\n"
            
        results_text += f"""💰 Costo: 2 crediti
📊 Nuovo saldo: {await self.get_user_balance(user_id)} crediti

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(results_text, parse_mode='HTML')
        
    async def search_password_exact(self, update: Update, msg, password: str, user_id: int, data_italiana: str):
        """Ricerca password - Formato esatto"""
        user_lang = await self.get_user_language(user_id)
        search_results = await self.api.search_password(password)
        
        now = datetime.now()
        
        if user_lang == 'it':
            results_text = f"""✅ **Ricerca password completata**

🔐 Password: {password}

"""
        else:
            results_text = f"""✅ **Password search completed**

🔐 Password: {password}

"""
            
        if search_results:
            results_text += f"🚨 **Password trovata in ({len(search_results)}):**\n\n" if user_lang == 'it' else f"🚨 **Password found in ({len(search_results)}):**\n\n"
            
            for i, result in enumerate(search_results, 1):
                source = result.get('source', 'Unknown')
                found_in = result.get('found_in', 'Unknown')
                count = result.get('count', 0)
                
                results_text += f"{i}. {found_in} ({source}) - {count} occorrenze\n"
                
            results_text += "\n⚠️ **Questa password è compromessa! Cambiala immediatamente.**\n" if user_lang == 'it' else "\n⚠️ **This password is compromised! Change it immediately.**\n"
        else:
            results_text += "✅ **Password non trovata in database noti**\n" if user_lang == 'it' else "✅ **Password not found in known databases**\n"
            
        results_text += f"""\n💰 Costo: 2 crediti
📊 Nuovo saldo: {await self.get_user_balance(user_id)} crediti

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(results_text, parse_mode='HTML')
        
    async def search_hash_exact(self, update: Update, msg, hash_str: str, user_id: int, data_italiana: str):
        """Ricerca hash - Formato esatto"""
        user_lang = await self.get_user_language(user_id)
        search_results = await self.api.search_hash(hash_str)
        
        now = datetime.now()
        
        # Determina tipo hash
        hash_length = len(hash_str)
        if hash_length == 32:
            hash_type = "MD5"
        elif hash_length == 40:
            hash_type = "SHA1"
        elif hash_length == 64:
            hash_type = "SHA256"
        else:
            hash_type = "Hash"
            
        if user_lang == 'it':
            results_text = f"""✅ **Ricerca hash completata**

🔑 {hash_type}: {hash_str}

"""
        else:
            results_text = f"""✅ **Hash search completed**

🔑 {hash_type}: {hash_str}

"""
            
        if search_results:
            results_text += f"🚨 **Hash trovato in ({len(search_results)}):**\n\n" if user_lang == 'it' else f"🚨 **Hash found in ({len(search_results)}):**\n\n"
            
            for i, result in enumerate(search_results, 1):
                found_in = result.get('found_in', 'Unknown')
                count = result.get('count', 0)
                
                results_text += f"{i}. {found_in} - {count} occorrenze\n"
        else:
            results_text += "❌ **Hash non trovato in database**\n" if user_lang == 'it' else "❌ **Hash not found in databases**\n"
            
        results_text += f"""\n💰 Costo: 2 crediti
📊 Nuovo saldo: {await self.get_user_balance(user_id)} crediti

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(results_text, parse_mode='HTML')
        
    async def search_document_exact(self, update: Update, msg, document: str, user_id: int, data_italiana: str):
        """Ricerca documento - Formato esatto come immagini"""
        user_lang = await self.get_user_language(user_id)
        search_results = await self.api.search_document(document)
        
        now = datetime.now()
        
        if user_lang == 'it':
            results_text = f"""✅ **Ricerca documento completata**

📄 Documento: {document}

"""
        else:
            results_text = f"""✅ **Document search completed**

📄 Document: {document}

"""
            
        if search_results:
            results_text += f"👤 **Informazioni trovate ({len(search_results)}):**\n\n" if user_lang == 'it' else f"👤 **Information found ({len(search_results)}):**\n\n"
            
            for i, result in enumerate(search_results, 1):
                doc_type = result.get('type', 'N/A')
                name = result.get('name', 'N/A')
                home_address = result.get('home_address', 'N/A')
                work_address = result.get('work_address', 'N/A')
                city = result.get('city', 'N/A')
                phone = result.get('phone', 'N/A')
                email = result.get('email', 'N/A')
                
                results_text += f"""{i}. 📋 {doc_type}
   👤 {name}
   🏠 {home_address}
   🏢 {work_address}
   📍 {city}
   📱 {phone}
   📧 {email}

"""
        else:
            results_text += "❌ **Nessun documento trovato**\n" if user_lang == 'it' else "❌ **No document found**\n"
            
        results_text += f"""💰 Costo: 2 crediti
📊 Nuovo saldo: {await self.get_user_balance(user_id)} crediti

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(results_text, parse_mode='HTML')
        
    async def search_address_exact(self, update: Update, msg, address: str, user_id: int, data_italiana: str):
        """Ricerca indirizzo - Formato esatto come immagini"""
        user_lang = await self.get_user_language(user_id)
        is_work_address = any(word in address.lower() for word in ['ufficio', 'lavoro', 'azienda', 'company', 'sede'])
        search_results = await self.api.search_address(address, is_work_address)
        
        now = datetime.now()
        
        address_type = "lavorativo 🏢" if is_work_address else "casa 🏠"
        
        if user_lang == 'it':
            results_text = f"""✅ **Ricerca indirizzo completata**

{address_type if user_lang == 'it' else 'work 🏢' if is_work_address else 'home 🏠'} Indirizzo: {address}

"""
        else:
            results_text = f"""✅ **Address search completed**

{'Work 🏢' if is_work_address else 'Home 🏠'} Address: {address}

"""
            
        if search_results:
            results_text += f"👤 **Persone trovate ({len(search_results)}):**\n\n" if user_lang == 'it' else f"👤 **People found ({len(search_results)}):**\n\n"
            
            for i, result in enumerate(search_results, 1):
                name = result.get('name', 'N/A')
                document = result.get('document', 'N/A')
                found_address = result.get('address', 'N/A')
                city = result.get('city', 'N/A')
                phone = result.get('phone', 'N/A')
                email = result.get('email', 'N/A')
                
                results_text += f"""{i}. 👤 {name}
   🆔 {document}
   📍 {found_address}, {city}
   📱 {phone}
   📧 {email}

"""
        else:
            results_text += "❌ **Nessuna persona trovata a questo indirizzo**\n" if user_lang == 'it' else "❌ **No people found at this address**\n"
            
        results_text += f"""💰 Costo: 2 crediti
📊 Nuovo saldo: {await self.get_user_balance(user_id)} crediti

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(results_text, parse_mode='HTML')
        
    async def search_facebook_complete(self, update: Update, msg, query: str, user_id: int, data_italiana: str):
        """Ricerca Facebook completa"""
        user_lang = await self.get_user_language(user_id)
        now = datetime.now()
        
        # Cerca nei leak Facebook
        fb_results = []
        try:
            # Cerca per nome
            if ' ' in query:  # Probabilmente un nome
                name_parts = query.split()
                for part in name_parts:
                    results = await db.fetch_all(
                        "SELECT * FROM facebook_leaks WHERE name LIKE ? OR surname LIKE ? LIMIT 5",
                        [f'%{part}%', f'%{part}%']
                    )
                    fb_results.extend(results)
            else:
                # Cerca per ID o username
                results = await db.fetch_all(
                    "SELECT * FROM facebook_leaks WHERE facebook_id = ? OR phone = ? LIMIT 10",
                    [query, query]
                )
                fb_results.extend(results)
        except Exception as e:
            logger.error(f"Errore ricerca Facebook: {e}")
            
        if user_lang == 'it':
            results_text = f"""✅ **Ricerca Facebook completata**

📘 Query: {query}

"""
        else:
            results_text = f"""✅ **Facebook search completed**

📘 Query: {query}

"""
            
        if fb_results:
            # Rimuovi duplicati
            unique_results = []
            seen_ids = set()
            
            for result in fb_results:
                if isinstance(result, tuple):
                    fb_id = result[2]  # facebook_id
                else:
                    fb_id = result['facebook_id']
                    
                if fb_id not in seen_ids:
                    seen_ids.add(fb_id)
                    unique_results.append(result)
                    
            results_text += f"👤 **Profili trovati ({len(unique_results)}):**\n\n" if user_lang == 'it' else f"👤 **Profiles found ({len(unique_results)}):**\n\n"
            
            for i, result in enumerate(unique_results[:5], 1):
                if isinstance(result, tuple):
                    name = result[3]  # name
                    surname = result[4]  # surname
                    phone = result[1]  # phone
                    city = result[8]  # city
                    fb_id = result[2]  # facebook_id
                else:
                    name = result['name']
                    surname = result['surname']
                    phone = result['phone']
                    city = result['city']
                    fb_id = result['facebook_id']
                    
                full_name = f"{name} {surname}".strip()
                phone_display = f" | 📱 {phone}" if phone else ""
                city_display = f" | 📍 {city}" if city else ""
                
                results_text += f"{i}. {full_name}{phone_display}{city_display} (ID: {fb_id})\n"
                
            if len(unique_results) > 5:
                results_text += f"\n... e altri {len(unique_results) - 5} profili\n"
        else:
            results_text += "❌ **Nessun profilo Facebook trovato**\n" if user_lang == 'it' else "❌ **No Facebook profiles found**\n"
            
        results_text += f"""\n💰 Costo: 2 crediti
📊 Nuovo saldo: {await self.get_user_balance(user_id)} crediti

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await msg.edit_text(results_text, parse_mode='HTML')
        
    async def menu_completo(self, update: Update, context: CallbackContext):
        """Mostra il menu completo"""
        user_id = update.effective_user.id
        user_lang = await self.get_user_language(user_id)
        
        now = datetime.now()
        data_italiana = now.strftime("%d/%m/%Y")
        
        if user_lang == 'it':
            text = f"""📋 **Menu Completamente Funzionale**

{translations[user_lang]['composite_examples']}

📌 Email + Telefono + Nome:
·example@gmail.com +79002206090 Petrov Ivan

📌 Nome + Città + Telefono:
·Maxim Sergeevich Mosca +79001234567

📌 Username + Email + Password:
·ShadowPlayer228 example@mail.ru 123qwe

📌 Nome Completo + Data Nascita:
·Petrov Maxim Sergeevich 16/02/1995

📌 Telefono + Email + IP:
·+79002206090 example@gmail.com 192.168.1.1

📌 Hash + Email + Telefono:
·5f4dcc3b5aa765d61d8327deb882cf99 admin@gmail.com +79001112233

📌 Password + Username + Email:
·Qwerty123! ShadowPlayer example@protonmail.com

📌 Facebook ID + Telefono + Nome:
·1000123456789 +79003334455 Ivan Petrov

📌 Documento + Indirizzo + Nome:
·AA1234567 Via Roma 123 Mario Rossi
·123456789 Milano Luigi Bianchi

{translations[user_lang]['combine_what']}
·Email: example@
·Telefono: +39, +7, +44
·Nomi: Nome, Cognome, Completo
·Username: qualsiasi
·IP: IPv4
·Password: qualsiasi
·Hash: MD5, SHA1, SHA256
·Documenti: Carta ID, Passaporto, CF
·Indirizzi: Casa, Ufficio, Azienda
·Date: GG/MM/AAAA

{translations[user_lang]['mass_search']}
·/utf8 per istruzioni file
·Massimo 50 righe
·Formato UTF-8

💰 Crediti disponibili: {await self.get_user_balance(user_id)}
📊Ricerche effettuate: {await self.get_user_searches(user_id)}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        else:
            text = f"""📋 **Fully Functional Menu**

{translations[user_lang]['composite_examples']}

📌 Email + Phone + Name:
·example@gmail.com +79002206090 Petrov Ivan

📌 Name + City + Phone:
·Maxim Sergeevich Moscow +79001234567

📌 Username + Email + Password:
·ShadowPlayer228 example@mail.ru 123qwe

📌 Full Name + Birth Date:
·Petrov Maxim Sergeevich 16/02/1995

📌 Phone + Email + IP:
·+79002206090 example@gmail.com 192.168.1.1

📌 Hash + Email + Phone:
·5f4dcc3b5aa765d61d8327deb882cf99 admin@gmail.com +79001112233

📌 Password + Username + Email:
·Qwerty123! ShadowPlayer example@protonmail.com

📌 Facebook ID + Phone + Name:
·1000123456789 +79003334455 Ivan Petrov

📌 Document + Address + Name:
·AA1234567 Via Roma 123 Mario Rossi
·123456789 Milano Luigi Bianchi

{translations[user_lang]['combine_what']}
·Email: example@
·Phone: +39, +7, +44
·Names: Name, Surname, Full
·Username: any
·IP: IPv4
·Password: any
·Hash: MD5, SHA1, SHA256
·Documents: ID Card, Passport, Tax Code
·Addresses: Home, Office, Company
·Dates: DD/MM/YYYY

{translations[user_lang]['mass_search']}
·/utf8 for file instructions
·Maximum 50 lines
·UTF-8 format

💰 Available credits: {await self.get_user_balance(user_id)}
📊Searches performed: {await self.get_user_searches(user_id)}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
            
        keyboard = [[InlineKeyboardButton("🔙 Indietro" if user_lang == 'it' else "🔙 Back", 
                                        callback_data='back_to_main')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if update.callback_query:
            await update.callback_query.edit_message_text(
                text, 
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
        else:
            await update.message.reply_text(
                text, 
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
            
    async def show_balance(self, update: Update, context: CallbackContext):
        """Mostra il saldo"""
        user_id = update.effective_user.id
        user_lang = await self.get_user_language(user_id)
        
        balance = await self.get_user_balance(user_id)
        searches = await self.get_user_searches(user_id)
        
        now = datetime.now()
        data_italiana = now.strftime("%d/%m/%Y")
        
        if user_lang == 'it':
            text = f"""💎 **Il tuo Saldo**

💎 Saldo attuale: {balance} crediti
🔍Costo per ricerca: 2 crediti
📊Ricerche effettuate: {searches}
🎯Ricerche disponibili: {int(balance / 2)}

🛒 Per acquistare crediti: /buy
🔍Per una ricerca: invia qualsiasi dato

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        else:
            text = f"""💎 **Your Balance**

💎 Current balance: {balance} credits
🔍Cost per search: 2 credits
📊Searches performed: {searches}
🎯Available searches: {int(balance / 2)}

🛒 To buy credits: /buy
🔍For a search: send any data

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
            
        await update.message.reply_text(text, parse_mode='HTML')
        
    async def admin_stats(self, update: Update, context: CallbackContext):
        """Statistiche admin"""
        user_id = update.effective_user.id
        
        if user_id != ADMIN_ID:
            await update.message.reply_text("❌ Accesso negato.")
            return
            
        try:
            # Statistiche utenti
            users = await db.fetch_all("SELECT COUNT(*) FROM users")
            searches = await db.fetch_all("SELECT COUNT(*) FROM searches")
            credits = await db.fetch_all("SELECT SUM(balance) FROM users")
            
            total_users = users[0][0] if users else 0
            total_searches = searches[0][0] if searches else 0
            total_credits = credits[0][0] if credits and credits[0][0] else 0
            
            # Ultimi 5 utenti
            recent_users = await db.fetch_all(
                "SELECT user_id, username, registration_date FROM users ORDER BY registration_date DESC LIMIT 5"
            )
            
            text = f"""📊 **Statistiche Admin**

📊 Statistiche:
·👥 Utenti totali: {total_users}
·🔍 Ricerche totali: {total_searches}
·💎 Credit totali: {total_credits}

👥 Ultimi 5 utenti:"""
            
            for user in recent_users:
                if isinstance(user, tuple):
                    user_id = user[0]
                    username = user[1] or "N/A"
                    reg_date = user[2]
                else:
                    user_id = user['user_id']
                    username = user['username'] or "N/A"
                    reg_date = user['registration_date']
                    
                text += f"\n· {user_id} (@{username}) - {reg_date}"
                
            await update.message.reply_text(text, parse_mode='HTML')
            
        except Exception as e:
            logger.error(f"❌ Errore statistiche admin: {e}")
            await update.message.reply_text(f"❌ Errore: {e}")
            
    async def handle_callback(self, update: Update, context: CallbackContext):
        """Gestisce callback queries"""
        query = update.callback_query
        await query.answer()
        
        data = query.data
        
        if data == 'search':
            await self.show_search_menu(update, context)
        elif data == 'shop':
            await self.show_shop(update, context)
        elif data == 'settings':
            await self.show_settings(update, context)
        elif data == 'menu':
            await self.menu_completo(update, context)
        elif data == 'help':
            await self.show_help(update, context)
        elif data == 'back_to_main':
            await self.show_main_menu(update, context)
        elif data == 'language':
            await self.show_language_menu(update, context)
        elif data == 'profile':
            await self.show_profile(update, context)
        elif data == 'lang_it':
            await self.change_language(update, context, 'it')
        elif data == 'lang_en':
            await self.change_language(update, context, 'en')
        elif data.startswith('buy_'):
            # Gestione acquisto (da implementare)
            await query.answer("Funzionalità acquisto in sviluppo!")
            
    async def help_command(self, update: Update, context: CallbackContext):
        """Comando /help"""
        user_id = update.effective_user.id
        user_lang = await self.get_user_language(user_id)
        
        now = datetime.now()
        data_italiana = now.strftime("%d/%m/%Y")
        
        if user_lang == 'it':
            text = f"""🤖 **LeakosintBot - Guida Rapida**

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
·👤 Nome Cognote 🏙️ Città
·📄 AA1234567 🏠 Via Roma 123
·👤 Mario Rossi 📄 123456789

💎 SISTEMA CREDITI:
·🔍 1 ricerca = 2 crediti
·🎁 Partenza: 4 crediti gratis
·🛒 Ricarica: /buy

📈 STATISTICHE: /balance
📋MENU COMPLETO: /menu
🛒ACQUISTA: /buy

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        else:
            text = f"""🤖 **LeakosintBot - Quick Guide**

🔍 SEND:
·📧 Email: example@gmail.com
·📱 Phone: +393331234567
·👤 Name: Mario Rossi
·👥 Username: shadowplayer
·🌐 IP: 8.8.8.8
·🔐 Password: 123qwe
·🔑 Hash: 5f4dcc3b5aa765d61d8327deb882cf99
·📄 Document: AA1234567, 123456789
·🏠 Home address: Via Roma 123, Milano
·🏢 Work address: Office Via Torino 45

📊 SUPPORTED FORMATS:
·👤 Petrov 📱 79002206090
·👤 Maxim Sergeevich 🌐 127.0.0.1
·👤 Petrov Maxim Sergeevich 📅 16/02/1995
·👤 Username 📧 example@gmail.com
·👤 Name Surname 🏙️ City
·📄 AA1234567 🏠 Via Roma 123
·👤 Mario Rossi 📄 123456789

💎 CREDIT SYSTEM:
·🔍 1 search = 2 credits
·🎁 Start: 4 free credits
·🛒 Recharge: /buy

📈 STATISTICS: /balance
📋FULL MENU: /menu
🛒BUY: /buy

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
            
        await update.message.reply_text(text, parse_mode='HTML')
        
    async def utf8_instructions(self, update: Update, context: CallbackContext):
        """Istruzioni per file UTF-8"""
        user_id = update.effective_user.id
        user_lang = await self.get_user_language(user_id)
        
        now = datetime.now()
        data_italiana = now.strftime("%d/%m/%Y")
        
        if user_lang == 'it':
            text = f"""📋 **ISTRUZIONI RICERCA DI MASSA**

🔧 ISTRUZIONI PER FILE .txt:

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
+79002206090
Petrov Ivan
ShadowPlayer228
127.0.0.1
Petrov 79002206090
Maxim Sergeevich
example@mail.ru
AA1234567
Via Roma 123, Milano
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

💰 COSTO: 2 crediti per riga

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        else:
            text = f"""📋 **MASS SEARCH INSTRUCTIONS**

🔧 INSTRUCTIONS FOR .txt FILES:

1. 📝 Create a text file with:
· Encoding: UTF-8
· Extension: .txt
· One request per line

2. 💻 HOW TO SAVE AS UTF-8:
⚙️ Windows (Notepad):
· Open Notepad
· Write searches (one per line)
· File → Save As
· File name: "searches.txt"
· Type: "All files"
· Encoding: "UTF-8"

⚙️ Windows (Notepad++):
· Open Notepad++
· Write searches
· Encoding → Convert to UTF-8
· File → Save

⚙️ Mac/Linux (TextEdit/Terminal):
· Use terminal: nano/nvim
· Write searches
· Save as: UTF-8

3. 📋 EXAMPLE CONTENT:
example@gmail.com
+79002206090
Petrov Ivan
ShadowPlayer228
127.0.0.1
Petrov 79002206090
Maxim Sergeevich
example@mail.ru
AA1234567
Via Roma 123, Milano
Office Via Torino 45

4. ⚠️ WARNINGS:
· MAX 50 lines per file
· Only text (.txt)
· NO .doc, .pdf, .xlsx
· Correct encoding: UTF-8

5. 📤 UPLOAD:
· Use the 📎 icon in Telegram
· Select the .txt file
· Wait for processing

💰 COST: 2 credits per line

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
            
        await update.message.reply_text(text, parse_mode='HTML')
        
    async def handle_document(self, update: Update, context: CallbackContext):
        """Gestisce file document (per ricerca di massa)"""
        user_id = update.effective_user.id
        user_lang = await self.get_user_language(user_id)
        document = update.message.document
        
        # Verifica che sia un file .txt
        if not document.file_name.endswith('.txt'):
            if user_lang == 'it':
                text = "❌ Solo file .txt sono supportati. Usa /utf8 per istruzioni."
            else:
                text = "❌ Only .txt files are supported. Use /utf8 for instructions."
            await update.message.reply_text(text)
            return
            
        # Verifica saldo
        balance = await self.get_user_balance(user_id)
        
        # Scarica file
        file = await context.bot.get_file(document.file_id)
        file_bytes = await file.download_as_bytearray()
        
        now = datetime.now()
        data_italiana = now.strftime("%d/%m/%Y")
        
        if user_lang == 'it':
            wait_text = f"""📄 **Elaborazione file in corso...**

📄 File: {document.file_name}
🔍Lettura righe...

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        else:
            wait_text = f"""📄 **File processing in progress...**

📄 File: {document.file_name}
🔍Reading lines...

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
            
        msg = await update.message.reply_text(wait_text, parse_mode='HTML')
        
        try:
            # Prova diverse codifiche
            encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']
            lines = []
            
            for encoding in encodings:
                try:
                    content = file_bytes.decode(encoding)
                    lines = [line.strip() for line in content.split('\n') if line.strip()]
                    break
                except UnicodeDecodeError:
                    continue
                    
            if not lines:
                if user_lang == 'it':
                    error_text = f"""📄 File: {document.file_name}
⚠️Il file non è in formato UTF-8

📌 Usa un editor che supporta UTF-8:
· Notepad++ (Windows)
· Sublime Text
· Visual Studio Code

🔧 Salva come: "UTF-8 senza BOM"

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
                else:
                    error_text = f"""📄 File: {document.file_name}
⚠️File is not in UTF-8 format

📌 Use an editor that supports UTF-8:
· Notepad++ (Windows)
· Sublime Text
· Visual Studio Code

🔧 Save as: "UTF-8 without BOM"

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
                await msg.edit_text(error_text)
                return
                
            # Limita a 50 righe
            if len(lines) > 50:
                lines = lines[:50]
                
            if not lines:
                if user_lang == 'it':
                    error_text = f"""📄 File: {document.file_name}
⚠️Il file non contiene righe valide

📌 Formato richiesto:
· Una query per riga
· Esempio: example@gmail.com +79002206090 Petrov Ivan

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
                else:
                    error_text = f"""📄 File: {document.file_name}
⚠️File does not contain valid lines

📌 Required format:
· One query per line
· Example: example@gmail.com +79002206090 Petrov Ivan

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
                await msg.edit_text(error_text)
                return
                
            # Calcola costo totale
            total_cost = len(lines) * 2
            
            if balance < total_cost:
                if user_lang == 'it':
                    error_text = f"""📄 File: {document.file_name}
📊Righe: {len(lines)}
💰Costo totale: {total_cost} crediti
💳Saldo attuale: {balance} crediti

🔢 Ti servono: {total_cost - balance} crediti in più
🛒Usa /buy per acquistare crediti

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
                else:
                    error_text = f"""📄 File: {document.file_name}
📊Lines: {len(lines)}
💰Total cost: {total_cost} credits
💳Current balance: {balance} credits

🔢 You need: {total_cost - balance} more credits
🛒Use /buy to purchase credits

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
                await msg.edit_text(error_text)
                return
                
            # Processa le righe
            success_count = 0
            error_count = 0
            
            for i, line in enumerate(lines, 1):
                try:
                    # Simula ricerca (in produzione, chiama la vera funzione di ricerca)
                    search_type = await self.analyze_query(line)
                    
                    # Salva ricerca
                    await db.execute(
                        """INSERT INTO searches (user_id, query, type, results, timestamp)
                        VALUES (?, ?, ?, ?, datetime('now'))""",
                        [user_id, line, search_type, 'processed']
                    )
                    
                    success_count += 1
                    
                except Exception as e:
                    logger.error(f"Errore elaborazione riga {i}: {e}")
                    error_count += 1
                    
                # Aggiorna progresso ogni 5 righe
                if i % 5 == 0 or i == len(lines):
                    if user_lang == 'it':
                        progress_text = f"""📄 File: {document.file_name}
📊Progresso: {i}/{len(lines)} righe
✅Successo: {success_count}
❌Errori: {error_count}

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
                    else:
                        progress_text = f"""📄 File: {document.file_name}
📊Progress: {i}/{len(lines)} lines
✅Success: {success_count}
❌Errors: {error_count}

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
                    await msg.edit_text(progress_text)
                    
            # Aggiorna saldo
            await self.update_user_balance(user_id, -total_cost)
            
            # Risultati finali
            if user_lang == 'it':
                final_text = f"""✅ **Elaborazione completata**

📄 File: {document.file_name}
📊Righe processate: {len(lines)}
✅Ricerche riuscite: {success_count}
❌Errori: {error_count}
💰Costo totale: {total_cost} crediti
💳Nuovo saldo: {await self.get_user_balance(user_id)} crediti

📝 RISULTATI DETTAGLIATI: """
            else:
                final_text = f"""✅ **Processing completed**

📄 File: {document.file_name}
📊Lines processed: {len(lines)}
✅Successful searches: {success_count}
❌Errors: {error_count}
💰Total cost: {total_cost} credits
💳New balance: {await self.get_user_balance(user_id)} credits

📝 DETAILED RESULTS: """
                
            # Aggiungi primi 5 risultati
            recent_searches = await db.fetch_all(
                "SELECT query, type FROM searches WHERE user_id = ? ORDER BY id DESC LIMIT 5",
                [user_id]
            )
            
            for j, search in enumerate(recent_searches, 1):
                if isinstance(search, tuple):
                    query = search[0]
                    search_type = search[1]
                else:
                    query = search['query']
                    search_type = search['type']
                    
                final_text += f"\n{j}. {query} ({search_type})"
                
            final_text += f"""\n\n⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
            
            await msg.edit_text(final_text, parse_mode='HTML')
            
        except Exception as e:
            logger.error(f"❌ Errore elaborazione file: {e}")
            
            if user_lang == 'it':
                error_text = f"""📄 File: {document.file_name}
⚠️Errore: {str(e)[:100]}

📌 Assicurati che:

1. Il file sia in formato .txt
2. La codifica sia UTF-8
3. Non superi le 50 righe

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
            else:
                error_text = f"""📄 File: {document.file_name}
⚠️Error: {str(e)[:100]}

📌 Make sure:

1. File is .txt format
2. Encoding is UTF-8
3. Doesn't exceed 50 lines

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
            try:
                await msg.edit_text(error_text)
            except:
                await update.message.reply_text(error_text)

# ==================== FLASK APP PER RENDER ====================

app = Flask(__name__)

@app.route('/')
def index():
    return '🤖 LeakosintBot is running!'

@app.route('/health')
def health():
    return 'OK', 200

# ==================== FUNZIONI PER CARICARE DATI NEL DATABASE ====================

async def load_facebook_leaks_data():
    """Carica dati Facebook leaks nel database"""
    try:
        facebook_leaks_files = [
            'facebook_leaks.csv',
            'data/facebook_leaks.csv',
            'facebook_data.csv',
            'leaks/facebook_2021.csv'
        ]
        
        for file_path in facebook_leaks_files:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    header = next(reader, None)
                    
                    count = 0
                    for row in reader:
                        if len(row) >= 12:
                            await db.execute('''INSERT OR IGNORE INTO facebook_leaks 
                                       (phone, facebook_id, name, surname, gender, birth_date,
                                        city, country, company, relationship_status, leak_date)
                                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', row[:11])
                            count += 1
                    
                    logger.info(f"✅ Facebook leaks data loaded from {file_path}: {count} records")
                    return True
        
        logger.info("⚠️ No Facebook leaks data file found, creating sample data")
        
        sample_data = [
            ('+393331234567', '1000123456789', 'Mario', 'Rossi', 'Male', '1985-03-15',
             'Milano', 'Italia', 'Tech Company', 'Single', '2021-04-22'),
            ('+393332345678', '1000234567890', 'Luigi', 'Bianchi', 'Male', '1990-07-22',
             'Roma', 'Italia', 'Marketing Agency', 'In a relationship', '2021-04-22'),
            ('+393333456789', '1000345678901', 'Giuseppe', 'Verdi', 'Male', '1982-11-30',
             'Firenze', 'Italia', 'Design Studio', 'Married', '2021-04-22')
        ]
        
        for data in sample_data:
            await db.execute('''INSERT OR IGNORE INTO facebook_leaks 
                       (phone, facebook_id, name, surname, gender, birth_date,
                        city, country, company, relationship_status, leak_date)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', data)
        
        logger.info(f"✅ Sample Facebook leaks data created: {len(sample_data)} records")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error loading Facebook leaks: {e}")
        return False

async def load_addresses_documents_data():
    """Carica dati documenti e indirizzi nel database"""
    try:
        # PRIMA assicurati che la tabella esista
        await db.execute('''CREATE TABLE IF NOT EXISTS addresses_documents (
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
        
        logger.info("✅ Tabella addresses_documents verificata/creata")
        
        addresses_files = [
            'addresses_documents.csv',
            'data/addresses.csv',
            'documents_data.csv',
            'leaks/addresses_leak.csv'
        ]
        
        for file_path in addresses_files:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    header = next(reader, None)
                    
                    count = 0
                    for row in reader:
                        if len(row) >= 10:
                            await db.execute('''INSERT OR IGNORE INTO addresses_documents 
                                       (document_number, document_type, full_name, home_address, work_address, 
                                        city, country, phone, email, source)
                                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', row[:10])
                            count += 1
                    
                    logger.info(f"✅ Addresses/documents data loaded from {file_path}: {count} records")
                    return True
        
        logger.info("⚠️ No addresses/documents data file found, creating sample data")
        
        sample_data = [
            ('AA1234567', 'Carta Identità', 'Mario Rossi', 'Via Roma 123', 'Ufficio Via Torino 45', 
             'Milano', 'Italia', '+393331234567', 'mario.rossi@email.com', 'Sample Database'),
            ('123456789', 'Codice Fiscale', 'Luigi Bianchi', 'Corso Vittorio 78', 'Azienda Via Milano 10',
             'Roma', 'Italia', '+393332345678', 'luigi.bianchi@email.com', 'Sample Database'),
            ('BB9876543', 'Passaporto', 'Giuseppe Verdi', 'Piazza Duomo 1', 'Sede Via Garibaldi 25',
             'Firenze', 'Italia', '+393333456789', 'giuseppe.verdi@email.com', 'Sample Database')
        ]
        
        for data in sample_data:
            await db.execute('''INSERT OR IGNORE INTO addresses_documents 
                       (document_number, document_type, full_name, home_address, work_address, 
                        city, country, phone, email, source)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', data)
        
        logger.info(f"✅ Sample addresses/documents data created: {len(sample_data)} records")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error loading addresses/documents: {e}")
        return False

async def verify_database_tables():
    """Verifica che tutte le tabelle esistano nel database"""
    try:
        tables = [
            ('users', '''CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                balance INTEGER DEFAULT 4,
                searches INTEGER DEFAULT 0,
                registration_date TEXT DEFAULT CURRENT_TIMESTAMP,
                subscription_type TEXT DEFAULT 'free',
                last_active TEXT DEFAULT CURRENT_TIMESTAMP,
                language TEXT DEFAULT 'en'
            )'''),
            
            ('searches', '''CREATE TABLE IF NOT EXISTS searches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                query TEXT,
                type TEXT,
                results TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )'''),
            
            ('breach_data', '''CREATE TABLE IF NOT EXISTS breach_data (
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
            )'''),
            
            ('facebook_leaks', '''CREATE TABLE IF NOT EXISTS facebook_leaks (
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
            )'''),
            
            ('addresses_documents', '''CREATE TABLE IF NOT EXISTS addresses_documents (
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
        ]
        
        for table_name, create_sql in tables:
            try:
                await db.execute(create_sql)
                logger.info(f"✅ Tabella {table_name} verificata/creata")
            except Exception as e:
                logger.error(f"❌ Errore creazione tabella {table_name}: {e}")
        
        logger.info("✅ Tutte le tabelle database verificate")
        return True
        
    except Exception as e:
        logger.error(f"❌ Errore verifica database: {e}")
        return False

# ==================== AVVIO BOT ====================

async def setup_bot():
    """Configura il bot con tutti gli handler"""
    logger.info("📥 Initializing database...")
    await db.initialize()
    
    logger.info("🔍 Verificando tabelle database...")
    await verify_database_tables()
    
    logger.info("📥 Loading Facebook leaks data...")
    await load_facebook_leaks_data()
    
    logger.info("📥 Loading addresses/documents data...")
    await load_addresses_documents_data()
    
    # Crea istanza bot
    bot = LeakosintBot()
    
    # Crea application
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Aggiungi handler
    application.add_handler(CommandHandler("start", bot.start))
    application.add_handler(CommandHandler("help", bot.help_command))
    application.add_handler(CommandHandler("balance", bot.show_balance))
    application.add_handler(CommandHandler("menu", bot.menu_completo))
    application.add_handler(CommandHandler("utf8", bot.utf8_instructions))
    application.add_handler(CommandHandler("admin", bot.admin_stats))
    
    # Handler per callback queries
    application.add_handler(CallbackQueryHandler(bot.handle_callback))
    
    # Handler per documenti (ricerche di massa)
    application.add_handler(MessageHandler(filters.Document.ALL, bot.handle_document))
    
    # Handler per messaggi di testo (ricerche normali)
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_message))
    
    return application

def start_polling():
    """Avvia il bot in modalità polling (per sviluppo)"""
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    application = loop.run_until_complete(setup_bot())
    
    logger.info("🤖 Bot avviato in modalità polling...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

def start_webhook():
    """Avvia il bot in modalità webhook (per Render)"""
    import asyncio
    import threading
    
    # Avvia Flask in un thread separato
    def run_flask():
        flask_app = Flask(__name__)
        
        @flask_app.route('/')
        def index():
            return '🤖 LeakosintBot is running!'
        
        @flask_app.route('/health')
        def health():
            return 'OK', 200
        
        port = int(os.environ.get('PORT', 8080))
        flask_app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False, threaded=True)
    
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    logger.info(f"✅ Server Flask avviato sulla porta {os.environ.get('PORT', 8080)}")
    
    # Aspetta che Flask sia avviato
    import time
    time.sleep(3)
    
    # Avvia il bot webhook
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    application = loop.run_until_complete(setup_bot())
    
    # Configura webhook per Render
    render_service_name = os.environ.get('RENDER_SERVICE_NAME', 'telegram-bot-osint')
    webhook_url = f"https://{render_service_name}.onrender.com"
    
    logger.info(f"🚀 Avvio bot webhook su Render")
    logger.info(f"🌐 Webhook URL: {webhook_url}/{BOT_TOKEN}")
    
    application.run_webhook(
        listen="0.0.0.0",
        port=8443,
        url_path=BOT_TOKEN,
        webhook_url=f"{webhook_url}/{BOT_TOKEN}",
        drop_pending_updates=True
    )

def main():
    """Funzione principale"""
    if os.environ.get('RENDER') or os.environ.get('WEBHOOK_URL'):
        logger.info("🎯 Modalità Render attivata")
        start_webhook()
    else:
        logger.info("🏠 Modalità sviluppo attivata")
        start_polling()

if __name__ == '__main__':
    main()
