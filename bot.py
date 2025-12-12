import os
import logging
import sys
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

# Configurazione logging avanzata
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('leakosint.log')
    ]
)
logger = logging.getLogger(__name__)

# ==================== CONFIGURAZIONE API ====================
BOT_TOKEN = "8464402911:AAGhLLYRF2HOf6DTCXsbK7Ry6kHFSB9kPnw"
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

# ==================== TRADUZIONI ====================
translations = {
    'it': {
        'processing': 'Analisi in corso...',
        'insufficient_credits': '❌ Crediti insufficienti! Usa /buy per acquistare crediti.',
        'credits_used': '💰 Crediti usati',
        'balance': '💳 Saldo'
    },
    'en': {
        'processing': 'Processing...',
        'insufficient_credits': '❌ Insufficient credits! Use /buy to buy credits.',
        'credits_used': '💰 Credits used',
        'balance': '💳 Balance'
    }
}

# ==================== CLASSI PRINCIPALI ====================

class LeakSearchAPI:
    """API per ricerche nei data breach reali"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
    
    def is_email(self, text: str) -> bool:
        """Verifica se il testo è un'email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, text))
    
    def is_phone(self, text: str) -> bool:
        """Verifica se il testo è un numero di telefono"""
        # Pulisci il testo
        cleaned = re.sub(r'[^\d+]', '', text)
        return len(cleaned) >= 8 and len(cleaned) <= 15
    
    def is_ip(self, text: str) -> bool:
        """Verifica se il testo è un IP"""
        pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(pattern, text):
            parts = text.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        return False
    
    def is_hash(self, text: str) -> bool:
        """Verifica se il testo è un hash"""
        patterns = [
            r'^[a-f0-9]{32}$',  # MD5
            r'^[a-f0-9]{40}$',  # SHA1
            r'^[a-f0-9]{64}$'   # SHA256
        ]
        return any(re.match(pattern, text.lower()) for pattern in patterns)
    
    def is_document_number(self, text: str) -> bool:
        """Verifica se il testo è un numero di documento"""
        # Pattern per documenti italiani ed europei
        patterns = [
            r'^[A-Z]{2}\d{7}$',  # Carta identità italiana (AA1234567)
            r'^\d{9}$',          # Codice fiscale (9 cifre)
            r'^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$',  # Codice fiscale completo
            r'^[A-Z]{2}\d{5}[A-Z]{2}\d{4}$',  # Passaporto italiano (AA12345AA1234)
            r'^[A-Z]{1,2}\d{6,8}$',  # Patente di guida
            r'^\d{10,12}$',          # Documenti con solo numeri
            r'^[A-Z]{3}\d{6}[A-Z]$'  # Altri documenti
        ]
        return any(re.match(pattern, text, re.IGNORECASE) for pattern in patterns)
    
    def is_address(self, text: str) -> bool:
        """Verifica se il testo è un indirizzo"""
        # Controlla se contiene parole tipiche di indirizzi
        address_indicators = [
            'via', 'viale', 'piazza', 'corso', 'largo', 'vicolo',
            'street', 'avenue', 'boulevard', 'road', 'lane', 'drive',
            'strada', 'avenida', 'calle', 'rua', 'straße'
        ]
        
        # Controlla se contiene numero civico
        has_number = bool(re.search(r'\d+', text))
        
        # Controlla indicatori di indirizzo
        has_indicator = any(indicator in text.lower() for indicator in address_indicators)
        
        return has_number or has_indicator
    
    # ============ NUOVE FUNZIONI PER DOCUMENTI E INDIRIZZI ============
    
    async def search_document(self, document_number: str) -> Dict:
        """Ricerca numero documento in data breach"""
        results = []
        
        # Normalizza il documento
        doc_clean = document_number.upper().strip()
        
        # Dehashed API per documenti
        if DEHASHED_API_KEY:
            try:
                auth = base64.b64encode(f"{DEHASHED_EMAIL}:{DEHASHED_API_KEY}".encode()).decode()
                headers = {'Authorization': f'Basic {auth}'}
                response = self.session.get(
                    f'https://api.dehashed.com/search?query={quote_plus(doc_clean)}',
                    headers=headers, timeout=15
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('entries'):
                        for entry in data['entries'][:10]:
                            results.append({
                                'source': 'Dehashed',
                                'database': entry.get('database_name', 'Unknown'),
                                'document': entry.get('id_number') or entry.get('document') or doc_clean,
                                'full_name': f"{entry.get('name', '')} {entry.get('surname', '')}".strip(),
                                'address': entry.get('address'),
                                'phone': entry.get('phone'),
                                'email': entry.get('email'),
                                'date': entry.get('obtained')
                            })
            except Exception as e:
                logger.error(f"Dehashed document error: {e}")
        
        # Ricerca nel database locale per documenti
        c.execute('''SELECT * FROM addresses_documents WHERE 
                    document_number LIKE ? OR document_number = ? LIMIT 10''',
                 (f'%{doc_clean}%', doc_clean))
        db_results = c.fetchall()
        
        for row in db_results:
            results.append({
                'source': 'Local Database',
                'document_type': row[2],
                'document_number': row[1],
                'full_name': row[3],
                'home_address': row[4],
                'work_address': row[5],
                'city': row[6],
                'phone': row[8],
                'email': row[9]
            })
        
        # Snusbase API
        if SNUSBASE_API_KEY:
            try:
                headers = {'Auth': SNUSBASE_API_KEY}
                data = {'terms': [doc_clean], 'types': ['id']}
                response = self.session.post(
                    'https://api.snusbase.com/v3/search',
                    headers=headers, json=data, timeout=20
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('results'):
                        for entry in data['results'][:10]:
                            results.append({
                                'source': 'Snusbase',
                                'database': entry.get('database', 'Unknown'),
                                'document': entry.get('id_number') or doc_clean,
                                'name': entry.get('name'),
                                'email': entry.get('email'),
                                'phone': entry.get('phone')
                            })
            except Exception as e:
                logger.error(f"Snusbase document error: {e}")
        
        return {'found': len(results) > 0, 'results': results, 'count': len(results)}
    
    async def search_home_address(self, address: str) -> Dict:
        """Ricerca indirizzo di casa in data breach"""
        results = []
        
        # Normalizza l'indirizzo
        address_clean = address.strip()
        
        # Dehashed API per indirizzi
        if DEHASHED_API_KEY:
            try:
                auth = base64.b64encode(f"{DEHASHED_EMAIL}:{DEHASHED_API_KEY}".encode()).decode()
                headers = {'Authorization': f'Basic {auth}'}
                response = self.session.get(
                    f'https://api.dehashed.com/search?query={quote_plus(address_clean)}+home',
                    headers=headers, timeout=15
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('entries'):
                        for entry in data['entries'][:10]:
                            if entry.get('address'):
                                results.append({
                                    'source': 'Dehashed',
                                    'database': entry.get('database_name', 'Unknown'),
                                    'address': entry.get('address'),
                                    'full_name': f"{entry.get('name', '')} {entry.get('surname', '')}".strip(),
                                    'phone': entry.get('phone'),
                                    'email': entry.get('email'),
                                    'type': 'home',
                                    'date': entry.get('obtained')
                                })
            except Exception as e:
                logger.error(f"Dehashed home address error: {e}")
        
        # Ricerca nel database locale per indirizzi
        c.execute('''SELECT * FROM addresses_documents WHERE 
                    home_address LIKE ? OR address LIKE ? LIMIT 10''',
                 (f'%{address_clean}%', f'%{address_clean}%'))
        db_results = c.fetchall()
        
        for row in db_results:
            if row[4]:  # home_address
                results.append({
                    'source': 'Local Database',
                    'address_type': 'home',
                    'address': row[4],
                    'full_name': row[3],
                    'document_number': row[1],
                    'city': row[6],
                    'phone': row[8],
                    'email': row[9]
                })
        
        # Cerca in Facebook leaks per città/paese
        c.execute('''SELECT * FROM facebook_leaks WHERE 
                    city LIKE ? OR country LIKE ? LIMIT 10''',
                 (f'%{address_clean}%', f'%{address_clean}%'))
        fb_results = c.fetchall()
        
        for row in fb_results:
            results.append({
                'source': 'Facebook Leak 2021',
                'address_type': 'city/country',
                'city': row[7],
                'country': row[8],
                'full_name': f"{row[3]} {row[4]}",
                'phone': row[1],
                'facebook_id': row[2],
                'company': row[9]
            })
        
        return {'found': len(results) > 0, 'results': results, 'count': len(results)}
    
    async def search_work_address(self, address: str) -> Dict:
        """Ricerca indirizzo lavorativo in data breach"""
        results = []
        
        # Normalizza l'indirizzo
        address_clean = address.strip()
        
        # Dehashed API per indirizzi lavorativi
        if DEHASHED_API_KEY:
            try:
                auth = base64.b64encode(f"{DEHASHED_EMAIL}:{DEHASHED_API_KEY}".encode()).decode()
                headers = {'Authorization': f'Basic {auth}'}
                response = self.session.get(
                    f'https://api.dehashed.com/search?query={quote_plus(address_clean)}+work+company',
                    headers=headers, timeout=15
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('entries'):
                        for entry in data['entries'][:10]:
                            if entry.get('company') or entry.get('work_address'):
                                results.append({
                                    'source': 'Dehashed',
                                    'database': entry.get('database_name', 'Unknown'),
                                    'company': entry.get('company'),
                                    'address': entry.get('address') or entry.get('work_address'),
                                    'full_name': f"{entry.get('name', '')} {entry.get('surname', '')}".strip(),
                                    'phone': entry.get('phone'),
                                    'email': entry.get('email'),
                                    'type': 'work',
                                    'date': entry.get('obtained')
                                })
            except Exception as e:
                logger.error(f"Dehashed work address error: {e}")
        
        # Ricerca nel database locale per indirizzi lavorativi
        c.execute('''SELECT * FROM addresses_documents WHERE 
                    work_address LIKE ? OR company LIKE ? LIMIT 10''',
                 (f'%{address_clean}%', f'%{address_clean}%'))
        db_results = c.fetchall()
        
        for row in db_results:
            if row[5]:  # work_address
                results.append({
                    'source': 'Local Database',
                    'address_type': 'work',
                    'company': row[10] if len(row) > 10 else None,
                    'address': row[5],
                    'full_name': row[3],
                    'document_number': row[1],
                    'city': row[6],
                    'phone': row[8],
                    'email': row[9]
                })
        
        # Cerca in Facebook leaks per aziende
        c.execute('''SELECT * FROM facebook_leaks WHERE 
                    company LIKE ? LIMIT 10''',
                 (f'%{address_clean}%',))
        fb_results = c.fetchall()
        
        for row in fb_results:
            if row[9]:  # company
                results.append({
                    'source': 'Facebook Leak 2021',
                    'address_type': 'company',
                    'company': row[9],
                    'full_name': f"{row[3]} {row[4]}",
                    'phone': row[1],
                    'facebook_id': row[2],
                    'city': row[7],
                    'country': row[8]
                })
        
        # Hunter API per aziende (se disponibile)
        if HUNTER_API_KEY:
            try:
                response = self.session.get(
                    f'https://api.hunter.io/v2/domain-search?company={quote_plus(address_clean)}&api_key={HUNTER_API_KEY}',
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('data', {}).get('emails'):
                        for email in data['data']['emails'][:5]:
                            results.append({
                                'source': 'Hunter.io',
                                'company': address_clean,
                                'email': email.get('value'),
                                'name': email.get('first_name', '') + ' ' + email.get('last_name', ''),
                                'position': email.get('position'),
                                'type': 'work_email'
                            })
            except Exception as e:
                logger.error(f"Hunter work address error: {e}")
        
        return {'found': len(results) > 0, 'results': results, 'count': len(results)}
    
    # ============ FUNZIONI ESISTENTI (TUTTE PRESERVATE) ============
    
    async def search_email(self, email: str) -> Dict:
        """Ricerca email in data breach"""
        results = []
        
        # HIBP API
        if HIBP_API_KEY:
            try:
                headers = {'hibp-api-key': HIBP_API_KEY}
                response = self.session.get(
                    f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
                    headers=headers, timeout=10
                )
                if response.status_code == 200:
                    breaches = response.json()
                    for breach in breaches:
                        results.append({
                            'source': 'HIBP',
                            'breach': breach['Name'],
                            'date': breach.get('BreachDate'),
                            'data_classes': breach.get('DataClasses', []),
                            'description': breach.get('Description', '')
                        })
            except Exception as e:
                logger.error(f"HIBP error: {e}")
        
        # Dehashed API
        if DEHASHED_API_KEY:
            try:
                auth = base64.b64encode(f"{DEHASHED_EMAIL}:{DEHASHED_API_KEY}".encode()).decode()
                headers = {'Authorization': f'Basic {auth}'}
                response = self.session.get(
                    f'https://api.dehashed.com/search?query={quote_plus(email)}',
                    headers=headers, timeout=15
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('entries'):
                        for entry in data['entries'][:20]:
                            results.append({
                                'source': 'Dehashed',
                                'database': entry.get('database_name', 'Unknown'),
                                'email': entry.get('email'),
                                'password': entry.get('password'),
                                'hash': entry.get('hashed_password'),
                                'date': entry.get('obtained')
                            })
            except Exception as e:
                logger.error(f"Dehashed error: {e}")
        
        # Snusbase API
        if SNUSBASE_API_KEY:
            try:
                headers = {'Auth': SNUSBASE_API_KEY}
                data = {'terms': [email], 'types': ['email']}
                response = self.session.post(
                    'https://api.snusbase.com/v3/search',
                    headers=headers, json=data, timeout=20
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('results'):
                        for entry in data['results'][:15]:
                            results.append({
                                'source': 'Snusbase',
                                'database': entry.get('database', 'Unknown'),
                                'email': entry.get('email'),
                                'password': entry.get('password'),
                                'hash': entry.get('hash')
                            })
            except Exception as e:
                logger.error(f"Snusbase error: {e}")
        
        return {'found': len(results) > 0, 'results': results, 'count': len(results)}
    
    async def search_phone(self, phone: str) -> Dict:
        """Ricerca numero telefono in data breach"""
        results = []
        
        # Normalizza numero
        phone_clean = re.sub(r'[^\d+]', '', phone)
        
        # Dehashed per telefono
        if DEHASHED_API_KEY:
            try:
                auth = base64.b64encode(f"{DEHASHED_EMAIL}:{DEHASHED_API_KEY}".encode()).decode()
                headers = {'Authorization': f'Basic {auth}'}
                response = self.session.get(
                    f'https://api.dehashed.com/search?query={quote_plus(phone_clean)}',
                    headers=headers, timeout=15
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('entries'):
                        for entry in data['entries'][:15]:
                            results.append({
                                'source': 'Dehashed',
                                'database': entry.get('database_name', 'Unknown'),
                                'phone': entry.get('phone'),
                                'email': entry.get('email'),
                                'name': entry.get('name'),
                                'address': entry.get('address'),
                                'date': entry.get('obtained')
                            })
            except Exception as e:
                logger.error(f"Dehashed phone error: {e}")
        
        # Ricerca nel database Facebook leaks locale
        c.execute('''SELECT * FROM facebook_leaks WHERE phone LIKE ? LIMIT 10''',
                 (f'%{phone_clean[-10:]}%',))
        db_results = c.fetchall()
        
        for row in db_results:
            results.append({
                'source': 'Facebook Leak 2021',
                'phone': row[1],
                'facebook_id': row[2],
                'name': f"{row[3]} {row[4]}",
                'gender': row[5],
                'birth_date': row[6],
                'city': row[7],
                'country': row[8],
                'company': row[9]
            })
        
        # LeakCheck API
        if LEAKCHECK_API_KEY:
            try:
                params = {'key': LEAKCHECK_API_KEY, 'type': 'phone', 'query': phone_clean}
                response = self.session.get(
                    'https://leakcheck.io/api/public',
                    params=params, timeout=15
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success') and data.get('found'):
                        for result in data.get('result', [])[:10]:
                            results.append({
                                'source': 'LeakCheck',
                                'line': result.get('line', ''),
                                'sources': result.get('sources', [])
                            })
            except Exception as e:
                logger.error(f"LeakCheck error: {e}")
        
        return {'found': len(results) > 0, 'results': results, 'count': len(results)}
    
    async def search_username(self, username: str) -> Dict:
        """Ricerca username su social media e data breach"""
        social_results = []
        breach_results = []
        
        # Ricerca social media
        social_platforms = [
            ('📸 Instagram', f'https://instagram.com/{username}'),
            ('📘 Facebook', f'https://facebook.com/{username}'),
            ('🐦 Twitter', f'https://twitter.com/{username}'),
            ('💻 GitHub', f'https://github.com/{username}'),
            ('👽 Reddit', f'https://reddit.com/user/{username}'),
            ('📱 Telegram', f'https://t.me/{username}'),
            ('🔵 VKontakte', f'https://vk.com/{username}')
        ]
        
        for platform, url in social_platforms:
            try:
                response = self.session.get(url, timeout=5, allow_redirects=False)
                if response.status_code in [200, 301, 302]:
                    social_results.append({
                        'platform': platform,
                        'url': url,
                        'exists': True
                    })
            except:
                continue
        
        # Ricerca in data breach
        if DEHASHED_API_KEY:
            try:
                auth = base64.b64encode(f"{DEHASHED_EMAIL}:{DEHASHED_API_KEY}".encode()).decode()
                headers = {'Authorization': f'Basic {auth}'}
                response = self.session.get(
                    f'https://api.dehashed.com/search?query={quote_plus(username)}',
                    headers=headers, timeout=15
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('entries'):
                        for entry in data['entries'][:10]:
                            breach_results.append({
                                'source': 'Dehashed',
                                'username': entry.get('username'),
                                'email': entry.get('email'),
                                'password': entry.get('password'),
                                'date': entry.get('obtained')
                            })
            except Exception as e:
                logger.error(f"Dehashed username error: {e}")
        
        return {
            'social': social_results,
            'breach': breach_results,
            'social_count': len(social_results),
            'breach_count': len(breach_results)
        }
    
    async def search_name(self, name: str) -> Dict:
        """Ricerca per nome e cognome"""
        results = []
        
        # Split nome e cognome
        parts = name.split()
        if len(parts) >= 2:
            first_name, last_name = parts[0], parts[1]
            
            # Ricerca nel database Facebook leaks
            c.execute('''SELECT * FROM facebook_leaks WHERE 
                        (name LIKE ? OR surname LIKE ?) LIMIT 15''',
                     (f'%{first_name}%', f'%{last_name}%'))
            db_results = c.fetchall()
            
            for row in db_results:
                results.append({
                    'source': 'Facebook Leak 2021',
                    'phone': row[1],
                    'facebook_id': row[2],
                    'name': f"{row[3]} {row[4]}",
                    'gender': row[5],
                    'birth_date': row[6],
                    'city': row[7],
                    'country': row[8],
                    'company': row[9]
                })
        
        return {'found': len(results) > 0, 'results': results, 'count': len(results)}
    
    async def search_ip(self, ip: str) -> Dict:
        """Ricerca informazioni IP - VERSIONE CORRETTA"""
        info = {}
        
        logger.info(f"🌐 Ricerca IP: {ip}")
        
        # 1. IPInfo
        if IPINFO_API_KEY:
            logger.info(f"📡 Usando IPInfo API (key length: {len(IPINFO_API_KEY)})")
            try:
                response = self.session.get(
                    f'https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}',
                    timeout=15
                )
                logger.info(f"IPInfo Status: {response.status_code}")
                if response.status_code == 200:
                    info['ipinfo'] = response.json()
                else:
                    logger.warning(f"IPInfo error: HTTP {response.status_code}")
            except Exception as e:
                logger.error(f"IPInfo error: {e}")
        else:
            logger.warning("IPINFO_API_KEY non configurata")
        
        # 2. AbuseIPDB
        if ABUSEIPDB_KEY:
            logger.info(f"🛡️ Usando AbuseIPDB API")
            try:
                headers = {'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'}
                params = {'ipAddress': ip, 'maxAgeInDays': 90}
                response = self.session.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers=headers, params=params, timeout=15
                )
                logger.info(f"AbuseIPDB Status: {response.status_code}")
                if response.status_code == 200:
                    info['abuseipdb'] = response.json().get('data', {})
                elif response.status_code == 401:
                    logger.error("AbuseIPDB: API Key non valida")
                else:
                    logger.warning(f"AbuseIPDB error: HTTP {response.status_code}")
            except Exception as e:
                logger.error(f"AbuseIPDB error: {e}")
        else:
            logger.warning("ABUSEIPDB_KEY non configurata")
        
        # 3. Shodan - CONTROLLO MIGLIORATO
        if SHODAN_API_KEY:
            logger.info(f"🔓 Usando Shodan API (key: {SHODAN_API_KEY[:10]}...)")
            try:
                # Prima verifica che l'IP sia valido
                api = shodan.Shodan(SHODAN_API_KEY)
                
                # Test della API key
                try:
                    # Prova a fare una ricerca semplice
                    test_info = api.host('8.8.8.8')
                    logger.info("✅ Shodan API key funzionante")
                    
                    # Ora cerca l'IP richiesto
                    shodan_info = api.host(ip)
                    info['shodan'] = {
                        'ports': shodan_info.get('ports', []),
                        'hostnames': shodan_info.get('hostnames', []),
                        'org': shodan_info.get('org', ''),
                        'isp': shodan_info.get('isp', ''),
                        'vulns': shodan_info.get('vulns', [])
                    }
                except shodan.APIError as e:
                    error_msg = str(e)
                    logger.error(f"Shodan API Error: {error_msg}")
                    if '403' in error_msg:
                        info['shodan_error'] = "❌ API Key non valida o scaduta"
                    elif '404' in error_msg:
                        info['shodan_error'] = "IP non trovato in Shodan"
                    else:
                        info['shodan_error'] = f"Errore: {error_msg[:50]}"
                except Exception as e:
                    logger.error(f"Shodan general error: {e}")
                    info['shodan_error'] = "Errore di connessione"
                    
            except Exception as e:
                logger.error(f"Shodan setup error: {e}")
                info['shodan_error'] = "Errore configurazione Shodan"
        else:
            logger.warning("SHODAN_API_KEY non configurata")
        
        return info
    
    async def search_password(self, password: str) -> Dict:
        """Ricerca password in data breach"""
        results = []
        
        if DEHASHED_API_KEY:
            try:
                auth = base64.b64encode(f"{DEHASHED_EMAIL}:{DEHASHED_API_KEY}".encode()).decode()
                headers = {'Authorization': f'Basic {auth}'}
                response = self.session.get(
                    f'https://api.dehashed.com/search?query={quote_plus(password)}',
                    headers=headers, timeout=15
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('entries'):
                        for entry in data['entries'][:10]:
                            results.append({
                                'source': 'Dehashed',
                                'database': entry.get('database_name', 'Unknown'),
                                'email': entry.get('email'),
                                'password': entry.get('password'),
                                'username': entry.get('username'),
                                'date': entry.get('obtained')
                            })
            except Exception as e:
                logger.error(f"Dehashed password error: {e}")
        
        return {'found': len(results) > 0, 'results': results, 'count': len(results)}
    
    async def search_hash(self, hash_str: str) -> Dict:
        """Ricerca e decripta hash"""
        results = []
        
        # Identifica tipo hash
        hash_type = "Unknown"
        if len(hash_str) == 32 and re.match(r'^[a-f0-9]{32}$', hash_str):
            hash_type = "MD5"
        elif len(hash_str) == 40 and re.match(r'^[a-f0-9]{40}$', hash_str):
            hash_type = "SHA1"
        elif len(hash_str) == 64 and re.match(r'^[a-f0-9]{64}$', hash_str):
            hash_type = "SHA256"
        
        # Ricerca in Dehashed
        if DEHASHED_API_KEY:
            try:
                auth = base64.b64encode(f"{DEHASHED_EMAIL}:{DEHASHED_API_KEY}".encode()).decode()
                headers = {'Authorization': f'Basic {auth}'}
                response = self.session.get(
                    f'https://api.dehashed.com/search?query={quote_plus(hash_str)}',
                    headers=headers, timeout=15
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('entries'):
                        for entry in data['entries'][:5]:
                            if entry.get('hashed_password') == hash_str and entry.get('password'):
                                results.append({
                                    'source': 'Dehashed',
                                    'database': entry.get('database_name', 'Unknown'),
                                    'password': entry.get('password'),
                                    'email': entry.get('email'),
                                    'date': entry.get('obtained')
                                })
            except Exception as e:
                logger.error(f"Dehashed hash error: {e}")
        
        return {
            'hash_type': hash_type,
            'found': len(results) > 0,
            'results': results,
            'count': len(results)
        }
    
    async def search_variants(self, query: str) -> Dict:
        """Ricerca in tutti i formati come nelle immagini"""
        results = {
            'telegram': [],
            'facebook': [],
            'vk': [],
            'instagram': [],
            'composite': []
        }
        
        # Rimuovi spazi extra
        query = query.strip()
        
        # Ricerca Telegram
        try:
            # Cerca per username
            tg_url = f'https://t.me/{query}'
            response = self.session.get(tg_url, timeout=5)
            if response.status_code == 200 and 'tgme_page_title' in response.text:
                results['telegram'].append({
                    'type': 'username',
                    'url': tg_url,
                    'found': True
                })
        except:
            pass
        
        # Ricerca Facebook
        try:
            # Cerca per nome
            fb_url = f'https://www.facebook.com/public/{query.replace(" ", "-")}'
            response = self.session.get(fb_url, timeout=5)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                profiles = soup.find_all('div', {'class': '_2ph_'})
                if profiles:
                    results['facebook'].append({
                        'type': 'name',
                        'url': fb_url,
                        'found': True,
                        'count': len(profiles)
                    })
        except:
            pass
        
        # Ricerca VK
        try:
            vk_url = f'https://vk.com/people/{query.replace(" ", "%20")}'
            response = self.session.get(vk_url, timeout=5)
            if response.status_code == 200:
                results['vk'].append({
                    'type': 'name',
                    'url': vk_url,
                    'found': True
                })
        except:
            pass
        
        # Ricerca Instagram
        try:
            ig_url = f'https://www.instagram.com/{query.replace(" ", "")}/'
            response = self.session.get(ig_url, timeout=5, allow_redirects=False)
            if response.status_code in [200, 301, 302]:
                results['instagram'].append({
                    'type': 'username',
                    'url': ig_url,
                    'found': True
                })
        except:
            pass
        
        return results
    
    async def search_telegram_account(self, query: str) -> Dict:
        """Ricerca specifica per account Telegram"""
        results = {
            'by_username': [],
            'by_name': [],
            'by_id': []
        }
        
        # Cerca per username
        try:
            tg_url = f'https://t.me/{query}'
            response = self.session.get(tg_url, timeout=5)
            if response.status_code == 200 and 'tgme_page_title' in response.text:
                results['by_username'].append({
                    'url': tg_url,
                    'found': True,
                    'type': 'username'
                })
        except:
            pass
        
        # Cerca per ID (numerico)
        if query.isdigit():
            results['by_id'].append({
                'telegram_id': query,
                'found': False  # Telegram non permette ricerca per ID pubblico
            })
        
        # Cerca per nome
        if ' ' in query:
            results['by_name'].append({
                'name': query,
                'found': False  # Telegram non ha ricerca pubblica per nome
            })
        
        return results
    
    async def search_instagram_account(self, query: str) -> Dict:
        """Ricerca specifica per account Instagram"""
        results = {
            'by_username': [],
            'by_name': []
        }
        
        # Cerca per username
        try:
            ig_url = f'https://www.instagram.com/{query.replace(" ", "")}/'
            response = self.session.get(ig_url, timeout=5, allow_redirects=False)
            if response.status_code in [200, 301, 302]:
                results['by_username'].append({
                    'url': ig_url,
                    'found': True,
                    'type': 'username'
                })
        except:
            pass
        
        # Cerca per nome (simulato)
        if ' ' in query:
            results['by_name'].append({
                'name': query,
                'found': False,  # Instagram non ha ricerca pubblica per nome
                'note': 'Instagram richiede login per ricerca per nome'
            })
        
        return results
    
    async def search_facebook_account(self, query: str) -> Dict:
        """Ricerca specifica per account Facebook"""
        results = {
            'by_name': [],
            'by_id': []
        }
        
        # Cerca per nome
        try:
            fb_url = f'https://www.facebook.com/public/{query.replace(" ", "-")}'
            response = self.session.get(fb_url, timeout=5)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                profiles = soup.find_all('div', {'class': '_2ph_'})
                if profiles:
                    results['by_name'].append({
                        'url': fb_url,
                        'found': True,
                        'count': len(profiles),
                        'type': 'name'
                    })
        except:
            pass
        
        # Cerca per ID
        if query.isdigit():
            try:
                fb_url = f'https://www.facebook.com/profile.php?id={query}'
                response = self.session.get(fb_url, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    results['by_id'].append({
                        'url': fb_url,
                        'found': True,
                        'facebook_id': query,
                        'type': 'id'
                    })
            except:
                pass
        
        return results
    
    async def search_vk_account(self, query: str) -> Dict:
        """Ricerca specifica per account VKontakte"""
        results = {
            'by_name': [],
            'by_id': []
        }
        
        # Cerca per nome
        try:
            vk_url = f'https://vk.com/people/{query.replace(" ", "%20")}'
            response = self.session.get(vk_url, timeout=5)
            if response.status_code == 200:
                results['by_name'].append({
                    'url': vk_url,
                    'found': True,
                    'type': 'name'
                })
        except:
            pass
        
        # Cerca per ID
        if query.isdigit():
            try:
                vk_url = f'https://vk.com/id{query}'
                response = self.session.get(vk_url, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    results['by_id'].append({
                        'url': vk_url,
                        'found': True,
                        'vk_id': query,
                        'type': 'id'
                    })
            except:
                pass
        
        return results
    
    # ============ NUOVI METODI PER FACEBOOK ============
    
    async def search_facebook_advanced(self, query: str) -> Dict:
        """Ricerca avanzata su Facebook usando API multiple"""
        results = {
            'leak_data': [],
            'public_info': [],
            'graph_api': [],
            'search_engines': []
        }
        
        # 1. Cerca nel database Facebook leaks locale
        c.execute('''SELECT * FROM facebook_leaks WHERE 
                    name LIKE ? OR surname LIKE ? OR phone LIKE ? 
                    ORDER BY found_date DESC LIMIT 10''',
                 (f'%{query}%', f'%{query}%', f'%{query}%'))
        db_results = c.fetchall()
        
        for row in db_results:
            results['leak_data'].append({
                'type': 'facebook_leak_2021',
                'phone': row[1],
                'facebook_id': row[2],
                'full_name': f"{row[3]} {row[4]}",
                'gender': row[5],
                'birth_date': row[6],
                'city': row[7],
                'country': row[8],
                'company': row[9],
                'leak_date': row[11]
            })
        
        # 2. Ricerca con Graph API (se disponibile)
        if FACEBOOK_GRAPH_API_KEY and ' ' in query:
            try:
                # Split nome e cognome
                parts = query.split()
                if len(parts) >= 2:
                    first_name, last_name = parts[0], ' '.join(parts[1:])
                    
                    # Cerca utenti pubblici (limitato)
                    search_url = f'https://graph.facebook.com/v18.0/search'
                    params = {
                        'q': query,
                        'type': 'user',
                        'fields': 'id,name,first_name,last_name',
                        'access_token': FACEBOOK_GRAPH_API_KEY,
                        'limit': 5
                    }
                    
                    response = self.session.get(search_url, params=params, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        if data.get('data'):
                            for user in data['data']:
                                results['graph_api'].append({
                                    'type': 'graph_api',
                                    'facebook_id': user.get('id'),
                                    'name': user.get('name'),
                                    'first_name': user.get('first_name'),
                                    'last_name': user.get('last_name'),
                                    'profile_url': f'https://facebook.com/{user.get("id")}'
                                })
            except Exception as e:
                logger.error(f"Facebook Graph API error: {e}")
        
        # 3. Ricerca nei motori di ricerca
        try:
            # Bing search per Facebook
            bing_url = f'https://www.bing.com/search?q=site%3Afacebook.com+{quote_plus(query)}'
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = self.session.get(bing_url, headers=headers, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                links = soup.find_all('a', href=True)
                
                for link in links:
                    href = link.get('href', '')
                    if 'facebook.com' in href and '/people/' in href:
                        results['search_engines'].append({
                            'type': 'bing_search',
                            'url': href,
                            'title': link.get_text(strip=True)[:100]
                        })
        except Exception as e:
            logger.error(f"Search engine error: {e}")
        
        # 4. Cerca in altri database leak
        if DEHASHED_API_KEY:
            try:
                auth = base64.b64encode(f"{DEHASHED_EMAIL}:{DEHASHED_API_KEY}".encode()).decode()
                headers = {'Authorization': f'Basic {auth}'}
                response = self.session.get(
                    f'https://api.dehashed.com/search?query={quote_plus("facebook.com")}+{quote_plus(query)}',
                    headers=headers, timeout=15
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('entries'):
                        for entry in data['entries'][:5]:
                            if 'facebook' in entry.get('email', '').lower() or 'facebook' in entry.get('password', '').lower():
                                results['leak_data'].append({
                                    'type': 'dehashed_facebook',
                                    'email': entry.get('email'),
                                    'password': entry.get('password'),
                                    'username': entry.get('username'),
                                    'name': entry.get('name'),
                                    'database': entry.get('database_name'),
                                    'date': entry.get('obtained')
                                })
            except Exception as e:
                logger.error(f"Dehashed Facebook error: {e}")
        
        return results
    
    async def search_facebook_by_phone(self, phone: str) -> Dict:
        """Ricerca Facebook per numero di telefono"""
        results = []
        
        # Normalizza il numero
        phone_clean = re.sub(r'[^\d+]', '', phone)[-10:]  # Ultimi 10 numeri
        
        # Cerca nel database Facebook leaks
        c.execute('''SELECT * FROM facebook_leaks WHERE phone LIKE ? ORDER BY found_date DESC LIMIT 15''',
                 (f'%{phone_clean}%',))
        db_results = c.fetchall()
        
        for row in db_results:
            results.append({
                'source': 'Facebook Leak 2021',
                'phone': row[1],
                'facebook_id': row[2],
                'name': f"{row[3]} {row[4]}",
                'gender': row[5],
                'birth_date': row[6],
                'city': row[7],
                'country': row[8],
                'company': row[9],
                'relationship_status': row[10],
                'leak_date': row[11]
            })
        
        # Cerca in altri database
        if SNUSBASE_API_KEY:
            try:
                headers = {'Auth': SNUSBASE_API_KEY}
                data = {'terms': [phone_clean], 'types': ['phone']}
                response = self.session.post(
                    'https://api.snusbase.com/v3/search',
                    headers=headers, json=data, timeout=20
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('results'):
                        for entry in data['results']:
                            if 'facebook' in str(entry).lower():
                                results.append({
                                    'source': 'Snusbase',
                                    'phone': phone_clean,
                                    'email': entry.get('email'),
                                    'password': entry.get('password'),
                                    'hash': entry.get('hash')
                                })
            except Exception as e:
                logger.error(f"Snusbase phone error: {e}")
        
        return {'found': len(results) > 0, 'results': results, 'count': len(results)}
    
    async def search_facebook_by_email(self, email: str) -> Dict:
        """Ricerca Facebook per email"""
        results = []
        
        # Cerca email nel formato facebook
        facebook_email = email.lower()
        
        # Dehashed API
        if DEHASHED_API_KEY:
            try:
                auth = base64.b64encode(f"{DEHASHED_EMAIL}:{DEHASHED_API_KEY}".encode()).decode()
                headers = {'Authorization': f'Basic {auth}'}
                response = self.session.get(
                    f'https://api.dehashed.com/search?query={quote_plus(facebook_email)}+facebook',
                    headers=headers, timeout=15
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('entries'):
                        for entry in data['entries'][:10]:
                            results.append({
                                'source': 'Dehashed',
                                'database': entry.get('database_name', 'Unknown'),
                                'email': entry.get('email'),
                                'password': entry.get('password'),
                                'name': entry.get('name'),
                                'username': entry.get('username'),
                                'date': entry.get('obtained')
                            })
            except Exception as e:
                logger.error(f"Dehashed Facebook email error: {e}")
        
        # Snusbase API
        if SNUSBASE_API_KEY:
            try:
                headers = {'Auth': SNUSBASE_API_KEY}
                data = {'terms': [email], 'types': ['email']}
                response = self.session.post(
                    'https://api.snusbase.com/v3/search',
                    headers=headers, json=data, timeout=20
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('results'):
                        for entry in data['results']:
                            if 'facebook' in str(entry).lower():
                                results.append({
                                    'source': 'Snusbase',
                                    'database': entry.get('database', 'Unknown'),
                                    'email': entry.get('email'),
                                    'password': entry.get('password')
                                })
            except Exception as e:
                logger.error(f"Snusbase Facebook email error: {e}")
        
        return {'found': len(results) > 0, 'results': results, 'count': len(results)}
    
    async def search_facebook_by_id(self, fb_id: str) -> Dict:
        """Ricerca Facebook per ID"""
        results = []
        
        # Verifica se è un ID numerico
        if fb_id.isdigit():
            # Cerca nel database leaks
            c.execute('''SELECT * FROM facebook_leaks WHERE facebook_id = ?''', (fb_id,))
            db_results = c.fetchall()
            
            for row in db_results:
                results.append({
                    'source': 'Facebook Leak 2021',
                    'facebook_id': row[2],
                    'name': f"{row[3]} {row[4]}",
                    'phone': row[1],
                    'gender': row[5],
                    'birth_date': row[6],
                    'city': row[7],
                    'country': row[8]
                })
            
            # Prova ad accedere al profilo pubblico
            try:
                profile_url = f'https://facebook.com/{fb_id}'
                response = self.session.get(profile_url, timeout=10, allow_redirects=True)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Estrai metadati
                    title = soup.find('title')
                    if title:
                        title_text = title.get_text(strip=True)
                        results.append({
                            'source': 'facebook_profile',
                            'url': profile_url,
                            'title': title_text,
                            'accessible': True
                        })
            except Exception as e:
                logger.error(f"Facebook ID profile error: {e}")
        
        return {'found': len(results) > 0, 'results': results, 'count': len(results)}

class LeakosintBot:
    """Bot principale con interfaccia come nelle immagini"""
    
    def __init__(self):
        self.api = LeakSearchAPI()
    
    # ==================== NUOVE FUNZIONI PER INTERFACCIA ====================
    
    async def show_main_menu(self, update: Update, context: CallbackContext):
        """Mostra il menu principale con interfaccia come nella foto"""
        user = update.effective_user
        user_id = user.id
        
        # Registra utente se non esiste
        self.register_user(user_id, user.username)
        
        # Ottieni data in italiano
        now = datetime.now()
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        # Crea tastiera inline - CON FORMATO ESATTO COME NELLA FOTO
        keyboard = [
            [InlineKeyboardButton("🔍 Ricerca", callback_data='ricerca')],
            [InlineKeyboardButton("shop💸", callback_data='shop_button')],  # CAMBIATO da buy💰 a shop💸
            [InlineKeyboardButton("⚙️ Impostazioni", callback_data='impostazioni')],
            [InlineKeyboardButton("📋 Menu", callback_data='menu_button')],
            [InlineKeyboardButton("help❓", callback_data='help_button')]  # AGGIUNTO PULSANTE HELP
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # Testo come nella foto
        menu_text = f"""# Posso cercare tutto. Inviami la tua richiesta.🔍

⏰ {now.hour:02d}:{now.minute:02d}

Trova ciò che nascondono🕵🏻‍♂️

•🔍 Ricerca

•shop💸

•⚙️ Impostazioni

•📋 Menu

•help❓

{data_italiana}"""
        
        # Invia o modifica il messaggio
        if update.callback_query:
            await update.callback_query.edit_message_text(menu_text, reply_markup=reply_markup)
        else:
            await update.message.reply_text(menu_text, reply_markup=reply_markup)
    
    def register_user(self, user_id: int, username: str):
        """Registra un nuovo utente"""
        c.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
        if not c.fetchone():
            c.execute('''INSERT INTO users (user_id, username, balance) 
                       VALUES (?, ?, 10.0)''', (user_id, username))
            conn.commit()
            return True
        return False
    
    def get_user_balance(self, user_id: int) -> float:
        c.execute('SELECT balance FROM users WHERE user_id = ?', (user_id,))
        result = c.fetchone()
        return result[0] if result else 0.0
    
    def get_user_language(self, user_id: int) -> str:
        """Ottiene la lingua dell'utente (semplificato: sempre italiano)"""
        return 'it'
    
    def get_user_searches(self, user_id: int) -> int:
        c.execute('SELECT searches FROM users WHERE user_id = ?', (user_id,))
        result = c.fetchone()
        return result[0] if result else 0
    
    def get_registration_date(self, user_id: int) -> str:
        c.execute('SELECT registration_date FROM users WHERE user_id = ?', (user_id,))
        result = c.fetchone()
        if result and result[0]:
            try:
                dt = datetime.strptime(result[0], '%Y-%m-%d %H:%M:%S')
                return dt.strftime('%d/%m/%Y')
            except:
                return result[0]
        return "Sconosciuta"
    
    def get_last_active(self, user_id: int) -> str:
        c.execute('SELECT last_active FROM users WHERE user_id = ?', (user_id,))
        result = c.fetchone()
        if result and result[0]:
            try:
                dt = datetime.strptime(result[0], '%Y-%m-%d %H:%M:%S')
                return dt.strftime('%d/%m/%Y %H:%M')
            except:
                return result[0]
        return "Sconosciuta"
    
    def get_subscription_type(self, user_id: int) -> str:
        c.execute('SELECT subscription_type FROM users WHERE user_id = ?', (user_id,))
        result = c.fetchone()
        return result[0] if result else 'free'
    
    def get_username(self, user_id: int) -> str:
        c.execute('SELECT username FROM users WHERE user_id = ?', (user_id,))
        result = c.fetchone()
        return result[0] if result else 'N/A'
    
    async def update_balance(self, user_id: int, cost: float = 2.0) -> bool:
        current = self.get_user_balance(user_id)
        if current >= cost:
            new_balance = current - cost
            c.execute('''UPDATE users SET balance = ?, searches = searches + 1, 
                       last_active = CURRENT_TIMESTAMP WHERE user_id = ?''', 
                      (new_balance, user_id))
            conn.commit()
            return True
        return False
    
    def add_credits(self, user_id: int, amount: float) -> bool:
        try:
            c.execute('''UPDATE users SET balance = balance + ?, 
                       last_active = CURRENT_TIMESTAMP WHERE user_id = ?''', 
                      (amount, user_id))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error adding credits: {e}")
            return False
    
    def log_search(self, user_id: int, query: str, search_type: str, results: str):
        c.execute('''INSERT INTO searches (user_id, query, type, results) 
                   VALUES (?, ?, ?, ?)''', (user_id, query, search_type, results))
        conn.commit()
    
    # ==================== HANDLER PER PULSANTI ====================
    
    async def handle_button_callback(self, update: Update, context: CallbackContext):
        """Gestisce i callback dei pulsanti inline"""
        query = update.callback_query
        await query.answer()
        
        user_id = query.from_user.id
        now = datetime.now()
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        if query.data == 'ricerca':
            # Mostra il menu di ricerca completo (quello che c'è nello start attuale)
            await self.show_search_menu(update, context)
            
        elif query.data == 'shop_button':  # CAMBIATO da buy_button a shop_button
            # Mostra i prezzi per l'acquisto crediti con crypto
            await self.show_shop_interface(update, context)
            
        elif query.data == 'impostazioni':
            # Mostra i dettagli utente CON PIÙ INFORMAZIONI
            balance = self.get_user_balance(user_id)
            searches = self.get_user_searches(user_id)
            reg_date = self.get_registration_date(user_id)
            last_active = self.get_last_active(user_id)
            sub_type = self.get_subscription_type(user_id)
            username = self.get_username(user_id)
            
            settings_text = f"""⚙️ IMPOSTAZIONI UTENTE

👤 Informazioni Personali:
🆔 ID Telegram: {user_id}
👤 Username: @{username}
📅 Registrato: {reg_date}
🕒 Ultima attività: {last_active}

💳 Sistema Credit:
💰 Crediti attuali: {balance:.1f}
🔍 Ricerche effettuate: {searches}
🎯 Ricerche disponibili: {int(balance / 2.0)}
📊 Abbonamento: {sub_type}

⚙️ Configurazioni:
🔔 Notifiche: Attive
🌐 Lingua: Italiano
💾 Salvataggio ricerche: 30 giorni

📊 Statistiche odierne:
- Ricerche oggi: {searches % 100}
- Crediti usati oggi: {(100 - balance) % 100:.1f}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
            
            keyboard = [[InlineKeyboardButton("🔙 Indietro", callback_data='back_to_main')]]
            await query.edit_message_text(settings_text, reply_markup=InlineKeyboardMarkup(keyboard))
            
        elif query.data == 'menu_button':
            # Mostra il menu completo
            await self.menu_completo(update, context)
            
        elif query.data == 'help_button':  # NUOVO: Handler per help button
            # Mostra il testo di aiuto
            await self.help_command_from_button(update, context)
            
        elif query.data == 'back_to_main':
            # Torna al menu principale
            await self.show_main_menu(update, context)
            
        elif query.data == 'back_from_search':
            # Torna al menu di ricerca
            await self.show_search_menu(update, context)
    
    async def help_command_from_button(self, update: Update, context: CallbackContext):
        """Mostra l'aiuto quando cliccato dal pulsante help"""
        await self.help_command(update, context)
    
    async def show_search_menu(self, update: Update, context: CallbackContext):
        """Mostra il menu di ricerca (quello che c'è attualmente nello start)"""
        user = update.effective_user
        user_id = user.id
        
        # Ottieni data in italiano
        now = datetime.now()
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        # Costruisci il messaggio
        text = f"""🔍 Puoi cercare i seguenti dati:

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

💰 Crediti disponibili: {self.get_user_balance(user_id):.1f} 📊Ricerche effettuate: {self.get_user_searches(user_id)}

📩 Inviami qualsiasi dato per iniziare la ricerca.

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        keyboard = [[InlineKeyboardButton("🔙 Indietro", callback_data='back_to_main')]]
        
        if update.callback_query:
            await update.callback_query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard))
        else:
            await update.message.reply_text(text, reply_markup=InlineKeyboardMarkup(keyboard))
    
    async def show_shop_interface(self, update: Update, context: CallbackContext):  # RINOMINATO da show_buy_interface
        """Mostra l'interfaccia di acquisto crediti con crypto"""
        now = datetime.now()
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        text = f"""shop💸 - ACQUISTA CREDITI CON CRYPTO

💎 PACCHETTI CREDITI:
━━━━━━━━━━━━━━━━━━━━
· 🟢 20 CREDITI = 2.0 USDT
· 🟡 50 CREDITI = 4.5 USDT
· 🔵 100 CREDITI = 8.0 USDT
· 🟣 200 CREDITI = 15.0 USDT

📊 CONVERSIONE:
━━━━━━━━━━━━━━━━━━━━
💰 2 crediti = 1 ricerca
💸 1 credito = 0.1 USDT

🎁 SCONTI:
━━━━━━━━━━━━━━━━━━━━
• +50 crediti: 10% sconto
• +100 crediti: 20% sconto
• +200 crediti: 25% sconto

🔗 PAGAMENTO CRYPTO:
━━━━━━━━━━━━━━━━━━━━
🌐 Rete: TRC20 (Tron) o BEP20 (BSC)
💰 Accettiamo: USDT, USDC, BTC, ETH
🔄 Conversione automatica

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
• Solo pagamenti crypto
• Nessun rimborso
• Verifica indirizzo
• Minimo 10 USDT

📞 SUPPORTO:
━━━━━━━━━━━━━━━━━━━━
• @Zerofilter00
• 24/7 disponibile

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        keyboard = [
            [InlineKeyboardButton("💳 Acquista 20 crediti", callback_data='buy_20')],
            [InlineKeyboardButton("💳 Acquista 50 crediti", callback_data='buy_50')],
            [InlineKeyboardButton("🔙 Indietro", callback_data='back_to_main')]
        ]
        
        if update.callback_query:
            await update.callback_query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard))
        else:
            await update.message.reply_text(text, reply_markup=InlineKeyboardMarkup(keyboard))
    
    # ============ MODIFICA DEL COMANDO START ============
    
    async def start(self, update: Update, context: CallbackContext):
        """Comando start - Mostra il menu principale con interfaccia"""
        await self.show_main_menu(update, context)
    
    # ============ FUNZIONI DI RICERCA COMPOSTA (ESISTENTI) ============
    
    def parse_composite_query(self, query: str) -> Dict:
        """Analizza query composte da più informazioni"""
        components = {
            'emails': [],
            'phones': [],
            'names': [],
            'usernames': [],
            'ips': [],
            'passwords': [],
            'hashes': [],
            'documents': [],      # NUOVO: documenti
            'addresses': [],      # NUOVO: indirizzi
            'other': []
        }
        
        # Rimuovi spazi multipli
        query = re.sub(r'\s+', ' ', query).strip()
        
        # Pattern per identificare componenti
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        phone_pattern = r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,9}'
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        hash_pattern = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
        document_pattern = r'\b[A-Z]{2}\d{7}\b|\b\d{9}\b|\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b|\b[A-Z]{2}\d{5}[A-Z]{2}\d{4}\b'
        
        # Trova tutte le email
        components['emails'] = re.findall(email_pattern, query, re.IGNORECASE)
        
        # Trova tutti i telefoni
        components['phones'] = re.findall(phone_pattern, query)
        
        # Trova tutti gli IP
        components['ips'] = re.findall(ip_pattern, query)
        
        # Trova tutti gli hash
        components['hashes'] = re.findall(hash_pattern, query)
        
        # NUOVO: Trova tutti i documenti
        components['documents'] = re.findall(document_pattern, query, re.IGNORECASE)
        
        # Rimuovi i componenti trovati dalla query per isolare nomi/usernames
        remaining_query = query
        
        for email in components['emails']:
            remaining_query = remaining_query.replace(email, '')
        
        for phone in components['phones']:
            remaining_query = remaining_query.replace(phone, '')
        
        for ip in components['ips']:
            remaining_query = remaining_query.replace(ip, '')
        
        for hash_val in components['hashes']:
            remaining_query = remaining_query.replace(hash_val, '')
        
        for doc in components['documents']:
            remaining_query = remaining_query.replace(doc, '')
        
        # Cerca password (stringhe alfanumeriche senza spazi)
        password_pattern = r'\b[a-zA-Z0-9_@#$%^&*!]{6,30}\b'
        password_candidates = re.findall(password_pattern, remaining_query)
        
        for pwd in password_candidates:
            # Se non è già classificato come email/phone/ip/hash e non contiene @
            if '@' not in pwd and not pwd.replace('_', '').replace('@', '').replace('#', '').replace('$', '').replace('%', '').replace('^', '').replace('&', '').replace('*', '').replace('!', '').isdigit():
                components['passwords'].append(pwd)
                remaining_query = remaining_query.replace(pwd, '')
        
        # NUOVO: Cerca indirizzi (conta parole come via, viale, corso, etc.)
        address_indicators = ['via', 'viale', 'piazza', 'corso', 'largo', 'vicolo', 'strada']
        remaining_parts = remaining_query.split()
        
        i = 0
        while i < len(remaining_parts):
            part = remaining_parts[i].lower()
            if part in address_indicators and i + 2 < len(remaining_parts):
                # Potrebbe essere un indirizzo
                address_parts = []
                # Prendi la parola successiva (nome via) e la successiva (numero)
                if i + 2 < len(remaining_parts):
                    address_parts = remaining_parts[i:i+3]
                    address = ' '.join(address_parts)
                    components['addresses'].append(address)
                    # Rimuovi dall'analisi successiva
                    for _ in range(3):
                        if i < len(remaining_parts):
                            remaining_parts.pop(i)
                    continue
            i += 1
        
        # Ricostruisci remaining_query
        remaining_query = ' '.join(remaining_parts)
        
        # Rimuovi punteggiatura e spazi extra
        remaining_query = re.sub(r'[^\w\s]', ' ', remaining_query).strip()
        remaining_parts = [p for p in remaining_query.split() if p]
        
        # Classifica le parti rimanenti
        for part in remaining_parts:
            if len(part) <= 30 and ' ' not in part:
                # Potrebbe essere username
                components['usernames'].append(part)
            else:
                # Potrebbe essere nome
                components['names'].append(part)
        
        # Unisci nomi multipli consecutivi
        if components['names']:
            combined_names = []
            current_name = []
            
            for part in remaining_parts:
                if part in components['names']:
                    current_name.append(part)
                else:
                    if current_name:
                        combined_names.append(' '.join(current_name))
                        current_name = []
            
            if current_name:
                combined_names.append(' '.join(current_name))
            
            components['names'] = combined_names
        
        return components

    def is_email(self, text: str) -> bool:
        """Verifica se il testo è un'email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, text))

    def is_phone(self, text: str) -> bool:
        """Verifica se il testo è un numero di telefono"""
        # Pulisci il testo
        cleaned = re.sub(r'[^\d+]', '', text)
        return len(cleaned) >= 8 and len(cleaned) <= 15

    def is_ip(self, text: str) -> bool:
        """Verifica se il testo è un IP"""
        pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(pattern, text):
            parts = text.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        return False

    def is_hash(self, text: str) -> bool:
        """Verifica se il testo è un hash"""
        patterns = [
            r'^[a-f0-9]{32}$',  # MD5
            r'^[a-f0-9]{40}$',  # SHA1
            r'^[a-f0-9]{64}$'   # SHA256
        ]
        return any(re.match(pattern, text.lower()) for pattern in patterns)
    
    def is_document(self, text: str) -> bool:
        """Verifica se il testo è un numero di documento"""
        return self.api.is_document_number(text)
    
    def is_address(self, text: str) -> bool:
        """Verifica se il testo è un indirizzo"""
        return self.api.is_address(text)

    def detect_search_type(self, query: str) -> str:
        """Determina automaticamente il tipo di ricerca"""
        query_lower = query.lower()
        
        # Email
        if '@' in query:
            return 'email'
        
        # Telefono
        phone_pattern = r'^[\+]?[0-9\s\-\(\)]{8,}$'
        if re.match(phone_pattern, re.sub(r'[^\d+]', '', query)):
            return 'phone'
        
        # IP
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, query):
            return 'ip'
        
        # Documento (NUOVO)
        if self.is_document(query):
            return 'document'
        
        # Indirizzo (NUOVO)
        address_indicators = ['via', 'viale', 'piazza', 'corso', 'largo', 'vicolo', 'strada',
                             'street', 'avenue', 'boulevard', 'road', 'lane', 'drive']
        if any(indicator in query_lower for indicator in address_indicators) and any(c.isdigit() for c in query):
            return 'address'
        
        # Password (stringa semplice)
        if len(query) <= 30 and ' ' not in query:
            return 'password'
        
        # Hash
        hash_patterns = [
            r'^[a-f0-9]{32}$',  # MD5
            r'^[a-f0-9]{40}$',  # SHA1
            r'^[a-f0-9]{64}$'   # SHA256
        ]
        if any(re.match(pattern, query_lower) for pattern in hash_patterns):
            return 'hash'
        
        # Username (senza spazi)
        if ' ' not in query and len(query) <= 30:
            return 'username'
        
        # Nome (con spaci)
        return 'name'
    
    # ============ MODIFICA AL HANDLE_MESSAGE ============
    
    async def handle_message(self, update: Update, context: CallbackContext):
        """Gestisce tutti i messaggi di ricerca - CORRETTO"""
        try:
            user_id = update.effective_user.id
            query = update.message.text.strip()
            
            logger.info(f"📥 Ricevuta query da user {user_id}: {query[:50]}")
            
            if not query or len(query) < 2:
                await update.message.reply_text("❌ Query troppo corta. Invia almeno 2 caratteri.")
                return
            
            # Controlla crediti
            current_balance = self.get_user_balance(user_id)
            if current_balance < 2:
                user_lang = self.get_user_language(user_id)
                await update.message.reply_text(translations[user_lang]['insufficient_credits'])
                return
            
            # Messaggio di attesa
            now = datetime.now()
            mesi = {
                1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
                5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
                9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
            }
            data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
            
            user_lang = self.get_user_language(user_id)
            wait_text = f"""🔍 {translations[user_lang]['processing']}
            
Query: {query[:50]}{'...' if len(query) > 50 else ''}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
            
            # Invia messaggio di attesa
            try:
                msg = await update.message.reply_text(wait_text)
            except Exception as e:
                logger.error(f"Errore invio messaggio: {e}")
                await update.message.reply_text("❌ Errore iniziale. Riprova.")
                return
            
            # Processa la ricerca
            try:
                await self.process_search(update, msg, query, user_id, data_italiana)
            except Exception as e:
                logger.error(f"Errore ricerca: {e}")
                error_text = f"""❌ Errore durante la ricerca
                    
🔧 Dettaglio: {str(e)[:200]}
                    
💡 Riprova con una query diversa.

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
                try:
                    await msg.edit_text(error_text)
                except:
                    await update.message.reply_text(error_text[:4000])
                
        except Exception as e:
            logger.error(f"Errore generale handle_message: {e}")
            await update.message.reply_text("❌ Errore interno. Riprova più tardi.")
    
    # ============ NUOVO METODO PROCESS_SEARCH ============
    
    async def process_search(self, update: Update, msg, query: str, user_id: int, data_italiana: str):
        """Processa la ricerca - CENTRALIZZATO"""
        try:
            # Deduci il tipo di ricerca
            search_type = self.detect_search_type(query)
            logger.info(f"🔍 Tipo ricerca rilevato: {search_type} per query: {query}")
            
            # Aggiorna il bilancio
            if not await self.update_balance(user_id, 2):
                await msg.edit_text("❌ Errore aggiornamento crediti")
                return
            
            # Esegui la ricerca appropriata
            if search_type == 'email':
                results = await self.api.search_email(query)
                result_text = self.format_email_results(query, results, user_id, data_italiana)
            elif search_type == 'phone':
                results = await self.api.search_phone(query)
                result_text = self.format_phone_results(query, results, user_id, data_italiana)
            elif search_type == 'name':
                results = await self.api.search_name(query)
                result_text = self.format_name_results(query, results, user_id, data_italiana)
            elif search_type == 'username':
                results = await self.api.search_username(query)
                result_text = self.format_username_results(query, results, user_id, data_italiana)
            elif search_type == 'ip':
                results = await self.api.search_ip(query)
                result_text = self.format_ip_results(query, results, user_id, data_italiana)
            elif search_type == 'password':
                results = await self.api.search_password(query)
                result_text = self.format_password_results(query, results, user_id, data_italiana)
            elif search_type == 'hash':
                results = await self.api.search_hash(query)
                result_text = self.format_hash_results(query, results, user_id, data_italiana)
            elif search_type == 'document':
                results = await self.api.search_document(query)
                result_text = self.format_document_results(query, results, user_id, data_italiana)
            elif search_type == 'address':
                results_home = await self.api.search_home_address(query)
                results_work = await self.api.search_work_address(query)
                result_text = self.format_address_results(query, results_home, results_work, user_id, data_italiana)
            else:
                # Ricerca composita
                components = self.parse_composite_query(query)
                total_components = sum(len(v) for v in components.values())
                if total_components >= 2:
                    result_text = self.format_composite_results(query, components, user_id, data_italiana)
                else:
                    results = await self.api.search_variants(query)
                    result_text = self.format_variant_results(query, results, user_id, data_italiana)
            
            # Assicurati che il testo non sia vuoto
            if not result_text or len(result_text.strip()) < 10:
                result_text = f"""🔍 NESSUN RISULTATO TROVATO

Query: {query}

⚠️ La ricerca non ha prodotto risultati nei database conosciuti.

💡 Suggerimenti:
• Verifica l'ortografia
• Prova un formato diverso
• Usa dati più specifici

💰 Crediti usati: 2
💳 Saldo: {self.get_user_balance(user_id)}

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
            
            # Invia i risultati
            try:
                await msg.edit_text(result_text[:4000])
            except Exception as e:
                logger.error(f"Errore edit messaggio: {e}")
                # Invia in parti
                parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
                for part in parts:
                    if part.strip():
                        await update.message.reply_text(part)
                        
        except Exception as e:
            logger.error(f"Errore process_search: {e}")
            raise
    
    # ============ METODI FORMATTAZIONE ============
    
    def format_email_results(self, email: str, results: Dict, user_id: int, data_italiana: str) -> str:
        """Formatta risultati email"""
        now = datetime.now()
        
        if results['found']:
            result_text = f"""📧 RISULTATI EMAIL: {email}
            
✅ TROVATA in {results['count']} database
            
📊 DETTAGLI:"""
            
            for i, result in enumerate(results['results'][:5], 1):
                result_text += f"\n\n{i}. {result['source']}"
                if result.get('password'):
                    result_text += f"\n   🔐 Password: {result['password'][:30]}..."
                if result.get('date'):
                    result_text += f"\n   📅 Data: {result['date']}"
                if result.get('database'):
                    result_text += f"\n   📁 Database: {result['database']}"
        else:
            result_text = f"""📧 RICERCA EMAIL: {email}
            
❌ NON TROVATA nei database conosciuti
            
💡 Prova con:
• Email completa: nome.cognome@dominio.com
• Formato diverso
• Altri servizi"""
        
        # Aggiungi footer
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        return result_text
    
    def format_phone_results(self, phone: str, results: Dict, user_id: int, data_italiana: str) -> str:
        """Formatta risultati telefono"""
        now = datetime.now()
        
        result_text = f"""📱 RICERCA TELEFONO: {phone}"""
        
        # Info sul telefono
        try:
            parsed = phonenumbers.parse(phone, None)
            if phonenumbers.is_valid_number(parsed):
                country = geocoder.description_for_number(parsed, "it")
                carrier_name = carrier.name_for_number(parsed, "it")
                result_text += f"\n\n📞 INFORMAZIONI:"
                if country:
                    result_text += f"\n🌍 Paese: {country}"
                if carrier_name:
                    result_text += f"\n📡 Operatore: {carrier_name}"
        except:
            pass
        
        if results['found']:
            result_text += f"\n\n✅ TROVATO in {results['count']} database"
            
            for i, result in enumerate(results['results'][:3], 1):
                result_text += f"\n\n{i}. {result['source']}"
                if result.get('name'):
                    result_text += f"\n   👤 Nome: {result['name']}"
                if result.get('email'):
                    result_text += f"\n   📧 Email: {result['email']}"
        else:
            result_text += f"\n\n❌ NON TROVATO nei database"
        
        # Footer
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        return result_text
    
    def format_name_results(self, name: str, results: Dict, user_id: int, data_italiana: str) -> str:
        """Formatta risultati nome"""
        now = datetime.now()
        
        result_text = f"""👤 RICERCA NOME: {name}"""
        
        if results['found']:
            result_text += f"\n\n✅ TROVATO in {results['count']} record"
            
            for i, result in enumerate(results['results'][:3], 1):
                result_text += f"\n\n{i}. {result['source']}"
                if result.get('name'):
                    result_text += f"\n   👤 Nome: {result['name']}"
                if result.get('phone'):
                    result_text += f"\n   📱 Telefono: {result['phone']}"
                if result.get('city'):
                    result_text += f"\n   🏙️ Città: {result['city']}"
        else:
            result_text += f"\n\n❌ NON TROVATO nei database"
        
        # Footer
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        return result_text
    
    def format_username_results(self, username: str, results: Dict, user_id: int, data_italiana: str) -> str:
        """Formatta risultati username"""
        now = datetime.now()
        
        result_text = f"""👥 RICERCA USERNAME: {username}"""
        
        if results['social_count'] > 0:
            result_text += f"\n\n📱 ACCOUNT SOCIAL TROVATI: {results['social_count']}"
            
            for i, social in enumerate(results['social'][:3], 1):
                result_text += f"\n\n{i}. {social['platform']}"
                result_text += f"\n   🔗 {social['url']}"
        
        if results['breach_count'] > 0:
            result_text += f"\n\n🔓 DATA BREACH TROVATI: {results['breach_count']}"
            
            for i, breach in enumerate(results['breach'][:2], 1):
                result_text += f"\n\n{i}. {breach['source']}"
                if breach.get('email'):
                    result_text += f"\n   📧 Email: {breach['email']}"
        
        if results['social_count'] == 0 and results['breach_count'] == 0:
            result_text += f"\n\n❌ NESSUN ACCOUNT TROVATO"
        
        # Footer
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        return result_text
    
    def format_ip_results(self, ip: str, results: Dict, user_id: int, data_italiana: str) -> str:
        """Formatta risultati IP"""
        now = datetime.now()
        
        result_text = f"""🌐 RICERCA IP: {ip}"""
        
        # Informazioni IPInfo
        if results.get('ipinfo'):
            info = results['ipinfo']
            result_text += f"\n\n📍 GEO-LOCALIZZAZIONE:"
            result_text += f"\n  🏙️ Città: {info.get('city', 'N/A')}"
            result_text += f"\n  🗺️ Regione: {info.get('region', 'N/A')}"
            result_text += f"\n  🌍 Paese: {info.get('country', 'N/A')}"
            result_text += f"\n  📡 ISP: {info.get('org', info.get('isp', 'N/A'))}"
        
        # Informazioni AbuseIPDB
        if results.get('abuseipdb'):
            abuse = results['abuseipdb']
            result_text += f"\n\n⚠️ THREAT INTEL:"
            result_text += f"\n  ⚠️ Score: {abuse.get('abuseConfidenceScore', 0)}/100"
            result_text += f"\n  📊 Reports: {abuse.get('totalReports', 0)}"
        
        # Informazioni Shodan
        if results.get('shodan'):
            shodan_info = results['shodan']
            result_text += f"\n\n🔓 SERVIZI ESPOSTI:"
            if shodan_info.get('ports'):
                ports = shodan_info['ports'][:5]
                result_text += f"\n  🚪 Porte: {', '.join(map(str, ports))}"
            if shodan_info.get('hostnames'):
                result_text += f"\n  🌐 Hostnames: {', '.join(shodan_info['hostnames'][:3])}"
        
        if results.get('shodan_error'):
            result_text += f"\n\n⚠️ SHODAN: {results['shodan_error']}"
        
        # Footer
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        return result_text
    
    def format_password_results(self, password: str, results: Dict, user_id: int, data_italiana: str) -> str:
        """Formatta risultati password"""
        now = datetime.now()
        
        result_text = f"""🔐 RICERCA PASSWORD: {password[:10]}..."""
        
        if results['found']:
            result_text += f"\n\n⚠️ PASSWORD TROVATA IN: {results['count']} database"
            
            for i, result in enumerate(results['results'][:2], 1):
                result_text += f"\n\n{i}. {result['source']}"
                result_text += f"\n   📁 Database: {result.get('database', 'Unknown')}"
                if result.get('email'):
                    result_text += f"\n   📧 Email: {result['email']}"
        else:
            result_text += f"\n\n✅ PASSWORD SICURA"
            result_text += f"\n🔐 Password non trovata nei database."
        
        # Forza password
        strength = "🔴 DEBOLE"
        if len(password) >= 12 and any(c.isdigit() for c in password) and any(c.isalpha() for c in password):
            strength = "🟢 FORTE"
        elif len(password) >= 8:
            strength = "🟡 MEDIA"
        
        result_text += f"\n\n📊 SICUREZZA: {strength}"
        result_text += f"\n📏 Lunghezza: {len(password)} caratteri"
        
        # Footer
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        return result_text
    
    def format_hash_results(self, hash_str: str, results: Dict, user_id: int, data_italiana: str) -> str:
        """Formatta risultati hash"""
        now = datetime.now()
        
        result_text = f"""🔑 RICERCA HASH: {hash_str[:20]}..."""
        
        result_text += f"\n\n📊 TIPO HASH: {results['hash_type']}"
        result_text += f"\n📏 Lunghezza: {len(hash_str)} caratteri"
        
        if results['found']:
            result_text += f"\n\n🎉 HASH DECRIPTATO!"
            
            for i, result in enumerate(results['results'][:2], 1):
                result_text += f"\n\n{i}. {result['source']}"
                result_text += f"\n   🔓 Password: {result['password']}"
                if result.get('email'):
                    result_text += f"\n   📧 Email: {result['email']}"
        else:
            result_text += f"\n\n❌ HASH NON TROVATO"
            result_text += f"\n🔑 Hash non presente nei database."
        
        # Footer
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        return result_text
    
    def format_document_results(self, document: str, results: Dict, user_id: int, data_italiana: str) -> str:
        """Formatta risultati documento"""
        now = datetime.now()
        
        result_text = f"""📄 RICERCA DOCUMENTO: {document}"""
        
        if results['found']:
            result_text += f"\n\n✅ TROVATO in {results['count']} database"
            
            for i, result in enumerate(results['results'][:3], 1):
                result_text += f"\n\n{i}. {result['source']}"
                if result.get('full_name'):
                    result_text += f"\n   👤 Nome: {result['full_name']}"
                if result.get('address'):
                    result_text += f"\n   🏠 Indirizzo: {result['address']}"
                if result.get('phone'):
                    result_text += f"\n   📱 Telefono: {result['phone']}"
        else:
            result_text += f"\n\n❌ NON TROVATO nei database"
        
        # Informazioni sul tipo di documento
        doc_type = "Sconosciuto"
        if re.match(r'^[A-Z]{2}\d{7}$', document):
            doc_type = "Carta d'Identità 🇮🇹"
        elif re.match(r'^\d{9}$', document):
            doc_type = "Codice Fiscale 🇮🇹"
        elif re.match(r'^[A-Z]{2}\d{5}[A-Z]{2}\d{4}$', document):
            doc_type = "Passaporto 🇮🇹"
        
        result_text += f"\n\n📋 TIPO DOCUMENTO: {doc_type}"
        
        # Footer
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        return result_text
    
    def format_address_results(self, address: str, home_results: Dict, work_results: Dict, user_id: int, data_italiana: str) -> str:
        """Formatta risultati indirizzo"""
        now = datetime.now()
        
        # Determina se è indirizzo di casa o lavorativo
        is_work_address = any(word in address.lower() for word in ['ufficio', 'lavoro', 'azienda', 'company', 'sede'])
        
        if is_work_address:
            address_type = "🏢 INDIRIZZO LAVORATIVO"
            results = work_results
        else:
            address_type = "🏠 INDIRIZZO DI CASA"
            results = home_results
        
        result_text = f"""{address_type}
{address}"""
        
        if results['found']:
            result_text += f"\n\n✅ TROVATO in {results['count']} database"
            
            for i, result in enumerate(results['results'][:3], 1):
                result_text += f"\n\n{i}. {result['source']}"
                if result.get('full_name'):
                    result_text += f"\n   👤 Nome: {result['full_name']}"
                if result.get('phone'):
                    result_text += f"\n   📱 Telefono: {result['phone']}"
                if result.get('email'):
                    result_text += f"\n   📧 Email: {result['email']}"
        else:
            result_text += f"\n\n❌ NON TROVATO nei database"
            result_text += f"\n💡 Suggerimento: Prova con formato 'Via Roma 123, Milano'"
        
        # Footer
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        return result_text
    
    def format_composite_results(self, query: str, components: Dict, user_id: int, data_italiana: str) -> str:
        """Formatta risultati query composita"""
        now = datetime.now()
        
        result_text = f"""🔍 RICERCA COMPOSTA
Query: {query[:100]}"""
        
        total_components = sum(len(v) for v in components.values())
        result_text += f"\n\n📊 Componenti identificati: {total_components}"
        
        # Mostra componenti trovati
        if components['emails']:
            result_text += f"\n\n📧 Email: {', '.join(components['emails'][:2])}"
        if components['phones']:
            result_text += f"\n\n📱 Telefoni: {', '.join(components['phones'][:2])}"
        if components['names']:
            result_text += f"\n\n👤 Nomi: {', '.join(components['names'][:2])}"
        if components['documents']:
            result_text += f"\n\n📄 Documenti: {', '.join(components['documents'][:2])}"
        if components['addresses']:
            result_text += f"\n\n🏠 Indirizzi: {', '.join(components['addresses'][:2])}"
        
        result_text += f"\n\n💡 Eseguo ricerche separate per ogni componente..."
        
        # Footer
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        return result_text
    
    def format_variant_results(self, query: str, results: Dict, user_id: int, data_italiana: str) -> str:
        """Formatta risultati varianti"""
        now = datetime.now()
        
        result_text = f"""🔍 RICERCA GENERICA
Query: {query}"""
        
        found_any = False
        
        if results['telegram']:
            result_text += f"\n\n📱 Telegram: Account trovato"
            found_any = True
        if results['facebook']:
            result_text += f"\n\n📘 Facebook: {results['facebook'][0].get('count', 0)} profili trovati"
            found_any = True
        if results['instagram']:
            result_text += f"\n\n📸 Instagram: Account trovato"
            found_any = True
        if results['vk']:
            result_text += f"\n\n🔵 VKontakte: Account trovato"
            found_any = True
        
        if not found_any:
            result_text += f"\n\n❌ NESSUN RISULTATO DIRETTO"
            result_text += f"\n💡 Prova con una ricerca più specifica"
        
        # Footer
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        return result_text
    
    # ============ FUNZIONI DI RICERCA ESISTENTI (PRESERVATE PER COMPATIBILITÀ) ============
    
    async def search_composite_advanced(self, update: Update, msg, query: str, user_id: int, data_italiana: str):
        """Ricerca composta avanzata - Supporta query con più informazioni"""
        
        # Analizza la query
        components = self.parse_composite_query(query)
        
        now = datetime.now()
        result_text = f"""🔍 RICERCA COMPOSTA AVANZATA
- Query: {query}"""
        
        all_results = []
        
        # 1. Ricerca per email
        if components['emails']:
            result_text += f"\n\n📧 EMAIL TROVATE: {len(components['emails'])}"
            for i, email in enumerate(components['emails'][:3], 1):
                result_text += f"\n  {i}. {email}"
                
                # Esegui ricerca per email
                email_results = await self.api.search_email(email)
                if email_results['found']:
                    result_text += f"\n     ✅ Trovata in {email_results['count']} database"
                    if email_results['results']:
                        first_result = email_results['results'][0]
                        if first_result.get('password'):
                            result_text += f"\n     🔐 Password: {first_result['password'][:30]}..."
        
        # 2. Ricerca per telefono
        if components['phones']:
            result_text += f"\n\n📱 TELEFONI TROVATI: {len(components['phones'])}"
            for i, phone in enumerate(components['phones'][:3], 1):
                result_text += f"\n  {i}. {phone}"
                
                # Info base telefono
                try:
                    parsed = phonenumbers.parse(phone, None)
                    country = geocoder.description_for_number(parsed, "it")
                    if country:
                        result_text += f"\n     🌍 Paese: {country}"
                except:
                    pass
                
                # Ricerca nei leak
                phone_results = await self.api.search_phone(phone)
                if phone_results['found']:
                    result_text += f"\n     ✅ Trovato in {phone_results['count']} database"
        
        # 3. Ricerca per nome
        if components['names']:
            result_text += f"\n\n👤 NOMI TROVATI: {len(components['names'])}"
            for i, name in enumerate(components['names'][:3], 1):
                result_text += f"\n  {i}. {name}"
                
                # Ricerca nei data breach
                name_results = await self.api.search_name(name)
                if name_results['found']:
                    result_text += f"\n     ✅ Trovato in {name_results['count']} record"
                    if name_results['results']:
                        first_result = name_results['results'][0]
                        if first_result.get('phone'):
                            result_text += f"\n     📱 Telefono: {first_result['phone']}"
                        if first_result.get('city'):
                            result_text += f"\n     🏙️ Città: {first_result['city']}"
        
        # 4. Ricerca per username
        if components['usernames']:
            result_text += f"\n\n👥 USERNAME TROVATI: {len(components['usernames'])}"
            for i, username in enumerate(components['usernames'][:3], 1):
                result_text += f"\n  {i}. {username}"
                
                # Ricerca social
                social_results = await self.api.search_username(username)
                if social_results['social_count'] > 0:
                    result_text += f"\n     ✅ {social_results['social_count']} account social"
            
            # Aggiungi i link ai social trovati con emoji
            for social in social_results['social']:
                platform = social['platform']
                url = social['url']
                result_text += f"\n     - {platform}: {url}"
        
        # 5. Ricerca per IP
        if components['ips']:
            result_text += f"\n\n🌐 IP TROVATI: {len(components['ips'])}"
            for i, ip in enumerate(components['ips'][:2], 1):
                result_text += f"\n  {i}. {ip}"
                
                # Ricerca info IP
                ip_results = await self.api.search_ip(ip)
                if ip_results.get('ipinfo'):
                    info = ip_results['ipinfo']
                    if info.get('city'):
                        result_text += f"\n     🏙️ Città: {info['city']}"
                    if info.get('country'):
                        result_text += f"\n     🌍 Paese: {info['country']}"
        
        # 6. Ricerca password
        if components['passwords']:
            result_text += f"\n\n🔐 PASSWORD TROVATI: {len(components['passwords'])}"
            for i, pwd in enumerate(components['passwords'][:2], 1):
                result_text += f"\n  {i}. {pwd[:10]}..."
                
                # Ricerca password
                pwd_results = await self.api.search_password(pwd)
                if pwd_results['found']:
                    result_text += f"\n     ⚠️ Trovata in {pwd_results['count']} database"
        
        # 7. Ricerca hash
        if components['hashes']:
            result_text += f"\n\n🔑 HASH TROVATI: {len(components['hashes'])}"
            for i, hash_val in enumerate(components['hashes'][:2], 1):
                result_text += f"\n  {i}. {hash_val[:20]}..."
                
                # Ricerca hash
                hash_results = await self.api.search_hash(hash_val)
                if hash_results['found']:
                    result_text += f"\n     🎉 Hash decriptato!"
        
        # 8. NUOVO: Ricerca documenti
        if components['documents']:
            result_text += f"\n\n📄 DOCUMENTI TROVATI: {len(components['documents'])}"
            for i, doc in enumerate(components['documents'][:2], 1):
                result_text += f"\n  {i}. {doc}"
                
                # Ricerca documento
                doc_results = await self.api.search_document(doc)
                if doc_results['found']:
                    result_text += f"\n     🔓 Trovato in {doc_results['count']} database"
                    if doc_results['results']:
                        first_result = doc_results['results'][0]
                        if first_result.get('full_name'):
                            result_text += f"\n     👤 Nome: {first_result['full_name']}"
        
        # 9. NUOVO: Ricerca indirizzi
        if components['addresses']:
            result_text += f"\n\n🏠 INDIRIZZI TROVATI: {len(components['addresses'])}"
            for i, address in enumerate(components['addresses'][:2], 1):
                result_text += f"\n  {i}. {address}"
                
                # Cerca se è indirizzo di casa o lavorativo
                if any(word in address.lower() for word in ['ufficio', 'lavoro', 'azienda', 'company']):
                    # Ricerca indirizzo lavorativo
                    work_results = await self.api.search_work_address(address)
                    if work_results['found']:
                        result_text += f"\n     🏢 Indirizzo lavorativo trovato"
                else:
                    # Ricerca indirizzo di casa
                    home_results = await self.api.search_home_address(address)
                    if home_results['found']:
                        result_text += f"\n     🏠 Indirizzo di casa trovato"
        
        # Se nessun componente trovato, cerca come query normale
        total_components = sum(len(v) for v in components.values())
        if total_components == 0:
            result_text += f"\n\n🔍 NESSUNA INFORMAZIONE STRUTTURATA RILEVATA"
            result_text += f"\n📝 Eseguo ricerca standard..."
            
            # Ricerca standard
            search_type = self.detect_search_type(query)
            if search_type == 'email':
                email_results = await self.api.search_email(query)
                if email_results['found']:
                    result_text += f"\n✅ Trovata in {email_results['count']} database"
            elif search_type == 'phone':
                phone_results = await self.api.search_phone(query)
                if phone_results['found']:
                    result_text += f"\n✅ Trovato in {phone_results['count']} database"
            elif search_type == 'name':
                name_results = await self.api.search_name(query)
                if name_results['found']:
                    result_text += f"\n✅ Trovato in {name_results['count']} record"
            elif search_type == 'document':
                doc_results = await self.api.search_document(query)
                if doc_results['found']:
                    result_text += f"\n✅ Trovato in {doc_results['count']} database"
            elif search_type == 'address':
                # Prova entrambi i tipi di indirizzo
                home_results = await self.api.search_home_address(query)
                work_results = await self.api.search_work_address(query)
                if home_results['found'] or work_results['found']:
                    result_text += f"\n✅ Indirizzo trovato"
            else:
                # Ricerca combinata
                variant_results = await self.api.search_variants(query)
                found_any = any(len(v) > 0 for v in variant_results.values())
                if found_any:
                    result_text += f"\n✅ Risultati trovati"
        
        # Informazioni di correlazione
        if total_components >= 2:
            result_text += f"\n\n🔗 CORRELAZIONI TROVATE:"
            result_text += f"\n📊 Componenti identificati: {total_components}"
            
            # Cerca correlazioni nel database
            correlations = []
            
            # Cerca per combinazioni email + telefono
            if components['emails'] and components['phones']:
                for email in components['emails'][:1]:
                    for phone in components['phones'][:1]:
                        # Cerca nel database
                        c.execute('''SELECT COUNT(*) FROM breach_data WHERE 
                                    (email = ? OR phone = ?) AND 
                                    (email = ? OR phone = ?)''',
                                 (email, email, phone, phone))
                        count = c.fetchone()[0]
                        if count > 0:
                            correlations.append(f"📧 {email} ↔ 📱 {phone}")
            
            # Cerca per combinazioni nome + telefono
            if components['names'] and components['phones']:
                for name in components['names'][:1]:
                    for phone in components['phones'][:1]:
                        # Cerca nel database Facebook leaks
                        phone_clean = re.sub(r'[^\d+]', '', phone)[-10:]
                        c.execute('''SELECT COUNT(*) FROM facebook_leaks WHERE 
                                    phone LIKE ? AND (name LIKE ? OR surname LIKE ?)''',
                                 (f'%{phone_clean}%', f'%{name[:5]}%', f'%{name[:5]}%'))
                        count = c.fetchone()[0]
                        if count > 0:
                            correlations.append(f"👤 {name[:15]}... ↔ 📱 {phone}")
            
            # NUOVO: Cerca per combinazioni documento + nome
            if components['documents'] and components['names']:
                for doc in components['documents'][:1]:
                    for name in components['names'][:1]:
                        c.execute('''SELECT COUNT(*) FROM addresses_documents WHERE 
                                    document_number LIKE ? AND full_name LIKE ?''',
                                 (f'%{doc}%', f'%{name}%'))
                        count = c.fetchone()[0]
                        if count > 0:
                            correlations.append(f"📄 {doc} ↔ 👤 {name[:15]}...")
            
            if correlations:
                for corr in correlations[:3]:
                    result_text += f"\n  - {corr}"
            else:
                result_text += f"\n  - Nessuna correlazione diretta trovata"
        
        # MODIFICATO: 2 crediti invece di 0.5
        result_text += f"\n\n💰 Crediti usati: 2.0"
        result_text += f"\n💳 Saldo: {self.get_user_balance(user_id):.1f}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n---\n{data_italiana}"
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    # ============ COMANDI AGGIUNTIVI ============
    
    async def menu_completo(self, update: Update, context: CallbackContext):
        """Mostra il menu completo"""
        user_id = update.effective_user.id
        
        # Ottieni data in italiano
        now = datetime.now()
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        menu_text = f"""📝 RICERCHE COMPOSTE SUPPORTATE:

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
📊 Ricerche effettuate: {self.get_user_searches(user_id)}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        keyboard = [[InlineKeyboardButton("🔙 Indietro", callback_data='back_to_main')]]
        
        if update.callback_query:
            await update.callback_query.edit_message_text(menu_text, reply_markup=InlineKeyboardMarkup(keyboard))
        else:
            await update.message.reply_text(menu_text, reply_markup=InlineKeyboardMarkup(keyboard))
    
    async def balance_command(self, update: Update, context: CallbackContext):
        """Mostra il saldo crediti"""
        user_id = update.effective_user.id
        balance = self.get_user_balance(user_id)
        searches = self.get_user_searches(user_id)
        
        now = datetime.now()
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        text = f"""💰 CREDITI DISPONIBILI

💎 Saldo attuale: {balance:.1f} crediti
🔍 Costo per ricerca: 2.0 crediti
📊 Ricerche effettuate: {searches}
🎯 Ricerche disponibili: {int(balance / 2.0)}

🛒 Per acquistare crediti: /buy
🔍 Per una ricerca: invia qualsiasi dato

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        await update.message.reply_text(text)
    
    async def buy_command(self, update: Update, context: CallbackContext):
        """Acquista crediti"""
        # Ora chiama show_shop_interface invece di show_buy_interface
        await self.show_shop_interface(update, context)
    
    async def admin_panel(self, update: Update, context: CallbackContext):
        """Pannello amministrativo"""
        user_id = update.effective_user.id
        
        if user_id != ADMIN_ID:
            await update.message.reply_text("❌ Accesso negato")
            return
        
        # Statistiche
        c.execute('SELECT COUNT(*) FROM users')
        total_users = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM searches')
        total_searches = c.fetchone()[0]
        
        c.execute('SELECT SUM(balance) FROM users')
        total_credits = c.fetchone()[0] or 0
        
        now = datetime.now()
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        admin_text = f"""🛡️ PANNELLO AMMINISTRATIVO

📊 Statistiche:
· 👥 Utenti totali: {total_users}
· 🔍 Ricerche totali: {total_searches}
· 💎 Credit totali: {total_credits:.1f}

👥 Ultimi 5 utenti:"""
        
        c.execute('SELECT user_id, username, balance, searches FROM users ORDER BY user_id DESC LIMIT 5')
        users = c.fetchall()
        
        for user in users:
            admin_text += f"\n\n- 👤 ID: {user[0]} | @{user[1] or 'N/A'}"
            admin_text += f"\n  💎 Crediti: {user[2]} | 🔍 Ricerche: {user[3]}"
        
        admin_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        admin_text += f"\n---\n{data_italiana}"
        
        await update.message.reply_text(admin_text)
    
    async def addcredits_command(self, update: Update, context: CallbackContext):
        """Aggiunge crediti a un utente (solo admin)"""
        user_id = update.effective_user.id
        
        if user_id != ADMIN_ID:
            await update.message.reply_text("❌ Accesso negato")
            return
        
        if not context.args or len(context.args) < 2:
            await update.message.reply_text(
                "❌ Uso: /addcredits <user_id> <amount>\n"
                "Esempio: /addcredits 123456789 50.0"
            )
            return
        
        try:
            target_user_id = int(context.args[0])
            amount = float(context.args[1])
            
            # Verifica se l'utente esiste
            c.execute('SELECT * FROM users WHERE user_id = ?', (target_user_id,))
            user = c.fetchone()
            
            if not user:
                await update.message.reply_text(f"❌ Utente {target_user_id} non trovato")
                return
            
            # Aggiungi crediti
            success = self.add_credits(target_user_id, amount)
            
            if success:
                # Ottieni nuovo saldo
                c.execute('SELECT balance FROM users WHERE user_id = ?', (target_user_id,))
                new_balance = c.fetchone()[0]
                
                await update.message.reply_text(
                    f"✅ Aggiunti {amount} crediti all'utente {target_user_id}\n"
                    f"💎 Nuovo saldo: {new_balance:.1f} crediti"
                )
                
                # Notifica l'utente se possibile
                try:
                    await context.bot.send_message(
                        chat_id=target_user_id,
                        text=f"🎉 Hai ricevuto {amount} crediti!\n"
                             f"💎 Saldo attuale: {new_balance:.1f} crediti\n"
                             f"🔍 Ricerche disponibili: {int(new_balance / 2.0)}"
                    )
                except:
                    pass
            else:
                await update.message.reply_text("❌ Errore durante l'aggiunta dei crediti")
                
        except ValueError:
            await update.message.reply_text("❌ Formato non valido. Usa: /addcredits <user_id> <amount>")
        except Exception as e:
            logger.error(f"Add credits error: {e}")
            await update.message.reply_text(f"❌ Errore: {str(e)}")
    
    async def help_command(self, update: Update, context: CallbackContext):
        """Comando help"""
        now = datetime.now()
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        help_text = f"""🤖 COME USARE LEAKOSINTBOT

🔍 INVIA:
· 📧 Email: example@gmail.com
· 📱 Telefono: +393331234567
· 👤 Nome: Mario Rossi
· 👥 Username: shadowplayer
· 🌐 IP: 8.8.8.8
· 🔐 Password: 123qwe
· 🔑 Hash: 5f4dcc3b5aa765d61d8327deb882cf99
· 📄 Documento: AA1234567, 123456789
· 🏠 Indirizzo casa: Via Roma 123, Milano
· 🏢 Indirizzo lavoro: Ufficio Via Torino 45

📊 FORMATI SUPPORTATI:
· 👤 Petrov 📱 79002206090
· 👤 Maxim Sergeevich 🌐 127.0.0.1
· 👤 Petrov Maxim Sergeevich 📅 16/02/1995
· 👤 Username 📧 example@gmail.com
· 👤 Nome Cognome 🏙️ Città
· 📄 AA1234567 🏠 Via Roma 123
· 👤 Mario Rossi 📄 123456789

💎 SISTEMA CREDITI:
· 🔍 1 ricerca = 2.0 crediti
· 🎁 Partenza: 10 crediti gratis
· 🛒 Ricarica: /buy

📈 STATISTICHE: /balance
📋 MENU COMPLETO: /menu
🛒 ACQUISTA: /buy
🛡️ ADMIN: /admin (solo admin)
➕ AGGIUNGI CREDITI: /addcredits (solo admin)
🔧 TEST API: /testapi (solo admin)

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        if update.callback_query:
            await update.callback_query.edit_message_text(help_text)
        else:
            await update.message.reply_text(help_text)
    
    async def utf8_command(self, update: Update, context: CallbackContext):
        """Comando per istruzioni UTF-8"""
        now = datetime.now()
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        utf8_text = f"""📄 FORMATO UTF-8 PER FILE

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
   Maxim Sergeevich example@mail.ru
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

💰 COSTO: 2.0 crediti per riga

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await update.message.reply_text(utf8_text)
    
    async def test_api_command(self, update: Update, context: CallbackContext):
        """Testa tutte le API configurate"""
        user_id = update.effective_user.id
        
        if user_id != ADMIN_ID and user_id != update.effective_user.id:
            await update.message.reply_text("❌ Accesso negato")
            return
        
        now = datetime.now()
        
        # Verifica configurazione base
        test_text = f"""🔧 TEST CONFIGURAZIONE API
Data: {now.strftime('%d/%m/%Y %H:%M:%S')}

🤖 TELEGRAM BOT:
- BOT_TOKEN: {'✅ OK' if BOT_TOKEN and len(BOT_TOKEN) > 30 else '❌ ERRORE'}

🔍 API OSINT CONFIGURATE:"""
        
        # Lista API con stato
        apis = [
            ('SHODAN', SHODAN_API_KEY, 'Shodan'),
            ('HUNTER', HUNTER_API_KEY, 'Hunter.io'),
            ('HIBP', HIBP_API_KEY, 'HaveIBeenPwned'),
            ('DEHASHED', DEHASHED_API_KEY, 'Dehashed'),
            ('SNUSBASE', SNUSBASE_API_KEY, 'Snusbase'),
            ('IPINFO', IPINFO_API_KEY, 'IPInfo'),
            ('ABUSEIPDB', ABUSEIPDB_KEY, 'AbuseIPDB'),
            ('LEAKCHECK', LEAKCHECK_API_KEY, 'LeakCheck')
        ]
        
        for env_name, api_key, service_name in apis:
            if api_key and len(api_key) > 10:
                status = f"✅ Configurata ({len(api_key)} caratteri)"
            elif api_key:
                status = f"⚠️ Troppo corta ({len(api_key)} caratteri)"
            else:
                status = "❌ Non configurata"
            test_text += f"\n- {service_name}: {status}"
        
        test_text += f"\n\n📊 DATABASE STATISTICS:"
        c.execute('SELECT COUNT(*) FROM users')
        total_users = c.fetchone()[0]
        test_text += f"\n- Utenti registrati: {total_users}"
        
        c.execute('SELECT COUNT(*) FROM searches')
        total_searches = c.fetchone()[0]
        test_text += f"\n- Ricerche totali: {total_searches}"
        
        c.execute('SELECT SUM(balance) FROM users')
        total_credits = c.fetchone()[0] or 0
        test_text += f"\n- Credit totali: {total_credits}"
        
        # Test connessione API esterne
        test_text += "\n\n🔍 TEST CONNESSIONE API ESTERNE:"
        
        # Test IPInfo (se configurata)
        if IPINFO_API_KEY:
            try:
                test_ip = "8.8.8.8"
                response = self.api.session.get(
                    f'https://ipinfo.io/{test_ip}/json?token={IPINFO_API_KEY}',
                    timeout=10
                )
                if response.status_code == 200:
                    test_text += f"\n- IPInfo: ✅ Connessione OK"
                else:
                    test_text += f"\n- IPInfo: ❌ HTTP {response.status_code}"
            except Exception as e:
                test_text += f"\n- IPInfo: ❌ Errore: {str(e)[:50]}"
        else:
            test_text += "\n- IPInfo: ⚠️ Non configurata"
        
        # Test HIBP (se configurata)
        if HIBP_API_KEY:
            try:
                headers = {'hibp-api-key': HIBP_API_KEY}
                response = self.api.session.get(
                    'https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com',
                    headers=headers,
                    timeout=10
                )
                if response.status_code in [200, 404]:
                    test_text += f"\n- HIBP: ✅ API Key valida"
                elif response.status_code == 401:
                    test_text += f"\n- HIBP: ❌ API Key non valida"
                else:
                    test_text += f"\n- HIBP: ⚠️ HTTP {response.status_code}"
            except Exception as e:
                test_text += f"\n- HIBP: ❌ Errore: {str(e)[:50]}"
        else:
            test_text += "\n- HIBP: ⚠️ Non configurata"
        
        await update.message.reply_text(test_text[:4000])
    
    async def handle_social_search(self, update: Update, context: CallbackContext):
        """Gestisce ricerche social specifiche"""
        user_id = update.effective_user.id
        query = update.message.text.strip()
        
        if not query:
            return
        
        # Verifica crediti - MODIFICATO: 2 crediti invece di 0.5
        if not await self.update_balance(user_id, 2.0):
            await update.message.reply_text(
                "❌ Crediti insufficienti! Usa /buy per acquistare crediti."
            )
            return
        
        # Ottieni data in italiano
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        now = datetime.now()
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        # Crea messaggio di attesa
        wait_text = f"""🔍 Analisi social media in corso...

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        msg = await update.message.reply_text(wait_text)
        
        try:
            # Se la query contiene "telegram" o "tg"
            if "telegram" in query.lower() or "tg" in query.lower():
                clean_query = query.lower().replace("telegram", "").replace("tg", "").strip()
                # Usa la funzione search_social_exact per ora
                await self.search_social_exact(update, msg, clean_query, user_id, data_italiana)
            
            # Se la query contiene "instagram" o "ig"
            elif "instagram" in query.lower() or "ig" in query.lower():
                clean_query = query.lower().replace("instagram", "").replace("ig", "").strip()
                await self.search_social_exact(update, msg, clean_query, user_id, data_italiana)
            
            # Se la query contiene "facebook" o "fb"
            elif "facebook" in query.lower() or "fb" in query.lower():
                clean_query = query.lower().replace("facebook", "").replace("fb", "").strip()
                await self.search_facebook_complete(update, msg, clean_query, user_id, data_italiana)
            
            # Se la query contiene "vk" o "vkontakte"
            elif "vk" in query.lower() or "vkontakte" in query.lower():
                clean_query = query.lower().replace("vk", "").replace("vkontakte", "").strip()
                await self.search_social_exact(update, msg, clean_query, user_id, data_italiana)
            
            else:
                # Ricerca standard
                await self.search_social_exact(update, msg, query, user_id, data_italiana)
            
        except Exception as e:
            logger.error(f"Social search error: {e}")
            error_text = f"""❌ Errore durante la ricerca social
Query: {query}

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
            try:
                await msg.edit_text(error_text)
            except:
                await update.message.reply_text(error_text)
    
    async def handle_document(self, update: Update, context: CallbackContext):
        """Gestisce file di testo per ricerche di massa"""
        user_id = update.effective_user.id
        
        # Verifica se è un documento
        if not update.message.document:
            await update.message.reply_text("❌ Per favore invia un file di testo (.txt)")
            return
        
        document = update.message.document
        
        # Verifica che sia un file di testo
        if not (document.mime_type == 'text/plain' or 
                document.file_name.endswith('.txt')):
            await update.message.reply_text(
                "❌ Formato non supportato. Carica solo file .txt in UTF-8"
            )
            return
        
        # Verifica crediti preliminare - MODIFICATO: 2 crediti invece di 0.5
        if self.get_user_balance(user_id) < 2.0:
            await update.message.reply_text(
                "❌ Crediti insufficienti! Usa /buy per acquistare crediti."
            )
            return
        
        # Ottieni data in italiano per messaggio
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        now = datetime.now()
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        # Messaggio di attesa
        wait_text = f"""📋 ANALISI FILE IN CORSO...

📄 File: {document.file_name}
🔍 Lettura righe...

⏰ {now.hour:02d}:{now.minute:02d}
---
{data_italiana}"""
        
        msg = await update.message.reply_text(wait_text)
        
        try:
            # Scarica il file
            file = await context.bot.get_file(document.file_id)
            file_content = await file.download_as_bytearray()
            
            # Decodifica in UTF-8
            try:
                text = file_content.decode('utf-8')
            except UnicodeDecodeError:
                error_text = f"""❌ ERRORE DECODIFICA

📄 File: {document.file_name}
⚠️ Il file non è in formato UTF-8

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
            
            # Dividi in righe
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            
            if not lines:
                error_text = f"""❌ FILE VUOTO

📄 File: {document.file_name}
⚠️ Il file non contiene righe valide

📌 Formato richiesto:
  · Una query per riga
  · Esempio:
    example@gmail.com
    +79002206090
    Petrov Ivan

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
                await msg.edit_text(error_text)
                return
            
            # Limita a 50 righe per sicurezza
            if len(lines) > 50:
                lines = lines[:50]
                await msg.edit_text(f"⚠️ Limitato a 50 righe (massimo consentito)")
            
            # Calcola costo totale - MODIFICATO: 2 crediti invece di 0.5
            total_cost = len(lines) * 2.0
            current_balance = self.get_user_balance(user_id)
            
            if current_balance < total_cost:
                error_text = f"""❌ CREDITI INSUFFICIENTI

📄 File: {document.file_name}
📊 Righe: {len(lines)}
💰 Costo totale: {total_cost:.1f} crediti
💳 Saldo attuale: {current_balance:.1f} crediti

🔢 Ti servono: {total_cost - current_balance:.1f} crediti in più
🛒 Usa /buy per acquistare crediti

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
                await msg.edit_text(error_text)
                return
            
            # Deduci crediti
            await self.update_balance(user_id, total_cost)
            
            # Processa le righe
            all_results = []
            success_count = 0
            error_count = 0
            
            for i, line in enumerate(lines, 1):
                try:
                    # Determina tipo di ricerca
                    search_type = self.detect_search_type(line)
                    
                    # Esegui ricerca
                    if search_type == 'email':
                        results = await self.api.search_email(line)
                        result_str = f"📧 {line}: {'✅ TROVATI' if results['found'] else '❌ NON TROVATI'} ({results['count']})"
                    elif search_type == 'phone':
                        results = await self.api.search_phone(line)
                        result_str = f"📱 {line}: {'✅ TROVATI' if results['found'] else '❌ NON TROVATI'} ({results['count']})"
                    elif search_type == 'name':
                        results = await self.api.search_name(line)
                        result_str = f"👤 {line}: {'✅ TROVATI' if results['found'] else '❌ NON TROVATI'} ({results['count']})"
                    elif search_type == 'username':
                        results = await self.api.search_username(line)
                        result_str = f"👥 {line}: {'✅ TROVATI' if results['social_count'] > 0 else '❌ NON TROVATI'}"
                    elif search_type == 'document':
                        results = await self.api.search_document(line)
                        result_str = f"📄 {line}: {'✅ TROVATI' if results['found'] else '❌ NON TROVATI'} ({results['count']})"
                    elif search_type == 'address':
                        results_home = await self.api.search_home_address(line)
                        results_work = await self.api.search_work_address(line)
                        found = results_home['found'] or results_work['found']
                        result_str = f"🏠/🏢 {line}: {'✅ TROVATI' if found else '❌ NON TROVATI'}"
                    else:
                        results = await self.api.search_variants(line)
                        result_str = f"🔍 {line}: {'✅ RISULTATI' if any(r for r in results.values()) else '❌ NESSUNO'}"
                    
                    all_results.append(f"{i}. {result_str}")
                    success_count += 1
                    
                    # Aggiorna stato ogni 10 righe
                    if i % 10 == 0:
                        progress_text = f"""📋 ANALISI FILE IN CORSO...

📄 File: {document.file_name}
📊 Progresso: {i}/{len(lines)} righe
✅ Successo: {success_count}
❌ Errori: {error_count}

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
                        await msg.edit_text(progress_text)
                        
                except Exception as e:
                    all_results.append(f"{i}. ❌ {line}: Errore ({str(e)[:50]})")
                    error_count += 1
                    continue
            
            # Prepara risultati finali
            result_text = f"""📋 RISULTATI RICERCA DI MASSA

📄 File: {document.file_name}
📊 Righe processate: {len(lines)}
✅ Ricerche riuscite: {success_count}
❌ Errori: {error_count}
💰 Costo totale: {total_cost:.1f} crediti
💳 Nuovo saldo: {self.get_user_balance(user_id):.1f} crediti

📝 RISULTATI DETTAGLIATI:
"""
            
            # Aggiungi risultati (massimo 20 per non superare limite)
            for result in all_results[:20]:
                result_text += f"\n{result}"
            
            if len(all_results) > 20:
                result_text += f"\n\n📌 ... e altre {len(all_results) - 20} righe"
            
            result_text += f"\n\n⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}"
            result_text += f"\n---\n{data_italiana}"
            
            # Invia risultati
            try:
                await msg.edit_text(result_text)
            except:
                # Se troppo lungo, invia in parti
                await msg.delete()
                parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
                for part in parts:
                    await update.message.reply_text(part)
            
            # Log della ricerca
            self.log_search(user_id, f"FILE: {document.file_name}", "mass_search", 
                          f"Righe: {len(lines)}, Successi: {success_count}, Errori: {error_count}")
            
        except Exception as e:
            logger.error(f"Document processing error: {e}")
            error_text = f"""❌ ERRORE PROCESSAMENTO FILE

📄 File: {document.file_name}
⚠️ Errore: {str(e)[:100]}

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
    
    # ============ FUNZIONI DI RICERCA SPECIFICHE (PER COMPATIBILITÀ) ============
    
    async def search_email_exact(self, update: Update, msg, email: str, user_id: int, data_italiana: str):
        """Ricerca email - Formato esatto (per compatibilità)"""
        
        # Esegue ricerca
        search_results = await self.api.search_email(email)
        
        # Usa il nuovo metodo di formattazione
        result_text = self.format_email_results(email, search_results, user_id, data_italiana)
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_phone_exact(self, update: Update, msg, phone: str, user_id: int, data_italiana: str):
        """Ricerca telefono - Formato esatto (per compatibilità)"""
        
        # Ricerca nei data breach
        search_results = await self.api.search_phone(phone)
        
        # Usa il nuovo metodo di formattazione
        result_text = self.format_phone_results(phone, search_results, user_id, data_italiana)
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_name_exact(self, update: Update, msg, name: str, user_id: int, data_italiana: str):
        """Ricerca per nome - Formato esatto (per compatibilità)"""
        
        # Ricerca nei data breach
        search_results = await self.api.search_name(name)
        
        # Usa il nuovo metodo di formattazione
        result_text = self.format_name_results(name, search_results, user_id, data_italiana)
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_social_exact(self, update: Update, msg, username: str, user_id: int, data_italiana: str):
        """Ricerca username - Formato esatto (per compatibilità)"""
        
        # Ricerca social media e data breach
        search_results = await self.api.search_username(username)
        
        # Usa il nuovo metodo di formattazione
        result_text = self.format_username_results(username, search_results, user_id, data_italiana)
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_ip_exact(self, update: Update, msg, ip: str, user_id: int, data_italiana: str):
        """Ricerca IP - Formato esatto (per compatibilità)"""
        
        # Ricerca informazioni IP
        search_results = await self.api.search_ip(ip)
        
        # Usa il nuovo metodo di formattazione
        result_text = self.format_ip_results(ip, search_results, user_id, data_italiana)
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_password_exact(self, update: Update, msg, password: str, user_id: int, data_italiana: str):
        """Ricerca password - Formato esatto (per compatibilità)"""
        
        # Ricerca password
        search_results = await self.api.search_password(password)
        
        # Usa il nuovo metodo di formattazione
        result_text = self.format_password_results(password, search_results, user_id, data_italiana)
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_hash_exact(self, update: Update, msg, hash_str: str, user_id: int, data_italiana: str):
        """Ricerca hash - Formato esatto (per compatibilità)"""
        
        # Ricerca hash
        search_results = await self.api.search_hash(hash_str)
        
        # Usa il nuovo metodo di formattazione
        result_text = self.format_hash_results(hash_str, search_results, user_id, data_italiana)
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_document_exact(self, update: Update, msg, document: str, user_id: int, data_italiana: str):
        """Ricerca documento - Formato esatto come immagini (per compatibilità)"""
        
        # Esegue ricerca
        search_results = await self.api.search_document(document)
        
        # Usa il nuovo metodo di formattazione
        result_text = self.format_document_results(document, search_results, user_id, data_italiana)
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_address_exact(self, update: Update, msg, address: str, user_id: int, data_italiana: str):
        """Ricerca indirizzo - Formato esatto come immagini (per compatibilità)"""
        
        # Determina se è indirizzo di casa o lavorativo
        is_work_address = any(word in address.lower() for word in ['ufficio', 'lavoro', 'azienda', 'company', 'sede'])
        
        if is_work_address:
            # Ricerca indirizzo lavorativo
            search_results = await self.api.search_work_address(address)
            home_results = {'found': False, 'results': []}
        else:
            # Ricerca indirizzo di casa
            search_results = await self.api.search_home_address(address)
            work_results = {'found': False, 'results': []}
        
        # Usa il nuovo metodo di formattazione
        result_text = self.format_address_results(address, search_results, {'found': False, 'results': []}, user_id, data_italiana)
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_facebook_complete(self, update: Update, msg, query: str, user_id: int, data_italiana: str):
        """Ricerca Facebook completa (per compatibilità)"""
        
        now = datetime.now()
        
        # Messaggio iniziale
        result_text = f"""📘 RICERCA FACEBOOK COMPLETA
- {query} - Analisi in corso..."""
        
        try:
            await msg.edit_text(result_text)
        except:
            pass
        
        all_results = {
            'by_name': [],
            'by_phone': [],
            'by_email': [],
            'by_id': [],
            'leaks': []
        }
        
        # 1. Determina tipo di query
        if '@' in query:
            # Ricerca per email
            email_results = await self.api.search_facebook_by_email(query)
            all_results['by_email'] = email_results['results']
        elif re.match(r'^[\d\s\-\+\(\)]{8,}$', query.replace(' ', '')):
            # Ricerca per telefono
            phone_results = await self.api.search_facebook_by_phone(query)
            all_results['by_phone'] = phone_results['results']
        elif query.isdigit():
            # Ricerca per ID
            id_results = await self.api.search_facebook_by_id(query)
            all_results['by_id'] = id_results['results']
        else:
            # Ricerca per nome
            advanced_results = await self.api.search_facebook_advanced(query)
            all_results['by_name'] = advanced_results['leak_data']
            all_results['leaks'] = advanced_results['leak_data']
        
        # Costruisci risultato finale
        result_text = f"""📘 RISULTATI RICERCA FACEBOOK
- Query: {query}"""
        
        total_results = 0
        
        # 1. Risultati da data breach
        leak_results = []
        leak_results.extend(all_results['by_name'])
        leak_results.extend(all_results['by_phone'])
        leak_results.extend(all_results['by_email'])
        leak_results.extend(all_results['by_id'])
        
        if leak_results:
            unique_leaks = []
            seen = set()
            for item in leak_results:
                identifier = f"{item.get('facebook_id', '')}-{item.get('phone', '')}-{item.get('email', '')}"
                if identifier not in seen:
                    seen.add(identifier)
                    unique_leaks.append(item)
            
            if unique_leaks:
                total_results = len(unique_leaks)
                result_text += f"\n\n🔓 DATI TROVATI IN DATA BREACH: {total_results}"
                
                for i, leak in enumerate(unique_leaks[:3], 1):
                    result_text += f"\n\n  {i}. 📊 {leak.get('source', 'Database')}"
                    
                    if leak.get('name'):
                        result_text += f"\n     👤 Nome: {leak['name']}"
                    
                    if leak.get('facebook_id'):
                        result_text += f"\n     🆔 Facebook ID: {leak['facebook_id']}"
                        result_text += f"\n     🔗 Profilo: https://facebook.com/{leak['facebook_id']}"
                    
                    if leak.get('phone'):
                        result_text += f"\n     📱 Telefono: {leak['phone']}"
                    
                    if leak.get('email'):
                        result_text += f"\n     📧 Email: {leak['email']}"
                    
                    if leak.get('password'):
                        result_text += f"\n     🔐 Password: {leak['password']}"
                    
                    if leak.get('city'):
                        result_text += f"\n     🏙️ Città: {leak['city']}"
                    
                    if leak.get('birth_date'):
                        result_text += f"\n     🎂 Nascita: {leak['birth_date']}"
        
        # 2. Ricerca pubblica (solo se nome)
        if ' ' in query and not query.isdigit() and '@' not in query:
            try:
                # Usa motori di ricerca
                search_url = f"https://www.google.com/search?q=site:facebook.com+{quote_plus(query)}"
                result_text += f"\n\n🔍 RICERCA PUBBLICA:"
                result_text += f"\n  - Google: {search_url}"
                
                bing_url = f"https://www.bing.com/search?q=site%3Afacebook.com+{quote_plus(query)}"
                result_text += f"\n  - Bing: {bing_url}"
            except:
                pass
        
        if total_results == 0:
            result_text += f"\n\n❌ NESSUN RISULTATO DIRETTO"
            result_text += f"\n📘 Facebook ha limitato le ricerche pubbliche."
            result_text += f"\n💡 Suggerimenti:"
            result_text += f"\n  - Cerca con numero telefono: +39XXXXXXXXXX"
            result_text += f"\n  - Cerca con email: nome.cognome@gmail.com"
            result_text += f"\n  - Cerca con ID Facebook: 1000XXXXXXX"
        
        # 3. Metodi alternativi
        result_text += f"\n\n🔄 METODI ALTERNATIVI:"
        result_text += f"\n  - 🔍 Cerca su Google: 'site:facebook.com {query}'"
        result_text += f"\n  - 📱 Cerca su Bing: 'site:facebook.com {query}'"
        result_text += f"\n  - 👥 Cerca su LinkedIn"
        result_text += f"\n  - 📧 Cerca con email associata"
        
        # MODIFICATO: 2 crediti invece di 0.5
        result_text += f"\n\n💰 Crediti usati: 2.0"
        result_text += f"\n💳 Saldo: {self.get_user_balance(user_id):.1f}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n---\n{data_italiana}"
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)

# ==================== FUNZIONE PER CARICARE DATI FACEBOOK LEAKS ====================

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
                    reader = csv.reader(f)
                    header = next(reader, None)  # Skip header if exists
                    
                    count = 0
                    for row in reader:
                        if len(row) >= 11:
                            c.execute('''INSERT OR IGNORE INTO facebook_leaks 
                                       (phone, facebook_id, name, surname, gender, birth_date, city, country, company, relationship_status, leak_date)
                                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', row[:11])
                            count += 1
                    
                    conn.commit()
                    logger.info(f"✅ Facebook leaks data loaded from {file_path}: {count} records")
                    return True
        
        logger.warning("⚠️ No Facebook leaks data file found")
        return False
        
    except Exception as e:
        logger.error(f"Error loading Facebook leaks: {e}")
        return False

# ==================== FUNZIONE PER CARICARE DATI DOCUMENTI E INDIRIZZI ====================

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
                    reader = csv.reader(f)
                    header = next(reader, None)  # Skip header if exists
                    
                    count = 0
                    for row in reader:
                        if len(row) >= 10:  # Assicurati che ci siano abbastanza colonne
                            c.execute('''INSERT OR IGNORE INTO addresses_documents 
                                       (document_number, document_type, full_name, home_address, work_address, 
                                        city, country, phone, email, source)
                                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', row[:10])
                            count += 1
                    
                    conn.commit()
                    logger.info(f"✅ Addresses/documents data loaded from {file_path}: {count} records")
                    return True
        
        # Se non ci sono file, crea alcuni dati di esempio
        logger.info("⚠️ No addresses/documents data file found, creating sample data")
        
        # Dati di esempio (per testing)
        sample_data = [
            ('AA1234567', 'Carta Identità', 'Mario Rossi', 'Via Roma 123', 'Ufficio Via Torino 45', 
             'Milano', 'Italia', '+393331234567', 'mario.rossi@email.com', 'Sample Database'),
            ('123456789', 'Codice Fiscale', 'Luigi Bianchi', 'Corso Vittorio 78', 'Azienda Via Milano 10',
             'Roma', 'Italia', '+393332345678', 'luigi.bianchi@email.com', 'Sample Database'),
            ('BB9876543', 'Passaporto', 'Giuseppe Verdi', 'Piazza Duomo 1', 'Sede Via Garibaldi 25',
             'Firenze', 'Italia', '+393333456789', 'giuseppe.verdi@email.com', 'Sample Database')
        ]
        
        for data in sample_data:
            c.execute('''INSERT OR IGNORE INTO addresses_documents 
                       (document_number, document_type, full_name, home_address, work_address, 
                        city, country, phone, email, source)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', data)
        
        conn.commit()
        logger.info(f"✅ Sample addresses/documents data created: {len(sample_data)} records")
        return True
        
    except Exception as e:
        logger.error(f"Error loading addresses/documents: {e}")
        return False

# ==================== FUNZIONI WEBHOOK PER RENDER ====================

def start_webhook():
    """Avvia bot in modalità webhook per Render"""
    from telegram.ext import ApplicationBuilder
    
    bot = LeakosintBot()
    application = ApplicationBuilder().token(BOT_TOKEN).build()
    
    # Configura webhook
    webhook_url = os.environ.get('WEBHOOK_URL', '')
    port = int(os.environ.get('PORT', 10000))
    
    if webhook_url:
        application.run_webhook(
            listen="0.0.0.0",
            port=port,
            url_path=BOT_TOKEN,
            webhook_url=f"{webhook_url}/{BOT_TOKEN}"
        )
    else:
        logger.error("❌ WEBHOOK_URL non configurata per modalità Render")
        sys.exit(1)

def start_polling():
    """Avvia bot in modalità polling per sviluppo"""
    bot = LeakosintBot()
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Handler comandi
    application.add_handler(CommandHandler("start", bot.start))
    application.add_handler(CommandHandler("menu", bot.menu_completo))
    application.add_handler(CommandHandler("balance", bot.balance_command))
    application.add_handler(CommandHandler("buy", bot.buy_command))
    application.add_handler(CommandHandler("admin", bot.admin_panel))
    application.add_handler(CommandHandler("addcredits", bot.addcredits_command))
    application.add_handler(CommandHandler("help", bot.help_command))
    application.add_handler(CommandHandler("utf8", bot.utf8_command))
    application.add_handler(CommandHandler("testapi", bot.test_api_command))
    
    # Handler per callback dei pulsanti inline
    application.add_handler(CallbackQueryHandler(bot.handle_button_callback))
    
    # Handler per ricerche social specifiche
    application.add_handler(MessageHandler(
        filters.Regex(r'(?i)(telegram|instagram|facebook|vk|tg|ig|fb|vkontakte)') & ~filters.COMMAND,
        bot.handle_social_search
    ))
    
    # Handler per documenti (ricerca di massa)
    application.add_handler(MessageHandler(
        filters.Document.ALL & ~filters.COMMAND,
        bot.handle_document
    ))
    
    # Handler per messaggi di testo (ricerche normali)
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_message))
    
    # Avvia bot
    logger.info("✅ LeakosintBot avviato con successo con interfaccia a pulsanti!")
    logger.info("✅ Modifiche applicate: shop💸, help❓, crypto payment, user details")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

# ==================== MAIN MIGLIORATO ====================

def main():
    """Funzione principale - VERSIONE MIGLIORATA"""
    try:
        logger.info("=" * 60)
        logger.info("🚀 AVVIO LEAKOSINT BOT")
        logger.info("=" * 60)
        
        # Verifica configurazione critica
        if not BOT_TOKEN or BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
            logger.critical("❌ BOT_TOKEN non configurato!")
            sys.exit(1)
        
        logger.info(f"🤖 Bot Token: {BOT_TOKEN[:10]}...{BOT_TOKEN[-5:]}")
        logger.info(f"👑 Admin ID: {ADMIN_ID}")
        
        # Verifica API configurate
        logger.info("🔧 API CONFIGURATE:")
        
        critical_apis = [
            ('DEHASHED_EMAIL', DEHASHED_EMAIL),
            ('DEHASHED_API_KEY', DEHASHED_API_KEY),
            ('HIBP_API_KEY', HIBP_API_KEY),
            ('SNUSBASE_API_KEY', SNUSBASE_API_KEY)
        ]
        
        for name, key in critical_apis:
            if key and len(key) > 10 and key != f"YOUR_REAL_{name}":
                logger.info(f"  ✅ {name}: Configurata ({len(key)} caratteri)")
            elif key and key != f"YOUR_REAL_{name}":
                logger.warning(f"  ⚠️ {name}: Troppo corta ({len(key)} caratteri)")
            else:
                logger.warning(f"  ❌ {name}: Non configurata")
        
        # Carica dati
        logger.info("📥 Caricamento database...")
        load_facebook_leaks_data()
        load_addresses_documents_data()
        
        # Avvio bot
        if os.environ.get('RENDER'):
            logger.info("🎯 Modalità Render attivata")
            start_webhook()
        else:
            logger.info("🏠 Modalità sviluppo attivata")
            start_polling()
            
    except Exception as e:
        logger.critical(f"❌ ERRORE CRITICO AVVIO: {e}")
        import traceback
        logger.critical(traceback.format_exc())
        sys.exit(1)

if __name__ == '__main__':
    main()
