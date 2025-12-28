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
import threading
import time
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
from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import pooling

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

# ==================== CONFIGURAZIONE DATABASE TIDB ====================
# TiDB Cloud connection settings (MySQL compatible)
TIDB_HOST = os.environ.get('TIDB_HOST', 'localhost')
TIDB_PORT = os.environ.get('TIDB_PORT', '4000')
TIDB_USER = os.environ.get('TIDB_USER', 'root')
TIDB_PASSWORD = os.environ.get('TIDB_PASSWORD', '')
TIDB_DATABASE = os.environ.get('TIDB_DATABASE', 'test')

# ==================== CONFIGURAZIONE DATABASE WEBHOST ====================
# Secondo database TiDB per webhost_data
WEBHOST_HOST = os.environ.get('WEBHOST_HOST', TIDB_HOST)  # Usa stesso host se non specificato
WEBHOST_PORT = os.environ.get('WEBHOST_PORT', TIDB_PORT)
WEBHOST_USER = os.environ.get('WEBHOST_USER', TIDB_USER)
WEBHOST_PASSWORD = os.environ.get('WEBHOST_PASSWORD', TIDB_PASSWORD)
WEBHOST_DATABASE = os.environ.get('WEBHOST_DATABASE', 'webhost_data')

# ==================== CONFIGURAZIONE API ====================
BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
if not BOT_TOKEN:
    logger.error("❌ BOT_TOKEN non configurato! Configura la variabile d'ambiente TELEGRAM_BOT_TOKEN")
    sys.exit(1)

ADMIN_ID = int(os.environ.get('ADMIN_ID', 0))

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
        
        # Testi di ricerca
        'search_menu_title': '🔍 Puoi cercare i seguenti dati:',
        'search_email': '📧 Cerca per posta',
        'search_name': '👤 Cerca per nome o nick',
        'search_phone': '📱 Cerca per numero di telefono',
        'search_document': '📄 Cerca per documento',
        'search_home_address': '🏠 Cerca per indirizzo di casa',
        'search_work_address': '🏢 Cerca per indirizzo lavorativo',
        'search_password': '🔐 Ricerca password',
        'search_telegram': '📱 Cerca un account Telegram',
        'search_facebook': '📘 Cerca l\'account Facebook',
        'search_vk': '🔵 Cerca l\'account VKontakte',
        'search_instagram': '📸 Cerca account Instagram',
        'search_ip': '🌐 Cerca tramite IP',
        'search_mass': '📋 Ricerca di massa: /utf8 per istruzioni',
        'search_composite': '📝 Le richieste composite in tutti i formati sono supportate:',
        
        # Impostazioni
        'settings_title': '⚙️ IMPOSTAZIONI UTENTE',
        'personal_info': '👤 Informazioni Personali:',
        'credit_system': '💳 Sistema Crediti:',
        'configurations': '⚙️ Configurazioni:',
        'today_stats': '📊 Statistiche odierne:',
        
        # Shop
        'shop_title': 'shop💸 - ACQUISTA CREDITI CON CRYPTO',
        'credit_packages': '💎 PACCHETTI CREDITI:',
        'payment_addresses': '🔗 INDIRIZZI DI PAGAMENTO:',
        'conversion': '📊 CONVERSIONE:',
        'discounts': '🎁 SCONTI:',
        'how_to_buy': '📝 COME ACQUISTARE:',
        'warnings': '⚠️ AVVERTENZE:',
        'support': '📞 SUPPORTO:',
        
        # Menu completo
        'menu_title': '📝 RICERCHE COMPOSTE SUPPORTATE:',
        'composite_examples': '📌 Esempi di ricerche composte:',
        'combine_what': '🔍 PUOI COMBINARE:',
        'mass_search': '📋 RICERCA DI MASSA:',
        
        # Bot risposte
        'processing': '🔍 Analisi in corso...',
        'no_results': '❌ NESSUN RISULTATO',
        'credits_used': '💰 Crediti usati:',
        'balance': '💳 Saldo:',
        'insufficient_credits': '❌ Crediti insufficienti! Usa /buy per acquistare crediti.',
        'error': '❌ Errore durante la ricerca',
        
        # Conferma cambio lingua
        'lang_changed': '✅ Lingua impostata su {lang_name} 🇮🇹\n\nTutti i menu e i messaggi saranno ora in italiano.'
    },
    'en': {
        'language': 'English 🇬🇧',
        'main_menu': '# I can search everything. Send me your request.🔍\n\nFind what they hide🕵🏻‍♂️\n\n•🔍 Search\n\n•shop💸\n\n•⚙️ Settings\n\n•📋 Menu\n\n•help❓',
        'search': '🔍 Search',
        'shop': 'shop💸',
        'settings': '⚙️ Settings',
        'menu': '📋 Menu',
        'help': 'help❓',
        'language_btn': '🌐 Language',
        'back': '🔙 Back',
        'buy_20': '💳 Buy 20 credits',
        'buy_50': '💳 Buy 50 credits',
        'buy_100': '💳 Buy 100 credits',
        'buy_200': '💳 Buy 200 credits',
        'buy_500': '💳 Buy 500 credits',
        'buy_1000': '💳 Buy 1000 credits',
        
        # Testi di ricerca
        'search_menu_title': '🔍 You can search for the following data:',
        'search_email': '📧 Search by email',
        'search_name': '👤 Search by name or nickname',
        'search_phone': '📱 Search by phone number',
        'search_document': '📄 Search by document',
        'search_home_address': '🏠 Search by home address',
        'search_work_address': '🏢 Search by work address',
        'search_password': '🔐 Password search',
        'search_telegram': '📱 Search Telegram account',
        'search_facebook': '📘 Search Facebook account',
        'search_vk': '🔵 Search VKontakte account',
        'search_instagram': '📸 Search Instagram account',
        'search_ip': '🌐 Search by IP',
        'search_mass': '📋 Mass search: /utf8 for instructions',
        'search_composite': '📝 Composite requests in all formats are supported:',
        
        # Impostazioni
        'settings_title': '⚙️ USER SETTINGS',
        'personal_info': '👤 Personal Information:',
        'credit_system': '💳 Credit System:',
        'configurations': '⚙️ Configurations:',
        'today_stats': '📊 Today\'s statistics:',
        
        # Shop
        'shop_title': 'shop💸 - BUY CREDITS WITH CRYPTO',
        'credit_packages': '💎 CREDIT PACKAGES:',
        'payment_addresses': '🔗 PAYMENT ADDRESSES:',
        'conversion': '📊 CONVERSION:',
        'discounts': '🎁 DISCOUNTS:',
        'how_to_buy': '📝 HOW TO BUY:',
        'warnings': '⚠️ WARNINGS:',
        'support': '📞 SUPPORT:',
        
        # Menu completo
        'menu_title': '📝 COMPOSITE SEARCHES SUPPORTED:',
        'composite_examples': '📌 Composite search examples:',
        'combine_what': '🔍 YOU CAN COMBINE:',
        'mass_search': '📋 MASS SEARCH:',
        
        # Bot risposte
        'processing': '🔍 Analysis in progress...',
        'no_results': '❌ NO RESULTS',
        'credits_used': '💰 Credits used:',
        'balance': '💳 Balance:',
        'insufficient_credits': '❌ Insufficient credits! Use /buy to buy credits.',
        'error': '❌ Error during search',
        
        # Conferma cambio lingua
        'lang_changed': '✅ Language set to {lang_name} 🇬🇧\n\nAll menus and messages will now be in English.'
    }
}

# Database setup - TiDB Cloud (MySQL compatible)
class DatabaseManager:
    def __init__(self):
        self.connection_pool = None
        self.webhost_connection_pool = None  # Nuovo pool per webhost_data
        self.init_connection_pool()
        self.init_webhost_connection_pool()  # Inizializza secondo pool
        self.init_tables()
        
        # DEBUG: Verifica la tabella
        self.debug_users_mvvidster()
        self.debug_webhost_tables()  # Debug per webhost_data
    
    def init_connection_pool(self):
        try:
            self.connection_pool = pooling.MySQLConnectionPool(
                pool_name="leakosint_pool",
                pool_size=5,
                pool_reset_session=True,
                host=TIDB_HOST,
                port=int(TIDB_PORT),
                user=TIDB_USER,
                password=TIDB_PASSWORD,
                database=TIDB_DATABASE,
                autocommit=False
            )
            logger.info("✅ Database connection pool initialized")
        except Exception as e:
            logger.error(f"❌ Error initializing database connection pool: {e}")
            sys.exit(1)
    
    def init_webhost_connection_pool(self):
        """Inizializza il pool di connessioni per il database webhost_data"""
        try:
            self.webhost_connection_pool = pooling.MySQLConnectionPool(
                pool_name="webhost_pool",
                pool_size=3,
                pool_reset_session=True,
                host=WEBHOST_HOST,
                port=int(WEBHOST_PORT),
                user=WEBHOST_USER,
                password=WEBHOST_PASSWORD,
                database=WEBHOST_DATABASE,
                autocommit=False
            )
            logger.info("✅ Webhost database connection pool initialized")
        except Exception as e:
            logger.error(f"❌ Error initializing webhost database connection pool: {e}")
            # Non blocchiamo l'app se il secondo database non è disponibile
            self.webhost_connection_pool = None
    
    def get_connection(self):
        try:
            return self.connection_pool.get_connection()
        except Exception as e:
            logger.error(f"❌ Error getting database connection: {e}")
            # Try to reconnect
            self.init_connection_pool()
            return self.connection_pool.get_connection()
    
    def get_webhost_connection(self):
        """Ottiene una connessione al database webhost_data"""
        if not self.webhost_connection_pool:
            self.init_webhost_connection_pool()
            if not self.webhost_connection_pool:
                return None
        
        try:
            return self.webhost_connection_pool.get_connection()
        except Exception as e:
            logger.error(f"❌ Error getting webhost database connection: {e}")
            return None
    
    def execute_query(self, query, params=None, fetchone=False, fetchall=False, commit=False):
        conn = self.get_connection()
        cursor = conn.cursor()
        result = None
        
        try:
            cursor.execute(query, params or ())
            
            if commit:
                conn.commit()
            
            if fetchone:
                result = cursor.fetchone()
            elif fetchall:
                result = cursor.fetchall()
            else:
                result = cursor.lastrowid if query.strip().upper().startswith('INSERT') else cursor.rowcount
                
        except Exception as e:
            logger.error(f"❌ Database query error: {e}")
            logger.error(f"Query: {query}")
            logger.error(f"Params: {params}")
            if conn:
                conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()
        
        return result
    
    def execute_webhost_query(self, query, params=None, fetchone=False, fetchall=False, commit=False):
        """Esegue una query sul database webhost_data"""
        conn = self.get_webhost_connection()
        if conn is None:
            logger.error("❌ Webhost database connection not available")
            return None
        
        cursor = conn.cursor()
        result = None
        
        try:
            cursor.execute(query, params or ())
            
            if commit:
                conn.commit()
            
            if fetchone:
                result = cursor.fetchone()
            elif fetchall:
                result = cursor.fetchall()
            else:
                result = cursor.lastrowid if query.strip().upper().startswith('INSERT') else cursor.rowcount
                
        except Exception as e:
            logger.error(f"❌ Webhost database query error: {e}")
            logger.error(f"Query: {query}")
            logger.error(f"Params: {params}")
            if conn:
                conn.rollback()
        finally:
            cursor.close()
            conn.close()
        
        return result

    def debug_webhost_tables(self):
        """Debug delle tabelle nel database webhost_data"""
        try:
            conn = self.get_webhost_connection()
            if conn is None:
                logger.error("❌ Cannot connect to webhost database for debug")
                return
            
            cursor = conn.cursor()
            
            # Ottieni tutte le tabelle
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()
            
            logger.info("📋 Tabelle nel database webhost_data:")
            for table in tables:
                table_name = table[0]
                logger.info(f"  - {table_name}")
                
                # Descrivi la tabella
                cursor.execute(f"DESCRIBE {table_name}")
                columns = cursor.fetchall()
                
                logger.info(f"    Colonne di {table_name}:")
                for col in columns:
                    logger.info(f"      - {col[0]}: {col[1]}")
                
                # Conta i record
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                count = cursor.fetchone()[0]
                logger.info(f"    Record totali: {count}")
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"❌ Errore debug webhost tables: {e}")

    def init_tables(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # Tabelle database
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                user_id BIGINT PRIMARY KEY,
                username VARCHAR(255),
                balance INT DEFAULT 4,
                searches INT DEFAULT 0,
                registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                subscription_type VARCHAR(50) DEFAULT 'free',
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                language VARCHAR(10) DEFAULT 'en'
            )''')
            
            cursor.execute('''CREATE TABLE IF NOT EXISTS searches (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT,
                query TEXT,
                type VARCHAR(50),
                results LONGTEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_id (user_id),
                INDEX idx_timestamp (timestamp)
            )''')
            
            cursor.execute('''CREATE TABLE IF NOT EXISTS breach_data (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255),
                phone VARCHAR(50),
                name VARCHAR(255),
                surname VARCHAR(255),
                username VARCHAR(255),
                password TEXT,
                hash VARCHAR(255),
                source VARCHAR(255),
                breach_name VARCHAR(255),
                breach_date VARCHAR(50),
                found_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_email (email),
                INDEX idx_phone (phone),
                INDEX idx_username (username)
            )''')
            
            cursor.execute('''CREATE TABLE IF NOT EXISTS facebook_leaks (
                id INT AUTO_INCREMENT PRIMARY KEY,
                phone VARCHAR(50),
                facebook_id VARCHAR(100),
                name VARCHAR(255),
                surname VARCHAR(255),
                gender VARCHAR(20),
                birth_date VARCHAR(50),
                city VARCHAR(255),
                country VARCHAR(100),
                company VARCHAR(255),
                relationship_status VARCHAR(50),
                leak_date VARCHAR(50),
                found_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_phone (phone),
                INDEX idx_facebook_id (facebook_id),
                INDEX idx_name (name)
            )''')
            
            # NUOVA TABELLA PER INDIRIZZI E DOCUMENTI
            cursor.execute('''CREATE TABLE IF NOT EXISTS addresses_documents (
                id INT AUTO_INCREMENT PRIMARY KEY,
                document_number VARCHAR(100),
                document_type VARCHAR(100),
                full_name VARCHAR(255),
                home_address TEXT,
                work_address TEXT,
                city VARCHAR(255),
                country VARCHAR(100),
                phone VARCHAR(50),
                email VARCHAR(255),
                source VARCHAR(255),
                found_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_document (document_number),
                INDEX idx_phone (phone),
                INDEX idx_email (email)
            )''')
            
            # NUOVA TABELLA users_mvvidster
            cursor.execute('''CREATE TABLE IF NOT EXISTS users_mvvidster (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT,
                disp_name VARCHAR(255),
                reg_date DATETIME,
                profile_photo INT DEFAULT 0,
                email VARCHAR(255),
                original_id BIGINT,
                phone VARCHAR(50),  # Aggiungi se vuoi
                city VARCHAR(255),  # Aggiungi se vuoi
                country VARCHAR(100),  # Aggiungi se vuoi
                found_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_id (user_id),
                INDEX idx_disp_name (disp_name),
                INDEX idx_email (email),
                INDEX idx_reg_date (reg_date)
            )''')
            
            conn.commit()
            logger.info("✅ Database tables initialized successfully")
        except Exception as e:
            logger.error(f"❌ Error initializing database tables: {e}")
            conn.rollback()
        finally:
            cursor.close()
            conn.close()
    
    def debug_users_mvvidster(self):
        """Debug della tabella users_mvvidster"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Conta i record
            cursor.execute("SELECT COUNT(*) FROM users_mvvidster")
            count = cursor.fetchone()[0]
            logger.info(f"✅ Totale record in users_mvvidster: {count}")
            
            # Mostra struttura
            cursor.execute("DESCRIBE users_mvvidster")
            columns = cursor.fetchall()
            
            logger.info("📋 Struttura users_mvvidster:")
            for col in columns:
                logger.info(f"  - {col[0]}: {col[1]}")
            
            # Mostra qualche dato di esempio
            cursor.execute('''SELECT id, user_id, disp_name, email, reg_date 
                            FROM users_mvvidster LIMIT 5''')
            rows = cursor.fetchall()
            
            logger.info("📊 Esempi di dati:")
            for row in rows:
                logger.info(f"  ID:{row[0]} UserID:{row[1]} Name:'{row[2]}' Email:'{row[3]}' Date:{row[4]}")
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"❌ Errore debug users_mvvidster: {e}")

    def search_users_mvvidster_all_fields(self, search_term: str):
        """Cerca nella tabella users_mvvidster in tutti i campi"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Prepara la query per cercare in tutti i campi rilevanti
            query = '''
                SELECT * FROM users_mvvidster 
                WHERE 
                    disp_name LIKE %s OR
                    email LIKE %s OR
                    user_id LIKE %s OR
                    reg_date LIKE %s OR
                    original_id LIKE %s
                LIMIT 20
            '''
            
            search_pattern = f'%{search_term}%'
            cursor.execute(query, (search_pattern, search_pattern, search_pattern, 
                                 search_pattern, search_pattern))
            
            results = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            return results
            
        except Exception as e:
            logger.error(f"Errore ricerca users_mvvidster: {e}")
            return []

    def search_webhost_data(self, search_term: str):
        """Cerca nei database webhost_data in tutte le tabelle e colonne"""
        results = []
        
        try:
            conn = self.get_webhost_connection()
            if conn is None:
                return results
            
            cursor = conn.cursor()
            
            # Ottieni tutte le tabelle
            cursor.execute("SHOW TABLES")
            tables = [table[0] for table in cursor.fetchall()]
            
            search_pattern = f'%{search_term}%'
            
            for table in tables:
                try:
                    # Ottieni le colonne della tabella
                    cursor.execute(f"SHOW COLUMNS FROM {table}")
                    columns = [column[0] for column in cursor.fetchall()]
                    
                    # Costruisci la query per cercare in tutte le colonne
                    if columns:
                        # Filtra solo colonne di tipo testo (varchar, text, ecc.)
                        text_columns = []
                        for col in columns:
                            cursor.execute(f"SELECT DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = %s AND COLUMN_NAME = %s", (table, col))
                            data_type = cursor.fetchone()
                            if data_type and any(t in data_type[0].lower() for t in ['char', 'text', 'varchar']):
                                text_columns.append(col)
                        
                        if text_columns:
                            # Crea le condizioni OR per ogni colonna di testo
                            conditions = " OR ".join([f"{col} LIKE %s" for col in text_columns])
                            query = f"SELECT * FROM {table} WHERE {conditions} LIMIT 10"
                            
                            # Parametri: search_pattern per ogni colonna
                            params = [search_pattern] * len(text_columns)
                            
                            cursor.execute(query, params)
                            rows = cursor.fetchall()
                            
                            for row in rows:
                                result = {
                                    'source': 'webhost_data',
                                    'table': table,
                                    'search_term': search_term,
                                    'data': {}
                                }
                                
                                # Aggiungi tutti i valori delle colonne
                                for i, col in enumerate(columns):
                                    if i < len(row):
                                        result['data'][col] = row[i]
                                
                                results.append(result)
                                
                except Exception as e:
                    logger.error(f"Errore ricerca nella tabella {table}: {e}")
                    continue
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Errore ricerca webhost_data: {e}")
        
        return results

    def search_webhost_by_email(self, email: str):
        """Cerca email specifica nel database webhost_data"""
        results = []
        
        try:
            conn = self.get_webhost_connection()
            if conn is None:
                return results
            
            cursor = conn.cursor()
            
            # Ottieni tutte le tabelle
            cursor.execute("SHOW TABLES")
            tables = [table[0] for table in cursor.fetchall()]
            
            email_pattern = f'%{email}%'
            
            for table in tables:
                try:
                    # Verifica se la tabella ha una colonna email
                    cursor.execute(f"SHOW COLUMNS FROM {table} LIKE '%email%'")
                    email_columns = cursor.fetchall()
                    
                    if email_columns:
                        # Cerca in tutte le colonne che contengono 'email' nel nome
                        for col_info in email_columns:
                            col_name = col_info[0]
                            query = f"SELECT * FROM {table} WHERE {col_name} LIKE %s LIMIT 10"
                            cursor.execute(query, (email_pattern,))
                            rows = cursor.fetchall()
                            
                            # Ottieni tutti i nomi delle colonne per questa tabella
                            cursor.execute(f"DESCRIBE {table}")
                            all_columns = [col[0] for col in cursor.fetchall()]
                            
                            for row in rows:
                                result = {
                                    'source': 'webhost_data',
                                    'table': table,
                                    'type': 'email',
                                    'email': email,
                                    'data': {}
                                }
                                
                                # Aggiungi tutti i valori delle colonne
                                for i, col in enumerate(all_columns):
                                    if i < len(row):
                                        result['data'][col] = row[i]
                                
                                results.append(result)
                                
                except Exception as e:
                    logger.error(f"Errore ricerca email nella tabella {table}: {e}")
                    continue
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Errore ricerca webhost_by_email: {e}")
        
        return results

    def search_webhost_by_username(self, username: str):
        """Cerca username specifico nel database webhost_data"""
        results = []
        
        try:
            conn = self.get_webhost_connection()
            if conn is None:
                return results
            
            cursor = conn.cursor()
            
            # Ottieni tutte le tabelle
            cursor.execute("SHOW TABLES")
            tables = [table[0] for table in cursor.fetchall()]
            
            username_pattern = f'%{username}%'
            
            for table in tables:
                try:
                    # Verifica se la tabella ha una colonna username
                    cursor.execute(f"SHOW COLUMNS FROM {table} WHERE Field LIKE '%username%' OR Field LIKE '%user%'")
                    username_columns = cursor.fetchall()
                    
                    if username_columns:
                        # Cerca in tutte le colonne che contengono 'username' o 'user' nel nome
                        for col_info in username_columns:
                            col_name = col_info[0]
                            query = f"SELECT * FROM {table} WHERE {col_name} LIKE %s LIMIT 10"
                            cursor.execute(query, (username_pattern,))
                            rows = cursor.fetchall()
                            
                            # Ottieni tutti i nomi delle colonne per questa tabella
                            cursor.execute(f"DESCRIBE {table}")
                            all_columns = [col[0] for col in cursor.fetchall()]
                            
                            for row in rows:
                                result = {
                                    'source': 'webhost_data',
                                    'table': table,
                                    'type': 'username',
                                    'username': username,
                                    'data': {}
                                }
                                
                                # Aggiungi tutti i valori delle colonne
                                for i, col in enumerate(all_columns):
                                    if i < len(row):
                                        result['data'][col] = row[i]
                                
                                results.append(result)
                                
                except Exception as e:
                    logger.error(f"Errore ricerca username nella tabella {table}: {e}")
                    continue
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Errore ricerca webhost_by_username: {e}")
        
        return results

    def search_webhost_by_ip(self, ip: str):
        """Cerca indirizzo IP specifico nel database webhost_data"""
        results = []
        
        try:
            conn = self.get_webhost_connection()
            if conn is None:
                return results
            
            cursor = conn.cursor()
            
            # Ottieni tutte le tabelle
            cursor.execute("SHOW TABLES")
            tables = [table[0] for table in cursor.fetchall()]
            
            ip_pattern = f'%{ip}%'
            
            for table in tables:
                try:
                    # Verifica se la tabella ha una colonna ip_address
                    cursor.execute(f"SHOW COLUMNS FROM {table} WHERE Field LIKE '%ip%'")
                    ip_columns = cursor.fetchall()
                    
                    if ip_columns:
                        # Cerca in tutte le colonne che contengono 'ip' nel nome
                        for col_info in ip_columns:
                            col_name = col_info[0]
                            query = f"SELECT * FROM {table} WHERE {col_name} LIKE %s LIMIT 10"
                            cursor.execute(query, (ip_pattern,))
                            rows = cursor.fetchall()
                            
                            # Ottieni tutti i nomi delle colonne per questa tabella
                            cursor.execute(f"DESCRIBE {table}")
                            all_columns = [col[0] for col in cursor.fetchall()]
                            
                            for row in rows:
                                result = {
                                    'source': 'webhost_data',
                                    'table': table,
                                    'type': 'ip',
                                    'ip_address': ip,
                                    'data': {}
                                }
                                
                                # Aggiungi tutti i valori delle colonne
                                for i, col in enumerate(all_columns):
                                    if i < len(row):
                                        result['data'][col] = row[i]
                                
                                results.append(result)
                                
                except Exception as e:
                    logger.error(f"Errore ricerca IP nella tabella {table}: {e}")
                    continue
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Errore ricerca webhost_by_ip: {e}")
        
        return results

# Initialize database manager
db = DatabaseManager()

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
        patterns = [
            r'^[A-Z]{2}\d{7}$',  # Carta identità italiana
            r'^\d{9}$',          # Codice fiscale
            r'^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$',
            r'^[A-Z]{2}\d{5}[A-Z]{2}\d{4}$',
            r'^[A-Z]{1,2}\d{6,8}$',
            r'^\d{10,12}$',
            r'^[A-Z]{3}\d{6}[A-Z]$'
        ]
        return any(re.match(pattern, text, re.IGNORECASE) for pattern in patterns)
    
    def is_address(self, text: str) -> bool:
        """Verifica se il testo è un indirizzo"""
        address_indicators = [
            'via', 'viale', 'piazza', 'corso', 'largo', 'vicolo',
            'street', 'avenue', 'boulevard', 'road', 'lane', 'drive',
            'strada', 'avenida', 'calle', 'rua', 'straße'
        ]
        
        has_number = bool(re.search(r'\d+', text))
        has_indicator = any(indicator in text.lower() for indicator in address_indicators)
        
        return has_number or has_indicator
    
    async def search_email(self, email: str) -> Dict:
        """Ricerca email in data breach - POTENZIATA"""
        results = []
        email_clean = email.lower().strip()
        
        # Cerca nella tabella users_mvvidster PER EMAIL
        db_results = db.execute_query(
            '''SELECT * FROM users_mvvidster WHERE email LIKE %s LIMIT 20''',
            (f'%{email_clean}%',),
            fetchall=True
        )
        
        for row in db_results:
            results.append({
                'source': 'users_mvvidster',
                'type': 'email',
                'email': row[5],
                'user_id': row[1],
                'username': row[2],
                'display_name': row[2],
                'registration_date': row[3],
                'profile_photo_id': row[4],
                'original_id': row[6],
                'city': row[8] if len(row) > 8 else None,
                'country': row[9] if len(row) > 9 else None
            })
        
        # Cerca nel database webhost_data
        webhost_results = db.search_webhost_by_email(email_clean)
        for result in webhost_results:
            results.append({
                'source': 'webhost_data',
                'type': 'email',
                'email': result['email'],
                'table': result['table'],
                'data': result['data']
            })
        
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
    
    async def search_username_mvvidster(self, username: str) -> Dict:
        """Ricerca username nella tabella users_mvvidster"""
        results = []
        
        # Cerca username (disp_name) nella tabella users_mvvidster
        db_results = db.execute_query(
            '''SELECT * FROM users_mvvidster WHERE disp_name LIKE %s LIMIT 20''',
            (f'%{username}%',),
            fetchall=True
        )
        
        for row in db_results:
            results.append({
                'source': 'users_mvvidster',
                'type': 'username',
                'username': row[2],
                'user_id': row[1],
                'email': row[5],
                'display_name': row[2],
                'registration_date': row[3],
                'profile_photo_id': row[4],
                'original_id': row[6],
                'city': row[8] if len(row) > 8 else None,
                'country': row[9] if len(row) > 9 else None
            })
        
        return {'found': len(results) > 0, 'results': results, 'count': len(results)}

    async def search_date_mvvidster(self, date_str: str) -> Dict:
        """Ricerca per data di registrazione nella tabella users_mvvidster"""
        results = []
        
        # Cerca per data di registrazione
        db_results = db.execute_query(
            '''SELECT * FROM users_mvvidster WHERE reg_date LIKE %s LIMIT 20''',
            (f'%{date_str}%',),
            fetchall=True
        )
        
        for row in db_results:
            results.append({
                'source': 'users_mvvidster',
                'type': 'date',
                'registration_date': row[3],
                'username': row[2],
                'user_id': row[1],
                'email': row[5],
                'display_name': row[2],
                'profile_photo_id': row[4],
                'original_id': row[6],
                'city': row[8] if len(row) > 8 else None,
                'country': row[9] if len(row) > 9 else None
            })
        
        return {'found': len(results) > 0, 'results': results, 'count': len(results)}

    async def search_all_fields_mvvidster(self, search_term: str) -> Dict:
        """Ricerca completa in tutti i campi della tabella users_mvvidster"""
        results = []
        
        # Usa la nuova funzione del DatabaseManager
        db_results = db.search_users_mvvidster_all_fields(search_term)
        
        for row in db_results:
            results.append({
                'source': 'users_mvvidster',
                'type': 'all_fields',
                'search_term': search_term,
                'username': row[2],
                'user_id': row[1],
                'email': row[5],
                'display_name': row[2],
                'registration_date': row[3],
                'profile_photo_id': row[4],
                'original_id': row[6],
                'city': row[8] if len(row) > 8 else None,
                'country': row[9] if len(row) > 9 else None
            })
        
        return {'found': len(results) > 0, 'results': results, 'count': len(results)}
    
    async def search_name(self, name: str) -> Dict:
        """Ricerca per nome e cognome - POTENZIATA CON MVVIDSTER"""
        results = []
        
        # Cerca nella tabella users_mvvidster per disp_name
        db_results = db.execute_query(
            '''SELECT * FROM users_mvvidster WHERE disp_name LIKE %s LIMIT 15''',
            (f'%{name}%',),
            fetchall=True
        )
        
        for row in db_results:
            results.append({
                'source': 'users_mvvidster',
                'type': 'name',
                'username': row[2],
                'display_name': row[2],
                'user_id': row[1],
                'email': row[5],
                'registration_date': row[3],
                'profile_photo_id': row[4],
                'original_id': row[6],
                'city': row[8] if len(row) > 8 else None,
                'country': row[9] if len(row) > 9 else None
            })
        
        # Cerca nel database webhost_data
        webhost_results = db.search_webhost_data(name)
        for result in webhost_results:
            results.append({
                'source': 'webhost_data',
                'type': 'name',
                'search_term': name,
                'table': result['table'],
                'data': result['data']
            })
        
        parts = name.split()
        
        if len(parts) >= 2:
            first_name, last_name = parts[0], parts[1]
            
            # Ricerca nel database TiDB (tabella facebook_leaks mantenuta per compatibilità)
            fb_results = db.execute_query(
                '''SELECT * FROM facebook_leaks WHERE 
                (name LIKE %s OR surname LIKE %s) LIMIT 15''',
                (f'%{first_name}%', f'%{last_name}%'),
                fetchall=True
            )
            
            for row in fb_results:
                results.append({
                    'source': 'Facebook Leak 2021',
                    'type': 'facebook',
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
    
    def detect_search_type(self, query: str) -> str:
        """Determina automaticamente il tipo di ricerca"""
        query_lower = query.lower()
        
        if '@' in query:
            return 'email'
        
        phone_pattern = r'^[\+]?[0-9\s\-\(\)]{8,}$'
        if re.match(phone_pattern, re.sub(r'[^\d+]', '', query)):
            return 'phone'
        
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, query):
            return 'ip'
        
        if self.is_document_number(query):
            return 'document'
        
        address_indicators = ['via', 'viale', 'piazza', 'corso', 'largo', 'vicolo', 'strada',
                             'street', 'avenue', 'boulevard', 'road', 'lane', 'drive']
        if any(indicator in query_lower for indicator in address_indicators) and any(c.isdigit() for c in query):
            return 'address'
        
        # Controlla se è una data (formato YYYY-MM-DD)
        date_pattern = r'^\d{4}-\d{2}-\d{2}$'
        if re.match(date_pattern, query):
            return 'date_mvvidster'
        
        # Controlla se è un numero (potrebbe essere user_id o original_id)
        if query.isdigit():
            return 'user_id_mvvidster'
        
        if len(query) <= 30 and ' ' not in query:
            return 'username_mvvidster'
        
        hash_patterns = [
            r'^[a-f0-9]{32}$',
            r'^[a-f0-9]{40}$',
            r'^[a-f0-9]{64}$'
        ]
        if any(re.match(pattern, query_lower) for pattern in hash_patterns):
            return 'hash'
        
        # Default: cerca come nome/username generico
        return 'name_mvvidster'
    
    async def search_document(self, document_number: str) -> Dict:
        """Ricerca numero documento in data breach"""
        results = []
        doc_clean = document_number.upper().strip()
        
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
        
        # Ricerca nel database TiDB
        db_results = db.execute_query(
            '''SELECT * FROM addresses_documents WHERE 
            document_number LIKE %s OR document_number = %s LIMIT 10''',
            (f'%{doc_clean}%', doc_clean),
            fetchall=True
        )
        
        for row in db_results:
            results.append({
                'source': 'TiDB Database',
                'document_type': row[2],
                'document_number': row[1],
                'full_name': row[3],
                'home_address': row[4],
                'work_address': row[5],
                'city': row[6],
                'phone': row[8],
                'email': row[9]
            })
        
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
        address_clean = address.strip()
        
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
        
        # Ricerca nel database TiDB
        db_results = db.execute_query(
            '''SELECT * FROM addresses_documents WHERE 
            home_address LIKE %s OR home_address LIKE %s LIMIT 10''',
            (f'%{address_clean}%', f'%{address_clean}%'),
            fetchall=True
        )
        
        for row in db_results:
            if row[4]:
                results.append({
                    'source': 'TiDB Database',
                    'address_type': 'home',
                    'address': row[4],
                    'full_name': row[3],
                    'document_number': row[1],
                    'city': row[6],
                    'phone': row[8],
                    'email': row[9]
                })
        
        # Cerca nella tabella users_mvvidster
        mvvidster_results = db.execute_query(
            '''SELECT * FROM users_mvvidster WHERE 
            city LIKE %s OR country LIKE %s LIMIT 10''',
            (f'%{address_clean}%', f'%{address_clean}%'),
            fetchall=True
        )
        
        for row in mvvidster_results:
            results.append({
                'source': 'users_mvvidster',
                'address_type': 'city/country',
                'city': row[8] if len(row) > 8 else None,
                'country': row[9] if len(row) > 9 else None,
                'username': row[2],
                'user_id': row[1],
                'email': row[5],
                'registration_date': row[3]
            })
        
        # Cerca nel database webhost_data
        webhost_results = db.search_webhost_data(address_clean)
        for result in webhost_results:
            results.append({
                'source': 'webhost_data',
                'address_type': 'general',
                'search_term': address_clean,
                'table': result['table'],
                'data': result['data']
            })
        
        # Cerca anche nella tabella facebook_leaks (se esiste ancora)
        fb_results = db.execute_query(
            '''SELECT * FROM facebook_leaks WHERE 
            city LIKE %s OR country LIKE %s LIMIT 10''',
            (f'%{address_clean}%', f'%{address_clean}%'),
            fetchall=True
        )
        
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
        address_clean = address.strip()
        
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
        
        # Ricerca nel database TiDB
        db_results = db.execute_query(
            '''SELECT * FROM addresses_documents WHERE 
            work_address LIKE %s OR work_address LIKE %s LIMIT 10''',
            (f'%{address_clean}%', f'%{address_clean}%'),
            fetchall=True
        )
        
        for row in db_results:
            if row[5]:
                results.append({
                    'source': 'TiDB Database',
                    'address_type': 'work',
                    'company': row[10] if len(row) > 10 else None,
                    'address': row[5],
                    'full_name': row[3],
                    'document_number': row[1],
                    'city': row[6],
                    'phone': row[8],
                    'email': row[9]
                })
        
        # Cerca nel database webhost_data
        webhost_results = db.search_webhost_data(address_clean)
        for result in webhost_results:
            results.append({
                'source': 'webhost_data',
                'address_type': 'work',
                'search_term': address_clean,
                'table': result['table'],
                'data': result['data']
            })
        
        # Cerca nella tabella facebook_leaks (se esiste ancora)
        fb_results = db.execute_query(
            '''SELECT * FROM facebook_leaks WHERE 
            company LIKE %s LIMIT 10''',
            (f'%{address_clean}%',),
            fetchall=True
        )
        
        for row in fb_results:
            if row[9]:
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
    
    async def search_phone(self, phone: str) -> Dict:
        """Ricerca numero telefono in data breach"""
        results = []
        phone_clean = re.sub(r'[^\d+]', '', phone)
        
        # Prima controlla se abbiamo la colonna phone nella tabella users_mvvidster
        # Se non c'è, cerca solo per email e disp_name
        db_results = db.execute_query(
            '''SELECT * FROM users_mvvidster WHERE 
            email LIKE %s OR disp_name LIKE %s OR user_id LIKE %s LIMIT 10''',
            (f'%{phone_clean[-10:]}%', f'%{phone_clean}%', f'%{phone_clean}%'),
            fetchall=True
        )
        
        for row in db_results:
            # row[0]=id, row[1]=user_id, row[2]=disp_name, row[3]=reg_date, 
            # row[4]=profile_photo, row[5]=email, row[6]=original_id
            results.append({
                'source': 'users_mvvidster',
                'user_id': row[1],
                'username': row[2],
                'display_name': row[2],
                'email': row[5],
                'registration_date': row[3],
                'profile_photo_id': row[4],
                'original_id': row[6]
            })
        
        # Cerca nel database webhost_data
        webhost_results = db.search_webhost_data(phone_clean)
        for result in webhost_results:
            results.append({
                'source': 'webhost_data',
                'type': 'phone',
                'phone': phone_clean,
                'table': result['table'],
                'data': result['data']
            })
        
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
        
        # Ricerca nel database TiDB (tabella facebook_leaks mantenuta per compatibilità)
        fb_results = db.execute_query(
            '''SELECT * FROM facebook_leaks WHERE phone LIKE %s LIMIT 10''',
            (f'%{phone_clean[-10:]}%',),
            fetchall=True
        )
        
        for row in fb_results:
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
        """Ricerca username su social media e data breach - POTENZIATO CON API OSINT"""
        results = []
        
        # Cerca nella tabella users_mvvidster
        db_results = db.execute_query(
            '''SELECT * FROM users_mvvidster WHERE disp_name LIKE %s LIMIT 10''',
            (f'%{username}%',),
            fetchall=True
        )
        
        for row in db_results:
            results.append({
                'source': 'users_mvvidster',
                'username': row[2],
                'display_name': row[2],
                'user_id': row[1],
                'email': row[5],
                'registration_date': row[3],
                'profile_photo_id': row[4],
                'original_id': row[6]
            })
        
        # Cerca nel database webhost_data
        webhost_results = db.search_webhost_by_username(username)
        for result in webhost_results:
            results.append({
                'source': 'webhost_data',
                'type': 'username',
                'username': username,
                'table': result['table'],
                'data': result['data']
            })
        
        social_results = []
        breach_results = []
        
        # ============ API WHATSMYNAME (GRATIS, SENZA KEY) ============
        try:
            whatsmyname_url = f"{WHATSMYNAME_API_URL}/identities/{quote_plus(username)}"
            response = self.session.get(whatsmyname_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('sites'):
                    for site in data['sites'][:20]:  # Limita a 20 siti
                        if site.get('status') == 'claimed':
                            social_results.append({
                                'platform': f"🌐 {site.get('name', 'Unknown')}",
                                'url': site.get('url', ''),
                                'exists': True,
                                'source': 'Whatsmyname API',
                                'claimed': True
                            })
        except Exception as e:
            logger.error(f"Whatsmyname API error: {e}")
        
        # ============ API INSTANTUSERNAME (GRATIS) ============
        try:
            instant_url = f"{INSTANTUSERNAME_API}/check/{quote_plus(username)}"
            response = self.session.get(instant_url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                for platform, info in data.get('services', {}).items():
                    if info.get('available') == False:  # False = username TAKEN
                        social_results.append({
                            'platform': f"📱 {platform}",
                            'url': f"https://{platform}.com/{username}",
                            'exists': True,
                            'source': 'InstantUsername API',
                            'claimed': True
                        })
        except Exception as e:
            logger.error(f"InstantUsername error: {e}")
        
        # ============ API NAMEAPI (SE C'È API KEY) ============
        if NAMEAPI_KEY:
            try:
                nameapi_url = f"https://api.nameapi.org/rest/v5.3/username/search"
                params = {
                    'apiKey': NAMEAPI_KEY,
                    'username': username,
                    'context': 'social'
                }
                response = self.session.get(nameapi_url, params=params, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('matches'):
                        for match in data['matches'][:10]:
                            if match.get('available') == False:
                                social_results.append({
                                    'platform': f"🔍 {match.get('service', 'Unknown')}",
                                    'url': match.get('url', f"https://{match.get('service')}.com/{username}"),
                                    'exists': True,
                                    'source': 'NameAPI',
                                    'claimed': True
                                })
            except Exception as e:
                logger.error(f"NameAPI error: {e}")
        
        # ============ API SOCIAL-SEARCHER (SE C'È API KEY) ============
        if SOCIAL_SEARCHER_KEY:
            try:
                social_url = "https://api.social-searcher.com/v2/search"
                params = {
                    'q': username,
                    'network': 'web',
                    'type': 'username',
                    'key': SOCIAL_SEARCHER_KEY,
                    'limit': 15
                }
                response = self.session.get(social_url, params=params, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('posts'):
                        unique_platforms = set()
                        for post in data['posts'][:10]:
                            if post.get('network'):
                                platform = post['network'].capitalize()
                                if platform not in unique_platforms:
                                    unique_platforms.add(platform)
                                    social_results.append({
                                        'platform': f"📢 {platform}",
                                        'url': post.get('url', ''),
                                        'exists': True,
                                        'source': 'Social-Searcher API',
                                        'mentions': post.get('count', 1)
                                    })
            except Exception as e:
                logger.error(f"Social-Searcher error: {e}")
        
        # ============ CONTROLLI MANUALI (BACKUP) ============
        social_platforms = [
            ('📸 Instagram', f'https://instagram.com/{username}'),
            ('📘 Facebook', f'https://facebook.com/{username}'),
            ('🐦 Twitter', f'https://twitter.com/{username}'),
            ('💻 GitHub', f'https://github.com/{username}'),
            ('👽 Reddit', f'https://reddit.com/user/{username}'),
            ('📱 Telegram', f'https://t.me/{username}'),
            ('🔵 VKontakte', f'https://vk.com/{username}'),
            ('🎥 TikTok', f'https://tiktok.com/@{username}'),
            ('💼 LinkedIn', f'https://linkedin.com/in/{username}'),
            ('📌 Pinterest', f'https://pinterest.com/{username}')
        ]
        
        # Evita duplicati: controlla se la piattaforma è già stata trovata
        existing_platforms = [r['platform'] for r in social_results]
        
        for platform, url in social_platforms:
            if platform in existing_platforms:
                continue
                
            try:
                response = self.session.get(url, timeout=3, allow_redirects=False)
                if response.status_code in [200, 301, 302]:
                    social_results.append({
                        'platform': platform,
                        'url': url,
                        'exists': True,
                        'source': 'Direct check'
                    })
            except:
                continue
        
        # ============ DATA BREACH CHECK (ESISTENTE) ============
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
        
        # Rimuovi duplicati basati su URL
        unique_results = []
        seen_urls = set()
        for result in social_results:
            if result['url'] not in seen_urls:
                seen_urls.add(result['url'])
                unique_results.append(result)
        
        return {
            'social': unique_results,
            'breach': breach_results,
            'social_count': len(unique_results),
            'breach_count': len(breach_results),
            'api_sources': list(set([r.get('source', 'Unknown') for r in unique_results]))
        }
    
    async def search_username_advanced(self, username: str) -> Dict:
        """Ricerca avanzata username con tutte le API disponibili"""
        all_results = {
            'whatsmyname': [],
            'instantusername': [],
            'manual': [],
            'breach': [],
            'variants': []
        }
        
        # 1. Whatsmyname (completo)
        try:
            response = self.session.get(
                f"https://api.whatsmyname.app/v0/identities/{quote_plus(username)}",
                timeout=15
            )
            if response.status_code == 200:
                data = response.json()
                all_results['whatsmyname'] = data.get('sites', [])
        except:
            pass
        
        # 2. Ricerca varianti (username simili)
        username_lower = username.lower()
        common_variants = [
            username_lower,
            username_lower + "123",
            username_lower + "_",
            "real" + username_lower,
            username_lower + "official"
        ]
        
        for variant in common_variants[:3]:
            try:
                variant_url = f"https://api.whatsmyname.app/v0/identities/{quote_plus(variant)}"
                response = self.session.get(variant_url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('sites'):
                        all_results['variants'].append({
                            'variant': variant,
                            'sites': data['sites'][:5]
                        })
            except:
                continue
        
        return all_results
    
    async def search_ip(self, ip: str) -> Dict:
        """Ricerca informazioni IP"""
        info = {}
        
        # Cerca nel database webhost_data
        webhost_results = db.search_webhost_by_ip(ip)
        if webhost_results:
            info['webhost_data'] = {
                'found': True,
                'count': len(webhost_results),
                'results': webhost_results[:5]  # Limita a 5 risultati
            }
        
        if IPINFO_API_KEY:
            try:
                response = self.session.get(
                    f'https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}',
                    timeout=10
                )
                if response.status_code == 200:
                    info['ipinfo'] = response.json()
            except Exception as e:
                logger.error(f"IPInfo error: {e}")
        
        if ABUSEIPDB_KEY:
            try:
                headers = {'Key': ABUSEIPDB_KEY}
                params = {'ipAddress': ip, 'maxAgeInDays': 90}
                response = self.session.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers=headers, params=params, timeout=10
                )
                if response.status_code == 200:
                    info['abuseipdb'] = response.json().get('data', {})
            except Exception as e:
                logger.error(f"AbuseIPDB error: {e}")
        
        if SHODAN_API_KEY:
            try:
                api = shodan.Shodan(SHODAN_API_KEY)
                shodan_info = api.host(ip)
                info['shodan'] = {
                    'ports': shodan_info.get('ports', []),
                    'hostnames': shodan_info.get('hostnames', []),
                    'org': shodan_info.get('org', ''),
                    'isp': shodan_info.get('isp', '')
                }
            except Exception as e:
                logger.error(f"Shodan error: {e}")
        
        return info
    
    async def search_password(self, password: str) -> Dict:
        """Ricerca password in data breach"""
        results = []
        
        # Cerca nel database webhost_data
        webhost_results = db.search_webhost_data(password)
        for result in webhost_results:
            results.append({
                'source': 'webhost_data',
                'type': 'password',
                'password': password,
                'table': result['table'],
                'data': result['data']
            })
        
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
        
        hash_type = "Unknown"
        if len(hash_str) == 32 and re.match(r'^[a-f0-9]{32}$', hash_str):
            hash_type = "MD5"
        elif len(hash_str) == 40 and re.match(r'^[a-f0-9]{40}$', hash_str):
            hash_type = "SHA1"
        elif len(hash_str) == 64 and re.match(r'^[a-f0-9]{64}$', hash_str):
            hash_type = "SHA256"
        
        # Cerca nel database webhost_data
        webhost_results = db.search_webhost_data(hash_str)
        for result in webhost_results:
            results.append({
                'source': 'webhost_data',
                'type': 'hash',
                'hash': hash_str,
                'table': result['table'],
                'data': result['data']
            })
        
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
        
        query = query.strip()
        
        try:
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
        
        try:
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
        
        if query.isdigit():
            results['by_id'].append({
                'telegram_id': query,
                'found': False
            })
        
        if ' ' in query:
            results['by_name'].append({
                'name': query,
                'found': False
            })
        
        return results
    
    async def search_instagram_account(self, query: str) -> Dict:
        """Ricerca specifica per account Instagram"""
        results = {
            'by_username': [],
            'by_name': []
        }
        
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
        
        if ' ' in query:
            results['by_name'].append({
                'name': query,
                'found': False,
                'note': 'Instagram richiede login per ricerca per nome'
            })
        
        return results
    
    async def search_facebook_account(self, query: str) -> Dict:
        """Ricerca specifica per account Facebook"""
        results = {
            'by_name': [],
            'by_id': []
        }
        
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
    
    async def search_facebook_advanced(self, query: str) -> Dict:
        """Ricerca avanzata su Facebook usando API multiple"""
        results = {
            'leak_data': [],
            'public_info': [],
            'graph_api': [],
            'search_engines': []
        }
        
        # Ricerca nel database TiDB (tabella facebook_leaks mantenuta per compatibilità)
        fb_results = db.execute_query(
            '''SELECT * FROM facebook_leaks WHERE 
            name LIKE %s OR surname LIKE %s OR phone LIKE %s 
            ORDER BY found_date DESC LIMIT 10''',
            (f'%{query}%', f'%{query}%', f'%{query}%'),
            fetchall=True
        )
        
        for row in fb_results:
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
        
        # Ricerca nella tabella users_mvvidster
        mvvidster_results = db.execute_query(
            '''SELECT * FROM users_mvvidster WHERE 
            disp_name LIKE %s OR email LIKE %s 
            ORDER BY found_date DESC LIMIT 10''',
            (f'%{query}%', f'%{query}%'),
            fetchall=True
        )
        
        for row in mvvidster_results:
            results['leak_data'].append({
                'type': 'users_mvvidster',
                'username': row[2],
                'user_id': row[1],
                'email': row[5],
                'registration_date': row[3],
                'profile_photo_id': row[4],
                'original_id': row[6]
            })
        
        # Ricerca nel database webhost_data
        webhost_results = db.search_webhost_data(query)
        for result in webhost_results:
            results['leak_data'].append({
                'type': 'webhost_data',
                'source': 'webhost_data',
                'table': result['table'],
                'data': result['data']
            })
        
        if FACEBOOK_GRAPH_API_KEY and ' ' in query:
            try:
                parts = query.split()
                if len(parts) >= 2:
                    first_name, last_name = parts[0], ' '.join(parts[1:])
                    
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
        
        try:
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
        phone_clean = re.sub(r'[^\d+]', '', phone)[-10:]
        
        # Ricerca nella tabella users_mvvidster
        mvvidster_results = db.execute_query(
            '''SELECT * FROM users_mvvidster WHERE 
            (phone LIKE %s OR email LIKE %s OR disp_name LIKE %s) 
            ORDER BY found_date DESC LIMIT 15''',
            (f'%{phone_clean}%', f'%{phone_clean}%', f'%{phone_clean}%'),
            fetchall=True
        )
        
        for row in mvvidster_results:
            results.append({
                'source': 'users_mvvidster',
                'user_id': row[1],
                'username': row[2],
                'display_name': row[2],
                'email': row[5],
                'registration_date': row[3],
                'phone': row[7] if len(row) > 7 else None,
                'profile_photo_id': row[4],
                'original_id': row[6]
            })
        
        # Ricerca nel database TiDB (tabella facebook_leaks mantenuta per compatibilità)
        fb_results = db.execute_query(
            '''SELECT * FROM facebook_leaks WHERE phone LIKE %s ORDER BY found_date DESC LIMIT 15''',
            (f'%{phone_clean}%',),
            fetchall=True
        )
        
        for row in fb_results:
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
        
        # Ricerca nel database webhost_data
        webhost_results = db.search_webhost_data(phone_clean)
        for result in webhost_results:
            results.append({
                'source': 'webhost_data',
                'type': 'phone',
                'phone': phone_clean,
                'table': result['table'],
                'data': result['data']
            })
        
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
        facebook_email = email.lower()
        
        # Ricerca nella tabella users_mvvidster
        mvvidster_results = db.execute_query(
            '''SELECT * FROM users_mvvidster WHERE email LIKE %s ORDER BY found_date DESC LIMIT 10''',
            (f'%{facebook_email}%',),
            fetchall=True
        )
        
        for row in mvvidster_results:
            results.append({
                'source': 'users_mvvidster',
                'email': row[5],
                'user_id': row[1],
                'username': row[2],
                'display_name': row[2],
                'registration_date': row[3],
                'profile_photo_id': row[4],
                'original_id': row[6]
            })
        
        # Ricerca nel database webhost_data
        webhost_results = db.search_webhost_by_email(facebook_email)
        for result in webhost_results:
            results.append({
                'source': 'webhost_data',
                'type': 'email',
                'email': facebook_email,
                'table': result['table'],
                'data': result['data']
            })
        
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
        
        if fb_id.isdigit():
            # Ricerca nella tabella users_mvvidster
            mvvidster_results = db.execute_query(
                '''SELECT * FROM users_mvvidster WHERE user_id = %s''',
                (fb_id,),
                fetchall=True
            )
            
            for row in mvvidster_results:
                results.append({
                    'source': 'users_mvvidster',
                    'user_id': row[1],
                    'username': row[2],
                    'display_name': row[2],
                    'email': row[5],
                    'registration_date': row[3],
                    'profile_photo_id': row[4],
                    'original_id': row[6]
                })
            
            # Ricerca nel database TiDB (tabella facebook_leaks mantenuta per compatibilità)
            fb_results = db.execute_query(
                '''SELECT * FROM facebook_leaks WHERE facebook_id = %s''',
                (fb_id,),
                fetchall=True
            )
            
            for row in fb_results:
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
            
            # Ricerca nel database webhost_data
            webhost_results = db.search_webhost_data(fb_id)
            for result in webhost_results:
                results.append({
                    'source': 'webhost_data',
                    'type': 'id',
                    'id': fb_id,
                    'table': result['table'],
                    'data': result['data']
                })
            
            try:
                profile_url = f'https://facebook.com/{fb_id}'
                response = self.session.get(profile_url, timeout=10, allow_redirects=True)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
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
    
    async def search_webhost_complete(self, search_term: str) -> Dict:
        """Ricerca completa nel database webhost_data"""
        results = []
        
        # Cerca in tutti i campi del database webhost_data
        webhost_results = db.search_webhost_data(search_term)
        
        for result in webhost_results:
            results.append({
                'source': 'webhost_data',
                'type': 'general_search',
                'search_term': search_term,
                'table': result['table'],
                'data': result['data']
            })
        
        # Ricerca specifica per email
        if '@' in search_term:
            email_results = db.search_webhost_by_email(search_term)
            for result in email_results:
                # Evita duplicati
                duplicate = False
                for existing in results:
                    if existing.get('table') == result['table'] and existing.get('data') == result['data']:
                        duplicate = True
                        break
                if not duplicate:
                    results.append({
                        'source': 'webhost_data',
                        'type': 'email',
                        'email': search_term,
                        'table': result['table'],
                        'data': result['data']
                    })
        
        # Ricerca specifica per username
        elif len(search_term) <= 30 and ' ' not in search_term:
            username_results = db.search_webhost_by_username(search_term)
            for result in username_results:
                # Evita duplicati
                duplicate = False
                for existing in results:
                    if existing.get('table') == result['table'] and existing.get('data') == result['data']:
                        duplicate = True
                        break
                if not duplicate:
                    results.append({
                        'source': 'webhost_data',
                        'type': 'username',
                        'username': search_term,
                        'table': result['table'],
                        'data': result['data']
                    })
        
        # Ricerca specifica per IP
        elif self.is_ip(search_term):
            ip_results = db.search_webhost_by_ip(search_term)
            for result in ip_results:
                # Evita duplicati
                duplicate = False
                for existing in results:
                    if existing.get('table') == result['table'] and existing.get('data') == result['data']:
                        duplicate = True
                        break
                if not duplicate:
                    results.append({
                        'source': 'webhost_data',
                        'type': 'ip',
                        'ip_address': search_term,
                        'table': result['table'],
                        'data': result['data']
                    })
        
        return {'found': len(results) > 0, 'results': results, 'count': len(results)}

class LeakosintBot:
    """Bot principale con interfaccia come nelle immagini"""
    
    def __init__(self):
        self.api = LeakSearchAPI()
    
    def get_user_language(self, user_id: int) -> str:
        result = db.execute_query(
            'SELECT language FROM users WHERE user_id = %s',
            (user_id,),
            fetchone=True
        )
        return result[0] if result and result[0] else 'en'  # Default a 'en'
    
    def set_user_language(self, user_id: int, language: str):
        db.execute_query(
            'UPDATE users SET language = %s WHERE user_id = %s',
            (language, user_id),
            commit=True
        )
    
    async def show_main_menu(self, update: Update, context: CallbackContext):
        """Mostra il menu principale con interfaccia"""
        user = update.effective_user
        user_id = user.id
        
        self.register_user(user_id, user.username)
        
        now = datetime.now()
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        user_lang = self.get_user_language(user_id)
        
        keyboard = [
            [InlineKeyboardButton(translations[user_lang]['search'], callback_data='ricerca')],
            [InlineKeyboardButton(translations[user_lang]['shop'], callback_data='shop_button')],
            [InlineKeyboardButton(translations[user_lang]['settings'], callback_data='impostazioni')],
            [InlineKeyboardButton(translations[user_lang]['menu'], callback_data='menu_button')],
            [InlineKeyboardButton(translations[user_lang]['help'], callback_data='help_button')],
            [InlineKeyboardButton(translations[user_lang]['language_btn'], callback_data='language_settings')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        menu_text = translations[user_lang]['main_menu']
        menu_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}\n\n{data_italiana}"
        
        if update.callback_query:
            await update.callback_query.edit_message_text(menu_text, reply_markup=reply_markup)
        else:
            await update.message.reply_text(menu_text, reply_markup=reply_markup)
    
    def register_user(self, user_id: int, username: str):
        """Registra un nuovo utente"""
        result = db.execute_query(
            'SELECT * FROM users WHERE user_id = %s',
            (user_id,),
            fetchone=True
        )
        if not result:
            db.execute_query(
                '''INSERT INTO users (user_id, username, balance) 
                VALUES (%s, %s, 4)''',
                (user_id, username),
                commit=True
            )
            return True
        return False
    
    def get_user_balance(self, user_id: int) -> int:
        result = db.execute_query(
            'SELECT balance FROM users WHERE user_id = %s',
            (user_id,),
            fetchone=True
        )
        return int(result[0]) if result else 0
    
    def get_user_searches(self, user_id: int) -> int:
        result = db.execute_query(
            'SELECT searches FROM users WHERE user_id = %s',
            (user_id,),
            fetchone=True
        )
        return result[0] if result else 0
    
    def get_registration_date(self, user_id: int) -> str:
        result = db.execute_query(
            'SELECT registration_date FROM users WHERE user_id = %s',
            (user_id,),
            fetchone=True
        )
        if result and result[0]:
            try:
                dt = result[0]
                if isinstance(dt, datetime):
                    return dt.strftime('%d/%m/%Y')
                else:
                    dt = datetime.strptime(str(dt), '%Y-%m-%d %H:%M:%S')
                    return dt.strftime('%d/%m/%Y')
            except:
                return str(result[0])
        return "Sconosciuta"
    
    def get_last_active(self, user_id: int) -> str:
        result = db.execute_query(
            'SELECT last_active FROM users WHERE user_id = %s',
            (user_id,),
            fetchone=True
        )
        if result and result[0]:
            try:
                dt = result[0]
                if isinstance(dt, datetime):
                    return dt.strftime('%d/%m/%Y %H:%M')
                else:
                    dt = datetime.strptime(str(dt), '%Y-%m-%d %H:%M:%S')
                    return dt.strftime('%d/%m/%Y %H:%M')
            except:
                return str(result[0])
        return "Sconosciuta"
    
    def get_subscription_type(self, user_id: int) -> str:
        result = db.execute_query(
            'SELECT subscription_type FROM users WHERE user_id = %s',
            (user_id,),
            fetchone=True
        )
        return result[0] if result else 'free'
    
    def get_username(self, user_id: int) -> str:
        result = db.execute_query(
            'SELECT username FROM users WHERE user_id = %s',
            (user_id,),
            fetchone=True
        )
        return result[0] if result else 'N/A'
    
    async def update_balance(self, user_id: int, cost: int = 2) -> bool:
        current = self.get_user_balance(user_id)
        if current >= cost:
            new_balance = current - cost
            db.execute_query(
                '''UPDATE users SET balance = %s, searches = searches + 1, 
                last_active = CURRENT_TIMESTAMP WHERE user_id = %s''',
                (new_balance, user_id),
                commit=True
            )
            return True
        return False
    
    def add_credits(self, user_id: int, amount: int) -> bool:
        try:
            db.execute_query(
                '''UPDATE users SET balance = balance + %s, 
                last_active = CURRENT_TIMESTAMP WHERE user_id = %s''',
                (amount, user_id),
                commit=True
            )
            return True
        except Exception as e:
            logger.error(f"Error adding credits: {e}")
            return False
    
    def log_search(self, user_id: int, query: str, search_type: str, results: str):
        db.execute_query(
            '''INSERT INTO searches (user_id, query, type, results) 
            VALUES (%s, %s, %s, %s)''',
            (user_id, query, search_type, results),
            commit=True
        )
    
    async def handle_button_callback(self, update: Update, context: CallbackContext):
        """Gestisce i callback dei pulsanti inline"""
        query = update.callback_query
        await query.answer()
        
        user_id = query.from_user.id
        
        if query.data == 'ricerca':
            await self.show_search_menu(update, context)
            
        elif query.data == 'shop_button':
            await self.show_shop_interface(update, context)
            
        elif query.data == 'impostazioni':
            await self.show_settings(update, context)
            
        elif query.data == 'menu_button':
            await self.menu_completo(update, context)
            
        elif query.data == 'help_button':
            await self.help_command_from_button(update, context)
            
        elif query.data == 'language_settings':
            await self.show_language_settings(update, context)
            
        elif query.data == 'set_lang_it':
            await self.set_language(update, context, 'it')
            
        elif query.data == 'set_lang_en':
            await self.set_language(update, context, 'en')
            
        elif query.data == 'back_to_main':
            await self.show_main_menu(update, context)
            
        elif query.data == 'back_from_search':
            await self.show_search_menu(update, context)
            
        elif query.data == 'buy_20':
            await query.answer("Feature in sviluppo - Presto disponibile!", show_alert=True)
            
        elif query.data == 'buy_50':
            await query.answer("Feature in sviluppo - Presto disponibile!", show_alert=True)
            
        elif query.data == 'buy_100':
            await query.answer("Feature in sviluppo - Presto disponibile!", show_alert=True)
            
        elif query.data == 'buy_200':
            await query.answer("Feature in sviluppo - Presto disponibile!", show_alert=True)

        elif query.data == 'buy_500':
            await query.answer("Feature in sviluppo - Presto disponibile!", show_alert=True)
    
        elif query.data == 'buy_1000':
            await query.answer("Feature in sviluppo - Presto disponibile!", show_alert=True)

    async def show_settings(self, update: Update, context: CallbackContext):
        """Mostra le impostazioni utente"""
        query = update.callback_query
        user_id = query.from_user.id
        
        balance = self.get_user_balance(user_id)
        searches = self.get_user_searches(user_id)
        reg_date = self.get_registration_date(user_id)
        last_active = self.get_last_active(user_id)
        sub_type = self.get_subscription_type(user_id)
        username = self.get_username(user_id)
        user_lang = self.get_user_language(user_id)
        
        now = datetime.now()
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        lang_text = translations[user_lang]['language'] if user_lang in translations else 'Italiano 🇮🇹'
        
        settings_text = f"""⚙️ IMPOSTAZIONI UTENTE

👤 Informazioni Personali:
🆔 ID Telegram: {user_id}
👤 Username: @{username}
📅 Registrato: {reg_date}
🕒 Ultima attività: {last_active}

💳 Sistema Credit:
💰 Crediti attuali: {balance}
🔍 Ricerche effettuate: {searches}
🎯 Ricerche disponibili: {int(balance / 2)}
📊 Abbonamento: {sub_type}

⚙️ Configurazioni:
🔔 Notifiche: Attive
🌐 Lingua: {lang_text}
💾 Salvataggio ricerche: 30 giorni

📊 Statistiche odierne:
- Ricerche oggi: {searches % 100}
- Crediti usati oggi: {(100 - balance) % 100}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        keyboard = [
            [InlineKeyboardButton("🌐 Cambia Lingua", callback_data='language_settings')],
            [InlineKeyboardButton("🔙 Indietro", callback_data='back_to_main')]
        ]
        await query.edit_message_text(settings_text, reply_markup=InlineKeyboardMarkup(keyboard))
    
    async def show_language_settings(self, update: Update, context: CallbackContext):
        """Mostra le impostazioni della lingua"""
        user_id = update.effective_user.id
        current_lang = self.get_user_language(user_id)
        
        keyboard = [
            [
                InlineKeyboardButton("🇮🇹 Italiano", callback_data='set_lang_it'),
                InlineKeyboardButton("🇬🇧 English", callback_data='set_lang_en')
            ],
            [InlineKeyboardButton("🔙 Indietro", callback_data='impostazioni')]
        ]
        
        text = f"""🌐 IMPOSTAZIONI LINGUA

Lingua attuale: {translations[current_lang]['language']}

Seleziona una lingua:
🇮🇹 Italiano - Lingua italiana
🇬🇧 English - English language

Il cambio lingua influenzerà:
• Testi dei menu
• Messaggi del bot
• Istruzioni"""

        if update.callback_query:
            await update.callback_query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard))
        else:
            await update.message.reply_text(text, reply_markup=InlineKeyboardMarkup(keyboard))

    async def set_language(self, update: Update, context: CallbackContext, language: str):
        """Imposta la lingua per l'utente"""
        query = update.callback_query
        await query.answer()
        
        user_id = query.from_user.id
        self.set_user_language(user_id, language)
        
        # Usa il dizionario di traduzioni per il messaggio
        lang_name = translations[language]['language']
        confirm_text = translations[language]['lang_changed'].format(lang_name=lang_name.split()[0])
        
        await query.edit_message_text(confirm_text)
        
        # Ritorna al menu principale dopo 2 secondi
        await asyncio.sleep(2)
        await self.show_main_menu(update, context)
    
    async def help_command_from_button(self, update: Update, context: CallbackContext):
        """Mostra l'aiuto quando cliccato dal pulsante help"""
        await self.help_command(update, context)
    
    async def show_search_menu(self, update: Update, context: CallbackContext):
        """Mostra il menu di ricerca tradotto"""
        user = update.effective_user
        user_id = user.id
        user_lang = self.get_user_language(user_id)
        
        now = datetime.now()
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        if user_lang == 'it':
            text = f"""{translations[user_lang]['search_menu_title']}

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

📄 Cerca per documento

· AA1234567 - Carta Identità
· 123456789 - Codice Fiscale
· AA12345AA1234 - Passaporto

🏠 Cerca per indirizzo di casa

· Via Roma 123, Milano
· Corso Vittorio Emanuele 45, Roma
· Piazza del Duomo 1, Firenze

🏢 Cerca per indirizzo lavorativo

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

💰 Crediti disponibili: {self.get_user_balance(user_id)} 📊Ricerche effettuate: {self.get_user_searches(user_id)}

📩 Inviami qualsiasi dato per iniziare la ricerca.

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        else:
            text = f"""{translations[user_lang]['search_menu_title']}

📧 Search by email

· example@gmail.com - Search email
· example@ - Search without domain consideration
· @gmail.com - Search specific domains

👤 Search by name or nickname

· Petrov
· Petrov Maxim
· Petrov Sergeevich
· Maxim Sergeevich
· Petrov Maxim Sergeevich
· ShadowPlayer228

📱 Search by phone number

· +79002206090
· 79002206090
· 89002206090

📄 Search by document

· AA1234567 - Identity Card
· 123456789 - Tax Code
· AA12345AA1234 - Passport

🏠 Search by home address

· Via Roma 123, Milano
· Corso Vittorio Emanuele 45, Roma
· Piazza del Duomo 1, Firenze

🏢 Search by work address

· Office Via Torino 50, Milano
· Company Via Milano 10, Roma
· Headquarters Via Garibaldi 25, Napoli

🔐 Password search

· 123qwe

🚗 Search vehicles

· 0999MY777 - Search vehicles in Russia
· BO4561AX - Search vehicles with penal code
· XTA21150053965897 - Search by VIN

📱 Search Telegram account

· Petrov Ivan - Search by name and surname
· 314159265 - Search by account ID
· Petivan - Search by username

📘 Search Facebook account

· Petrov Ivan - Search by name
· 314159265 - Search by account ID

🔵 Search VKontakte account

· Petrov Ivan - Search by name and surname
· 314159265 - Search by account ID

📸 Search Instagram account

· Petrov Ivan - Search by name and surname
· 314159265 - Search by account ID

🌐 Search by IP

· 127.0.0.1

📋 Mass search: /utf8 for instructions

📝 Composite requests in all formats are supported:

· Petrov 79002206090
· Maxim Sergeevich 127.0.0.1
· Petrov Maxim Sergeevich
· AA1234567 Via Roma 123
· Mario Rossi 123456789 Milano

💰 Available credits: {self.get_user_balance(user_id)} 📊Searches performed: {self.get_user_searches(user_id)}

📩 Send me any data to start searching.

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        keyboard = [[InlineKeyboardButton(translations[user_lang]['back'], callback_data='back_to_main')]]
        
        if update.callback_query:
            await update.callback_query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard))
        else:
            await update.message.reply_text(text, reply_markup=InlineKeyboardMarkup(keyboard))


    async def show_shop_interface(self, update: Update, context: CallbackContext):
        """Mostra l'interfaccia di acquisto crediti con prezzi interi"""
        user_id = update.effective_user.id
        user_lang = self.get_user_language(user_id)
        
        now = datetime.now()
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        # PREZZI IN EURO (INTERI)
        eur_20 = 5     # 20 crediti = 5€
        eur_50 = 10    # 50 crediti = 10€
        eur_100 = 20   # 100 crediti = 20€
        eur_200 = 35   # 200 crediti = 35€
        eur_500 = 80   # 500 crediti = 80€
        eur_1000 = 150 # 1000 crediti = 150€
        
        # PREZZI IN DOLLARI (stessi numeri)
        usd_20 = 5     # 20 crediti = 5$
        usd_50 = 10    # 50 crediti = 10$
        usd_100 = 20   # 100 crediti = 20$
        usd_200 = 35   # 200 crediti = 35$
        usd_500 = 80   # 500 crediti = 80$
        usd_1000 = 150 # 1000 crediti = 150$
        
        # Formatta i prezzi
        if user_lang == 'it':
            text = f"""{translations[user_lang]['shop_title']}

{translations[user_lang]['credit_packages']}
━━━━━━━━━━━━━━━━━━━━
· 🟢 20 CREDITI = {eur_20}€ / {usd_20}$
· 🟡 50 CREDITI = {eur_50}€ / {usd_50}$
· 🔵 100 CREDITI = {eur_100}€ / {usd_100}$
· 🟣 200 CREDITI = {eur_200}€ / {usd_200}$
· 🔴 500 CREDITI = {eur_500}€ / {usd_500}$
· 🟤 1000 CREDITI = {eur_1000}€ / {usd_1000}$

{translations[user_lang]['payment_addresses']}
━━━━━━━━━━━━━━━━━━━━
Ⓜ️ XRM (Monero):

`459uXRXZknoRy3eq9TfZxKZ85jKWCZniBEh2U5GEg9VCYjT6f5U57cNjerJcpw2eF7jSmQwzh6sgmAQEL79HhM3NRmSu6ZT`

₿ BTC (Bitcoin):

`19rgimxDy1FKW5RvXWPQN4u9eevKySmJTu`

Ξ ETH (Ethereum):

`0x2e7edD5154Be461bae0BD9F79473FC54B0eeEE59`

💳 PayPal (EUR/USD):

https://www.paypal.me/BotAi36

📊 CONVERSIONE:
━━━━━━━━━━━━━━━━━━━━
💰 2 crediti = 1 ricerca

🎁 SCONTI:
━━━━━━━━━━━━━━━━━━━━
• 200 crediti: 10% sconto
• 500 crediti: 15% sconto  
• 1000 crediti: 20% sconto

📝 COME ACQUISTARE:
━━━━━━━━━━━━━━━━━━━━
1. Scegli il pacchetto
2. Invia l'importo corrispondente in crypto (copia e incolla indirizzi) o PayPal
3. Invia ID Profilo / Screenshot a @Zerofilter00 (o su messaggi PayPal)
4. Ricevi crediti in 5-15 minuti

⚠️ AVVERTENZE:
━━━━━━━━━━━━━━━━━━━━
• Invia l'importo esatto in €/$ o equivalente crypto
• Nessun rimborso
• Verifica indirizzo prima di inviare

📞 SUPPORTO:
━━━━━━━━━━━━━━━━━━━━
• @Zerofilter00
• 24/7 disponibile

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        else:
            text = f"""{translations[user_lang]['shop_title']}

{translations[user_lang]['credit_packages']}
━━━━━━━━━━━━━━━━━━━━
· 🟢 20 CREDITS = {eur_20}€ / {usd_20}$
· 🟡 50 CREDITS = {eur_50}€ / {usd_50}$
· 🔵 100 CREDITS = {eur_100}€ / {usd_100}$
· 🟣 200 CREDITS = {eur_200}€ / {usd_200}$
· 🔴 500 CREDITS = {eur_500}€ / {usd_500}$
· 🟤 1000 CREDITS = {eur_1000}€ / {usd_1000}$

{translations[user_lang]['payment_addresses']}
━━━━━━━━━━━━━━━━━━━━
Ⓜ️ XRM (Monero):

`459uXRXZknoRy3eq9TfZxKZ85jKWCZniBEh2U5GEg9VCYjT6f5U57cNjerJcpw2eF7jSmQwzh6sgmAQEL79HhM3NRmSu6ZT`

₿ BTC (Bitcoin):

`19rgimxDy1FKW5RvXWPQN4u9eevKySmJTu`

Ξ ETH (Ethereum):

`0x2e7edD5154Be461bae0BD9F79473FC54B0eeEE59`

💳 PayPal (EUR/USD):

https://www.paypal.me/BotAi36

📊 CONVERSION:
━━━━━━━━━━━━━━━━━━━━
💰 2 credits = 1 search

🎁 DISCOUNTS:
━━━━━━━━━━━━━━━━━━━━
• 200 credits: 10% discount
• 500 credits: 15% discount
• 1000 credits: 20% discount

📝 HOW TO BUY:
━━━━━━━━━━━━━━━━━━━━
1. Choose the package
2. Send the corresponding amount in crypto (copy and paste) or PayPal
3. Send ID Profile / Screenshot to @Zerofilter00 (or on PayPal messages)
4. Receive credits in 5-15 minutes

⚠️ WARNINGS:
━━━━━━━━━━━━━━━━━━━━
• Send the exact amount in €/$ or crypto equivalent
• No refunds
• Verify address before sending

📞 SUPPORT:
━━━━━━━━━━━━━━━━━━━━
• @Zerofilter00
• 24/7 available

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        keyboard = [
            [InlineKeyboardButton(f"💳 {eur_20}€ - 20c", callback_data='buy_20'),
             InlineKeyboardButton(f"💳 {eur_50}€ - 50c", callback_data='buy_50')],
            [InlineKeyboardButton(f"💳 {eur_100}€ - 100c", callback_data='buy_100'),
             InlineKeyboardButton(f"💳 {eur_200}€ - 200c", callback_data='buy_200')],
            [InlineKeyboardButton(f"💳 {eur_500}€ - 500c", callback_data='buy_500'),
             InlineKeyboardButton(f"💳 {eur_1000}€ - 1000c", callback_data='buy_1000')],
            [InlineKeyboardButton(translations[user_lang]['back'], callback_data='back_to_main')]
        ]
        
        if update.callback_query:
            await update.callback_query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard))
        else:
            await update.message.reply_text(text, reply_markup=InlineKeyboardMarkup(keyboard))

    
    async def start(self, update: Update, context: CallbackContext):
        """Comando start - Mostra il menu principale con interfaccia"""
        await self.show_main_menu(update, context)
    
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
            'documents': [],
            'addresses': [],
            'other': []
        }
        
        query = re.sub(r'\s+', ' ', query).strip()
        
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        phone_pattern = r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,9}'
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        hash_pattern = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
        document_pattern = r'\b[A-Z]{2}\d{7}\b|\b\d{9}\b|\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b|\b[A-Z]{2}\d{5}[A-Z]{2}\d{4}\b'
        
        components['emails'] = re.findall(email_pattern, query, re.IGNORECASE)
        components['phones'] = re.findall(phone_pattern, query)
        components['ips'] = re.findall(ip_pattern, query)
        components['hashes'] = re.findall(hash_pattern, query)
        components['documents'] = re.findall(document_pattern, query, re.IGNORECASE)
        
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
        
        password_pattern = r'\b[a-zA-Z0-9_@#$%^&*!]{6,30}\b'
        password_candidates = re.findall(password_pattern, remaining_query)
        
        for pwd in password_candidates:
            if '@' not in pwd and not pwd.replace('_', '').replace('@', '').replace('#', '').replace('$', '').replace('%', '').replace('^', '').replace('&', '').replace('*', '').replace('!', '').isdigit():
                components['passwords'].append(pwd)
                remaining_query = remaining_query.replace(pwd, '')
        
        address_indicators = ['via', 'viale', 'piazza', 'corso', 'largo', 'vicolo', 'strada']
        remaining_parts = remaining_query.split()
        
        i = 0
        while i < len(remaining_parts):
            part = remaining_parts[i].lower()
            if part in address_indicators and i + 2 < len(remaining_parts):
                address_parts = []
                if i + 2 < len(remaining_parts):
                    address_parts = remaining_parts[i:i+3]
                    address = ' '.join(address_parts)
                    components['addresses'].append(address)
                    for _ in range(3):
                        if i < len(remaining_parts):
                            remaining_parts.pop(i)
                    continue
            i += 1
        
        remaining_query = ' '.join(remaining_parts)
        remaining_query = re.sub(r'[^\w\s]', ' ', remaining_query).strip()
        remaining_parts = [p for p in remaining_query.split() if p]
        
        for part in remaining_parts:
            if len(part) <= 30 and ' ' not in part:
                components['usernames'].append(part)
            else:
                components['names'].append(part)
        
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
    
    async def handle_message(self, update: Update, context: CallbackContext):
        """Gestisce tutti i messaggi di ricerca"""
        user_id = update.effective_user.id
        query = update.message.text.strip()
        
        if not query:
            return
        
        if query.startswith('/'):
            return
        
        if not await self.update_balance(user_id, 2):
            user_lang = self.get_user_language(user_id)
            await update.message.reply_text(
                translations[user_lang]['insufficient_credits']
            )
            return
        
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        now = datetime.now()
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        user_lang = self.get_user_language(user_id)
        wait_text = f"""{translations[user_lang]['processing']}
⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        msg = await update.message.reply_text(wait_text)
        
        try:
            components = self.parse_composite_query(query)
            total_components = sum(len(v) for v in components.values())
            
            if total_components >= 2:
                await self.search_composite_advanced(update, msg, query, user_id, data_italiana)
            else:
                search_type = self.api.detect_search_type(query)
                
                if any(keyword in query.lower() for keyword in ['facebook', 'fb', 'face', 'フェイスブック']):
                    search_type = 'facebook'
                
                # Gestione specifica per MVVIDSTER
                if search_type == 'username_mvvidster' or search_type == 'name_mvvidster':
                    await self.search_mvvidster_complete(update, msg, query, user_id, data_italiana)
                elif search_type == 'date_mvvidster':
                    await self.search_mvvidster_complete(update, msg, query, user_id, data_italiana)
                elif search_type == 'user_id_mvvidster':
                    await self.search_mvvidster_complete(update, msg, query, user_id, data_italiana)
                elif search_type == 'email':
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
                    # Default: cerca in tutti i database
                    await self.search_all_databases(update, msg, query, user_id, data_italiana)
            
        except Exception as e:
            logger.error(f"Search error: {e}")
            user_lang = self.get_user_language(user_id)
            error_text = f"""{translations[user_lang]['error']}
Query: {query}
Errore: {str(e)[:100]}

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
            try:
                await msg.edit_text(error_text)
            except:
                await update.message.reply_text(error_text)
    
    async def search_all_databases(self, update: Update, msg, search_term: str, user_id: int, data_italiana: str):
        """Ricerca in tutti i database disponibili"""
        # Cerca in MVVIDSTER
        mvvidster_results = await self.api.search_all_fields_mvvidster(search_term)
        
        # Cerca in WEBHOST_DATA
        webhost_results = await self.api.search_webhost_complete(search_term)
        
        now = datetime.now()
        
        result_text = f"""🔍 RICERCA MULTI-DATABASE
- Termine: {search_term}
- Database consultati: users_mvvidster, webhost_data"""
        
        all_unique_results = []
        seen_ids = set()
        
        # Combina risultati da MVVIDSTER
        if mvvidster_results['found']:
            for result in mvvidster_results['results']:
                user_id_key = result.get('user_id')
                if user_id_key not in seen_ids:
                    seen_ids.add(user_id_key)
                    all_unique_results.append(result)
        
        # Combina risultati da WEBHOST_DATA
        if webhost_results['found']:
            for result in webhost_results['results']:
                # Crea un ID unico basato sui dati
                data_str = str(result.get('data', {}))
                if data_str not in seen_ids:
                    seen_ids.add(data_str)
                    all_unique_results.append(result)
        
        if all_unique_results:
            result_text += f"\n\n✅ RISULTATI TROVATI: {len(all_unique_results)}"
            
            mvvidster_count = sum(1 for r in all_unique_results if r.get('source') == 'users_mvvidster')
            webhost_count = sum(1 for r in all_unique_results if r.get('source') == 'webhost_data')
            
            result_text += f"\n📊 Per fonte:"
            result_text += f"\n  - users_mvvidster: {mvvidster_count} risultati"
            result_text += f"\n  - webhost_data: {webhost_count} risultati"
            
            # Mostra primi risultati da ogni fonte
            mvvidster_shown = 0
            webhost_shown = 0
            
            for i, result in enumerate(all_unique_results[:15], 1):
                source = result.get('source', 'Unknown')
                
                if source == 'users_mvvidster':
                    mvvidster_shown += 1
                    result_text += f"\n\n  {i}. [MVVIDSTER] 👤 {result.get('username', result.get('display_name', 'N/A'))}"
                    
                    if result.get('email'):
                        result_text += f"\n     📧 Email: {result['email']}"
                    
                    if result.get('user_id'):
                        result_text += f"\n     🆔 User ID: {result['user_id']}"
                    
                    if result.get('registration_date'):
                        result_text += f"\n     📅 Data registrazione: {result['registration_date']}"
                
                elif source == 'webhost_data':
                    webhost_shown += 1
                    table = result.get('table', 'Unknown')
                    data = result.get('data', {})
                    
                    result_text += f"\n\n  {i}. [WEBHOST] 📊 Tabella: {table}"
                    
                    # Mostra i dati più importanti
                    for key, value in list(data.items())[:5]:  # Limita a 5 campi
                        if value and str(value).strip():
                            result_text += f"\n     📋 {key}: {value}"
            
            if len(all_unique_results) > 15:
                result_text += f"\n\n📊 Altri {len(all_unique_results) - 15} risultati non mostrati..."
        
        else:
            user_lang = self.get_user_language(user_id)
            result_text += f"\n\n{translations[user_lang]['no_results']}"
            result_text += f"\n❌ Nessun risultato trovato nei database per: {search_term}"
            
            result_text += f"\n\n💡 Suggerimenti:"
            result_text += f"\n  · Prova con email completa"
            result_text += f"\n  · Prova con username"
            result_text += f"\n  · Prova con indirizzo IP"
            result_text += f"\n  · Prova con password (se disponibile)"
        
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_mvvidster_complete(self, update: Update, msg, search_term: str, user_id: int, data_italiana: str):
        """Ricerca completa nella tabella users_mvvidster"""
        # Prima cerca in tutti i campi
        all_results = await self.api.search_all_fields_mvvidster(search_term)
        
        # Poi cerca specificamente per username
        username_results = await self.api.search_username_mvvidster(search_term)
        
        # Poi cerca specificamente per data
        date_results = await self.api.search_date_mvvidster(search_term)
        
        now = datetime.now()
        
        result_text = f"""🔍 RICERCA COMPLETA MVVIDSTER
- Termine: {search_term}
- Database: users_mvvidster"""
        
        all_unique_results = []
        seen_ids = set()
        
        # Combina tutti i risultati evitando duplicati
        for source_results in [all_results, username_results, date_results]:
            if source_results['found']:
                for result in source_results['results']:
                    user_id_key = result.get('user_id')
                    if user_id_key not in seen_ids:
                        seen_ids.add(user_id_key)
                        all_unique_results.append(result)
        
        if all_unique_results:
            result_text += f"\n\n✅ RISULTATI TROVATI: {len(all_unique_results)}"
            
            for i, result in enumerate(all_unique_results[:10], 1):
                result_text += f"\n\n  {i}. 👤 {result.get('username', result.get('display_name', 'N/A'))}"
                
                if result.get('email'):
                    result_text += f"\n     📧 Email: {result['email']}"
                
                if result.get('user_id'):
                    result_text += f"\n     🆔 User ID: {result['user_id']}"
                
                if result.get('registration_date'):
                    result_text += f"\n     📅 Data registrazione: {result['registration_date']}"
                
                if result.get('original_id'):
                    result_text += f"\n     🔗 Original ID: {result['original_id']}"
                
                if result.get('profile_photo_id') and result['profile_photo_id'] > 0:
                    result_text += f"\n     📸 Foto profilo: Si (ID: {result['profile_photo_id']})"
                
                if result.get('city'):
                    result_text += f"\n     🏙️ Città: {result['city']}"
                
                if result.get('country'):
                    result_text += f"\n     🌍 Paese: {result['country']}"
                
                result_text += f"\n     📊 Fonte: {result.get('source', 'users_mvvidster')}"
            
            if len(all_unique_results) > 10:
                result_text += f"\n\n📊 Altri {len(all_unique_results) - 10} risultati non mostrati..."
        
        else:
            user_lang = self.get_user_language(user_id)
            result_text += f"\n\n{translations[user_lang]['no_results']}"
            result_text += f"\n❌ Nessun risultato trovato in users_mvvidster per: {search_term}"
            
            result_text += f"\n\n💡 Cerca con:"
            result_text += f"\n  · Username/disp_name"
            result_text += f"\n  · Email"
            result_text += f"\n  · User ID"
            result_text += f"\n  · Data (formato: YYYY-MM-DD)"
            result_text += f"\n  · Original ID"
        
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_composite_advanced(self, update: Update, msg, query: str, user_id: int, data_italiana: str):
        """Ricerca composta avanzata - Supporta query con più informazioni"""
        components = self.parse_composite_query(query)
        
        now = datetime.now()
        result_text = f"""🔍 RICERCA COMPOSTA AVANZATA
- Query: {query}"""
        
        all_results = []
        
        if components['emails']:
            result_text += f"\n\n📧 EMAIL TROVATE: {len(components['emails'])}"
            for i, email in enumerate(components['emails'][:3], 1):
                result_text += f"\n  {i}. {email}"
                email_results = await self.api.search_email(email)
                if email_results['found']:
                    result_text += f"\n     ✅ Trovata in {email_results['count']} database"
                    if email_results['results']:
                        first_result = email_results['results'][0]
                        if first_result.get('password'):
                            result_text += f"\n     🔐 Password: {first_result['password'][:30]}..."
        
        if components['phones']:
            result_text += f"\n\n📱 TELEFONI TROVATI: {len(components['phones'])}"
            for i, phone in enumerate(components['phones'][:3], 1):
                result_text += f"\n  {i}. {phone}"
                try:
                    parsed = phonenumbers.parse(phone, None)
                    country = geocoder.description_for_number(parsed, "it")
                    if country:
                        result_text += f"\n     🌍 Paese: {country}"
                except:
                    pass
                
                phone_results = await self.api.search_phone(phone)
                if phone_results['found']:
                    result_text += f"\n     ✅ Trovato in {phone_results['count']} database"
        
        if components['names']:
            result_text += f"\n\n👤 NOMI TROVATI: {len(components['names'])}"
            for i, name in enumerate(components['names'][:3], 1):
                result_text += f"\n  {i}. {name}"
                name_results = await self.api.search_name(name)
                if name_results['found']:
                    result_text += f"\n     ✅ Trovato in {name_results['count']} record"
                    if name_results['results']:
                        first_result = name_results['results'][0]
                        if first_result.get('phone'):
                            result_text += f"\n     📱 Telefono: {first_result['phone']}"
                        if first_result.get('city'):
                            result_text += f"\n     🏙️ Città: {first_result['city']}"
        
        if components['usernames']:
            result_text += f"\n\n👥 USERNAME TROVATI: {len(components['usernames'])}"
            for i, username in enumerate(components['usernames'][:3], 1):
                result_text += f"\n  {i}. {username}"
                social_results = await self.api.search_username(username)
                if social_results['social_count'] > 0:
                    result_text += f"\n     ✅ {social_results['social_count']} account social"
            
            for social in social_results['social']:
                platform = social['platform']
                url = social['url']
                result_text += f"\n     - {platform}: {url}"
        
        if components['ips']:
            result_text += f"\n\n🌐 IP TROVATI: {len(components['ips'])}"
            for i, ip in enumerate(components['ips'][:2], 1):
                result_text += f"\n  {i}. {ip}"
                ip_results = await self.api.search_ip(ip)
                if ip_results.get('ipinfo'):
                    info = ip_results['ipinfo']
                    if info.get('city'):
                        result_text += f"\n     🏙️ Città: {info['city']}"
                    if info.get('country'):
                        result_text += f"\n     🌍 Paese: {info['country']}"
        
        if components['passwords']:
            result_text += f"\n\n🔐 PASSWORD TROVATI: {len(components['passwords'])}"
            for i, pwd in enumerate(components['passwords'][:2], 1):
                result_text += f"\n  {i}. {pwd[:10]}..."
                pwd_results = await self.api.search_password(pwd)
                if pwd_results['found']:
                    result_text += f"\n     ⚠️ Trovata in {pwd_results['count']} database"
        
        if components['hashes']:
            result_text += f"\n\n🔑 HASH TROVATI: {len(components['hashes'])}"
            for i, hash_val in enumerate(components['hashes'][:2], 1):
                result_text += f"\n  {i}. {hash_val[:20]}..."
                hash_results = await self.api.search_hash(hash_val)
                if hash_results['found']:
                    result_text += f"\n     🎉 Hash decriptato!"
        
        if components['documents']:
            result_text += f"\n\n📄 DOCUMENTI TROVATI: {len(components['documents'])}"
            for i, doc in enumerate(components['documents'][:2], 1):
                result_text += f"\n  {i}. {doc}"
                doc_results = await self.api.search_document(doc)
                if doc_results['found']:
                    result_text += f"\n     🔓 Trovato in {doc_results['count']} database"
                    if doc_results['results']:
                        first_result = doc_results['results'][0]
                        if first_result.get('full_name'):
                            result_text += f"\n     👤 Nome: {first_result['full_name']}"
        
        if components['addresses']:
            result_text += f"\n\n🏠 INDIRIZZI TROVATI: {len(components['addresses'])}"
            for i, address in enumerate(components['addresses'][:2], 1):
                result_text += f"\n  {i}. {address}"
                if any(word in address.lower() for word in ['ufficio', 'lavoro', 'azienda', 'company']):
                    work_results = await self.api.search_work_address(address)
                    if work_results['found']:
                        result_text += f"\n     🏢 Indirizzo lavorativo trovato"
                else:
                    home_results = await self.api.search_home_address(address)
                    if home_results['found']:
                        result_text += f"\n     🏠 Indirizzo di casa trovato"
        
        total_components = sum(len(v) for v in components.values())
        if total_components == 0:
            result_text += f"\n\n🔍 NESSUNA INFORMAZIONE STRUTTURATA RILEVATA"
            result_text += f"\n📝 Eseguo ricerca standard..."
            
            search_type = self.api.detect_search_type(query)
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
                home_results = await self.api.search_home_address(query)
                work_results = await self.api.search_work_address(query)
                if home_results['found'] or work_results['found']:
                    result_text += f"\n✅ Indirizzo trovato"
            else:
                variant_results = await self.api.search_variants(query)
                found_any = any(len(v) > 0 for v in variant_results.values())
                if found_any:
                    result_text += f"\n✅ Risultati trovati"
        
        if total_components >= 2:
            result_text += f"\n\n🔗 CORRELAZIONI TROVATE:"
            result_text += f"\n📊 Componenti identificati: {total_components}"
            
            correlations = []
            
            if components['emails'] and components['phones']:
                for email in components['emails'][:1]:
                    for phone in components['phones'][:1]:
                        count = db.execute_query(
                            '''SELECT COUNT(*) FROM breach_data WHERE 
                            (email = %s OR phone = %s) AND 
                            (email = %s OR phone = %s)''',
                            (email, email, phone, phone),
                            fetchone=True
                        )[0]
                        if count > 0:
                            correlations.append(f"📧 {email} ↔ 📱 {phone}")
            
            if components['names'] and components['phones']:
                for name in components['names'][:1]:
                    for phone in components['phones'][:1]:
                        phone_clean = re.sub(r'[^\d+]', '', phone)[-10:]
                        count = db.execute_query(
                            '''SELECT COUNT(*) FROM facebook_leaks WHERE 
                            phone LIKE %s AND (name LIKE %s OR surname LIKE %s)''',
                            (f'%{phone_clean}%', f'%{name[:5]}%', f'%{name[:5]}%'),
                            fetchone=True
                        )[0]
                        if count > 0:
                            correlations.append(f"👤 {name[:15]}... ↔ 📱 {phone}")
            
            if components['documents'] and components['names']:
                for doc in components['documents'][:1]:
                    for name in components['names'][:1]:
                        count = db.execute_query(
                            '''SELECT COUNT(*) FROM addresses_documents WHERE 
                            document_number LIKE %s AND full_name LIKE %s''',
                            (f'%{doc}%', f'%{name}%'),
                            fetchone=True
                        )[0]
                        if count > 0:
                            correlations.append(f"📄 {doc} ↔ 👤 {name[:15]}...")
            
            if correlations:
                for corr in correlations[:3]:
                    result_text += f"\n  - {corr}"
            else:
                result_text += f"\n  - Nessuna correlazione diretta trovata"
        
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_email_exact(self, update: Update, msg, email: str, user_id: int, data_italiana: str):
        """Ricerca email - Formato esatto"""
        search_results = await self.api.search_email(email)
        
        now = datetime.now()
        result_text = f"""📧 Cerca per posta
- {email} - Cerca la posta"""
        
        if search_results['found']:
            user_lang = self.get_user_language(user_id)
            result_text += f"\n\n✅ RISULTATI TROVATI: {search_results['count']}"
            
            sources = {}
            for result in search_results['results'][:15]:
                source = result['source']
                if source not in sources:
                    sources[source] = []
                sources[source].append(result)
            
            for source, entries in list(sources.items())[:3]:
                result_text += f"\n\n{source}:"
                for entry in entries[:2]:
                    if source == 'Dehashed':
                        result_text += f"\n  - Database: {entry.get('database', 'Unknown')}"
                        if entry.get('password'):
                            result_text += f"\n    🔐 Password: {entry['password']}"
                        if entry.get('date'):
                            result_text += f"\n    📅 Data: {entry['date']}"
                    elif source == 'HIBP':
                        result_text += f"\n  - Violazione: {entry.get('breach', 'Unknown')}"
                        result_text += f"\n    📅 Data: {entry.get('date', 'Unknown')}"
                    elif source == 'users_mvvidster':
                        result_text += f"\n  - Username: {entry.get('username', 'N/A')}"
                        result_text += f"\n    User ID: {entry.get('user_id', 'N/A')}"
                        if entry.get('registration_date'):
                            result_text += f"\n    📅 Data registrazione: {entry['registration_date']}"
                    elif source == 'webhost_data':
                        result_text += f"\n  - Tabella: {entry.get('table', 'Unknown')}"
                        data = entry.get('data', {})
                        if 'password' in data:
                            result_text += f"\n    🔐 Password: {data['password'][:20]}..."
                        if 'created_at' in data:
                            result_text += f"\n    📅 Creato il: {data['created_at']}"
                        if 'ip_address' in data:
                            result_text += f"\n    🌐 IP: {data['ip_address']}"
        
        else:
            user_lang = self.get_user_language(user_id)
            result_text += f"\n\n{translations[user_lang]['no_results']}"
            result_text += f"\n📭 L'email non è stata trovata nei database conosciuti."
        
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_phone_exact(self, update: Update, msg, phone: str, user_id: int, data_italiana: str):
        """Ricerca telefono - Formato esatto"""
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
        result_text = f"""📱 Cerca per numero di telefono
- {phone} - Cerca il numero"""
        
        if phone_info:
            result_text += f"\n\n📞 INFORMAZIONI:"
            result_text += f"\n  - 🌍 Paese: {phone_info.get('country', 'N/A')}"
            result_text += f"\n  - 📡 Operatore: {phone_info.get('carrier', 'N/A')}"
            result_text += f"\n  - 📋 Formato: {phone_info.get('national', 'N/A')}"
        
        if search_results['found']:
            mvvidster_results = []
            facebook_results = []
            webhost_results = []
            other_results = []
            
            for result in search_results['results']:
                if result['source'] == 'users_mvvidster':
                    mvvidster_results.append(result)
                elif result['source'] == 'Facebook Leak 2021':
                    facebook_results.append(result)
                elif result['source'] == 'webhost_data':
                    webhost_results.append(result)
                else:
                    other_results.append(result)
            
            if mvvidster_results:
                result_text += f"\n\n📊 USERS_MVVIDSTER:"
                result_text += f"\n  📊 Trovati: {len(mvvidster_results)} record"
                
                for i, result in enumerate(mvvidster_results[:2], 1):
                    result_text += f"\n\n  {i}. 👤 {result.get('username', 'N/A')}"
                    if result.get('user_id'):
                        result_text += f"\n     🆔 User ID: {result['user_id']}"
                    if result.get('email'):
                        result_text += f"\n     📧 Email: {result['email']}"
                    if result.get('registration_date'):
                        result_text += f"\n     📅 Data registrazione: {result['registration_date']}"
            
            if webhost_results:
                result_text += f"\n\n🌐 WEBHOST_DATA:"
                result_text += f"\n  📊 Trovati: {len(webhost_results)} record"
                
                for i, result in enumerate(webhost_results[:2], 1):
                    result_text += f"\n\n  {i}. 📊 Tabella: {result.get('table', 'Unknown')}"
                    data = result.get('data', {})
                    if 'email' in data:
                        result_text += f"\n     📧 Email: {data['email']}"
                    if 'username' in data:
                        result_text += f"\n     👤 Username: {data['username']}"
                    if 'ip_address' in data:
                        result_text += f"\n     🌐 IP: {data['ip_address']}"
                    if 'password' in data:
                        result_text += f"\n     🔐 Password: {data['password'][:20]}..."
            
            if facebook_results:
                result_text += f"\n\n🔓 FACEBOOK LEAK 2021:"
                result_text += f"\n  📊 Trovati: {len(facebook_results)} record"
                
                for i, result in enumerate(facebook_results[:2], 1):
                    result_text += f"\n\n  {i}. 👤 {result.get('name', 'N/A')}"
                    if result.get('facebook_id'):
                        result_text += f"\n     📘 ID: {result['facebook_id']}"
                    if result.get('gender'):
                        result_text += f"\n     ⚤ Genere: {result['gender']}"
                    if result.get('city'):
                        result_text += f"\n     🏙️ Città: {result['city']}"
            
            if other_results:
                result_text += f"\n\n📊 ALTRI DATABASE:"
                for result in other_results[:2]:
                    result_text += f"\n  - {result['source']}"
                    if result.get('email'):
                        result_text += f"\n    📧 Email: {result['email']}"
                    if result.get('name'):
                        result_text += f"\n    👤 Nome: {result['name']}"
        
        else:
            user_lang = self.get_user_language(user_id)
            result_text += f"\n\n{translations[user_lang]['no_results']}"
            result_text += f"\n📵 Il numero non è stato trovato."
        
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_name_exact(self, update: Update, msg, name: str, user_id: int, data_italiana: str):
        """Ricerca per nome - Formato esatto"""
        search_results = await self.api.search_name(name)
        username = name.split()[0] if ' ' in name else name
        social_results = await self.api.search_username(username)
        
        now = datetime.now()
        result_text = f"""👤 Cerca per nome o nick
- {name} - Cerca il nome"""
        
        if search_results['found']:
            result_text += f"\n\n🔓 DATA BREACH TROVATI: {search_results['count']}"
            
            for i, result in enumerate(search_results['results'][:3], 1):
                result_text += f"\n\n  {i}. 👤 {result.get('username', result.get('display_name', 'N/A'))}"
                if result.get('source') == 'users_mvvidster':
                    if result.get('user_id'):
                        result_text += f"\n     🆔 User ID: {result['user_id']}"
                    if result.get('email'):
                        result_text += f"\n     📧 Email: {result['email']}"
                    if result.get('registration_date'):
                        result_text += f"\n     📅 Data registrazione: {result['registration_date']}"
                elif result.get('source') == 'Facebook Leak 2021':
                    if result.get('phone'):
                        result_text += f"\n     📱 Telefono: {result['phone']}"
                    if result.get('facebook_id'):
                        result_text += f"\n     📘 Facebook ID: {result['facebook_id']}"
                    if result.get('city'):
                        result_text += f"\n     🏙️ Città: {result['city']}"
                elif result.get('source') == 'webhost_data':
                    result_text += f"\n     📊 Tabella: {result.get('table', 'Unknown')}"
                    data = result.get('data', {})
                    if 'email' in data:
                        result_text += f"\n     📧 Email: {data['email']}"
                    if 'username' in data:
                        result_text += f"\n     👤 Username: {data['username']}"
        
        if social_results['social_count'] > 0:
            result_text += f"\n\n📱 ACCOUNT SOCIAL TROVATI: {social_results['social_count']}"
            
            for social in social_results['social'][:4]:
                platform = social['platform']
                result_text += f"\n  - {platform}: {social['url']}"
        
        if not search_results['found'] and social_results['social_count'] == 0:
            user_lang = self.get_user_language(user_id)
            result_text += f"\n\n{translations[user_lang]['no_results']}"
            result_text += f"\n👤 Il nome non è stato trovato."
        
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_social_exact(self, update: Update, msg, username: str, user_id: int, data_italiana: str):
        """Ricerca username - Formato esatto con API potenziate"""
        # PRIMA usa le nuove API
        search_results = await self.api.search_username(username)
        # POI ricerca avanzata
        advanced_results = await self.api.search_username_advanced(username)
        
        now = datetime.now()
        result_text = f"""👥 RICERCA USERNAME AVANZATA
- {username} - Analisi su 300+ piattaforme"""
        
        # Statistiche
        api_sources = search_results.get('api_sources', [])
        result_text += f"\n\n📊 FONTI UTILIZZATE: {', '.join(api_sources)}"
        
        if search_results['social_count'] > 0:
            result_text += f"\n\n✅ ACCOUNT TROVATI: {search_results['social_count']}"
            
            # Raggruppa per piattaforma principale
            platforms = {}
            for social in search_results['social'][:15]:  # Limita a 15
                platform = social['platform']
                if platform not in platforms:
                    platforms[platform] = []
                platforms[platform].append(social)
            
            for platform, accounts in list(platforms.items())[:10]:
                result_text += f"\n\n{platform}:"
                for account in accounts[:2]:
                    result_text += f"\n  🔗 {account['url']}"
                    if account.get('source'):
                        result_text += f" ({account['source']})"
        
        # Varianti trovate
        if advanced_results.get('variants'):
            result_text += f"\n\n🔍 VARIANTI TROVATE:"
            for variant in advanced_results['variants'][:3]:
                if variant.get('sites'):
                    result_text += f"\n  · {variant['variant']}: {len(variant['sites'])} siti"
        
        if search_results['breach_count'] > 0:
            result_text += f"\n\n🔓 DATA BREACH TROVATI: {search_results['breach_count']}"
            for breach in search_results['breach'][:3]:
                result_text += f"\n  - {breach['source']}"
                if breach.get('email'):
                    result_text += f"\n    📧 Email: {breach['email']}"
                if breach.get('password'):
                    result_text += f"\n    🔐 Password: {breach['password'][:15]}..."
        
        # Cerca nel database webhost_data
        webhost_results = db.search_webhost_by_username(username)
        if webhost_results:
            result_text += f"\n\n🌐 WEBHOST_DATA TROVATI: {len(webhost_results)} record"
            for i, result in enumerate(webhost_results[:3], 1):
                result_text += f"\n\n  {i}. 📊 Tabella: {result['table']}"
                data = result['data']
                if 'email' in data:
                    result_text += f"\n     📧 Email: {data['email']}"
                if 'password' in data:
                    result_text += f"\n     🔐 Password: {data['password'][:20]}..."
                if 'created_at' in data:
                    result_text += f"\n     📅 Creato il: {data['created_at']}"
                if 'ip_address' in data:
                    result_text += f"\n     🌐 IP: {data['ip_address']}"
        
        if search_results['social_count'] == 0 and search_results['breach_count'] == 0 and not webhost_results:
            user_lang = self.get_user_language(user_id)
            result_text += f"\n\n{translations[user_lang]['no_results']}"
            result_text += f"\n👤 Username non trovato su nessuna piattaforma conosciuta."
            result_text += f"\n\n💡 PROVA CON:"
            result_text += f"\n  · Varianti: {username}123, real{username}"
            result_text += f"\n  · Nome completo: se contiene spazi"
            result_text += f"\n  · Email: se è un indirizzo email"
        
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_ip_exact(self, update: Update, msg, ip: str, user_id: int, data_italiana: str):
        """Ricerca IP - Formato esatto"""
        search_results = await self.api.search_ip(ip)
        
        now = datetime.now()
        result_text = f"""🌐 Cerca tramite IP
- {ip} - Analisi IP"""
        
        if search_results.get('ipinfo'):
            info = search_results['ipinfo']
            result_text += f"\n\n📍 GEO-LOCALIZZAZIONE:"
            result_text += f"\n  - 🏙️ Città: {info.get('city', 'N/A')}"
            result_text += f"\n  - 🗺️ Regione: {info.get('region', 'N/A')}"
            result_text += f"\n  - 🌍 Paese: {info.get('country', 'N/A')}"
            result_text += f"\n  - 📡 ISP: {info.get('org', info.get('isp', 'N/A'))}"
        
        if search_results.get('abuseipdb'):
            abuse = search_results['abuseipdb']
            result_text += f"\n\n⚠️ THREAT INTEL:"
            result_text += f"\n  - ⚠️ Score: {abuse.get('abuseConfidenceScore', 0)}/100"
            result_text += f"\n  - 📊 Reports: {abuse.get('totalReports', 0)}"
        
        if search_results.get('shodan'):
            shodan_info = search_results['shodan']
            result_text += f"\n\n🔓 SERVIZI ESPOSTI:"
            if shodan_info.get('ports'):
                ports = shodan_info['ports'][:5]
                result_text += f"\n  - 🚪 Porte: {', '.join(map(str, ports))}"
        
        # Mostra risultati da webhost_data
        if search_results.get('webhost_data'):
            webhost_info = search_results['webhost_data']
            if webhost_info['found']:
                result_text += f"\n\n🌐 WEBHOST_DATA TROVATI: {webhost_info['count']} record"
                for i, result in enumerate(webhost_info['results'][:3], 1):
                    result_text += f"\n\n  {i}. 📊 Tabella: {result['table']}"
                    data = result['data']
                    if 'email' in data:
                        result_text += f"\n     📧 Email: {data['email']}"
                    if 'username' in data:
                        result_text += f"\n     👤 Username: {data['username']}"
                    if 'password' in data:
                        result_text += f"\n     🔐 Password: {data['password'][:20]}..."
        
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_password_exact(self, update: Update, msg, password: str, user_id: int, data_italiana: str):
        """Ricerca password - Formato esatto"""
        search_results = await self.api.search_password(password)
        
        now = datetime.now()
        result_text = f"""🔐 Ricerca password
- {password} - Analisi password"""
        
        if search_results['found']:
            result_text += f"\n\n⚠️ PASSWORD TROVATA IN: {search_results['count']} database"
            
            emails_found = []
            for result in search_results['results'][:2]:
                if result.get('email'):
                    emails_found.append(result['email'])
                
                result_text += f"\n\n  - {result['source']}"
                if result['source'] == 'webhost_data':
                    result_text += f"\n    📊 Tabella: {result.get('table', 'Unknown')}"
                    data = result.get('data', {})
                    if 'email' in data:
                        result_text += f"\n    📧 Email: {data['email']}"
                    if 'username' in data:
                        result_text += f"\n    👤 Username: {data['username']}"
                    if 'created_at' in data:
                        result_text += f"\n    📅 Creato il: {data['created_at']}"
                else:
                    result_text += f"\n    📁 Database: {result.get('database', 'Unknown')}"
                    if result.get('email'):
                        result_text += f"\n    📧 Email: {result['email']}"
                    if result.get('date'):
                        result_text += f"\n    📅 Data: {result['date']}"
            
            if emails_found:
                unique_emails = list(set(emails_found))[:2]
                result_text += f"\n\n📧 EMAIL ASSOCIATE:"
                for email in unique_emails:
                    result_text += f"\n  - {email}"
        else:
            result_text += f"\n\n✅ PASSWORD SICURA"
            result_text += f"\n🔐 Password non trovata nei database."
        
        strength = "🔴 DEBOLE"
        if len(password) >= 12 and any(c.isdigit() for c in password) and any(c.isalpha() for c in password):
            strength = "🟢 FORTE"
        elif len(password) >= 8:
            strength = "🟡 MEDIA"
        
        result_text += f"\n\n📊 SICUREZZA: {strength}"
        result_text += f"\n📏 Lunghezza: {len(password)} caratteri"
        
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_hash_exact(self, update: Update, msg, hash_str: str, user_id: int, data_italiana: str):
        """Ricerca hash - Formato esatto"""
        search_results = await self.api.search_hash(hash_str)
        
        now = datetime.now()
        result_text = f"""🔑 Ricerca hash
- {hash_str} - Analisi hash"""
        
        result_text += f"\n\n📊 TIPO HASH: {search_results['hash_type']}"
        result_text += f"\n📏 Lunghezza: {len(hash_str)} caratteri"
        
        if search_results['found']:
            result_text += f"\n\n🎉 HASH DECRIPTATO!"
            
            for result in search_results['results'][:2]:
                result_text += f"\n\n  - {result['source']}"
                if result['source'] == 'webhost_data':
                    result_text += f"\n    📊 Tabella: {result.get('table', 'Unknown')}"
                    data = result.get('data', {})
                    if 'email' in data:
                        result_text += f"\n    📧 Email: {data['email']}"
                    if 'username' in data:
                        result_text += f"\n    👤 Username: {data['username']}"
                else:
                    result_text += f"\n    🔓 Password: {result['password']}"
                    if result.get('email'):
                        result_text += f"\n    📧 Email: {result['email']}"
        else:
            user_lang = self.get_user_language(user_id)
            result_text += f"\n\n{translations[user_lang]['no_results']}"
            result_text += f"\n🔑 Hash non presente nei database."
        
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_document_exact(self, update: Update, msg, document: str, user_id: int, data_italiana: str):
        """Ricerca documento - Formato esatto come immagini"""
        search_results = await self.api.search_document(document)
        
        now = datetime.now()
        result_text = f"""📄 Cerca per documento
- {document} - Ricerca numero documento"""
        
        if search_results['found']:
            result_text += f"\n\n✅ RISULTATI TROVATI: {search_results['count']}"
            
            sources = {}
            for result in search_results['results'][:10]:
                source = result['source']
                if source not in sources:
                    sources[source] = []
                sources[source].append(result)
            
            for source, entries in list(sources.items())[:3]:
                result_text += f"\n\n{source}:"
                for entry in entries[:2]:
                    result_text += f"\n  - 📄 Documento: {entry.get('document', document)}"
                    if entry.get('full_name'):
                        result_text += f"\n    👤 Nome: {entry['full_name']}"
                    if entry.get('address'):
                        result_text += f"\n    🏠 Indirizzo: {entry['address']}"
                    if entry.get('phone'):
                        result_text += f"\n    📱 Telefono: {entry['phone']}"
                    if entry.get('email'):
                        result_text += f"\n    📧 Email: {entry['email']}"
        
        else:
            user_lang = self.get_user_language(user_id)
            result_text += f"\n\n{translations[user_lang]['no_results']}"
            result_text += f"\n📄 Il documento non è stato trovato nei database conosciuti."
        
        doc_type = "Sconosciuto"
        if re.match(r'^[A-Z]{2}\d{7}$', document):
            doc_type = "Carta d'Identità 🇮🇹"
        elif re.match(r'^\d{9}$', document):
            doc_type = "Codice Fiscale 🇮🇹"
        elif re.match(r'^[A-Z]{2}\d{5}[A-Z]{2}\d{4}$', document):
            doc_type = "Passaporto 🇮🇹"
        elif re.match(r'^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$', document):
            doc_type = "Codice Fiscale Completo 🇮🇹"
        
        result_text += f"\n\n📋 TIPO DOCUMENTO: {doc_type}"
        
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_address_exact(self, update: Update, msg, address: str, user_id: int, data_italiana: str):
        """Ricerca indirizzo - Formato esatto come immagini"""
        is_work_address = any(word in address.lower() for word in ['ufficio', 'lavoro', 'azienda', 'company', 'sede'])
        
        if is_work_address:
            search_results = await self.api.search_work_address(address)
            address_type = "🏢 INDIRIZZO LAVORATIVO"
        else:
            search_results = await self.api.search_home_address(address)
            address_type = "🏠 INDIRIZZO DI CASA"
        
        now = datetime.now()
        result_text = f"""{address_type}
- {address} - Ricerca indirizzo"""
        
        if search_results['found']:
            result_text += f"\n\n✅ RISULTATI TROVATI: {search_results['count']}"
            
            people = []
            companies = []
            webhost_data = []
            
            for result in search_results['results'][:8]:
                if result.get('source') == 'webhost_data':
                    webhost_data.append(result)
                elif result.get('company') or result.get('address_type') == 'work':
                    companies.append(result)
                else:
                    people.append(result)
            
            if people:
                result_text += f"\n\n👤 PERSONE ASSOCIATE:"
                for i, person in enumerate(people[:3], 1):
                    result_text += f"\n\n  {i}. 👤 {person.get('full_name', person.get('username', 'N/A'))}"
                    if person.get('phone'):
                        result_text += f"\n     📱 Telefono: {person['phone']}"
                    if person.get('email'):
                        result_text += f"\n     📧 Email: {person['email']}"
                    if person.get('document_number'):
                        result_text += f"\n     📄 Documento: {person['document_number']}"
            
            if companies:
                result_text += f"\n\n🏢 AZIENDE/LAVORI:"
                for i, company in enumerate(companies[:3], 1):
                    result_text += f"\n\n  {i}. 🏢 {company.get('company', 'Azienda')}"
                    if company.get('address'):
                        result_text += f"\n     📍 Indirizzo: {company['address']}"
                    if company.get('full_name'):
                        result_text += f"\n     👤 Persona: {company['full_name']}"
            
            if webhost_data:
                result_text += f"\n\n🌐 WEBHOST_DATA:"
                for i, result in enumerate(webhost_data[:3], 1):
                    result_text += f"\n\n  {i}. 📊 Tabella: {result.get('table', 'Unknown')}"
                    data = result.get('data', {})
                    if 'email' in data:
                        result_text += f"\n     📧 Email: {data['email']}"
                    if 'username' in data:
                        result_text += f"\n     👤 Username: {data['username']}"
                    if 'ip_address' in data:
                        result_text += f"\n     🌐 IP: {data['ip_address']}"
                    if 'password' in data:
                        result_text += f"\n     🔐 Password: {data['password'][:20]}..."
        
        else:
            user_lang = self.get_user_language(user_id)
            result_text += f"\n\n{translations[user_lang]['no_results']}"
            result_text += f"\n📍 L'indirizzo non è stato trovato nei database conosciuti."
            
            result_text += f"\n\n💡 SUGGERIMENTI:"
            result_text += f"\n  - Cerca con formato: 'Via Roma 123, Milano'"
            result_text += f"\n  - Per indirizzo lavorativo: 'Ufficio Via Torino 45'"
            result_text += f"\n  - Per indirizzo casa: 'Casa Via Verdi 12'"
        
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def search_facebook_complete(self, update: Update, msg, query: str, user_id: int, data_italiana: str):
        """Ricerca Facebook completa"""
        now = datetime.now()
        
        user_lang = self.get_user_language(user_id)
        result_text = f"""📘 RICERCA FACEBOOK COMPLETA
- {query} - {translations[user_lang]['processing']}"""
        
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
        
        if '@' in query:
            email_results = await self.api.search_facebook_by_email(query)
            all_results['by_email'] = email_results['results']
        elif re.match(r'^[\d\s\-\+\(\)]{8,}$', query.replace(' ', '')):
            phone_results = await self.api.search_facebook_by_phone(query)
            all_results['by_phone'] = phone_results['results']
        elif query.isdigit():
            id_results = await self.api.search_facebook_by_id(query)
            all_results['by_id'] = id_results['results']
        else:
            advanced_results = await self.api.search_facebook_advanced(query)
            all_results['by_name'] = advanced_results['leak_data']
            all_results['leaks'] = advanced_results['leak_data']
        
        result_text = f"""📘 RISULTATI RICERCA FACEBOOK
- Query: {query}"""
        
        total_results = 0
        
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
                    elif leak.get('username'):
                        result_text += f"\n     👤 Username: {leak['username']}"
                    
                    if leak.get('facebook_id'):
                        result_text += f"\n     🆔 Facebook ID: {leak['facebook_id']}"
                        result_text += f"\n     🔗 Profilo: https://facebook.com/{leak['facebook_id']}"
                    elif leak.get('user_id'):
                        result_text += f"\n     🆔 User ID: {leak['user_id']}"
                    
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
                    elif leak.get('registration_date'):
                        result_text += f"\n     📅 Data registrazione: {leak['registration_date']}"
        
        if ' ' in query and not query.isdigit() and '@' not in query:
            try:
                search_url = f"https://www.google.com/search?q=site:facebook.com+{quote_plus(query)}"
                result_text += f"\n\n🔍 RICERCA PUBBLICA:"
                result_text += f"\n  - Google: {search_url}"
                
                bing_url = f"https://www.bing.com/search?q=site%3Afacebook.com+{quote_plus(query)}"
                result_text += f"\n  - Bing: {bing_url}"
            except:
                pass
        
        if total_results == 0:
            user_lang = self.get_user_language(user_id)
            result_text += f"\n\n{translations[user_lang]['no_results']}"
            result_text += f"\n📘 Facebook ha limitato le ricerche pubbliche."
            result_text += f"\n💡 Suggerimenti:"
            result_text += f"\n  - Cerca con numero telefono: +39XXXXXXXXXX"
            result_text += f"\n  - Cerca con email: nome.cognome@gmail.com"
            result_text += f"\n  - Cerca con ID Facebook: 1000XXXXXXX"
        
        result_text += f"\n\n🔄 METODI ALTERNATIVI:"
        result_text += f"\n  - 🔍 Cerca su Google: 'site:facebook.com {query}'"
        result_text += f"\n  - 📱 Cerca su Bing: 'site:facebook.com {query}'"
        result_text += f"\n  - 👥 Cerca su LinkedIn"
        result_text += f"\n  - 📧 Cerca con email associata"
        
        user_lang = self.get_user_language(user_id)
        result_text += f"\n\n{translations[user_lang]['credits_used']} 2"
        result_text += f"\n{translations[user_lang]['balance']} {self.get_user_balance(user_id)}"
        result_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        result_text += f"\n\n{data_italiana}"
        
        try:
            await msg.edit_text(result_text)
        except:
            await msg.delete()
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part)
    
    async def menu_completo(self, update: Update, context: CallbackContext):
        """Mostra il menu completo"""
        user_id = update.effective_user.id
        user_lang = self.get_user_language(user_id)
        
        now = datetime.now()
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        menu_text = f"""{translations[user_lang]['menu_title']}

{translations[user_lang]['composite_examples']}

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

{translations[user_lang]['combine_what']}
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

{translations[user_lang]['mass_search']}
· /utf8 per istruzioni file
· Massimo 50 righe
· Formato UTF-8

💰 Crediti disponibili: {self.get_user_balance(user_id)}
📊 Ricerche effettuate: {self.get_user_searches(user_id)}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        keyboard = [[InlineKeyboardButton(translations[user_lang]['back'], callback_data='back_to_main')]]
        
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

💎 Saldo attuale: {balance} crediti
🔍 Costo per ricerca: 2 crediti
📊 Ricerche effettuate: {searches}
🎯 Ricerche disponibili: {int(balance / 2)}

🛒 Per acquistare crediti: /buy
🔍 Per una ricerca: invia qualsiasi dato

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        await update.message.reply_text(text)
    
    async def buy_command(self, update: Update, context: CallbackContext):
        """Acquista crediti"""
        await self.show_shop_interface(update, context)
    
    async def admin_panel(self, update: Update, context: CallbackContext):
        """Pannello amministrativo"""
        user_id = update.effective_user.id
        
        if user_id != ADMIN_ID:
            await update.message.reply_text("❌ Accesso negato")
            return
        
        total_users = db.execute_query('SELECT COUNT(*) FROM users', fetchone=True)[0]
        total_searches = db.execute_query('SELECT COUNT(*) FROM searches', fetchone=True)[0]
        total_credits = db.execute_query('SELECT SUM(balance) FROM users', fetchone=True)[0] or 0
        
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
· 💎 Credit totali: {total_credits}

👥 Ultimi 5 utenti:"""
        
        users = db.execute_query(
            'SELECT user_id, username, balance, searches FROM users ORDER BY user_id DESC LIMIT 5',
            fetchall=True
        )
        
        for user in users:
            admin_text += f"\n\n- 👤 ID: {user[0]} | @{user[1] or 'N/A'}"
            admin_text += f"\n  💎 Crediti: {user[2]} | 🔍 Ricerche: {user[3]}"
        
        admin_text += f"\n\n⏰ {now.hour:02d}:{now.minute:02d}"
        admin_text += f"\n\n{data_italiana}"
        
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
                "Esempio: /addcredits 123456789 50"
            )
            return
        
        try:
            target_user_id = int(context.args[0])
            amount = int(context.args[1])
            
            user = db.execute_query(
                'SELECT * FROM users WHERE user_id = %s',
                (target_user_id,),
                fetchone=True
            )
            
            if not user:
                await update.message.reply_text(f"❌ Utente {target_user_id} non trovato")
                return
            
            success = self.add_credits(target_user_id, amount)
            
            if success:
                new_balance = db.execute_query(
                    'SELECT balance FROM users WHERE user_id = %s',
                    (target_user_id,),
                    fetchone=True
                )[0]
                
                await update.message.reply_text(
                    f"✅ Aggiunti {amount} crediti all'utente {target_user_id}\n"
                    f"💎 Nuovo saldo: {new_balance} crediti"
                )
                
                try:
                    await context.bot.send_message(
                        chat_id=target_user_id,
                        text=f"🎉 Hai ricevuto {amount} crediti!\n"
                             f"💎 Saldo attuale: {new_balance} crediti\n"
                             f"🔍 Ricerche disponibili: {int(new_balance / 2)}"
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
    
    async def debug_mvvidster(self, update: Update, context: CallbackContext):
        """Comando per debug della tabella users_mvvidster"""
        user_id = update.effective_user.id
        
        if user_id != ADMIN_ID:
            await update.message.reply_text("❌ Accesso negato")
            return
        
        try:
            # Conta i record
            count = db.execute_query("SELECT COUNT(*) FROM users_mvvidster", fetchone=True)[0]
            
            # Prendi alcuni esempi
            samples = db.execute_query(
                "SELECT id, user_id, disp_name, email, reg_date FROM users_mvvidster LIMIT 10",
                fetchall=True
            )
            
            text = f"""🔧 DEBUG TABELLA USERS_MVVIDSTER

📊 Statistiche:
· Record totali: {count}
· Ultimi 10 record:

"""
            
            for i, row in enumerate(samples, 1):
                text += f"\n{i}. ID:{row[0]} UserID:{row[1]} Name:'{row[2]}' Email:'{row[3]}' Date:{row[4]}"
            
            # Mostra le colonne
            columns = db.execute_query("DESCRIBE users_mvvidster", fetchall=True)
            text += f"\n\n📋 Colonne della tabella:"
            for col in columns:
                text += f"\n  - {col[0]}: {col[1]}"
            
            await update.message.reply_text(text)
            
        except Exception as e:
            await update.message.reply_text(f"❌ Errore debug: {e}")
    
    async def help_command(self, update: Update, context: CallbackContext):
        """Comando help"""
        now = datetime.now()
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        help_text = f"""🤖 COME USARE Zeroshadebot

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
· 👤 Nome Cognote 🏙️ Città
· 📄 AA1234567 🏠 Via Roma 123
· 👤 Mario Rossi 📄 123456789

💎 SISTEMA CREDITI:
· 🔍 1 ricerca = 2 crediti
· 🎁 Partenza: 4 crediti gratis
· 🛒 Ricarica: /buy

📈 STATISTICHE: /balance
📋 MENU COMPLETO: /menu
🛒 ACQUISTA: /buy

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

💰 COSTO: 2 crediti per riga

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        await update.message.reply_text(utf8_text)
    
    async def handle_social_search(self, update: Update, context: CallbackContext):
        """Gestisce ricerche social specifiche"""
        user_id = update.effective_user.id
        query = update.message.text.strip()
        
        if not query:
            return
        
        if not await self.update_balance(user_id, 2):
            user_lang = self.get_user_language(user_id)
            await update.message.reply_text(
                translations[user_lang]['insufficient_credits']
            )
            return
        
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        now = datetime.now()
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        user_lang = self.get_user_language(user_id)
        wait_text = f"""🔍 {translations[user_lang]['processing']}

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        msg = await update.message.reply_text(wait_text)
        
        try:
            if "telegram" in query.lower() or "tg" in query.lower():
                clean_query = query.lower().replace("telegram", "").replace("tg", "").strip()
                await self.search_social_exact(update, msg, clean_query, user_id, data_italiana)
            
            elif "instagram" in query.lower() or "ig" in query.lower():
                clean_query = query.lower().replace("instagram", "").replace("ig", "").strip()
                await self.search_social_exact(update, msg, clean_query, user_id, data_italiana)
            
            elif "facebook" in query.lower() or "fb" in query.lower():
                clean_query = query.lower().replace("facebook", "").replace("fb", "").strip()
                await self.search_facebook_complete(update, msg, clean_query, user_id, data_italiana)
            
            elif "vk" in query.lower() or "vkontakte" in query.lower():
                clean_query = query.lower().replace("vk", "").replace("vkontakte", "").strip()
                await self.search_social_exact(update, msg, clean_query, user_id, data_italiana)
            
            else:
                await self.search_social_exact(update, msg, query, user_id, data_italiana)
            
        except Exception as e:
            logger.error(f"Social search error: {e}")
            user_lang = self.get_user_language(user_id)
            error_text = f"""{translations[user_lang]['error']}
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
        
        if not update.message.document:
            await update.message.reply_text("❌ Per favore invia un file di testo (.txt)")
            return
        
        document = update.message.document
        
        if not (document.mime_type == 'text/plain' or 
                document.file_name.endswith('.txt')):
            await update.message.reply_text(
                "❌ Formato non supportato. Carica solo file .txt in UTF-8"
            )
            return
        
        if self.get_user_balance(user_id) < 2:
            user_lang = self.get_user_language(user_id)
            await update.message.reply_text(
                translations[user_lang]['insufficient_credits']
            )
            return
        
        mesi = {
            1: 'gennaio', 2: 'febbraio', 3: 'marzo', 4: 'aprile',
            5: 'maggio', 6: 'giugno', 7: 'luglio', 8: 'agosto',
            9: 'settembre', 10: 'ottobre', 11: 'novembre', 12: 'dicembre'
        }
        now = datetime.now()
        data_italiana = f"{now.day} {mesi.get(now.month, 'novembre')}"
        
        wait_text = f"""📋 ANALISI FILE IN CORSO...

📄 File: {document.file_name}
🔍 Lettura righe...

⏰ {now.hour:02d}:{now.minute:02d}

{data_italiana}"""
        
        msg = await update.message.reply_text(wait_text)
        
        try:
            file = await context.bot.get_file(document.file_id)
            file_content = await file.download_as_bytearray()
            
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

{data_italiana}"""
                await msg.edit_text(error_text)
                return
            
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
            
            if len(lines) > 50:
                lines = lines[:50]
                await msg.edit_text(f"⚠️ Limitato a 50 righe (massimo consentito)")
            
            total_cost = len(lines) * 2
            current_balance = self.get_user_balance(user_id)
            
            if current_balance < total_cost:
                error_text = f"""❌ CREDITI INSUFFICIENTI

📄 File: {document.file_name}
📊 Righe: {len(lines)}
💰 Costo totale: {total_cost} crediti
💳 Saldo attuale: {current_balance} crediti

🔢 Ti servono: {total_cost - current_balance} crediti in più
🛒 Usa /buy per acquistare crediti

⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}

{data_italiana}"""
                await msg.edit_text(error_text)
                return
            
            await self.update_balance(user_id, total_cost)
            
            all_results = []
            success_count = 0
            error_count = 0
            
            for i, line in enumerate(lines, 1):
                try:
                    search_type = self.api.detect_search_type(line)
                    
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
            
            result_text = f"""📋 RISULTATI RICERCA DI MASSA

📄 File: {document.file_name}
📊 Righe processate: {len(lines)}
✅ Ricerche riuscite: {success_count}
❌ Errori: {error_count}
💰 Costo totale: {total_cost} crediti
💳 Nuovo saldo: {self.get_user_balance(user_id)} crediti

📝 RISULTATI DETTAGLIATI:
"""
            
            for result in all_results[:20]:
                result_text += f"\n{result}"
            
            if len(all_results) > 20:
                result_text += f"\n\n📌 ... e altre {len(all_results) - 20} righe"
            
            result_text += f"\n\n⏰ {datetime.now().hour:02d}:{datetime.now().minute:02d}"
            result_text += f"\n\n{data_italiana}"
            
            try:
                await msg.edit_text(result_text)
            except:
                await msg.delete()
                parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
                for part in parts:
                    await update.message.reply_text(part)
            
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

# ==================== FUNZIONE PER CARICARE DATI FACEBOOK LEAKS ====================

def load_facebook_leaks_data():
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
                        if len(row) >= 11:
                            db.execute_query(
                                '''INSERT IGNORE INTO facebook_leaks 
                                (phone, facebook_id, name, surname, gender, birth_date, city, country, company, relationship_status, leak_date)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                                row[:11],
                                commit=True
                            )
                            count += 1
                    
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
                            db.execute_query(
                                '''INSERT IGNORE INTO addresses_documents 
                                (document_number, document_type, full_name, home_address, work_address, 
                                 city, country, phone, email, source)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                                row[:10],
                                commit=True
                            )
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
            db.execute_query(
                '''INSERT IGNORE INTO addresses_documents 
                (document_number, document_type, full_name, home_address, work_address, 
                 city, country, phone, email, source)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                data,
                commit=True
            )
        
        logger.info(f"✅ Sample addresses/documents data created: {len(sample_data)} records")
        return True
        
    except Exception as e:
        logger.error(f"Error loading addresses/documents: {e}")
        return False

# ==================== FUNZIONE PER CARICARE DATI USERS_MVVIDSTER ====================

def load_users_mvvidster_data():
    """Carica dati users_mvvidster nel database"""
    try:
        mvvidster_files = [
            'users_mvvidster.csv',
            'data/users_mvvidster.csv',
            'myvidster_data.csv',
            'leaks/mvvidster_leak.csv'
        ]
        
        for file_path in mvvidster_files:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    header = next(reader, None)
                    
                    count = 0
                    for row in reader:
                        if len(row) >= 7:
                            # row[0]=id, row[1]=user_id, row[2]=disp_name, row[3]=reg_date,
                            # row[4]=profile_photo, row[5]=email, row[6]=original_id
                            db.execute_query(
                                '''INSERT IGNORE INTO users_mvvidster 
                                (user_id, disp_name, reg_date, profile_photo, email, original_id)
                                VALUES (%s, %s, %s, %s, %s, %s)''',
                                (row[1], row[2], row[3], row[4], row[5], row[6]),
                                commit=True
                            )
                            count += 1
                    
                    logger.info(f"✅ users_mvvidster data loaded from {file_path}: {count} records")
                    return True
        
        logger.info("⚠️ No users_mvvidster data file found, creating sample data")
        
        # Creare dati di esempio
        sample_data = [
            (1001, 'john_doe', '2021-05-15 10:30:00', 0, 'john.doe@example.com', None),
            (1002, 'jane_smith', '2021-06-20 14:45:00', 0, 'jane.smith@example.com', None),
            (1003, 'alex_wong', '2021-07-10 09:15:00', 0, 'alex.wong@example.com', None),
            (1004, 'maria_garcia', '2021-08-05 16:20:00', 0, 'maria.garcia@example.com', None),
            (1005, 'robert_brown', '2021-09-12 11:10:00', 0, 'robert.brown@example.com', None)
        ]
        
        for data in sample_data:
            db.execute_query(
                '''INSERT IGNORE INTO users_mvvidster 
                (user_id, disp_name, reg_date, profile_photo, email, original_id)
                VALUES (%s, %s, %s, %s, %s, %s)''',
                data,
                commit=True
            )
        
        logger.info(f"✅ Sample users_mvvidster data created: {len(sample_data)} records")
        return True
        
    except Exception as e:
        logger.error(f"Error loading users_mvvidster: {e}")
        return False

# ==================== SERVER WEB SEMPLIFICATO PER UPTIMEROBOT ====================

# ==================== SERVER WEB SEMPLIFICATO PER UPTIMEROBOT ====================
# IMPORTANTE: Usa l'app Flask da keep_alive.py invece di crearne un'altra

# Avvia il server Flask solo quando necessario
def run_keep_alive():
    """Avvia il server Flask da keep_alive.py"""
    try:
        port = int(os.environ.get('PORT', 10000))
        logging.info(f"🚀 Avvio Flask (keep_alive) su porta {port}")
        keep_alive.app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False, threaded=True)
    except Exception as e:
        logging.error(f"Flask keep_alive error: {e}")

# Avvia Flask quando il bot è in produzione
if os.environ.get('RENDER') or os.environ.get('RAILWAY_STATIC_URL'):
    # Avvia Flask in background
    flask_thread = threading.Thread(target=run_keep_alive, daemon=True)
    flask_thread.start()
    logger.info(f"🚀 Flask server started on port {os.environ.get('PORT', 10000)}")
    
    # Ping automatico per mantenere il bot attivo
    def keep_alive_ping():
        import time
        time.sleep(30)
        while True:
            try:
                # Ping se stesso
                port = os.environ.get('PORT', 10000)
                requests.get(f"http://localhost:{port}/ping", timeout=5)
                logger.info("✅ Keep-alive ping sent")
            except Exception as e:
                logger.warning(f"⚠️ Keep-alive failed: {e}")
            time.sleep(300)  # Ogni 5 minuti
    
    # Avvia keep-alive
    keep_alive_thread = threading.Thread(target=keep_alive_ping, daemon=True)
    keep_alive_thread.start()
    
    # Ping automatico per mantenere il bot attivo
    def keep_alive():
        import time
        time.sleep(30)
        while True:
            try:
                # Ping se stesso
                port = os.environ.get('PORT', 8080)
                requests.get(f"http://localhost:{port}/ping", timeout=5)
                logger.info("✅ Keep-alive ping sent")
            except Exception as e:
                logger.warning(f"⚠️ Keep-alive failed: {e}")
            time.sleep(300)  # Ogni 5 minuti
    
    # Avvia keep-alive
    keep_alive_thread = threading.Thread(target=keep_alive, daemon=True)
    keep_alive_thread.start()

# ==================== AVVIO BOT SEMPLIFICATO ====================

async def setup_bot():
    """Configura il bot con tutti gli handler"""
    logger.info("📥 Loading Facebook leaks data...")
    load_facebook_leaks_data()
    
    logger.info("📥 Loading addresses/documents data...")
    load_addresses_documents_data()
    
    logger.info("📥 Loading users_mvvidster data...")
    load_users_mvvidster_data()
    
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Setup bot handlers
    bot = LeakosintBot()
    
    application.add_handler(CommandHandler("start", bot.start))
    application.add_handler(CommandHandler("menu", bot.menu_completo))
    application.add_handler(CommandHandler("balance", bot.balance_command))
    application.add_handler(CommandHandler("buy", bot.buy_command))
    application.add_handler(CommandHandler("admin", bot.admin_panel))
    application.add_handler(CommandHandler("addcredits", bot.addcredits_command))
    application.add_handler(CommandHandler("help", bot.help_command))
    application.add_handler(CommandHandler("utf8", bot.utf8_command))
    application.add_handler(CommandHandler("debug_mvvidster", bot.debug_mvvidster))
    
    application.add_handler(CallbackQueryHandler(bot.handle_button_callback))
    
    application.add_handler(MessageHandler(
        filters.Regex(r'(?i)(telegram|instagram|facebook|vk|tg|ig|fb|vkontakte)') & ~filters.COMMAND,
        bot.handle_social_search
    ))
    
    application.add_handler(MessageHandler(
        filters.Document.ALL & ~filters.COMMAND,
        bot.handle_document
    ))
    
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_message))
    
    return application

def main():
    """Funzione principale semplificata"""
    import asyncio
    
    if os.environ.get('RENDER') or os.environ.get('RAILWAY_STATIC_URL'):
        logger.info("🚀 Avvio in modalità produzione (webhook)")
        
        # Configurazione webhook semplice
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def start_webhook():
            application = await setup_bot()
            
            # IMPOSTA L'ISTANZA DEL BOT IN KEEP_ALIVE
            from keep_alive import set_bot_instance
            set_bot_instance(application)
            
            # Webhook URL da Render/Railway
            webhook_url = os.environ.get('WEBHOOK_URL') or os.environ.get('RAILWAY_STATIC_URL')
            
            if not webhook_url:
                # Su Render, l'URL è automatico
                app_name = os.environ.get('RENDER_SERVICE_NAME', 'your-app')
                webhook_url = f"https://{app_name}.onrender.com"
                logger.info(f"📝 Usando URL Render predefinito: {webhook_url}")
            
            # Aggiungi il path del webhook
            webhook_url = f"{webhook_url.rstrip('/')}/webhook/{BOT_TOKEN}"
            logger.info(f"🌐 Webhook URL: {webhook_url}")
            
            # Imposta webhook
            await application.bot.set_webhook(url=webhook_url)
            
            logger.info("✅ Bot ready! Webhook set successfully.")
            
            # Tieni il bot in esecuzione
            await asyncio.Event().wait()
        
        loop.run_until_complete(start_webhook())
        
    else:
        logger.info("🏠 Avvio in modalità sviluppo (polling)")
        
        # Avvio normale in polling
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def start_polling():
            application = await setup_bot()
            
            logger.info("🤖 Bot avviato in modalità polling...")
            await application.run_polling()
        
        loop.run_until_complete(start_polling())
