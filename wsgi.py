# wsgi.py
from bot import start_webhook
import os

# Imposta la variabile d'ambiente per indicare che siamo su Render
os.environ['RENDER'] = 'true'

# Avvia il bot in modalità webhook
if __name__ == '__main__':
    start_webhook()
