import os
import secrets

SECRET_KEY = os.environ.get('JWT_SECRET', secrets.token_hex(32))
DATABASE_URL = os.environ.get('DATABASE_URL')
FRONTEND_URL = os.environ.get('FRONTEND_URL', 'http://localhost:3000')

# First Purchase Bonus
FIRST_PURCHASE_BONUS_CREDITS = 10

# Square Payment
SQUARE_ACCESS_TOKEN = os.environ.get('SQUARE_ACCESS_TOKEN')
SQUARE_LOCATION_ID = os.environ.get('SQUARE_LOCATION_ID')
SQUARE_ENVIRONMENT = os.environ.get('SQUARE_ENVIRONMENT', 'sandbox')
SQUARE_API_URL = 'https://connect.squareupsandbox.com' if SQUARE_ENVIRONMENT == 'sandbox' else 'https://connect.squareup.com'

# Twilio SMS
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER')

# AI Route Optimizer
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
OLLAMA_URL = os.environ.get('OLLAMA_URL', 'http://localhost:11434')
OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'llama3.2:1b')