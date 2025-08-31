import os
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

class Config:
    # Flask Secret Key: Essencial para segurança (sessões, CSRF)
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'uma_chave_secreta_muito_forte_e_unica_aqui'

    # Configuração do Banco de Dados SQLAlchemy
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False # Desativa o rastreamento de modificações para economizar recursos

    # Configurações de E-mail (Flask-Mail)
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587) # Porta padrão para TLS
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None and os.environ.get('MAIL_USE_TLS').lower() == 'true'
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL') is not None and os.environ.get('MAIL_USE_SSL').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') # Remetente padrão para e-mails

    # Configurações do Twilio (para WhatsApp e SMS)
    TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')
    TWILIO_WHATSAPP_NUMBER = os.environ.get('TWILIO_WHATSAPP_NUMBER')

    # Outras configurações específicas do seu aplicativo podem vir aqui
    # ...