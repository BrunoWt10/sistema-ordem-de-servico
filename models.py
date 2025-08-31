from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy() # Inicializa a instância do SQLAlchemy AQUI

# Modelo de Usuário
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='funcionario') # 'admin' ou 'funcionario'
    date_joined = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Relacionamento 1:N com Order e ActivityLog (um usuário pode criar várias OS e logs)
    orders = db.relationship('Order', backref='author', lazy=True)
    activity_logs = db.relationship('ActivityLog', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.role}')"

# Modelo de Ordem de Serviço
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_name = db.Column(db.String(100), nullable=False)
    client_contact = db.Column(db.String(100), nullable=False) # Pode ser telefone ou email
    equipment_type = db.Column(db.String(100), nullable=False)
    equipment_model = db.Column(db.String(100), nullable=False)
    reported_defect = db.Column(db.Text, nullable=False)
    solution_applied = db.Column(db.Text, nullable=True)
    service_value = db.Column(db.Float, nullable=True) # Valor do serviço, pode ser nulo inicialmente
    status = db.Column(db.String(50), nullable=False, default='Aberto') # Ex: Aberto, Em Andamento, Concluído, Aguardando Peça
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    date_completed = db.Column(db.DateTime, nullable=True) # Data de conclusão do serviço

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Usuário que registrou/editou a OS

    # Relacionamento 1:N com ActivityLog (uma OS pode ter vários logs de atividade)
    activity_logs = db.relationship('ActivityLog', backref='order', lazy=True, cascade="all, delete-orphan")


    def __repr__(self):
        return f"Order('{self.id}', '{self.client_name}', '{self.equipment_model}', '{self.status}')"

# Modelo de Log de Atividade (para rastrear mudanças nas OS)
class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=True) # Pode ser nulo se a OS for deletada
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.Text, nullable=False) # Descrição da ação (ex: "Status alterado para Concluído")
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"ActivityLog('{self.id}', 'OS:{self.order_id}', 'User:{self.user_id}', '{self.action}', '{self.timestamp}')"