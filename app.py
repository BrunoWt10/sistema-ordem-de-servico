import os
from datetime import datetime, date
from flask import Flask, render_template, url_for, flash, redirect, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DecimalField, SelectField, DateField, SelectMultipleField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Optional
from wtforms_sqlalchemy.fields import QuerySelectField, QuerySelectMultipleField
from sqlalchemy import func, inspect
from sqlalchemy.orm import relationship, backref
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import json # Para lidar com roles como JSON se não usar a tabela de associação

# --- Configuração ---
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'sua_chave_secreta_muito_segura'
    # Configuração do banco de dados SQLite
    SQLITE_FILE_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'site.db')
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{SQLITE_FILE_PATH}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # ADICIONADOS PARA DEBUG DE CAMINHO DO DB
    print(f"DEBUG DB PATH: {SQLITE_FILE_PATH}")
    print(f"DEBUG SQLALCHEMY_DATABASE_URI: {SQLALCHEMY_DATABASE_URI}")

    # Configuração do Flask-Mail (exemplo com Gmail)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('EMAIL_USER') or 'seu_email@gmail.com' # Use variáveis de ambiente ou defina aqui
    MAIL_PASSWORD = os.environ.get('EMAIL_PASS') or 'sua_senha_de_app_ou_email' # Use variáveis de ambiente ou defina aqui
    MAIL_DEFAULT_SENDER = ('BZMDCell OS', MAIL_USERNAME)

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
mail = Mail(app)

# --- Funções Auxiliares ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_email(to, subject, template, **kwargs):
    msg = Message(subject, recipients=[to])
    msg.html = render_template(template, **kwargs)
    try:
        mail.send(msg)
        print(f"E-mail enviado para {to}")
    except Exception as e:
        print(f"Erro ao enviar e-mail para {to}: {e}")
        flash(f'Erro ao enviar e-mail de notificação para {to}: {e}', 'warning')

# Placeholder para o envio de mensagens de WhatsApp
# Em um ambiente de produção, você integraria uma API como Twilio aqui.
def send_whatsapp_message(to_phone_number, message_body):
    print(f"Simulando envio de WhatsApp para {to_phone_number}: {message_body}")
    flash(f'Mensagem de WhatsApp simulada enviada para {to_phone_number}.', 'info')
    # Exemplo (NÃO USAR EM PRODUÇÃO SEM CONFIGURAR UMA API REAL):
    # from twilio.rest import Client
    # account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
    # auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
    # twilio_phone_number = os.environ.get('TWILIO_PHONE_NUMBER') # Ex: "whatsapp:+14155238886"
    # client = Client(account_sid, auth_token)
    # try:
    #     message = client.messages.create(
    #         from_=twilio_phone_number,
    #         body=message_body,
    #         to=f'whatsapp:{to_phone_number}'
    #     )
    #     print(f"WhatsApp message sent: {message.sid}")
    # except Exception as e:
    #     print(f"Error sending WhatsApp message: {e}")

# Decorador para verificar papéis de usuário
def roles_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Você precisa estar logado para acessar esta página.', 'warning')
                return redirect(url_for('login'))
            
            # current_user.roles é uma lista de objetos Role
            user_roles = [role.name for role in current_user.roles]

            if not any(role in user_roles for role in roles):
                flash('Você não tem permissão para acessar esta página.', 'danger')
                return redirect(url_for('index'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

# --- Modelos de Banco de Dados ---

# Tabela de associação para relacionamento N:N entre User e Role
roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    
    # Relacionamento Many-to-Many com Role
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

    # Relacionamento One-to-Many com OS (um usuário pode ter várias OSs criadas)
    orders_created = db.relationship('OS', backref='author', lazy=True, foreign_keys='OS.user_id')
    # orders_assigned é criado pelo backref 'assigned_orders' na classe OS.

    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    def __repr__(self):
        return f"Role('{self.name}')"

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Relacionamento One-to-Many com OS
    orders = db.relationship('OS', backref='client', lazy=True)

    def __repr__(self):
        return f"Client('{self.name}', '{self.phone}')"

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=True) # Preço pode ser opcional

    # Relacionamento One-to-Many com OS
    orders = db.relationship('OS', backref='service', lazy=True)

    def __repr__(self):
        return f"Service('{self.name}', R${self.price or 'N/A'})"

class OS(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Quem criou a OS
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Aberta')
    priority = db.Column(db.String(50), nullable=False, default='Normal')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # A quem a OS foi atribuída
    completion_date = db.Column(db.Date, nullable=True)
    notes = db.Column(db.Text, nullable=True)

    # NOVO: Relacionamento para acessar o objeto User do técnico atribuído
    assigned_to = db.relationship('User', foreign_keys=[assigned_to_id], backref='assigned_orders')

    def __repr__(self):
        return f"OS('{self.id}', Cliente: '{self.client.name}', Serviço: '{self.service.name}', Status: '{self.status}')"

class Invoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    os_id = db.Column(db.Integer, db.ForeignKey('os.id'), unique=True, nullable=False) # Uma fatura para uma OS
    issue_date = db.Column(db.Date, nullable=False, default=date.today)
    total_amount = db.Column(db.Float, nullable=False)
    payment_status = db.Column(db.String(50), nullable=False, default='Pendente') # Ex: Pendente, Pago, Parcialmente Pago
    notes = db.Column(db.Text, nullable=True)

    os = db.relationship('OS', backref=db.backref('invoice', uselist=False), lazy=True)

    def __repr__(self):
        return f"Invoice('{self.id}', OS: '{self.os_id}', Total: '{self.total_amount}', Status: '{self.payment_status}')"

# --- Formulários ---

class RegistrationForm(FlaskForm):
    username = StringField('Nome de Usuário', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmar Senha', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Cadastrar')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Esse nome de usuário já existe. Por favor, escolha um diferente.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Esse email já existe. Por favor, escolha um diferente.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    remember = BooleanField('Lembrar-me')
    submit = SubmitField('Login')

class UpdateAccountForm(FlaskForm):
    username = StringField('Nome de Usuário', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Atualizar')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Esse nome de usuário já existe. Por favor, escolha um diferente.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Esse email já existe. Por favor, escolha um diferente.')

class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Solicitar Redefinição de Senha')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Nova Senha', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmar Nova Senha', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Redefinir Senha')

def get_all_roles():
    return Role.query.all()

class UserForm(FlaskForm):
    username = StringField('Nome de Usuário', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    # Usa SelectMultipleField para permitir múltiplas seleções de papéis
    role = QuerySelectMultipleField(
        'Papéis',
        query_factory=get_all_roles,
        get_label='name',
        validators=[DataRequired()],
        render_kw={'class': 'form-control', 'multiple': True} # Para Bootstrap e permitir múltipla seleção
    )
    password = PasswordField('Senha (deixe em branco para não alterar)')
    confirm_password = PasswordField('Confirmar Senha', validators=[EqualTo('password', message='As senhas devem ser iguais.')])
    submit = SubmitField('Salvar Usuário')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user and user.id != getattr(self, '_original_user_id', None):
            raise ValidationError('Esse nome de usuário já existe. Por favor, escolha um diferente.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user and user.id != getattr(self, '_original_user_id', None):
            raise ValidationError('Esse email já existe. Por favor, escolha um diferente.')

class ClientForm(FlaskForm):
    name = StringField('Nome do Cliente', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[Optional(), Email()])
    phone = StringField('Telefone', validators=[DataRequired(), Length(min=10, max=20)])
    address = TextAreaField('Endereço', validators=[Optional(), Length(max=200)])
    submit = SubmitField('Salvar Cliente')

class ServiceForm(FlaskForm):
    name = StringField('Nome do Serviço', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Descrição', validators=[Optional(), Length(max=500)])
    price = DecimalField('Preço (R$)', validators=[Optional()], places=2)
    submit = SubmitField('Salvar Serviço')

def get_clients_choices():
    return Client.query.order_by(Client.name).all()

def get_services_choices():
    return Service.query.order_by(Service.name).all()

def get_technicians_choices():
    # Retorna usuários com o papel de 'tecnico' ou 'admin'
    return User.query.join(User.roles).filter(Role.name.in_(['tecnico', 'admin'])).order_by(User.username).all()


class OSForm(FlaskForm):
    client = QuerySelectField(
        'Cliente',
        query_factory=get_clients_choices,
        get_label='name',
        allow_blank=True,
        blank_text='-- Selecione um Cliente --',
        validators=[DataRequired()]
    )
    service = QuerySelectField(
        'Serviço',
        query_factory=get_services_choices,
        get_label='name',
        allow_blank=True,
        blank_text='-- Selecione um Serviço --',
        validators=[DataRequired()]
    )
    description = TextAreaField('Descrição Detalhada', validators=[DataRequired(), Length(min=10)])
    status = SelectField('Status', choices=[
        ('Aberta', 'Aberta'),
        ('Em Andamento', 'Em Andamento'),
        ('Aguardando Peças', 'Aguardando Peças'),
        ('Aguardando Aprovação', 'Aguardando Aprovação'),
        ('Concluída', 'Concluída'),
        ('Cancelada', 'Cancelada')
    ], validators=[DataRequired()])
    priority = SelectField('Prioridade', choices=[
        ('Baixa', 'Baixa'),
        ('Normal', 'Normal'),
        ('Alta', 'Alta'),
        ('Urgente', 'Urgente')
    ], validators=[DataRequired()])
    
    assigned_to = QuerySelectField(
        'Atribuído a (Técnico)',
        query_factory=get_technicians_choices,
        get_label='username',
        allow_blank=True,
        blank_text='-- Não atribuído --',
        validators=[Optional()]
    )
    completion_date = DateField('Data de Conclusão Prevista', format='%Y-%m-%d', validators=[Optional()])
    notes = TextAreaField('Observações Internas', validators=[Optional(), Length(max=500)])
    
    submit = SubmitField('Salvar Ordem de Serviço')

class InvoiceForm(FlaskForm):
    # O campo OS será populado dinamicamente na rota
    # os_id = SelectField('Ordem de Serviço', coerce=int, validators=[DataRequired()])
    issue_date = DateField('Data da Emissão', format='%Y-%m-%d', validators=[DataRequired()], default=date.today)
    total_amount = DecimalField('Valor Total (R$)', validators=[DataRequired()], places=2)
    payment_status = SelectField('Status do Pagamento', choices=[
        ('Pendente', 'Pendente'),
        ('Pago', 'Pago'),
        ('Parcialmente Pago', 'Parcialmente Pago'),
        ('Cancelado', 'Cancelado')
    ], validators=[DataRequired()])
    notes = TextAreaField('Observações da Fatura', validators=[Optional(), Length(max=500)])
    submit = SubmitField('Salvar Fatura')


# --- Context Processors ---
@app.context_processor
def inject_user_count():
    with app.app_context():
        user_count = db.session.query(func.count(User.id)).scalar()
    return dict(user_count=user_count)

# --- Rotas ---

@app.route('/')
@app.route('/index')
@login_required
def index():
    # Exibir as últimas Ordens de Serviço recentes
    recent_os = OS.query.order_by(OS.created_at.desc()).limit(5).all()

    # Contagem de OS por status
    os_status_counts = db.session.query(OS.status, func.count(OS.id)).group_by(OS.status).all()
    status_counts_dict = {status: count for status, count in os_status_counts}
    
    total_os_abertas = status_counts_dict.get('Aberta', 0) + status_counts_dict.get('Em Andamento', 0) + \
                       status_counts_dict.get('Aguardando Peças', 0) + status_counts_dict.get('Aguardando Aprovação', 0)
    
    total_users = db.session.query(func.count(User.id)).scalar()

    return render_template('index.html', 
                           title='Painel de Controle',
                           recent_os=recent_os,
                           total_os_abertas=total_os_abertas,
                           total_users=total_users,
                           status_counts=status_counts_dict)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated and not current_user.has_role('admin'):
        flash('Você já está logado.', 'info')
        return redirect(url_for('index'))
    
    user_count = db.session.query(func.count(User.id)).scalar()
    
    if user_count > 0 and not (current_user.is_authenticated and current_user.has_role('admin')):
        flash('O registro de novos usuários está desativado. Contate o administrador.', 'danger')
        return redirect(url_for('login'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        # Se for o primeiro usuário, atribui a ele o papel de 'admin' e 'tecnico'
        if user_count == 0:
            admin_role = Role.query.filter_by(name='admin').first()
            tecnico_role = Role.query.filter_by(name='tecnico').first()
            if not admin_role:
                admin_role = Role(name='admin')
                db.session.add(admin_role)
            if not tecnico_role:
                tecnico_role = Role(name='tecnico')
                db.session.add(tecnico_role)
            
            user.roles.append(admin_role)
            user.roles.append(tecnico_role)
            db.session.commit()
            flash('Sua conta foi criada! Você foi configurado como Administrador e Técnico. Agora você pode fazer login.', 'success')
        else:
            # Para usuários posteriores, atribui o papel padrão (ex: 'tecnico')
            default_role = Role.query.filter_by(name='tecnico').first()
            if not default_role: # Cria o papel 'tecnico' se não existir
                default_role = Role(name='tecnico')
                db.session.add(default_role)
            user.roles.append(default_role)
            db.session.commit()
            flash('Sua conta foi criada! Você foi configurado como Técnico. Agora você pode fazer login.', 'success')
        
        return redirect(url_for('login'))
    return render_template('auth/register.html', title='Cadastrar', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login bem-sucedido!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login sem sucesso. Por favor, verifique seu email e senha.', 'danger')
    return render_template('auth/login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('login'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Sua conta foi atualizada com sucesso!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('auth/account.html', title='Minha Conta', form=form)

# --- Rotas de Redefinição de Senha ---
# (Apenas a estrutura, a lógica completa de token pode ser mais complexa)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # Em um aplicativo real, você geraria um token e enviaria por e-mail
            # com um link para a rota reset_token.
            # Por simplicidade, estamos apenas simulando o envio e a validação.
            print(f"Token de redefinição simulado enviado para {user.email}")
            flash('Um e-mail com instruções para redefinir sua senha foi enviado!', 'info')
        else:
            flash('Não há conta com esse email.', 'warning')
        return redirect(url_for('login'))
    return render_template('auth/reset_password_request.html', title='Redefinir Senha', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    # Validação do token (simulada, em um app real você decodificaria o token)
    # Por exemplo, user = User.verify_reset_token(token)
    user = User.query.filter_by(email='admin@example.com').first() # Apenas para simulação
    
    if not user:
        flash('Token inválido ou expirado.', 'warning')
        return redirect(url_for('reset_password_request'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Sua senha foi redefinida com sucesso! Você já pode fazer login.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/reset_token.html', title='Redefinir Senha', form=form)


# --- Rotas de Administração de Usuários ---

@app.route('/admin/users')
@login_required
@roles_required('admin')
def list_users():
    users = User.query.order_by(User.username).all()
    return render_template('admin/list_users.html', title='Gerenciar Usuários', users=users)

@app.route('/admin/users/new', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def create_user():
    form = UserForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        
        # Atribui os papéis selecionados
        for role_obj in form.role.data:
            user.roles.append(role_obj)
        
        db.session.add(user)
        db.session.commit()
        flash(f'Usuário {user.username} criado com sucesso!', 'success')
        return redirect(url_for('list_users'))
    return render_template('admin/edit_user.html', title='Criar Usuário', form=form)

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserForm()
    # Adiciona o ID do usuário para validação de campos únicos
    form._original_user_id = user.id

    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        if form.password.data: # Somente atualiza a senha se um valor foi fornecido
            user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        
        # Atualiza os papéis do usuário
        user.roles = [] # Limpa os papéis existentes
        for role_obj in form.role.data:
            user.roles.append(role_obj) # Adiciona os novos papéis
        
        db.session.commit()
        flash(f'Usuário {user.username} atualizado com sucesso!', 'success')
        return redirect(url_for('list_users'))
    elif request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
        # Pré-seleciona os papéis atuais do usuário
        form.role.data = user.roles
    return render_template('admin/edit_user.html', title='Editar Usuário', form=form, user=user)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@roles_required('admin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Você não pode deletar sua própria conta!', 'danger')
        return redirect(url_for('list_users'))
    
    # Verifica se o usuário tem OSs criadas ou atribuídas
    if user.orders_created.count() > 0 or user.assigned_orders.count() > 0:
        flash(f'Usuário {user.username} não pode ser deletado pois possui Ordens de Serviço associadas.', 'danger')
        return redirect(url_for('list_users'))

    db.session.delete(user)
    db.session.commit()
    flash(f'Usuário {user.username} deletado com sucesso!', 'success')
    return redirect(url_for('list_users'))

# --- Rotas de Clientes ---
@app.route('/clients')
@login_required
def list_clients():
    clients = Client.query.order_by(Client.name).all()
    return render_template('clients/list_clients.html', title='Gerenciar Clientes', clients=clients)

@app.route('/clients/new', methods=['GET', 'POST'])
@login_required
def create_client():
    form = ClientForm()
    if form.validate_on_submit():
        # Verifica se o e-mail ou telefone já existem
        existing_email = Client.query.filter_by(email=form.email.data).first() if form.email.data else None
        existing_phone = Client.query.filter_by(phone=form.phone.data).first()
        
        if existing_email:
            flash('Já existe um cliente com este e-mail.', 'danger')
            return render_template('clients/create_client.html', title='Novo Cliente', form=form)
        if existing_phone:
            flash('Já existe um cliente com este telefone.', 'danger')
            return render_template('clients/create_client.html', title='Novo Cliente', form=form)

        client = Client(name=form.name.data, email=form.email.data, 
                        phone=form.phone.data, address=form.address.data)
        db.session.add(client)
        db.session.commit()
        flash(f'Cliente {client.name} cadastrado com sucesso!', 'success')
        return redirect(url_for('list_clients'))
    return render_template('clients/create_client.html', title='Novo Cliente', form=form)

@app.route('/clients/<int:client_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_client(client_id):
    client = Client.query.get_or_404(client_id)
    form = ClientForm()
    if form.validate_on_submit():
        # Verifica se o e-mail ou telefone já existem para OUTROS clientes
        existing_email = Client.query.filter(Client.email == form.email.data, Client.id != client_id).first() if form.email.data else None
        existing_phone = Client.query.filter(Client.phone == form.phone.data, Client.id != client_id).first()
        
        if existing_email:
            flash('Já existe outro cliente com este e-mail.', 'danger')
            return render_template('clients/edit_client.html', title='Editar Cliente', form=form, client=client)
        if existing_phone:
            flash('Já existe outro cliente com este telefone.', 'danger')
            return render_template('clients/edit_client.html', title='Editar Cliente', form=form, client=client)

        client.name = form.name.data
        client.email = form.email.data
        client.phone = form.phone.data
        client.address = form.address.data
        db.session.commit()
        flash(f'Cliente {client.name} atualizado com sucesso!', 'success')
        return redirect(url_for('list_clients'))
    elif request.method == 'GET':
        form.name.data = client.name
        form.email.data = client.email
        form.phone.data = client.phone
        form.address.data = client.address
    return render_template('clients/edit_client.html', title='Editar Cliente', form=form, client=client)

@app.route('/clients/<int:client_id>/delete', methods=['POST'])
@login_required
def delete_client(client_id):
    client = Client.query.get_or_404(client_id)
    # Verifica se há Ordens de Serviço associadas
    if client.orders.count() > 0:
        flash(f'Cliente {client.name} não pode ser deletado pois possui Ordens de Serviço associadas.', 'danger')
        return redirect(url_for('list_clients'))
    
    db.session.delete(client)
    db.session.commit()
    flash(f'Cliente {client.name} deletado com sucesso!', 'success')
    return redirect(url_for('list_clients'))

# --- Rotas de Serviços ---
@app.route('/services')
@login_required
def list_services():
    services = Service.query.order_by(Service.name).all()
    return render_template('services/list_services.html', title='Gerenciar Serviços', services=services)

@app.route('/services/new', methods=['GET', 'POST'])
@login_required
def create_service():
    form = ServiceForm()
    if form.validate_on_submit():
        # Opcional: Verificar se já existe um serviço com o mesmo nome
        existing_service = Service.query.filter(func.lower(Service.name) == func.lower(form.name.data)).first()
        if existing_service:
            flash('Já existe um serviço com este nome. Por favor, escolha um nome diferente.', 'danger')
            return render_template('services/create_service.html', title='Novo Serviço', form=form)

        service = Service(name=form.name.data, description=form.description.data, price=form.price.data)
        db.session.add(service)
        db.session.commit()
        flash(f'Serviço {service.name} cadastrado com sucesso!', 'success')
        return redirect(url_for('list_services'))
    return render_template('services/create_service.html', title='Novo Serviço', form=form)

@app.route('/services/<int:service_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_service(service_id):
    service = Service.query.get_or_404(service_id)
    form = ServiceForm()
    if form.validate_on_submit():
        # Opcional: Verificar se já existe outro serviço com o mesmo nome
        existing_service = Service.query.filter(func.lower(Service.name) == func.lower(form.name.data), Service.id != service_id).first()
        if existing_service:
            flash('Já existe outro serviço com este nome. Por favor, escolha um nome diferente.', 'danger')
            return render_template('services/edit_service.html', title='Editar Serviço', form=form, service=service)

        service.name = form.name.data
        service.description = form.description.data
        service.price = form.price.data
        db.session.commit()
        flash(f'Serviço {service.name} atualizado com sucesso!', 'success')
        return redirect(url_for('list_services'))
    elif request.method == 'GET':
        form.name.data = service.name
        form.description.data = service.description
        form.price.data = service.price
    return render_template('services/edit_service.html', title='Editar Serviço', form=form, service=service)

@app.route('/services/<int:service_id>/delete', methods=['POST'])
@login_required
def delete_service(service_id):
    service = Service.query.get_or_404(service_id)
    # Verifica se há Ordens de Serviço associadas
    if service.orders.count() > 0: # Changed from os_entries to orders based on Service model
        flash(f'Serviço {service.name} não pode ser deletado pois possui Ordens de Serviço associadas.', 'danger')
        return redirect(url_for('list_services'))
    
    db.session.delete(service)
    db.session.commit()
    flash(f'Serviço {service.name} deletado com sucesso!', 'success')
    return redirect(url_for('list_services'))

# --- Rotas de Ordens de Serviço (OS) ---

@app.route('/os')
@login_required
def list_os():
    print("DEBUG: Entrando na rota list_os")
    print(f"DEBUG: Usuário atual: {current_user.username} (ID: {current_user.id})")
    
    # Verifica os papéis do usuário logado
    user_roles_names = [role.name for role in current_user.roles]
    print(f"DEBUG: Papéis do usuário: {user_roles_names}")

    os_list = [] # Inicializa a lista vazia
    
    if current_user.has_role('admin'):
        print("DEBUG: Usuário é admin. Tentando buscar TODAS as OSs.")
        try:
            os_list = OS.query.order_by(OS.created_at.desc()).all()
            print(f"DEBUG: Consulta ALL para admin retornou {len(os_list)} OSs.")
        except Exception as e:
            print(f"ERROR: Erro ao buscar todas as OSs para admin: {e}")
            flash(f'Erro ao carregar Ordens de Serviço: {e}', 'danger')
            os_list = [] # Garante que a lista esteja vazia em caso de erro
    else:
        print(f"DEBUG: Usuário {current_user.username} (ID: {current_user.id}) NÃO é admin.")
        print("DEBUG: Filtrando OSs por user_id ou assigned_to_id.")
        try:
            os_list = OS.query.filter(
                (OS.user_id == current_user.id) | (OS.assigned_to_id == current_user.id)
            ).order_by(OS.created_at.desc()).all()
            print(f"DEBUG: Consulta FILTRADA para usuário retornou {len(os_list)} OSs.")
        except Exception as e:
            print(f"ERROR: Erro ao buscar OSs filtradas para usuário: {e}")
            flash(f'Erro ao carregar Ordens de Serviço: {e}', 'danger')
            os_list = [] # Garante que a lista esteja vazia em caso de erro

    if not os_list:
        print("DEBUG: Nenhuma Ordem de Serviço encontrada para exibição.")
    else:
        for os_entry in os_list:
            # Tenta acessar os relacionamentos para garantir que não há erro lazy loading
            client_name = os_entry.client.name if os_entry.client else "N/A"
            service_name = os_entry.service.name if os_entry.service else "N/A"
            author_name = os_entry.author.username if os_entry.author else "N/A"
            assigned_to_name = os_entry.assigned_to.username if os_entry.assigned_to else "N/A"
            print(f"DEBUG: OS ID: {os_entry.id}, Cliente: {client_name}, Serviço: {service_name}, Status: {os_entry.status}, Criado por: {author_name}, Atribuído a: {assigned_to_name}")

    return render_template('os/list_os.html', title='Gerenciar Ordens de Serviço', os_list=os_list)

@app.route('/os/new', methods=['GET', 'POST'])
@login_required
def create_os():
    form = OSForm()
    print(f"DEBUG: Request method: {request.method}")
    if form.validate_on_submit():
        print("DEBUG: Form validated on submit.")
        # Mapear os objetos selecionados para seus IDs
        client_id = form.client.data.id if form.client.data else None
        service_id = form.service.data.id if form.service.data else None
        assigned_to_id = form.assigned_to.data.id if form.assigned_to.data else None
        
        print(f"DEBUG: Client ID: {client_id}, Service ID: {service_id}, Assigned To ID: {assigned_to_id}")

        os_entry = OS(
            client_id=client_id,
            service_id=service_id,
            user_id=current_user.id, # Quem criou a OS
            description=form.description.data,
            status=form.status.data,
            priority=form.priority.data,
            assigned_to_id=assigned_to_id,
            completion_date=form.completion_date.data,
            notes=form.notes.data
        )
        db.session.add(os_entry)
        print("DEBUG: OS object added to session.")
        try:
            db.session.commit()
            print(f"DEBUG: OS #{os_entry.id} committed to database successfully!")
        except Exception as e:
            db.session.rollback()
            print(f"ERROR: Failed to commit OS to database: {e}")
            flash(f'Erro ao salvar Ordem de Serviço: {e}', 'danger')
            return render_template('os/create_os.html', title='Nova Ordem de Serviço', form=form)


        flash(f'Ordem de Serviço #{os_entry.id} criada com sucesso!', 'success')

        # Notificar o cliente via WhatsApp (se houver número e client definido)
        if os_entry.client and os_entry.client.phone:
            message_body = f"Olá {os_entry.client.name}, sua OS #{os_entry.id} foi criada. Status: {os_entry.status}. Descrição: {os_entry.description}."
            send_whatsapp_message(os_entry.client.phone, message_body)

        # Notificar o técnico atribuído (se houver e não for o criador)
        if os_entry.assigned_to and os_entry.assigned_to.id != current_user.id:
            if os_entry.assigned_to.email:
                send_email(
                    os_entry.assigned_to.email,
                    f'Nova OS atribuída a você: #{os_entry.id}',
                    'emails/os_assigned_notification.html', # Novo template para OS atribuída
                    os=os_entry, user=os_entry.assigned_to
                )
                flash(f'Notificação de nova OS enviada para {os_entry.assigned_to.username}.', 'info')
        
        return redirect(url_for('list_os'))
    else:
        print("DEBUG: Form validation failed.")
        # Imprime erros de validação do formulário no terminal para depuração
        for field, errors in form.errors.items():
            for error in errors:
                print(f"DEBUG: Form error - Field '{field}': {error}")

    return render_template('os/create_os.html', title='Nova Ordem de Serviço', form=form)

@app.route('/os/<int:os_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_os(os_id):
    os_entry = OS.query.get_or_404(os_id)

    # Restrição de acesso: Apenas o criador, o atribuído ou um admin podem editar
    if not current_user.has_role('admin') and \
       current_user.id != os_entry.user_id and \
       current_user.id != os_entry.assigned_to_id:
        flash('Você não tem permissão para editar esta Ordem de Serviço.', 'danger')
        return redirect(url_for('list_os'))

    form = OSForm()
    
    if form.validate_on_submit():
        old_status = os_entry.status # Para comparar e enviar notificação de mudança de status
        old_assigned_to_id = os_entry.assigned_to_id # Para comparar e enviar notificação de reatribuição

        os_entry.client_id = form.client.data.id
        os_entry.service_id = form.service.data.id
        os_entry.description = form.description.data
        os_entry.status = form.status.data
        os_entry.priority = form.priority.data
        os_entry.assigned_to_id = form.assigned_to.data.id if form.assigned_to.data else None
        os_entry.completion_date = form.completion_date.data
        os_entry.notes = form.notes.data
        db.session.commit()

        flash(f'Ordem de Serviço #{os_entry.id} atualizada com sucesso!', 'success')

        # Notificação de Mudança de Status (se o status mudou)
        if old_status != os_entry.status:
            if os_entry.client and os_entry.client.email:
                send_email(
                    os_entry.client.email,
                    f'Atualização de Status da OS #{os_entry.id}',
                    'emails/status_os_atualizado.html',
                    os=os_entry, old_status=old_status
                )
            if os_entry.client and os_entry.client.phone:
                message_body = f"Olá {os_entry.client.name}, o status da sua OS #{os_entry.id} foi atualizado de '{old_status}' para '{os_entry.status}'."
                send_whatsapp_message(os_entry.client.phone, message_body)

        # Notificação de Reatribuição (se o técnico atribuído mudou)
        if old_assigned_to_id != os_entry.assigned_to_id:
            if os_entry.assigned_to and os_entry.assigned_to.email:
                send_email(
                    os_entry.assigned_to.email,
                    f'OS reatribuída para você: #{os_entry.id}',
                    'emails/os_assigned_notification.html',
                    os=os_entry, user=os_entry.assigned_to
                )
            # Notificar o técnico anterior se ele foi desatribuído
            if old_assigned_to_id and not os_entry.assigned_to_id: # Se era atribuído e agora não é
                old_assignee = User.query.get(old_assigned_to_id)
                if old_assignee and old_assignee.email:
                    send_email(
                        old_assignee.email,
                        f'OS desatribuída: #{os_entry.id}',
                        'emails/os_desassigned_notification.html', # Você precisaria criar este template
                        os=os_entry, user=old_assignee
                    )
            elif old_assigned_to_id and os_entry.assigned_to_id and old_assigned_to_id != os_entry.assigned_to_id: # Se mudou para outro técnico
                 old_assignee = User.query.get(old_assigned_to_id)
                 if old_assignee and old_assignee.email:
                    send_email(
                        old_assignee.email,
                        f'OS desatribuída: #{os_entry.id}',
                        'emails/os_desassigned_notification.html',
                        os=os_entry, user=old_assignee
                    )

        return redirect(url_for('list_os'))
    
    elif request.method == 'GET':
        form.client.data = os_entry.client
        form.service.data = os_entry.service
        form.description.data = os_entry.description
        form.status.data = os_entry.status
        form.priority.data = os_entry.priority
        form.assigned_to.data = os_entry.assigned_to
        form.completion_date.data = os_entry.completion_date
        form.notes.data = os_entry.notes
        
    return render_template('os/edit_os.html', title='Editar Ordem de Serviço', form=form, os_entry=os_entry)

@app.route('/os/<int:os_id>/delete', methods=['POST'])
@login_required
def delete_os(os_id):
    os_entry = OS.query.get_or_404(os_id)

    # Verifica se há uma fatura associada antes de deletar a OS
    if os_entry.invoice:
        flash(f'OS #{os_entry.id} não pode ser deletada pois possui uma Fatura associada. Delete a Fatura primeiro.', 'danger')
        return redirect(url_for('list_os'))
        
    db.session.delete(os_entry)
    db.session.commit()
    flash(f'Ordem de Serviço #{os_entry.id} deletada com sucesso!', 'success')
    return redirect(url_for('list_os'))

@app.route('/os/<int:os_id>/view')
@login_required
def view_os(os_id):
    os_entry = OS.query.get_or_404(os_id)
    # Restrição de acesso: Apenas o criador, o atribuído ou um admin podem visualizar
    if not current_user.has_role('admin') and \
       current_user.id != os_entry.user_id and \
       current_user.id != os_entry.assigned_to_id:
        flash('Você não tem permissão para visualizar esta Ordem de Serviço.', 'danger')
        return redirect(url_for('list_os'))

    return render_template('os/view_os.html', title=f'Detalhes da OS #{os_id}', os_entry=os_entry)

@app.route('/os/<int:os_id>/print_note')
@login_required
def print_os_note(os_id):
    os_entry = OS.query.get_or_404(os_id)
    # Mesma lógica de permissão que view_os, ou defina uma própria
    if not current_user.has_role('admin') and \
       current_user.id != os_entry.user_id and \
       current_user.id != os_entry.assigned_to_id:
        flash('Você não tem permissão para imprimir esta nota de OS.', 'danger')
        return redirect(url_for('list_os'))
        
    return render_template('os/print_note.html', os_entry=os_entry) # Template simples para impressão

# --- Rotas de Faturas ---

@app.route('/invoices')
@login_required
def list_invoices():
    # Se o usuário não for admin, mostrar apenas as faturas de OSs criadas por ele ou atribuídas a ele
    if current_user.has_role('admin'):
        invoices = Invoice.query.order_by(Invoice.issue_date.desc()).all()
    else:
        # Pega as OSs onde o usuário é o criador ou atribuído
        user_os_ids = db.session.query(OS.id).filter(
            (OS.user_id == current_user.id) | (OS.assigned_to_id == current_user.id)
        ).subquery()
        invoices = Invoice.query.filter(Invoice.os_id.in_(user_os_ids)).order_by(Invoice.issue_date.desc()).all()

    return render_template('invoices/list_invoices.html', title='Gerenciar Faturas', invoices=invoices)

@app.route('/invoices/new/<int:os_id>', methods=['GET', 'POST'])
@login_required
def create_invoice(os_id):
    os_entry = OS.query.get_or_404(os_id)

    # Verifica se já existe uma fatura para esta OS
    if os_entry.invoice:
        flash(f'Já existe uma fatura para a OS #{os_id}.', 'warning')
        return redirect(url_for('view_invoice', invoice_id=os_entry.invoice.id))
    
    # Restrição de acesso: Apenas o criador da OS, o atribuído ou um admin podem criar fatura para ela
    if not current_user.has_role('admin') and \
       current_user.id != os_entry.user_id and \
       current_user.id != os_entry.assigned_to_id:
        flash('Você não tem permissão para criar fatura para esta Ordem de Serviço.', 'danger')
        return redirect(url_for('list_os'))

    form = InvoiceForm()
    # Preenche o valor total com o preço do serviço da OS por padrão, se existir
    if request.method == 'GET' and os_entry.service and os_entry.service.price:
        form.total_amount.data = os_entry.service.price

    if form.validate_on_submit():
        invoice = Invoice(
            os_id=os_id,
            issue_date=form.issue_date.data,
            total_amount=form.total_amount.data,
            payment_status=form.payment_status.data,
            notes=form.notes.data
        )
        db.session.add(invoice)
        db.session.commit()
        flash(f'Fatura para OS #{os_id} criada com sucesso!', 'success')
        return redirect(url_for('list_invoices'))
    return render_template('invoices/create_invoice.html', title=f'Criar Fatura para OS #{os_id}', form=form, os_entry=os_entry)

@app.route('/invoices/<int:invoice_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_invoice(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)
    os_entry = invoice.os # Acessa a OS relacionada

    # Restrição de acesso: Apenas o criador da OS, o atribuído ou um admin podem editar a fatura
    if not current_user.has_role('admin') and \
       current_user.id != os_entry.user_id and \
       current_user.id != os_entry.assigned_to_id:
        flash('Você não tem permissão para editar esta Fatura.', 'danger')
        return redirect(url_for('list_invoices'))

    form = InvoiceForm()
    if form.validate_on_submit():
        invoice.issue_date = form.issue_date.data
        invoice.total_amount = form.total_amount.data
        invoice.payment_status = form.payment_status.data
        invoice.notes = form.notes.data
        db.session.commit()
        flash(f'Fatura #{invoice.id} atualizada com sucesso!', 'success')
        return redirect(url_for('list_invoices'))
    elif request.method == 'GET':
        form.issue_date.data = invoice.issue_date
        form.total_amount.data = invoice.total_amount
        form.payment_status.data = invoice.payment_status
        form.notes.data = invoice.notes
    return render_template('invoices/edit_invoice.html', title=f'Editar Fatura #{invoice.id}', form=form, invoice=invoice)

@app.route('/invoices/<int:invoice_id>/delete', methods=['POST'])
@login_required
@roles_required('admin') # Apenas admins podem deletar faturas
def delete_invoice(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)
    db.session.delete(invoice)
    db.session.commit()
    flash(f'Fatura #{invoice.id} deletada com sucesso!', 'success')
    return redirect(url_for('list_invoices'))

@app.route('/invoices/<int:invoice_id>/view')
@login_required
def view_invoice(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)
    os_entry = invoice.os

    # Restrição de acesso para visualização da fatura
    if not current_user.has_role('admin') and \
       current_user.id != os_entry.user_id and \
       current_user.id != os_entry.assigned_to_id:
        flash('Você não tem permissão para visualizar esta Fatura.', 'danger')
        return redirect(url_for('list_invoices'))

    return render_template('invoices/view_invoice.html', title=f'Detalhes da Fatura #{invoice_id}', invoice=invoice)

@app.route('/invoices/<int:invoice_id>/print_invoice')
@login_required
def print_invoice(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)
    os_entry = invoice.os
    
    # Mesma lógica de permissão que view_invoice
    if not current_user.has_role('admin') and \
       current_user.id != os_entry.user_id and \
       current_user.id != os_entry.assigned_to_id:
        flash('Você não tem permissão para imprimir esta Fatura.', 'danger')
        return redirect(url_for('list_invoices'))
        
    return render_template('invoices/print_invoice.html', invoice=invoice, os_entry=os_entry)


# --- Inicialização ---
def create_tables_and_roles():
    inspector = inspect(db.engine)
    if not inspector.has_table("user"): # Verifica se a tabela 'user' (ou qualquer outra) existe
        print("Criando tabelas e papéis padrão no banco de dados...")
        db.create_all()
        # Adiciona papéis padrão se não existirem
        if not Role.query.filter_by(name='admin').first():
            db.session.add(Role(name='admin'))
        if not Role.query.filter_by(name='tecnico').first():
            db.session.add(Role(name='tecnico'))
        db.session.commit()
        print("Tabelas e papéis padrão criados com sucesso.")
    else:
        print("Banco de dados e papéis padrão verificados. Tabelas já existem.")

if __name__ == '__main__':
    with app.app_context():
        create_tables_and_roles()
    app.run(debug=True, host='0.0.0.0') # host='0.0.0.0' permite acesso de qualquer IP na rede
