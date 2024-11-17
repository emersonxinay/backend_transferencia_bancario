from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:emerson123@localhost/db_tranferencia'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get(
    'JWT_SECRET_KEY', 'supersecretkey')

db = SQLAlchemy(app)
migrate = Migrate(app, db)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    balance = db.Column(db.Float, nullable=False, default=100.0)

    # Relación de las transferencias enviadas
    sent_transactions = db.relationship(
        'Transaction', foreign_keys='Transaction.sender_id', backref='sender', lazy=True)

    # Relación de las transferencias recibidas
    received_transactions = db.relationship(
        'Transaction', foreign_keys='Transaction.receiver_id', backref='receiver', lazy=True)


class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(
        db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(
        db.Integer, db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


@app.route('/users', methods=['POST'])
def create_user():
    data = request.json
    if not all(key in data for key in ['name', 'email', 'password']):
        return jsonify({'message': 'Missing fields'}), 400
    email = data['email']
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 400
    hashed_password = bcrypt.generate_password_hash(
        data['password']).decode('utf-8')
    user = User(name=data['name'], email=email, password_hash=hashed_password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created', 'user_id': user.id})


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email, password = data.get('email'), data.get('password')
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password_hash, password):
        token = create_access_token(identity=user.id)
        return jsonify({'message': 'Login successful', 'access_token': token})
    return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/transfer', methods=['POST'])
@jwt_required()
def transfer():
    current_user_id = get_jwt_identity()
    data = request.json
    sender = User.query.get(current_user_id)
    receiver = User.query.get(data['receiver_id'])
    amount = data.get('amount', 0)
    if not sender or not receiver or amount <= 0 or sender.balance < amount:
        return jsonify({'message': f"Invalid transfer details, saldo insuficiente: solo tienes: {sender.balance} de saldo "}), 400
    sender.balance -= amount
    receiver.balance += amount
    transaction = Transaction(
        sender_id=sender.id, receiver_id=receiver.id, amount=amount)
    db.session.add(transaction)
    db.session.commit()
    return jsonify({'message': 'Transfer successful - Se transfirio exitosamente'})


@app.route('/user', methods=['GET'])
@jwt_required()
def get_user():
    user_id = get_jwt_identity()  # Obtén el ID del usuario autenticado
    user = User.query.get(user_id)
    if user:
        return jsonify({
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'balance': user.balance,
        })
    return jsonify({'message': 'User not found'}), 404


@app.route('/users/available', methods=['GET'])
@jwt_required()
def get_available_users():
    current_user_id = get_jwt_identity()
    # Obtener todos los usuarios excepto el que está logueado
    users = User.query.filter(User.id != current_user_id).all()
    user_list = [{"id": user.id, "name": user.name} for user in users]
    return jsonify(user_list)


@app.route('/transactions', methods=['GET'])
@jwt_required()
def get_transactions():
    user_id = get_jwt_identity()  # Obtiene el ID del usuario autenticado
    user = User.query.get(user_id)  # Obtiene el usuario desde la base de datos

    if not user:
        return jsonify({"message": "Usuario no encontrado"}), 404

    # Obtener los usuarios a los que se les envió y de quienes se recibieron transacciones
    receiver_ids = [
        transaction.receiver_id for transaction in user.sent_transactions]
    sender_ids = [
        transaction.sender_id for transaction in user.received_transactions]

    # Obtener los usuarios involucrados en las transacciones
    all_user_ids = set(receiver_ids + sender_ids)
    users = User.query.filter(User.id.in_(all_user_ids)).all()

    # Crear un diccionario de usuarios por ID para acceder rápidamente a sus nombres
    user_dict = {u.id: u.name for u in users}

    # Obtener todas las transferencias enviadas
    sent = [
        {
            "receiver_id": transaction.receiver_id,
            # Obtener el nombre del receptor
            "name": user_dict.get(transaction.receiver_id, 'Unknown'),
            "amount": transaction.amount,
            "date": transaction.timestamp.isoformat() if transaction.timestamp else datetime.utcnow().isoformat()
        } for transaction in user.sent_transactions
    ]

    # Obtener todas las transferencias recibidas
    received = [
        {
            "sender_id": transaction.sender_id,
            # Obtener el nombre del remitente
            "name": user_dict.get(transaction.sender_id, 'Unknown'),
            "amount": transaction.amount,
            "date": transaction.timestamp.isoformat() if transaction.timestamp else datetime.utcnow().isoformat()
        } for transaction in user.received_transactions
    ]

    # Unir las transferencias enviadas y recibidas en una lista
    transactions = {"sent": sent, "received": received}
    return jsonify(transactions)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
