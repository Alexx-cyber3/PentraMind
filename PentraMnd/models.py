from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    targets = db.relationship('Target', backref='owner', lazy=True)

class Target(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url_or_ip = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reports = db.relationship('ScanReport', backref='target', lazy=True)

class ScanReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)  # JSON or formatted text
    severity = db.Column(db.String(50))           # Low, Medium, High, Critical
    vulnerabilities_found = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    target_id = db.Column(db.Integer, db.ForeignKey('target.id'), nullable=False)
