import os
import json
from dotenv import load_dotenv
from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Target, ScanReport
from forms import RegistrationForm, LoginForm, TargetForm
from scanner import SecurityScanner

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', '5791628bb0b13ce0c676dfde280ba245')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///pentramind.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route("/")
@app.route("/home")
def home():
    return render_template('index.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(name=form.name.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/dashboard")
@login_required
def dashboard():
    targets = Target.query.filter_by(owner=current_user).order_by(Target.timestamp.desc()).all()
    return render_template('dashboard.html', targets=targets)

@app.route("/red-team")
@login_required
def red_team():
    targets = Target.query.filter_by(owner=current_user).order_by(Target.timestamp.desc()).all()
    return render_template('red_team.html', title='Red Team', targets=targets)

@app.route("/blue-team")
@login_required
def blue_team():
    targets = Target.query.filter_by(owner=current_user).order_by(Target.timestamp.desc()).all()
    return render_template('blue_team.html', title='Blue Team', targets=targets)

@app.route("/scan/new", methods=['GET', 'POST'])
@login_required
def new_scan():
    form = TargetForm()
    if form.validate_on_submit():
        target = Target(url_or_ip=form.url_or_ip.data, owner=current_user)
        db.session.add(target)
        db.session.commit()
        
        # Trigger Security Scan
        scan_type = form.scan_type.data
        if scan_type == 'ai':
            from ai_scanner import AIScanner
            scanner = AIScanner()
        else:
            scanner = SecurityScanner()
            
        scan_results = scanner.perform_scan(target.url_or_ip)
        
        # Save Report
        report = ScanReport(
            content=json.dumps(scan_results),
            severity=scan_results.get('severity', 'N/A'),
            vulnerabilities_found=len(scan_results.get('vulnerabilities', [])),
            target=target
        )
        db.session.add(report)
        db.session.commit()
        
        flash('Security scan completed!', 'success')
        return redirect(url_for('view_report', report_id=report.id, mode='red'))
    return render_template('new_scan.html', title='New Scan', form=form)

@app.route("/report/<int:report_id>")
@login_required
def view_report(report_id):
    mode = request.args.get('mode', 'default')
    report = db.session.get(ScanReport, report_id)
    if not report:
        flash('Report not found.', 'danger')
        return redirect(url_for('dashboard'))
    
    if report.target.owner != current_user:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    report_data = json.loads(report.content)
    return render_template('report.html', title='Scan Report', report=report, data=report_data, mode=mode)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)