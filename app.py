# app.py - Fixed Coaches Hub - Complete Invoice System
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, DecimalField, DateField, SelectField, TextAreaField, EmailField, PasswordField, IntegerField
from wtforms.validators import DataRequired, Email, Length, NumberRange, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import os
import csv
import io
import re
import random
from collections import defaultdict
from functools import wraps
import sqlalchemy as sa
from decimal import Decimal

# Import the match organizer utility
from utils import organize_matches

# Initialize Flask app
app = Flask(__name__)

# Environment detection
is_development = os.environ.get('FLASK_ENV') == 'development'

# Security Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['WTF_CSRF_TIME_LIMIT'] = 3600
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB

# Set security configs based on environment
if is_development:
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
else:
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# Database Configuration
database_url = os.environ.get('DATABASE_URL', 'sqlite:///coaches_hub.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# Database Models
class Coach(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    invoices = db.relationship('Invoice', backref='coach', lazy=True, cascade='all, delete-orphan')
    templates = db.relationship('InvoiceTemplate', backref='coach', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class InvoiceTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('coach.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    amount = db.Column(sa.Numeric(10, 2), nullable=False)
    description = db.Column(db.Text, nullable=False)
    default_due_days = db.Column(db.Integer, nullable=False, default=14)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    invoices = db.relationship('Invoice', backref='template', lazy=True)

class Invoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('coach.id'), nullable=False)
    template_id = db.Column(db.Integer, db.ForeignKey('invoice_template.id'), nullable=True)
    invoice_number = db.Column(db.String(50), unique=True, nullable=False)
    student_name = db.Column(db.String(100), nullable=False)
    student_email = db.Column(db.String(120), nullable=True)
    date_issued = db.Column(db.Date, nullable=False, default=datetime.utcnow().date())
    due_date = db.Column(db.Date, nullable=False)
    amount = db.Column(sa.Numeric(10, 2), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, paid, overdue
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime, nullable=True)
    
    def generate_invoice_number(self, coach_id):
        """Generate unique invoice number"""
        today = datetime.now()
        prefix = f"CH-{coach_id}-{today.strftime('%Y%m')}"
        
        # Get the highest existing number for this month
        existing = db.session.query(Invoice.invoice_number)\
            .filter(Invoice.invoice_number.like(f"{prefix}%"))\
            .order_by(Invoice.invoice_number.desc())\
            .first()
        
        if existing and existing[0]:
            try:
                last_num = int(existing[0].split('-')[-1])
                new_num = last_num + 1
            except (ValueError, IndexError):
                new_num = 1
        else:
            new_num = 1
        
        return f"{prefix}-{new_num:03d}"
    
    def update_status(self):
        """Update invoice status based on due date and payment"""
        if self.paid_at:
            self.status = 'paid'
        elif self.due_date < datetime.now().date():
            self.status = 'overdue'
        else:
            self.status = 'pending'

# Forms
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])

class InvoiceForm(FlaskForm):
    student_name = StringField('Student Name', validators=[DataRequired(), Length(min=2, max=100)])
    student_email = EmailField('Student Email (Optional)', validators=[Optional(), Email()])
    amount = DecimalField('Amount (£)', validators=[DataRequired(), NumberRange(min=0.01, max=9999.99)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=500)])
    due_date = DateField('Due Date', validators=[DataRequired()])

class TemplateForm(FlaskForm):
    name = StringField('Template Name', validators=[DataRequired(), Length(min=2, max=100)])
    amount = DecimalField('Amount (£)', validators=[DataRequired(), NumberRange(min=0.01, max=9999.99)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=1000)])
    default_due_days = IntegerField('Default Due Days', validators=[DataRequired(), NumberRange(min=1, max=365)])

class CSRFForm(FlaskForm):
    pass

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'coach_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Utility functions for match organizer
def validate_player_name(name):
    """Enhanced player name validation with security checks"""
    if not name or len(name.strip()) == 0:
        return False, "Player name cannot be empty"
    
    name = name.strip()
    
    if len(name) > 50:
        return False, "Player name too long (max 50 characters)"
    
    dangerous_chars = ['=', '+', '-', '@', '\t', '\r', '\n']
    if any(char in name for char in dangerous_chars):
        return False, "Player name contains potentially dangerous characters"
    
    if not re.match(r"^[a-zA-Z0-9\s\-'.]+$", name):
        return False, "Player name contains invalid characters"
    
    return True, ""

def sanitize_csv_field(field_value):
    """Sanitize CSV field to prevent formula injection"""
    if not field_value:
        return field_value
    
    field_value = str(field_value).strip()
    field_value = field_value.strip('"\'')
    
    if field_value and field_value[0] in ['=', '+', '-', '@', '\t', '\r']:
        field_value = "'" + field_value
    
    return field_value

def process_csv_upload_secure(file, existing_players):
    """Secure CSV upload processing with comprehensive validation"""
    try:
        if not file or not file.filename:
            return [], "No file provided"
        
        if not file.filename.lower().endswith('.csv'):
            return [], "File must have .csv extension"
        
        content = file.read().decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        
        required_columns = ['name', 'grade']
        if not reader.fieldnames or not all(col in reader.fieldnames for col in required_columns):
            return [], "CSV must have 'name' and 'grade' columns. Optional: 'max_rounds'"
        
        new_players = []
        added_count = 0
        skipped_count = 0
        
        for row_num, row in enumerate(reader, start=2):
            if row_num > 102:  # Limit to 100 players
                break
            
            name = sanitize_csv_field(row.get("name", "")).strip()
            grade_str = sanitize_csv_field(row.get("grade", "")).strip()
            max_rounds_str = sanitize_csv_field(row.get("max_rounds", "")).strip()
            
            is_valid_name, name_error = validate_player_name(name)
            if not is_valid_name:
                skipped_count += 1
                continue
            
            try:
                grade = int(grade_str.strip("'\""))
                if not (1 <= grade <= 4):
                    skipped_count += 1
                    continue
            except (ValueError, TypeError):
                skipped_count += 1
                continue
            
            max_rounds = None
            if max_rounds_str:
                try:
                    max_rounds = int(max_rounds_str.strip("'\""))
                    if not (1 <= max_rounds <= 10):
                        skipped_count += 1
                        continue
                except (ValueError, TypeError):
                    skipped_count += 1
                    continue
            
            if any(p["name"].lower() == name.lower() for p in existing_players + new_players):
                skipped_count += 1
                continue
            
            player = {"name": name, "grade": grade}
            if max_rounds is not None:
                player["max_rounds"] = max_rounds
            
            new_players.append(player)
            added_count += 1
        
        if added_count > 0:
            success_msg = f"Added {added_count} players"
            if skipped_count > 0:
                success_msg += f", skipped {skipped_count} invalid entries"
            return new_players, success_msg
        else:
            return [], "No valid players found in CSV file"
        
    except Exception as e:
        return [], "Error processing CSV file. Please check format and try again."

# Routes
@app.route('/')
def index():
    if 'coach_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        # Check if email already exists
        existing_coach = Coach.query.filter_by(email=form.email.data.lower()).first()
        if existing_coach:
            flash('Email already registered. Please use a different email.', 'error')
            return render_template('register.html', form=form)
        
        # Create new coach
        coach = Coach(
            name=form.name.data.strip(),
            email=form.email.data.lower()
        )
        coach.set_password(form.password.data)
        
        try:
            db.session.add(coach)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Registration error: {str(e)}")
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        coach = Coach.query.filter_by(email=form.email.data.lower()).first()
        
        if coach and coach.check_password(form.password.data):
            session['coach_id'] = coach.id
            session['coach_name'] = coach.name
            session.permanent = True
            flash(f'Welcome back, {coach.name}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    coach_id = session['coach_id']
    
    try:
        # Update invoice statuses first
        today = datetime.now().date()
        overdue_invoices = Invoice.query.filter(
            Invoice.coach_id == coach_id,
            Invoice.status == 'pending',
            Invoice.due_date < today
        ).all()
        
        for invoice in overdue_invoices:
            invoice.status = 'overdue'
        
        if overdue_invoices:
            db.session.commit()
        
        # Get invoice statistics
        total_invoices = Invoice.query.filter_by(coach_id=coach_id).count()
        pending_invoices = Invoice.query.filter_by(coach_id=coach_id, status='pending').count()
        overdue_count = Invoice.query.filter_by(coach_id=coach_id, status='overdue').count()
        
        # Calculate total pending amount
        pending_amount_result = db.session.query(db.func.sum(Invoice.amount))\
            .filter(Invoice.coach_id == coach_id, Invoice.status.in_(['pending', 'overdue']))\
            .scalar()
        total_pending_amount = float(pending_amount_result) if pending_amount_result else 0
        
        # Get recent invoices
        recent_invoices = Invoice.query.filter_by(coach_id=coach_id)\
            .order_by(Invoice.created_at.desc())\
            .limit(5).all()
        
        return render_template('dashboard.html',
                             total_invoices=total_invoices,
                             pending_invoices=pending_invoices,
                             overdue_count=overdue_count,
                             total_pending_amount=total_pending_amount,
                             recent_invoices=recent_invoices)
                             
    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard. Please try again.', 'error')
        return render_template('dashboard.html',
                             total_invoices=0,
                             pending_invoices=0,
                             overdue_count=0,
                             total_pending_amount=0,
                             recent_invoices=[])

# Match Organizer Routes
@app.route('/match-organizer', methods=['GET', 'POST'])
@login_required
def match_organizer():
    """Tennis match organizer with session management"""
    
    # Get current session data with coach-specific keys
    coach_id = session['coach_id']
    session_key = f"match_data_{coach_id}"
    
    # Initialize or get match session data
    if session_key not in session:
        session[session_key] = {
            "players": [],
            "courts": 1,
            "num_matches": 1,
            "match_type": "singles",
            "matchups": [],
            "player_match_counts": {},
            "rounds": {}
        }
    
    match_data = session[session_key]
    error = None

    if request.method == "POST":
        # Update session configuration
        try:
            courts_input = int(request.form.get("courts", match_data["courts"]))
            match_data["courts"] = max(1, min(20, courts_input))
            
            num_matches_input = int(request.form.get("num_matches", match_data["num_matches"]))
            match_data["num_matches"] = max(1, min(10, num_matches_input))
        except (ValueError, TypeError):
            error = "Invalid number format for courts or matches"
        
        match_type_input = request.form.get("match_type", match_data["match_type"])
        if match_type_input in ["singles", "doubles"]:
            match_data["match_type"] = match_type_input

        # Handle player management
        if "remove_player" in request.form:
            name_to_remove = request.form.get("remove_player", "").strip()
            if name_to_remove:
                match_data["players"] = [p for p in match_data["players"] if p["name"] != name_to_remove]
                # Clear matches when player is removed
                match_data.update({"matchups": [], "player_match_counts": {}, "rounds": {}})

        elif "upload_csv" in request.form:
            file = request.files.get("csv_file")
            new_players, message = process_csv_upload_secure(file, match_data["players"])
            
            if new_players:
                match_data["players"].extend(new_players)
                match_data.update({"matchups": [], "player_match_counts": {}, "rounds": {}})
                flash(message, 'success')
            else:
                error = message

        elif "reset" in request.form:
            session[session_key] = {
                "players": [],
                "courts": 1,
                "num_matches": 1,
                "match_type": "singles",
                "matchups": [],
                "player_match_counts": {},
                "rounds": {}
            }
            return redirect(url_for('match_organizer'))

        elif "add_player" in request.form:
            name = request.form.get("name", "").strip()
            grade_str = request.form.get("grade", "")
            max_rounds_str = request.form.get("max_rounds", "").strip()
            
            name = sanitize_csv_field(name)
            
            is_valid_name, name_error = validate_player_name(name)
            if not is_valid_name:
                error = name_error
            else:
                try:
                    grade = int(grade_str)
                    if not (1 <= grade <= 4):
                        error = "Grade must be between 1 and 4"
                    elif any(p["name"].lower() == name.lower() for p in match_data["players"]):
                        error = f"Player '{name}' already exists"
                    elif len(match_data["players"]) >= 100:
                        error = "Maximum 100 players allowed"
                    else:
                        max_rounds = None
                        if max_rounds_str:
                            try:
                                max_rounds = int(max_rounds_str)
                                if not (1 <= max_rounds <= 10):
                                    error = "Max rounds must be between 1 and 10"
                                elif max_rounds > match_data["num_matches"]:
                                    error = f"Max rounds cannot exceed total rounds ({match_data['num_matches']})"
                            except (ValueError, TypeError):
                                error = "Invalid max rounds format"
                        
                        if not error:
                            player = {"name": name, "grade": grade}
                            if max_rounds is not None:
                                player["max_rounds"] = max_rounds
                            
                            match_data["players"].append(player)
                            flash(f'Player {name} added successfully!', 'success')
                            return redirect(url_for('match_organizer'))
                except (TypeError, ValueError):
                    error = "Invalid grade selected"

        elif "organize_matches" in request.form or "reshuffle" in request.form:
            min_players = 2 if match_data["match_type"] == "singles" else 4
            
            if len(match_data["players"]) < min_players:
                error = f"Need at least {min_players} players for {match_data['match_type']} matches"
            elif len(match_data["players"]) > 100:
                error = "Too many players (max 100)"
            else:
                if "reshuffle" in request.form:
                    random.shuffle(match_data["players"])

                try:
                    matchups, player_match_counts, opponent_averages, opponent_diff = organize_matches(
                        match_data["players"], match_data["courts"], match_data["match_type"], match_data["num_matches"]
                    )

                    # Build round structure
                    round_structure = defaultdict(list)
                    for court_index, court_matches in enumerate(matchups):
                        for match, round_num in court_matches:
                            round_structure[round_num].append((court_index + 1, match))
                    rounds = dict(sorted(round_structure.items()))

                    match_data.update({
                        "matchups": matchups,
                        "player_match_counts": player_match_counts,
                        "rounds": rounds
                    })
                    
                    flash('Matches organized successfully!', 'success')
                        
                except Exception as e:
                    app.logger.error(f"Match organization error: {str(e)}")
                    error = "Error organizing matches. Please try again."
        
        # Save updated session data
        session[session_key] = match_data

    return render_template("match_organizer.html",
                         players=match_data["players"],
                         matchups=match_data["matchups"],
                         courts=match_data["courts"],
                         num_matches=match_data["num_matches"],
                         match_type=match_data["match_type"],
                         player_match_counts=match_data["player_match_counts"],
                         rounds=match_data["rounds"],
                         error=error)

# Invoice Management Routes
@app.route('/invoices')
@login_required
def invoices():
    coach_id = session['coach_id']
    status_filter = request.args.get('status', 'all')
    
    try:
        # Mark overdue invoices
        today = datetime.now().date()
        overdue_invoices = Invoice.query.filter(
            Invoice.coach_id == coach_id,
            Invoice.status == 'pending',
            Invoice.due_date < today
        ).all()
        
        for invoice in overdue_invoices:
            invoice.status = 'overdue'
        
        if overdue_invoices:
            db.session.commit()
        
        # Build query
        query = Invoice.query.filter_by(coach_id=coach_id)
        
        if status_filter != 'all':
            query = query.filter_by(status=status_filter)
        
        invoices = query.order_by(Invoice.created_at.desc()).all()
        csrf_form = CSRFForm()
        
        return render_template('invoices.html', 
                             invoices=invoices, 
                             status_filter=status_filter,
                             csrf_form=csrf_form)
                             
    except Exception as e:
        app.logger.error(f"Invoices page error: {str(e)}")
        flash('Error loading invoices. Please try again.', 'error')
        return render_template('invoices.html', 
                             invoices=[], 
                             status_filter=status_filter,
                             csrf_form=CSRFForm())

@app.route('/view-invoice/<int:invoice_id>')
@login_required
def view_invoice(invoice_id):
    try:
        invoice = Invoice.query.filter_by(
            id=invoice_id, 
            coach_id=session['coach_id']
        ).first()
        
        if not invoice:
            flash('Invoice not found.', 'error')
            return redirect(url_for('invoices'))
        
        # Update status if needed
        invoice.update_status()
        db.session.commit()
        
        csrf_form = CSRFForm()
        return render_template('view_invoice.html', invoice=invoice, csrf_form=csrf_form)
        
    except Exception as e:
        app.logger.error(f"View invoice error: {str(e)}")
        flash('Error loading invoice. Please try again.', 'error')
        return redirect(url_for('invoices'))

@app.route('/create-invoice', methods=['GET', 'POST'])
@login_required
def create_invoice():
    form = InvoiceForm()
    
    try:
        templates = InvoiceTemplate.query.filter_by(coach_id=session['coach_id'])\
            .order_by(InvoiceTemplate.name.asc()).all()
        
        if form.validate_on_submit():
            invoice = Invoice(
                coach_id=session['coach_id'],
                student_name=form.student_name.data.strip(),
                student_email=form.student_email.data.lower() if form.student_email.data else None,
                amount=form.amount.data,
                description=form.description.data.strip(),
                due_date=form.due_date.data
            )
            
            invoice.invoice_number = invoice.generate_invoice_number(session['coach_id'])
            
            try:
                db.session.add(invoice)
                db.session.commit()
                flash('Invoice created successfully!', 'success')
                return redirect(url_for('view_invoice', invoice_id=invoice.id))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Create invoice error: {str(e)}")
                flash('Failed to create invoice. Please try again.', 'error')
        
        return render_template('create_invoice.html', form=form, templates=templates)
        
    except Exception as e:
        app.logger.error(f"Create invoice page error: {str(e)}")
        flash('Error loading create invoice page.', 'error')
        return redirect(url_for('invoices'))

@app.route('/edit-invoice/<int:invoice_id>', methods=['GET', 'POST'])
@login_required
def edit_invoice(invoice_id):
    try:
        invoice = Invoice.query.filter_by(
            id=invoice_id, 
            coach_id=session['coach_id']
        ).first()
        
        if not invoice:
            flash('Invoice not found.', 'error')
            return redirect(url_for('invoices'))
        
        form = InvoiceForm(obj=invoice)
        
        if form.validate_on_submit():
            invoice.student_name = form.student_name.data.strip()
            invoice.student_email = form.student_email.data.lower() if form.student_email.data else None
            invoice.amount = form.amount.data
            invoice.description = form.description.data.strip()
            invoice.due_date = form.due_date.data
            
            # Update status based on new due date
            invoice.update_status()
            
            try:
                db.session.commit()
                flash('Invoice updated successfully!', 'success')
                return redirect(url_for('view_invoice', invoice_id=invoice.id))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Edit invoice error: {str(e)}")
                flash('Failed to update invoice. Please try again.', 'error')
        
        return render_template('edit_invoice.html', form=form, invoice=invoice)
        
    except Exception as e:
        app.logger.error(f"Edit invoice page error: {str(e)}")
        flash('Error loading edit invoice page.', 'error')
        return redirect(url_for('invoices'))

@app.route('/mark-paid/<int:invoice_id>', methods=['POST'])
@login_required
def mark_paid(invoice_id):
    csrf_form = CSRFForm()
    if not csrf_form.validate_on_submit():
        flash('Security token expired. Please try again.', 'error')
        return redirect(url_for('invoices'))
    
    try:
        invoice = Invoice.query.filter_by(
            id=invoice_id, 
            coach_id=session['coach_id']
        ).first()
        
        if not invoice:
            flash('Invoice not found.', 'error')
            return redirect(url_for('invoices'))
        
        if invoice.status != 'paid':
            invoice.status = 'paid'
            invoice.paid_at = datetime.utcnow()
            
            try:
                db.session.commit()
                flash(f'Invoice {invoice.invoice_number} marked as paid!', 'success')
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Mark paid error: {str(e)}")
                flash('Failed to update invoice. Please try again.', 'error')
        
        return redirect(request.referrer or url_for('invoices'))
        
    except Exception as e:
        app.logger.error(f"Mark paid error: {str(e)}")
        flash('Error updating invoice. Please try again.', 'error')
        return redirect(url_for('invoices'))

@app.route('/delete-invoice/<int:invoice_id>', methods=['POST'])
@login_required
def delete_invoice(invoice_id):
    csrf_form = CSRFForm()
    if not csrf_form.validate_on_submit():
        flash('Security token expired. Please try again.', 'error')
        return redirect(url_for('invoices'))
    
    try:
        invoice = Invoice.query.filter_by(
            id=invoice_id, 
            coach_id=session['coach_id']
        ).first()
        
        if not invoice:
            flash('Invoice not found.', 'error')
            return redirect(url_for('invoices'))
        
        invoice_number = invoice.invoice_number
        
        try:
            db.session.delete(invoice)
            db.session.commit()
            flash(f'Invoice {invoice_number} has been deleted.', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Delete invoice error: {str(e)}")
            flash('Failed to delete invoice. Please try again.', 'error')
        
        return redirect(url_for('invoices'))
        
    except Exception as e:
        app.logger.error(f"Delete invoice error: {str(e)}")
        flash('Error deleting invoice. Please try again.', 'error')
        return redirect(url_for('invoices'))

@app.route('/repeat-invoice/<int:invoice_id>')
@login_required
def repeat_invoice(invoice_id):
    try:
        original_invoice = Invoice.query.filter_by(
            id=invoice_id, 
            coach_id=session['coach_id']
        ).first()
        
        if not original_invoice:
            flash('Original invoice not found.', 'error')
            return redirect(url_for('invoices'))
        
        # Create form with original invoice data
        form = InvoiceForm()
        form.student_name.data = original_invoice.student_name
        form.student_email.data = original_invoice.student_email
        form.amount.data = original_invoice.amount
        form.description.data = original_invoice.description
        
        # Set due date to 14 days from today (or use template default if available)
        default_days = 14
        if original_invoice.template:
            default_days = original_invoice.template.default_due_days
        form.due_date.data = datetime.now().date() + timedelta(days=default_days)
        
        templates = InvoiceTemplate.query.filter_by(coach_id=session['coach_id'])\
            .order_by(InvoiceTemplate.name.asc()).all()
        
        flash(f'Creating new invoice based on {original_invoice.invoice_number}', 'info')
        return render_template('create_invoice.html', form=form, templates=templates)
        
    except Exception as e:
        app.logger.error(f"Repeat invoice error: {str(e)}")
        flash('Error creating repeat invoice. Please try again.', 'error')
        return redirect(url_for('invoices'))

# Template Management Routes
@app.route('/templates')
@login_required
def templates():
    try:
        coach_id = session['coach_id']
        templates = InvoiceTemplate.query.filter_by(coach_id=coach_id)\
            .order_by(InvoiceTemplate.name.asc()).all()
        
        csrf_form = CSRFForm()
        return render_template('templates.html', templates=templates, csrf_form=csrf_form)
        
    except Exception as e:
        app.logger.error(f"Templates page error: {str(e)}")
        flash('Error loading templates. Please try again.', 'error')
        return render_template('templates.html', templates=[], csrf_form=CSRFForm())

@app.route('/create-template', methods=['GET', 'POST'])
@login_required
def create_template():
    form = TemplateForm()
    
    if form.validate_on_submit():
        try:
            template = InvoiceTemplate(
                coach_id=session['coach_id'],
                name=form.name.data.strip(),
                amount=form.amount.data,
                description=form.description.data.strip(),
                default_due_days=form.default_due_days.data
            )
            
            db.session.add(template)
            db.session.commit()
            flash('Template created successfully!', 'success')
            return redirect(url_for('templates'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Create template error: {str(e)}")
            flash('Failed to create template. Please try again.', 'error')
    
    return render_template('create_template.html', form=form)

@app.route('/edit-template/<int:template_id>', methods=['GET', 'POST'])
@login_required
def edit_template(template_id):
    try:
        template = InvoiceTemplate.query.filter_by(
            id=template_id, 
            coach_id=session['coach_id']
        ).first()
        
        if not template:
            flash('Template not found.', 'error')
            return redirect(url_for('templates'))
        
        form = TemplateForm(obj=template)
        
        if form.validate_on_submit():
            template.name = form.name.data.strip()
            template.amount = form.amount.data
            template.description = form.description.data.strip()
            template.default_due_days = form.default_due_days.data
            template.updated_at = datetime.utcnow()
            
            try:
                db.session.commit()
                flash('Template updated successfully!', 'success')
                return redirect(url_for('templates'))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Edit template error: {str(e)}")
                flash('Failed to update template. Please try again.', 'error')
        
        return render_template('edit_template.html', form=form, template=template)
        
    except Exception as e:
        app.logger.error(f"Edit template page error: {str(e)}")
        flash('Error loading edit template page.', 'error')
        return redirect(url_for('templates'))

@app.route('/delete-template/<int:template_id>', methods=['POST'])
@login_required
def delete_template(template_id):
    csrf_form = CSRFForm()
    if not csrf_form.validate_on_submit():
        flash('Security token expired. Please try again.', 'error')
        return redirect(url_for('templates'))
    
    try:
        template = InvoiceTemplate.query.filter_by(
            id=template_id, 
            coach_id=session['coach_id']
        ).first()
        
        if not template:
            flash('Template not found.', 'error')
            return redirect(url_for('templates'))
        
        template_name = template.name
        
        try:
            db.session.delete(template)
            db.session.commit()
            flash(f'Template "{template_name}" has been deleted.', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Delete template error: {str(e)}")
            flash('Failed to delete template. Please try again.', 'error')
        
        return redirect(url_for('templates'))
        
    except Exception as e:
        app.logger.error(f"Delete template error: {str(e)}")
        flash('Error deleting template. Please try again.', 'error')
        return redirect(url_for('templates'))

@app.route('/use-template/<int:template_id>')
@login_required
def use_template(template_id):
    try:
        template = InvoiceTemplate.query.filter_by(
            id=template_id, 
            coach_id=session['coach_id']
        ).first()
        
        if not template:
            flash('Template not found.', 'error')
            return redirect(url_for('templates'))
        
        return redirect(url_for('create_invoice_from_template', template_id=template.id))
        
    except Exception as e:
        app.logger.error(f"Use template error: {str(e)}")
        flash('Error using template. Please try again.', 'error')
        return redirect(url_for('templates'))

@app.route('/create-invoice-from-template/<int:template_id>', methods=['GET', 'POST'])
@login_required
def create_invoice_from_template(template_id):
    try:
        template = InvoiceTemplate.query.filter_by(
            id=template_id, 
            coach_id=session['coach_id']
        ).first()
        
        if not template:
            flash('Template not found.', 'error')
            return redirect(url_for('templates'))
        
        form = InvoiceForm()
        
        # Pre-populate form with template data
        if request.method == 'GET':
            form.amount.data = template.amount
            form.description.data = template.description
            form.due_date.data = datetime.now().date() + timedelta(days=template.default_due_days)
        
        if form.validate_on_submit():
            invoice = Invoice(
                coach_id=session['coach_id'],
                template_id=template.id,
                student_name=form.student_name.data.strip(),
                student_email=form.student_email.data.lower() if form.student_email.data else None,
                amount=form.amount.data,
                description=form.description.data.strip(),
                due_date=form.due_date.data
            )
            
            invoice.invoice_number = invoice.generate_invoice_number(session['coach_id'])
            
            try:
                db.session.add(invoice)
                db.session.commit()
                flash('Invoice created successfully from template!', 'success')
                return redirect(url_for('view_invoice', invoice_id=invoice.id))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Create invoice from template error: {str(e)}")
                flash('Failed to create invoice. Please try again.', 'error')
        
        templates = InvoiceTemplate.query.filter_by(coach_id=session['coach_id'])\
            .order_by(InvoiceTemplate.name.asc()).all()
        
        return render_template('create_invoice.html', form=form, template=template, templates=templates)
        
    except Exception as e:
        app.logger.error(f"Create invoice from template error: {str(e)}")
        flash('Error creating invoice from template.', 'error')
        return redirect(url_for('templates'))

# Error handlers
@app.errorhandler(400)
def bad_request(error):
    return render_template('error.html', 
                         title="Bad Request", 
                         message="The request could not be understood by the server."), 400

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', 
                         title="Page Not Found", 
                         message="The page you are looking for could not be found."), 404

@app.errorhandler(413)
def payload_too_large(error):
    return render_template('error.html', 
                         title="File Too Large", 
                         message="The uploaded file is too large."), 413

@app.errorhandler(500)
def server_error(error):
    db.session.rollback()
    return render_template('error.html', 
                         title="Server Error", 
                         message="An internal server error occurred."), 500

# Security headers
@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    if not is_development:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    response.headers['Content-Security-Policy'] = ("default-src 'self'; "
                                                   "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                                                   "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
                                                   "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
                                                   "img-src 'self' data:;")
    return response

# Database initialization
def create_tables():
    """Create database tables and handle any schema migrations safely"""
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            
            # Verify critical tables exist
            inspector = sa.inspect(db.engine)
            required_tables = ['coach', 'invoice', 'invoice_template']
            existing_tables = inspector.get_table_names()
            
            missing_tables = [table for table in required_tables if table not in existing_tables]
            if missing_tables:
                app.logger.error(f"Missing database tables: {missing_tables}")
                raise Exception(f"Database initialization failed. Missing tables: {missing_tables}")
            
            app.logger.info("Database tables verified successfully")
            
        except Exception as e:
            app.logger.error(f"Database initialization error: {str(e)}")
            raise

# Health check endpoint
@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Test database connection
        db.session.execute(sa.text('SELECT 1'))
        return jsonify({
            'status': 'healthy', 
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy', 
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

if __name__ == '__main__':
    create_tables()
    app.run(debug=is_development, host='0.0.0.0', port=5000)