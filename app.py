# Standard Library Imports
import os
import uuid
import json
import logging
from datetime import datetime, timedelta
from io import BytesIO

# Third-Party Library Imports
import boto3
import pytz
import pandas as pd
import bcrypt
import traceback
from dotenv import load_dotenv
from botocore.config import Config
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, make_response, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from logging.handlers import RotatingFileHandler
from flask_sqlalchemy import SQLAlchemy
from alembic import op
import sqlalchemy as sa
from sqlalchemy.types import JSON 
from sqlalchemy.orm import relationship
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, SelectField, RadioField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from openpyxl import Workbook
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
import zipfile
from io import BytesIO
from flask import send_file


class SimpleForm(FlaskForm):
    pass

# Load environment variables
load_dotenv()

# Initialize Boto3 S3 client
s3 = boto3.client('s3')
# Your S3 bucket name
S3_BUCKET = 'pettycashdev'

app = Flask(__name__)
app.config.from_pyfile('config.py')

# Set up logging
log_file_path = 'app.log'
if not os.path.exists(log_file_path):
    open(log_file_path, 'w').close()  # Create the log file if it doesn't exist

# Set up a rotating file handler
handler = RotatingFileHandler(log_file_path, maxBytes=10000, backupCount=3)
handler.setLevel(logging.INFO)
formatter = logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
)
handler.setFormatter(formatter)

# Add the handler to the app logger
app.logger.addHandler(handler)

# Initialize Logging (before checking env vars)
logging.basicConfig(level=logging.INFO)

# Initialize Logging (before checking env vars)
logging.basicConfig(level=logging.INFO)

# Check for missing environment variables AFTER app is created
# required_env_vars = ['LOCAL_DATABASE_URI']
required_env_vars = ['SECRET_KEY', 'WTF_CSRF_SECRET_KEY', 'LOCAL_DATABASE_URI', 'RDS_DATABASE_URI', 'S3_BUCKET', 'S3_KEY', 'S3_SECRET', 'S3_REGION']
missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
if missing_vars:
    app.logger.error(f"Missing environment variables: {', '.join(missing_vars)}")
    raise RuntimeError(f"Missing environment variables: {', '.join(missing_vars)}")


s3_client = boto3.client(
    's3',
    aws_access_key_id=app.config['S3_KEY'],
    aws_secret_access_key=app.config['S3_SECRET'],
    region_name=app.config['S3_REGION'],
    config=Config(signature_version='s3v4')
)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('WTF_CSRF_SECRET_KEY')

# Flask session cookie configuration for production
app.config['SESSION_COOKIE_SECURE'] = False  
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Can be 'Strict' if you don't need cross-site cookie access
app.config['WTF_CSRF_ENABLED'] = True 
app.config['WTF_CSRF_SSL_STRICT'] = True  # Enforce CSRF tokens over HTTPS
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)  # Adjust session lifetime as needed
# Increase the max content length to 2GB (adjust as needed)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024  # 2GB


# Set the configurations based on the environment
FLASK_ENV = os.environ.get('FLASK_ENV', 'production')
if FLASK_ENV == 'production':
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('RDS_DATABASE_URI')
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('LOCAL_DATABASE_URI')

# Example for setting the time zone to Asia/Hong_Kong
tz = pytz.timezone('Asia/Hong_Kong')

db = SQLAlchemy(app)
# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

migrate = Migrate(app, db)

login_attempts = {}

csrf = CSRFProtect(app)

@app.before_request
def make_session_permanent():
    session.permanent = True

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))  # Use UUID as a string
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    company = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(150), nullable=False)
    approved = db.Column(db.Boolean, default=False)  # Add a column to handle approval status
    access_level = db.Column(db.String(20), default='read_only')
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)
    report_histories = db.relationship(
        "ReportHistory",
        back_populates="user"
    )

class Report(db.Model):
    __tablename__ = 'report'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    transaction_date = db.Column(db.Date, nullable=False)
    next_transaction_date = db.Column(db.Date, nullable=True) 
    date = db.Column(db.DateTime, default=lambda: datetime.now(tz))
    opening_balance = db.Column(db.Float, nullable=False)
    cash_addition = db.Column(db.Float, nullable=False, default=0.0)
    adjusted_opening_balance = db.Column(db.Float, nullable=True, default=None) 

    # Shop sales breakdown
    cash_sales = db.Column(db.Float, nullable=False, default=0.0)
    visa_sales = db.Column(db.Float, nullable=False, default=0.0)
    alipay_sales = db.Column(db.Float, nullable=False, default=0.0)
    wechat_sales = db.Column(db.Float, nullable=False, default=0.0)
    master_sales = db.Column(db.Float, nullable=False, default=0.0)
    unionpay_sales = db.Column(db.Float, nullable=False, default=0.0)
    amex_sales = db.Column(db.Float, nullable=False, default=0.0)
    octopus_sales = db.Column(db.Float, nullable=False, default=0.0)

    # Delivery sales breakdown
    deliveroo_sales = db.Column(db.Float, nullable=False, default=0.0)
    foodpanda_sales = db.Column(db.Float, nullable=False, default=0.0)
    keeta_sales = db.Column(db.Float, nullable=False, default=0.0)
    openrice_sales = db.Column(db.Float, nullable=False, default=0.0)

    # Aggregate fields
    shop_sales = db.Column(db.Float, nullable=False, default=0.0)
    delivery_sales = db.Column(db.Float, nullable=False, default=0.0)
    total_sales = db.Column(db.Float, nullable=False, default=0.0)

    # Other fields
    expenses = db.Column(db.Float, nullable=False)
    bank_deposit = db.Column(db.Float, nullable=False, default=0.0)
    closing_balance = db.Column(db.Float, nullable=False)
    receipt_files = db.Column(db.Text)  # Comma-separated list of S3 keys
    uploaded_by = db.Column(db.String(150), db.ForeignKey('user.username'), nullable=True)
    company = db.Column(db.String(150), nullable=False)
    shop_expenses = db.relationship('ShopExpense', backref='report', lazy=True)
    report_histories = db.relationship(
        'ReportHistory', 
        back_populates='report', 
        cascade='all, delete-orphan'
    )

    # Properties
    @property
    def total_expenses(self):
        return sum(expense.amount for expense in self.shop_expenses)


class ShopExpense(db.Model):
    __tablename__ = 'shop_expense'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id = db.Column(db.String(36), db.ForeignKey('report.id'), nullable=False)
    item = db.Column(db.String(150), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    remarks = db.Column(db.String(300), nullable=True)
    files = db.Column(db.Text)  # Comma-separated list of S3 keys
    s3_key = db.Column(db.String(255), nullable=True)  # Stores the S3 object key

class ReportHistory(db.Model):
    __tablename__ = 'report_history'
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.String(36), db.ForeignKey('report.id', ondelete='CASCADE'), nullable=False)
    company = db.Column(db.String(150), nullable=False, index=True)  # Limited to 150 for consistency with `Report`
    user_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='SET NULL'))  # Handle deleted users gracefully
    action = db.Column(db.String(50), nullable=False)  # "created", "edited", "deleted"
    field_changed = db.Column(db.String(255), nullable=True)  # Optional field
    old_value = db.Column(db.Text, nullable=True)  # Optional field
    new_value = db.Column(db.Text, nullable=True)  # Optional field
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    user = db.relationship('User', back_populates='report_histories')
    report = db.relationship('Report', back_populates='report_histories')

    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=1, max=150)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=1, max=150)])
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    company = StringField('Company', validators=[DataRequired(), Length(min=2, max=150)])  # Add this line
    role = SelectField('Role', choices=[('client', 'Client'), ('admin', 'Admin')], validators=[DataRequired()])

    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class RequestResetForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', 
        validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class AccessLevel:
    READ_ONLY = 'read_only'
    DOWNLOAD_ONLY = 'download_only'
    EDIT_DOWNLOAD = 'edit_download'

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')

            # Create a new user instance with data from the form
            new_user = User(
                id=str(uuid.uuid4()),  # Generate and convert UUID to string
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                username=form.username.data,
                password=hashed_password,
                company=form.company.data,
                role=form.role.data,
                approved=False if form.role.data == 'admin' else True
            )
            

            # Add the user to the database
            db.session.add(new_user)
            db.session.commit()

            # Provide feedback and redirect
            flash('Your account has been created! Please wait for super admin approval.' if new_user.role == 'admin' else 'You can now log in.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error during registration: {e}")
            flash('There was an error during registration. Please try again later.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html', form=form)


@app.route('/approve_user/<string:user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    if current_user.role != 'super_admin':
        flash("Only Super Admins can approve users.", "danger")
        return redirect(url_for('admin_dashboard'))

    user = User.query.get_or_404(user_id)
    user.approved = True  # Update approved field directly
    db.session.commit()
    flash(f"User {user.username} approved successfully.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/reject_user/<string:user_id>', methods=['POST'])
@login_required
def reject_user(user_id):
    if current_user.role != 'super_admin':
        flash("Not authorized", "danger")
        return redirect(url_for('admin_dashboard'))

    user = User.query.get_or_404(user_id)
    user.approved = False  # Set approved to False for rejection
    db.session.commit()
    flash(f"User {user.username} rejected and deactivated.", "warning")
    return redirect(url_for('admin_dashboard'))



@app.route('/update_user_access/<string:user_id>', methods=['POST'])
@login_required
def update_user_access(user_id):
    if current_user.role != 'super_admin':
        flash("Not authorized", "danger")
        return redirect(url_for('admin_dashboard'))

    # Fetch the user from the database
    user = User.query.filter_by(id=user_id).first()

    if not user:
        flash("User not found", "danger")
        return redirect(url_for('admin_dashboard'))

    # Get the new access level from the form
    access_level = request.form.get('access_level')

    # Update the access level
    if access_level:
        user.access_level = access_level
        db.session.commit()  # Save the change in the database
        flash(f"Access level updated for {user.username}.", "success")
    else:
        flash("Invalid access level.", "danger")

    return redirect(url_for('admin_dashboard'))


@app.route('/validate_username', methods=['POST'])
def validate_username():
    data = request.get_json()
    username = data.get('username')
    user = User.query.filter_by(username=username).first()
    return jsonify({'exists': user is not None})

csrf.exempt(validate_username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if user.approved:
                if check_password_hash(user.password, form.password.data):
                    login_user(user)
                    flash('Login Successful!', 'success')
                    
                    # Redirect based on role after successful login
                    if user.role == 'super_admin':
                        return redirect(url_for('admin'))
                    elif user.role == 'admin':
                        return redirect(url_for('admin'))
                    else:
                        return redirect(url_for('index'))
                else:
                    flash('Incorrect password.', 'danger')
            else:
                flash('Your account is not approved yet.', 'warning')
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/reset_request', methods=['GET', 'POST'])
@login_required  # Ensure the user is logged in
def reset_request():
    form = ChangePasswordForm()  
    if form.validate_on_submit():
        user = User.query.get(current_user.id)  # Get the current user
        if user and check_password_hash(user.password, form.current_password.data):
            if form.new_password.data == form.confirm_password.data:
                user.password = hash_password(form.new_password.data)  # Hash the new password
                db.session.commit()
                flash('Your password has been updated!', 'success')
                return redirect(url_for('profile'))  # Redirect to a profile or success page
            else:
                flash('New passwords do not match.', 'danger')
        else:
            flash('Current password is incorrect.', 'danger')

    return render_template('reset_request.html', form=form)  # Keep the same template

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    user = User.query.filter_by(reset_token=token).first()
    
    # Check if the user exists and if the token is valid
    if user is None:
        flash('That is an invalid or expired reset token', 'warning')
        return redirect(url_for('reset_request'))

    # Check if token is expired
    if user.reset_token_expiry and user.reset_token_expiry < datetime.now():
        flash('That reset token has expired', 'warning')
        return redirect(url_for('reset_request'))

    form = ResetPasswordForm()  # This should be your form for resetting the password
    if form.validate_on_submit():
        # Hash the new password
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user.password = hashed_password
        user.reset_token = None  # Clear the reset token
        user.reset_token_expiry = None  # Clear the expiration
        db.session.commit()
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_token.html', form=form)

@app.route('/admin_dashboard', methods=['GET'])
@login_required
def admin_dashboard():
    if current_user.role != 'super_admin':
        flash("Not authorized", "danger")
        return redirect(url_for('index'))

    # Query the database for pending and approved users
    pending_users = User.query.filter_by(approved=False).all()
    approved_users = User.query.filter_by(approved=True).all()

    return render_template(
        'admin_dashboard.html',
        pending_users=pending_users,
        approved_users=approved_users,
        super_admin=(current_user.role == 'super_admin')
    )

@app.route('/dashboard_admin', methods=['GET'])
@login_required
def admin2():
    if current_user.role not in ['admin', 'super_admin']:
        flash("Not authorized", "danger")
        return redirect(url_for('index'))
    for_approvals = User.query.filter_by(approved=False)
    approved_users = User.query.filter_by(approved=True)
    return render_template(
        'dashboard_admin.html',
        for_approvals=for_approvals,
        approved_users=approved_users
        )
@app.route('/update_access_level/<string:user_id>', methods=['POST'])
@login_required
def update_access_level(user_id):
    if current_user.role not in ['admin', 'super_admin']:
        flash('Not Authorized', 'danger')
        return redirect(url_for('index'))
    user = User.query.get_or_404(user_id)
    access_level = request.form['access_level']
    user.access_level = access_level
    db.session.commit()
    return redirect('/dashboard_admin')
    
    

@app.route('/approve_test/<string:user_id>', methods=['POST'])
def approve_test(user_id):
    if current_user.role != 'super_admin':
        flash('Not authorized', 'danger')
        return redirect(url_for('index'))
    user = User.query.get_or_404(user_id)
    user.approved = True; 
    db.session.commit()
    flash(f"{user.username} is aprroved.", "success")
    return redirect('/dashboard_admin')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.role not in ['admin', 'super_admin']:
        flash("Not authorized", "danger")
        return redirect(url_for('index'))

    # Get filter parameters from query strings
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    company = request.args.get('company')
    uploaded_by = request.args.get('uploaded_by')
    expenses = request.args.get('expenses')
    sales = request.args.get('sales')

    # Build the query dynamically based on filters
    query = Report.query

    # Filter by date range
    if start_date:
        query = query.filter(Report.transaction_date >= datetime.strptime(start_date, '%Y-%m-%d').date())
    if end_date:
        query = query.filter(Report.transaction_date <= datetime.strptime(end_date, '%Y-%m-%d').date())

    # Filter by company
    if company:
        query = query.filter(Report.company == company)

    # Filter by uploaded_by
    if uploaded_by:
        query = query.filter(Report.uploaded_by == uploaded_by)

    # Filter by expenses (exact value or range ±10%)
    if expenses:
        try:
            expenses = float(expenses)
            query = query.filter(Report.expenses.between(expenses * 0.9, expenses * 1.1))
        except ValueError:
            pass

    # Filter by sales (exact value or range ±10%)
    if sales:
        try:
            sales = float(sales)
            query = query.filter(Report.total_sales.between(sales * 0.9, sales * 1.1))
        except ValueError:
            pass

    # Fetch filtered reports
    reports = query.order_by(Report.date.desc()).all()

    # Calculate cumulative data
    cumulative_shop_sales_by_company = {}
    cumulative_delivery_sales_by_company = {}
    cumulative_total_sales_by_company = {}
    cumulative_expenses_by_company = {}

    for report in reports:
        company = report.company
        cumulative_shop_sales_by_company[company] = cumulative_shop_sales_by_company.get(company, 0) + (report.shop_sales or 0)
        cumulative_delivery_sales_by_company[company] = cumulative_delivery_sales_by_company.get(company, 0) + (report.delivery_sales or 0)
        cumulative_total_sales_by_company[company] = cumulative_total_sales_by_company.get(company, 0) + (report.total_sales or 0)
        cumulative_expenses_by_company[company] = cumulative_expenses_by_company.get(company, 0) + (report.expenses or 0)

    # Render template
    return render_template(
        'admin.html',
        reports=reports,
        cumulative_shop_sales_by_company=cumulative_shop_sales_by_company,
        cumulative_delivery_sales_by_company=cumulative_delivery_sales_by_company,
        cumulative_total_sales_by_company=cumulative_total_sales_by_company,
        cumulative_expenses_by_company=cumulative_expenses_by_company,
        super_admin=(current_user.role == 'super_admin')
    )


@app.route('/index')
@login_required
def index():
    reports = Report.query.filter_by(company=current_user.company).order_by(Report.date.desc()).all()

    cumulative_shop_sales = 0.0
    cumulative_delivery_sales = 0.0
    cumulative_expenses = 0.0

    for report in reports:
        try:
            total_shop_sales = report.shop_sales or 0.0
            total_delivery_sales = report.delivery_sales or 0.0
            total_expenses = sum(expense.amount for expense in report.shop_expenses)
            adjusted_opening_balance = report.opening_balance + (report.cash_addition or 0.0)
            closing_balance = adjusted_opening_balance + total_shop_sales - total_expenses - report.bank_deposit

            cumulative_shop_sales += total_shop_sales
            cumulative_delivery_sales += total_delivery_sales
            cumulative_expenses += total_expenses

            report.__dict__.update({
                "adjusted_opening_balance": adjusted_opening_balance,
                "total_shop_sales": total_shop_sales,
                "total_delivery_sales": total_delivery_sales,
                "total_sales": total_shop_sales + total_delivery_sales,
                "total_expenses": total_expenses,
                "closing_balance": closing_balance
            })

        except Exception as e:
            app.logger.error(f"Error processing report {report.id}: {e}")
            report.__dict__.update({
                "adjusted_opening_balance": 0.0,
                "total_shop_sales": 0.0,
                "total_delivery_sales": 0.0,
                "total_sales": 0.0,
                "total_expenses": 0.0
            })

    # Determine the most recent report
    most_recent_report = reports[0] if reports else None

    return render_template(
        'report_list.html',
        reports=reports,
        cumulative_shop_sales=cumulative_shop_sales,
        cumulative_delivery_sales=cumulative_delivery_sales,
        cumulative_expenses=cumulative_expenses,
        most_recent_report=most_recent_report
    )

# Helper Function: Upload a file to S3
def upload_file_to_s3(file, report_id):
    try:
        filename = secure_filename(file.filename)
        s3_key = f"expenses/{report_id}/{filename}"

        # Check the file size
        file_size = file.seek(0, os.SEEK_END)  # Move the cursor to the end to get size
        file.seek(0)  # Reset the cursor to the start

        if file_size > 5 * 1024 * 1024:  # If file is larger than 5MB, use multipart upload
            config = boto3.s3.transfer.TransferConfig(
                multipart_threshold=5 * 1024 * 1024,  # Threshold for multipart upload
                multipart_chunksize=5 * 1024 * 1024   # Each part is 5MB
            )
            transfer = boto3.s3.transfer.S3Transfer(s3_client)
            transfer.upload_fileobj(file, S3_BUCKET, s3_key, Config=config)
        else:  # For smaller files, use simple upload
            s3_client.upload_fileobj(file, S3_BUCKET, s3_key)

        return s3_key
    except Exception as e:
        app.logger.error(f"Error uploading file {file.filename}: {e}")
        raise

def download_file_from_s3(s3_key):
    """
    Fetch a file from the S3 bucket.
    :param s3_key: The key of the file to fetch from S3.
    :return: File data as bytes, or None if an error occurs.
    """
    try:
        s3_client = boto3.client('s3')  # Ensure boto3 is configured correctly
        response = s3_client.get_object(Bucket=S3_BUCKET, Key=s3_key)
        file_data = response['Body'].read()
        return file_data
    except NoCredentialsError:
        app.logger.error("S3 credentials not found.")
    except PartialCredentialsError:
        app.logger.error("Incomplete S3 credentials configuration.")
    except Exception as e:
        app.logger.error(f"Error fetching file from S3: {e}")
    return None    

def delete_files_from_s3(file_paths):
    """Delete files from S3 bucket."""
    if not file_paths:
        return

    objects_to_delete = [{'Key': path} for path in file_paths]
    try:
        s3_client.delete_objects(
            Bucket=S3_BUCKET,
            Delete={'Objects': objects_to_delete, 'Quiet': True}
        )
    except ClientError as e:
        app.logger.warning(f"Failed to delete some files from S3: {e}")


# Helper Function to Parse Nested Keys
def parse_nested_keys(data, prefix, existing_values=None):
    result = existing_values or {}
    for key, value in data.items():
        if key.startswith(prefix):
            subkey = key[len(prefix) + 1:-1]  # Extract key, e.g., cash, visa
            if value:  # Update only if the field has a value
                result[subkey] = float(value)
    return result

# Helper function for safe float conversion
def safe_float(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0

# Function to log history
def log_history(report_id, company, user_id, action, field_changed=None, old_value=None, new_value=None):
    try:  # Added try block to handle exceptions

        # Convert values to strings, handling None and various types
        old_value_str = str(old_value) if old_value is not None else None
        new_value_str = str(new_value) if new_value is not None else None

        history = ReportHistory(
            report_id=report_id,
            company=company,
            user_id=user_id,
            action=action,
            field_changed=field_changed,
            old_value=old_value_str,
            new_value=new_value_str
        )
        db.session.add(history)
        db.session.commit()
        return history  # Optional: return the created history object
    except Exception as e:
        app.logger.error(f"Error logging history: {e}")
        traceback.print_exc()  # Detailed error logging
        db.session.rollback()
        return None
    
# Define the allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx'}

def allowed_file(filename):
    """Check if a file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/report/<string:id>')
@login_required
def report_detail(id):
    try:
        report = Report.query.get_or_404(id)
        app.logger.debug(f"Report data: {report.__dict__}")

        # Fetch the history log for the report
        history_log = ReportHistory.query.filter_by(report_id=id).order_by(ReportHistory.timestamp.desc()).all()

        # Calculate adjusted opening balance for display
        report.adjusted_opening_balance = report.opening_balance + (report.cash_addition or 0.0)

        # Define display names for sales fields
        sales_display_names = {
            "cash_sales": "Cash",
            "visa_sales": "Visa",
            "alipay_sales": "Alipay",
            "wechat_sales": "WeChat",
            "master_sales": "MasterCard",
            "unionpay_sales": "UnionPay",
            "amex_sales": "Amex",
            "octopus_sales": "Octopus",
            "deliveroo_sales": "Deliveroo",
            "foodpanda_sales": "Foodpanda",
            "keeta_sales": "Keeta",
            "openrice_sales": "OpenRice",
        }

        # Shop and delivery sales breakdown
        # Pass breakdowns to the template
        shop_sales_data = {
            "cash": report.cash_sales,
            "visa": report.visa_sales,
            "alipay": report.alipay_sales,
            "wechat": report.wechat_sales,
            "master": report.master_sales,
            "unionpay": report.unionpay_sales,
            "amex": report.amex_sales,
            "octopus": report.octopus_sales,
        }

        delivery_sales_data = {
            "deliveroo": report.deliveroo_sales,
            "foodpanda": report.foodpanda_sales,
            "keeta": report.keeta_sales,
            "openrice": report.openrice_sales,
        }

        # Use shop_sales and delivery_sales directly
        total_shop_sales = report.shop_sales or 0.0
        total_delivery_sales = report.delivery_sales or 0.0
        total_sales = total_shop_sales + total_delivery_sales
        total_expenses = report.expenses or 0.0
        bank_deposit = report.bank_deposit or 0.0
        closing_balance = report.adjusted_opening_balance + total_shop_sales - total_expenses - report.bank_deposit

        # Process receipt files safely
        files = report.receipt_files.split(',') if report.receipt_files else []
        file_urls = []
        for file in files:
            if file:
                try:
                    file_url = s3_client.generate_presigned_url('get_object', Params={'Bucket': S3_BUCKET, 'Key': file}, ExpiresIn=3600)
                    file_urls.append(file_url)
                except Exception as e:
                    app.logger.error(f"Failed to generate URL for file {file}: {e}")

        app.logger.debug(f"Shop Sales Breakdown: {shop_sales_data}")
        app.logger.debug(f"Delivery Sales Breakdown: {delivery_sales_data}")

        # Render the template with the required variables
        return render_template(
            'report_detail.html',
            report=report,
            cash_addition=report.cash_addition, 
            total_shop_sales=total_shop_sales,
            total_expenses=total_expenses,
            total_sales=total_sales,
            bank_deposit=bank_deposit,
            files=file_urls,
            sales_display_names=sales_display_names,
            closing_balance=closing_balance,
            shop_sales_data=shop_sales_data, 
            delivery_sales_data=delivery_sales_data,  
            history_log=history_log
        )

    except Exception as e:
        app.logger.error(f"Error fetching report with id {id}: {e}")
        return jsonify({"status": "error", "message": f"Report with id {id} not found or other error occurred: {e}"}), 404


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_report():
    if request.method == 'POST':
        try:
            # Debugging logs
            app.logger.info(f"Raw form data: {request.form.to_dict(flat=False)}")
            app.logger.info(f"Raw file data: {request.files.to_dict(flat=False)}")

            # Deduplicate values in request.form
            cleaned_form = {key: request.form.getlist(key)[0] for key in request.form.keys()}
            app.logger.info(f"Cleaned form data: {cleaned_form}")


            # Ensure the company is not None or empty
            if not current_user.company:
                flash('Error: Your account does not have a company assigned. Please contact admin.', 'danger')
                return redirect(url_for('index'))
            
            # Parse sales data
            shop_sales_data = parse_nested_keys(request.form, 'sales[shop_sales]')
            delivery_sales_data = parse_nested_keys(request.form, 'sales[delivery_sales]')

            # Check if a report already exists for the selected transaction date
            transaction_date = datetime.strptime(request.form['transaction_date'], '%Y-%m-%d').date()
            app.logger.info(f"Checking for existing report with transaction_date: {transaction_date} for company: {current_user.company}")

            existing_report = Report.query.filter(
                Report.company == current_user.company,
                Report.transaction_date == transaction_date
            ).first()

            # Explicitly exclude reports that might have been added within the current session
            if existing_report and not hasattr(existing_report, '_sa_instance_state'):
                app.logger.warning(f"Duplicate report detected for date {transaction_date} - {existing_report}")
                raise ValueError(f"A report for {transaction_date} already exists. Please delete it first. 해당 날짜의 리포트가 이미 있습니다, 삭제하고 다시 제출 하시길 바랍니다.")


            # Default next_transaction_date to None
            next_transaction_date = None

            # Fetch the last report
            last_report = Report.query.filter_by(company=current_user.company).order_by(Report.transaction_date.desc()).first()

            # Determine the expected date and validate transaction_date
            if last_report:
                expected_date = last_report.transaction_date + timedelta(days=1)
                if transaction_date != expected_date:
                    raise ValueError(f"Transaction date must be {expected_date}.")
                next_transaction_date = expected_date
            else:
                app.logger.info("No previous reports found; this is the first report.")
                # For the first report, we let the user specify the transaction date
                expected_date = None
                next_transaction_date = transaction_date + timedelta(days=1)  # Infer next date after the first report

            
            # Calculate balances and sales totals
            opening_balance = safe_float(request.form['opening_balance'])
            cash_addition = safe_float(request.form.get('cash_addition', 0))
            adjusted_opening_balance = opening_balance + cash_addition
            bank_deposit = safe_float(request.form.get('bank_deposit', 0))
            total_shop_sales = sum(shop_sales_data.values())
            total_delivery_sales = sum(delivery_sales_data.values())
            total_sales = total_shop_sales + total_delivery_sales
            cash_sales = safe_float(request.form.get('sales[shop_sales][cash]', 0))


            # Initialize total expenses
            no_expense = request.form.get('no_expense') == 'true'
            total_expenses = 0

            # Process expenses if applicable
            expenses = []
            if not no_expense:
                index = 0
                while f'shopExpenses[{index}][item]' in request.form:
                    item = request.form.get(f'shopExpenses[{index}][item]')
                    amount = safe_float(request.form.get(f'shopExpenses[{index}][amount]', 0))
                    remarks = request.form.get(f'shopExpenses[{index}][remarks]', '')

                    # Process files for each expense
                    files = request.files.getlist(f'files[{index}][]')
                    files = [file for file in files if file and file.filename.strip()]

                    if not files:
                        raise ValueError(f"Expense {index + 1} must have at least one valid file attached.")

                    # Upload files to S3 and store file paths
                    file_paths = [upload_file_to_s3(file, str(uuid.uuid4())) for file in files]

                    # Create expense object
                    expense = ShopExpense(
                        report_id=None,  # Set report_id after report is committed
                        item=item,
                        amount=amount,
                        remarks=remarks,
                        files=','.join(file_paths)
                    )
                    expenses.append(expense)
                    total_expenses += amount
                    index += 1

            # Calculate closing balance after processing expenses
            closing_balance = (opening_balance + cash_addition + cash_sales) - total_expenses - bank_deposit

            # Create a new report
            report = Report(
                transaction_date=transaction_date,
                next_transaction_date=next_transaction_date,
                opening_balance=opening_balance,
                cash_addition=cash_addition,
                cash_sales=shop_sales_data.get('cash', 0),
                visa_sales=shop_sales_data.get('visa', 0),
                alipay_sales=shop_sales_data.get('alipay', 0),
                wechat_sales=shop_sales_data.get('wechat', 0),
                master_sales=shop_sales_data.get('master', 0),
                unionpay_sales=shop_sales_data.get('unionpay', 0),
                amex_sales=shop_sales_data.get('amex', 0),
                octopus_sales=shop_sales_data.get('octopus', 0),
                deliveroo_sales=delivery_sales_data.get('deliveroo', 0),
                foodpanda_sales=delivery_sales_data.get('foodpanda', 0),
                keeta_sales=delivery_sales_data.get('keeta', 0),
                openrice_sales=delivery_sales_data.get('openrice', 0),
                shop_sales=total_shop_sales,
                delivery_sales=total_delivery_sales,
                total_sales=total_sales,
                expenses=total_expenses,
                bank_deposit=bank_deposit,
                closing_balance=closing_balance,
                uploaded_by=current_user.username,
                company=current_user.company,
            )

            # Add the report to the database
            db.session.add(report)
            db.session.commit()

            # Update report_id for expenses and add them to the database
            for expense in expenses:
                expense.report_id = report.id
                db.session.add(expense)

            db.session.commit()
            app.logger.info(f"Report updated with total expenses: {total_expenses}")

            # Check if the request is AJAX
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"status": "success", "message": "Report submitted successfully.", "redirect_url": "/index"})
            else:
                flash("Report submitted successfully.", "success")
                return redirect(url_for('index'))

        except ValueError as ve:
            app.logger.error(f"Validation error: {ve}")
            return jsonify({"status": "error", "message": str(ve)}), 400

        except Exception as e:
            # Rollback on error
            db.session.rollback()
            app.logger.error(f"Error during report creation: {str(e)}")
            return jsonify({"status": "error", "message": "An error occurred."}), 500
        
 # For GET request, return the template
    last_report = Report.query.filter_by(company=current_user.company).order_by(Report.transaction_date.desc()).first()
    opening_balance = last_report.closing_balance if last_report else 0
    next_transaction_date = (last_report.transaction_date + timedelta(days=1)) if last_report else None
    is_first_report = last_report is None

    default_report = {
        "cash_sales": "",
        "visa_sales": "",
        "alipay_sales": "",
        "wechat_sales": "",
        "master_sales": "",
        "unionpay_sales": "",
        "amex_sales": "",
        "octopus_sales": "",
        "deliveroo_sales": "",
        "foodpanda_sales": "",
        "keeta_sales": "",
        "openrice_sales": "",
        "shop_sales": "",
        "delivery_sales": "",
        "total_sales": "",
        "expenses": "",
        "bank_deposit": "",
        "closing_balance": opening_balance,
        "cash_addition": "",
        "adjusted_opening_balance": opening_balance,
    }

    return render_template('index.html', opening_balance=opening_balance, report=default_report, next_transaction_date=next_transaction_date, is_first_report=is_first_report)

@app.route('/report/edit/<string:id>', methods=['GET', 'POST'])
@login_required
def edit_report(id):
    report = db.session.query(Report).filter_by(id=id).first()

    if not report:
        flash("Report not found.", "danger")
        return redirect(url_for('index'))

    # Authorization check
    if report.uploaded_by != current_user.username and current_user.role != 'super_admin':
        flash("You are not authorized to edit this report.", 'danger')
        return redirect(url_for('index'))

    # Ensure the report is the most recent
    most_recent_report = db.session.query(Report).filter_by(company=current_user.company).order_by(Report.transaction_date.desc()).first()
    if report.id != most_recent_report.id:
        flash("You can only edit the most recent report.가장 최근 리포트만 수정 가능합니다.", 'warning')
        return redirect(url_for('report_detail', id=report.id))

    if request.method == 'POST':
        try:
            #Debug incoming POST data
            app.logger.info(f"Received Edit Report Data: {request.form}")

            # Validate transaction date
            submitted_transaction_date = datetime.strptime(request.form.get('transaction_date'), '%Y-%m-%d').date()
            if submitted_transaction_date != report.transaction_date:
                flash("The transaction date cannot be changed.", 'danger')
                return redirect(url_for('edit_report', id=report.id))


            # Update financial fields
            report.opening_balance = safe_float(request.form.get('opening_balance', 0))
            report.cash_addition = safe_float(request.form.get('cash_addition', 0))
            report.bank_deposit = safe_float(request.form.get('bank_deposit', 0))

            # Parse and update sales data
            shop_sales_data = parse_nested_keys(
                request.form, 'sales[shop_sales]', 
                existing_values={
                    'cash': report.cash_sales,
                    'visa': report.visa_sales,
                    'alipay': report.alipay_sales,
                    'wechat': report.wechat_sales,
                    'master': report.master_sales,
                    'unionpay': report.unionpay_sales,
                    'amex': report.amex_sales,
                    'octopus': report.octopus_sales
                }
            )

            delivery_sales_data = parse_nested_keys(
                request.form, 'sales[delivery_sales]',
                existing_values={
                    'deliveroo': report.deliveroo_sales,
                    'foodpanda': report.foodpanda_sales,
                    'keeta': report.keeta_sales,
                    'openrice': report.openrice_sales
                }
            )

            # Update report fields
            report.cash_sales = shop_sales_data.get('cash', report.cash_sales)
            report.visa_sales = shop_sales_data.get('visa', report.visa_sales)
            report.alipay_sales = shop_sales_data.get('alipay', report.alipay_sales)
            report.wechat_sales = shop_sales_data.get('wechat', report.wechat_sales)
            report.master_sales = shop_sales_data.get('master', report.master_sales)
            report.unionpay_sales = shop_sales_data.get('unionpay', report.unionpay_sales)
            report.amex_sales = shop_sales_data.get('amex', report.amex_sales)
            report.octopus_sales = shop_sales_data.get('octopus', report.octopus_sales)

            report.deliveroo_sales = delivery_sales_data.get('deliveroo', report.deliveroo_sales)
            report.foodpanda_sales = delivery_sales_data.get('foodpanda', report.foodpanda_sales)
            report.keeta_sales = delivery_sales_data.get('keeta', report.keeta_sales)
            report.openrice_sales = delivery_sales_data.get('openrice', report.openrice_sales)

            # Delete old expenses and files before processing new expenses
            old_expenses = ShopExpense.query.filter_by(report_id=report.id).all()
            for expense in old_expenses:
                if expense.files:
                    delete_files_from_s3(expense.files.split(','))  # Delete files from S3

            db.session.query(ShopExpense).filter_by(report_id=report.id).delete(synchronize_session=False)

            total_expenses = 0
            index = 0

            if request.form.get('no_expense') != 'true':
                index = 0
                while f'shopExpenses[{index}][item]' in request.form:
                    item = request.form.get(f'shopExpenses[{index}][item]')
                    amount = safe_float(request.form.get(f'shopExpenses[{index}][amount]', 0))
                    remarks = request.form.get(f'shopExpenses[{index}][remarks]', '')

                    # Get existing files if no new files are uploaded
                    existing_files = request.form.get(f'existing_files[{index}]', '')
                    files = request.files.getlist(f'files[{index}][]')

                    # Initialize file_paths
                    file_paths = existing_files.split(',') if existing_files else []


                    if files and any(file.filename for file in files):  # If new files are uploaded
                        # Delete old files
                        if existing_files:
                            delete_files_from_s3(existing_files.split(','))

                        # Upload new files
                        file_paths = [upload_file_to_s3(file, str(uuid.uuid4())) for file in files if file]

                    # Add or update ShopExpense
                    db.session.add(ShopExpense(
                        report_id=report.id,
                        item=item,
                        amount=amount,
                        remarks=remarks,
                        files=','.join(file_paths)
                    ))

                    total_expenses += amount
                    index += 1


            report.expenses = total_expenses
            report.closing_balance = (report.opening_balance + report.cash_addition + report.cash_sales) - report.bank_deposit - report.expenses

            db.session.commit()
            app.logger.info(f"Updated report: {report.__dict__}")

            # Log the changes
            log_history(
                report_id=report.id,
                company=current_user.company,
                user_id=current_user.id,
                action="edited",
                field_changed="multiple_fields",
                old_value="Previous State",
                new_value="Updated State",
            )

            flash('Report updated successfully! 리포트 수정이 완료 됐습니다.', 'success')
            return redirect(url_for('report_detail', id=report.id))
        
        except ValueError as ve:
            app.logger.error(f"Validation error: {str(ve)}")
            flash(str(ve), 'danger')
            return redirect(url_for('edit_report', id=report.id))

        except Exception as e:
            app.logger.error(f"Unexpected error: {str(e)}")
            db.session.rollback()
            flash("An unexpected error occurred.", 'danger')


    # Prepare data for the template
    sales_data = {
        "shop_sales": {field.replace('_sales', ''): getattr(report, field, 0.0) for field in [
            'cash_sales', 'visa_sales', 'alipay_sales', 'wechat_sales',
            'master_sales', 'unionpay_sales', 'amex_sales', 'octopus_sales']},
        "delivery_sales": {field.replace('_sales', ''): getattr(report, field, 0.0) for field in [
            'deliveroo_sales', 'foodpanda_sales', 'keeta_sales', 'openrice_sales']}
    }

    return render_template('edit_report.html', report=report, sales_data=sales_data, expenses=report.expenses)


@app.route('/connect_xero')
def connect_xero():
    return 'Xero'
@app.route('/approve_report')
def approve_report():
    return 'Approve report'

@app.route('/report/delete/<string:id>', methods=['POST'])
@login_required
def delete_report(id):
    try:
        report = Report.query.get_or_404(id)

        # Update the `next_transaction_date` of the previous report
        prev_report = Report.query.filter(
            Report.company == report.company,
            Report.transaction_date < report.transaction_date
        ).order_by(Report.transaction_date.desc()).first()

        next_report = Report.query.filter(
            Report.company == report.company,
            Report.transaction_date > report.transaction_date
        ).order_by(Report.transaction_date.asc()).first()

        if prev_report:
            prev_report.next_transaction_date = next_report.transaction_date if next_report else None
            db.session.add(prev_report)

        # Delete associated files from S3
        if report.receipt_files:
            for file_key in report.receipt_files.split(','):
                try:
                    s3_client.delete_object(Bucket=S3_BUCKET, Key=file_key)
                except Exception as e:
                    app.logger.error(f"Failed to delete file {file_key} from S3: {e}")

        # Delete associated shop expenses
        ShopExpense.query.filter_by(report_id=report.id).delete()

        # Delete the report
        db.session.delete(report)
        db.session.commit()

        flash("Report deleted successfully.", "success")
        return redirect(url_for('index'))

    except Exception as e:
        app.logger.error(f"Error deleting report {id}: {e}")
        flash("Error deleting report. Please try again.", "danger")
        return redirect(url_for('report_detail', id=id))



@app.route('/download/<path:filename>', methods=['GET'])
@login_required
def download_file(filename):
    try:
        app.logger.info(f"Attempting to download file: {filename} from S3 bucket {S3_BUCKET}")
        s3_key = filename  # Assuming the filename stored in DB is the S3 key

        # Generate a pre-signed URL for the download
        download_url = s3_client.generate_presigned_url('get_object', Params={'Bucket': S3_BUCKET, 'Key': s3_key}, ExpiresIn=3600)
        return redirect(download_url)
    except Exception as e:
        app.logger.error(f"Error generating pre-signed URL: {e}")
        return jsonify({"status": "error", "message": str(e)}), 404


@app.route('/report/download/<string:id>', methods=['GET'])
@login_required
def download_report(id):
    try:
        # Fetch the report from the database
        report = Report.query.get_or_404(id)

        # Extract sales data
        shop_sales_data = {
            "cash": report.cash_sales,
            "visa": report.visa_sales,
            "alipay": report.alipay_sales,
            "wechat": report.wechat_sales,
            "master": report.master_sales,
            "unionpay": report.unionpay_sales,
            "amex": report.amex_sales,
            "octopus": report.octopus_sales,
        }

        delivery_sales_data = {
            "deliveroo": report.deliveroo_sales,
            "foodpanda": report.foodpanda_sales,
            "keeta": report.keeta_sales,
            "openrice": report.openrice_sales,
        }

        # Calculate total sales
        total_shop_sales = report.shop_sales  # Pre-calculated in the DB
        total_delivery_sales = report.delivery_sales  # Pre-calculated in the DB
        total_sales = report.total_sales  # Pre-calculated in the DB

        # Prepare data for the Excel file
        report_data = {
            'Date': [report.date.strftime('%Y-%m-%d')],
            'Transaction Date': [report.transaction_date.strftime('%Y-%m-%d')],
            'Opening Balance': [report.opening_balance],
            'Total Shop Sales': [total_shop_sales],
            'Total Delivery Sales': [total_delivery_sales],
            'Total Sales': [total_sales],
            'Cash Sales': [shop_sales_data.get('cash', 0)],
            'Visa Sales': [shop_sales_data.get('visa', 0)],
            'Alipay Sales': [shop_sales_data.get('alipay', 0)],
            'WeChat Sales': [shop_sales_data.get('wechat', 0)],
            'MasterCard Sales': [shop_sales_data.get('master', 0)],
            'UnionPay Sales': [shop_sales_data.get('unionpay', 0)],
            'Amex Sales': [shop_sales_data.get('amex', 0)],
            'Octopus Sales': [shop_sales_data.get('octopus', 0)],
            'Deliveroo Sales': [delivery_sales_data.get('deliveroo', 0)],
            'Foodpanda Sales': [delivery_sales_data.get('foodpanda', 0)],
            'Keeta Sales': [delivery_sales_data.get('keeta', 0)],
            'OpenRice Sales': [delivery_sales_data.get('openrice', 0)],
            'Expenses': [report.expenses],
            'Bank Deposit': [report.bank_deposit],
            'Closing Balance': [report.closing_balance],
            'Uploaded By': [report.uploaded_by]
        }

        # Convert the data to a pandas DataFrame
        df = pd.DataFrame(report_data)

        # Prepare the Excel file in memory
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Report')

        # Serve the Excel file as a download
        output.seek(0)
        response = make_response(output.read())
        response.headers['Content-Disposition'] = f'attachment; filename=report_{id}.xlsx'
        response.headers['Content-type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

        return response

    except Exception as e:
        app.logger.error(f"Error downloading report with id {id}: {e}")
        return jsonify({"status": "error", "message": "Error generating the Excel report"}), 500

@app.route('/admin/download_statements', methods=['GET', 'POST'])
@login_required
def download_statements():
    if request.method == 'GET':
        companies = db.session.query(Report.company).distinct().all()
        return render_template(
            'download_statements.html',
            companies=[c[0] for c in companies]
        )

    elif request.method == 'POST':
        try:
            # Input validation
            start_date = request.form.get('start_date')
            end_date = request.form.get('end_date')
            company = request.form.get('company')

            if not start_date or not end_date:
                return jsonify({"status": "error", "message": "Start date and end date are required."}), 400

            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
            except ValueError:
                return jsonify({"status": "error", "message": "Invalid date format. Use YYYY-MM-DD."}), 400

            # Query the database
            query = Report.query
            if company:
                query = query.filter(Report.company == company)
            query = query.filter(Report.transaction_date >= start_date)
            query = query.filter(Report.transaction_date <= end_date)

            reports = query.order_by(Report.transaction_date.asc()).all()
            if not reports:
                return jsonify({"status": "error", "message": "No reports found for the selected criteria."}), 404

            # Prepare data for Excel
            data_rows = []

            for report in reports:
                # Add cash sales
                data_rows.append({
                    'Transaction Date': report.transaction_date.strftime('%Y-%m-%d'),
                    'Company': report.company,
                    'Description': 'Cash Sales',
                    'Amount': report.cash_sales
                })

                # Add expenses (with negative amounts)
                for expense in report.shop_expenses:
                    data_rows.append({
                        'Transaction Date': report.transaction_date.strftime('%Y-%m-%d'),
                        'Company': report.company,
                        'Description': f'Expense: {expense.item}',
                        'Amount': -expense.amount
                    })

                # Add cash addition
                if report.cash_addition != 0:  # Include only if there's a non-zero cash addition
                    data_rows.append({
                        'Transaction Date': report.transaction_date.strftime('%Y-%m-%d'),
                        'Company': report.company,
                        'Description': 'Cash Addition',
                        'Amount': report.cash_addition
                    })

                # Add bank deposit (as a negative amount)
                if report.bank_deposit != 0:  # Include only if there's a non-zero bank deposit
                    data_rows.append({
                        'Transaction Date': report.transaction_date.strftime('%Y-%m-%d'),
                        'Company': report.company,
                        'Description': 'Bank Deposit',
                        'Amount': -report.bank_deposit
                    })

            # Generate Excel
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                pd.DataFrame(data_rows).to_excel(writer, index=False, sheet_name='Detailed Reports')
            output.seek(0)

            # Send the Excel file as a response
            response = make_response(output.read())
            response.headers['Content-Disposition'] = f'attachment; filename=statements_{datetime.now().strftime("%Y%m%d%H%M%S")}.xlsx'
            response.headers['Content-type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

            return response

        except Exception as e:
            app.logger.error(f"Error generating statements: {e}")
            return jsonify({"status": "error", "message": "An error occurred while generating the statements."}), 500
        
@app.route('/download_attachments', methods=['POST'])
@login_required
def download_attachments():
    try:
        # Retrieve form data
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        company = request.form.get('company')

        # Validate input
        if not start_date or not end_date:
            return jsonify({"status": "error", "message": "Start date and end date are required."}), 400

        # Convert dates to datetime objects
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid date format. Use YYYY-MM-DD."}), 400

        # Query the database for reports within the date range and company
        query = Report.query.filter(
            Report.transaction_date >= start_date,
            Report.transaction_date <= end_date
        )
        if company:
            query = query.filter(Report.company == company)

        reports = query.all()
        if not reports:
            return jsonify({"status": "error", "message": "No reports found for the selected criteria."}), 404

        # Create a ZIP file in memory
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for report in reports:
                # Use the transaction date as a subfolder name
                date_folder = report.transaction_date.strftime('%Y-%m-%d')
                for expense in report.shop_expenses:
                    if expense.files:
                        for file_path in expense.files.split(','):
                            # Fetch the file data from S3
                            file_data = download_file_from_s3(file_path)
                            if file_data:
                                # Create a path for the file inside the ZIP with the date as a subfolder
                                zip_file.writestr(f"{date_folder}/{os.path.basename(file_path)}", file_data)
                            else:
                                app.logger.warning(f"File {file_path} could not be fetched.")

        zip_buffer.seek(0)

        # Send the ZIP file as a response
        return send_file(
            zip_buffer,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f"attachments_{start_date}_{end_date}.zip"
        )

    except Exception as e:
        app.logger.error(f"Error generating attachments ZIP: {e}")
        return jsonify({"status": "error", "message": "An error occurred while generating the attachments ZIP."}), 500



if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False') == 'True'
    app.run(debug=debug_mode)
