import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, DateTimeField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
import string
import random
from flask_bcrypt import Bcrypt
from sqlalchemy import or_, inspect, text, case
from werkzeug.utils import secure_filename

# TF-IDF Algorithm for Item Matching (Advanced Data Structure: Sparse Matrix)
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-for-development')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///lostnfound.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Context processors
@app.context_processor
def inject_globals():
    return {
        'current_year': datetime.now().year,
        'isu_landmarks': [loc[0] for loc in ISU_LANDMARKS if loc[0] and loc[0] != 'other']
    }

# Models
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'user' or 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    reports = db.relationship('ItemReport', backref='reporter', lazy=True)
    claim_requests = db.relationship('ClaimRequest', backref='claimer', lazy=True)
    
    def __repr__(self):
        return f"User('{self.name}', '{self.email}', '{self.role}')"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class ItemReport(db.Model):
    __tablename__ = 'item_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(10), nullable=False)  # 'lost' or 'found'
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    date_time = db.Column(db.DateTime, nullable=False)
    photo_filename = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'claimed', 'completed'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # For found items - where they should be turned in
    dropoff_location = db.Column(db.String(200), default="SCC OFFICE")
    dropoff_confirmed = db.Column(db.Boolean, default=False)
    dropoff_date = db.Column(db.DateTime, nullable=True)
    
    # Explicitly specify which foreign key to use for this relationship
    claim_requests = db.relationship('ClaimRequest', 
                                    foreign_keys='ClaimRequest.report_id',
                                    backref='report', lazy=True)
    
    # Add relationship for when this is a lost report matched with a found item
    matched_claims = db.relationship('ClaimRequest',
                                   foreign_keys='ClaimRequest.lost_report_id',
                                   backref='lost_report', lazy=True)
    
    def __repr__(self):
        return f"ItemReport('{self.type}', '{self.title}', '{self.status}')"

class ClaimRequest(db.Model):
    __tablename__ = 'claim_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('item_reports.id'), nullable=False)
    claimer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    lost_report_id = db.Column(db.Integer, db.ForeignKey('item_reports.id'), nullable=True)  # Associated lost report ID
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'accepted', 'rejected', 'completed'
    admin_comment = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # New fields for enhanced claiming process
    pickup_location = db.Column(db.String(200), default="SCC OFFICE", nullable=True)
    pickup_instructions = db.Column(db.Text, nullable=True)
    pickup_contact = db.Column(db.String(100), nullable=True)
    claim_code = db.Column(db.String(20), nullable=True)
    pickup_date = db.Column(db.DateTime, nullable=True)  # When actually picked up
    pickup_confirmed = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f"ClaimRequest(Report: {self.report_id}, Claimer: {self.claimer_id}, Status: {self.status})"

# ISU Cauayan Campus Landmarks
ISU_LANDMARKS = [
    ('', 'Select a location...'),
    ('Main Gate / Entrance Arch', 'Main Gate / Entrance Arch'),
    ('Administration Building', 'Administration Building'),
    ('ICT / CCSICT Building', 'ICT / CCSICT Building'),
    ('Polytechnic / Technology Building', 'Polytechnic / Technology Building'),
    ('Education Building', 'Education Building'),
    ('Criminology Building', 'Criminology Building'),
    ('Campus Library', 'Campus Library'),
    ('Mini-Museum', 'Mini-Museum'),
    ('Multipurpose Hall / Gymnasium', 'Multipurpose Hall / Gymnasium'),
    ('Student Plaza / Open Grounds', 'Student Plaza / Open Grounds'),
    ('ISU Oval / Track & Open Field', 'ISU Oval / Track & Open Field'),
    ('Dormitories / Student Housing', 'Dormitories / Student Housing'),
    ('Canteen / Food Court Area', 'Canteen / Food Court Area'),
    ('Health Services / Clinic', 'Health Services / Clinic'),
    ('Registrar\'s Office', 'Registrar\'s Office'),
    ('Research & Extension Building', 'Research & Extension Building'),
    ('SCC Office', 'SCC Office'),
    ('other', '-- Other (Specify below) --'),
]

def generate_claim_code():
    """Generate a unique 8-character claim code"""
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=8))

# Forms
class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ItemReportForm(FlaskForm):
    title = StringField('Item Name', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(min=10, max=1000)])
    location = SelectField('Location', choices=ISU_LANDMARKS, validators=[DataRequired()])
    custom_location = StringField('Custom Location', validators=[Optional(), Length(max=100)])
    date_time = DateTimeField('Date & Time', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    photo = FileField('Upload Photo (Optional)', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField('Submit Report')
    
    def validate_custom_location(self, custom_location):
        if self.location.data == 'other' and not custom_location.data:
            raise ValidationError('Please specify the location when selecting "Other".')

class ClaimRequestForm(FlaskForm):
    message = TextAreaField('Your Claim Message', validators=[DataRequired(), Length(min=10, max=500)])
    submit = SubmitField('Submit Claim')

# Helper functions
def save_picture(form_photo):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_photo.filename)
    picture_filename = random_hex + f_ext
    picture_path = os.path.join(app.config['UPLOAD_FOLDER'], picture_filename)
    form_photo.save(picture_path)
    return picture_filename

# Routes - Authentication
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(name=form.name.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page if next_page else url_for('index'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Routes - Main
@app.route('/')
def index():
    # Get most recent approved reports
    reports = ItemReport.query.filter_by(status='approved').order_by(ItemReport.created_at.desc()).limit(10).all()
    return render_template('index.html', reports=reports)

@app.route('/search')
def search():
    # Get search parameters
    item_type = request.args.get('type', '')
    query = request.args.get('q', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    lost_id = request.args.get('lost_id', '')  # ID of the lost item to match with
    
    # Base query: only approved reports
    reports_query = ItemReport.query.filter_by(status='approved')
    
    # Apply filters if provided
    if item_type and item_type in ['lost', 'found']:
        reports_query = reports_query.filter_by(type=item_type)
    
    if query:
        reports_query = reports_query.filter(
            or_(
                ItemReport.title.ilike(f'%{query}%'),
                ItemReport.description.ilike(f'%{query}%'),
                ItemReport.location.ilike(f'%{query}%')
            )
        )
    
    # Apply date filters if provided
    if start_date:
        reports_query = reports_query.filter(ItemReport.date_time >= start_date)
    if end_date:
        reports_query = reports_query.filter(ItemReport.date_time <= end_date)
    
    # Order by most recent
    reports = reports_query.order_by(ItemReport.created_at.desc()).all()
    
    # Get the lost item if matching
    lost_item = None
    if lost_id and current_user.is_authenticated:
        lost_item = ItemReport.query.filter_by(
            id=lost_id, 
            reporter_id=current_user.id,
            type='lost',
            status='approved'
        ).first()
    
    return render_template('search.html', 
                          reports=reports, 
                          query=query, 
                          item_type=item_type, 
                          lost_item=lost_item)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    # Admin should use admin panel instead
    if current_user.role == 'admin':
        return redirect(url_for('admin_stats'))
    
    # Get user's reports separated by type
    lost_reports = ItemReport.query.filter_by(reporter_id=current_user.id, type='lost').order_by(ItemReport.created_at.desc()).all()
    found_reports = ItemReport.query.filter_by(reporter_id=current_user.id, type='found').order_by(ItemReport.created_at.desc()).all()
    
    # Get user's claim requests separated by status
    pending_claims = ClaimRequest.query.filter_by(claimer_id=current_user.id, status='pending').order_by(ClaimRequest.request_date.desc()).all()
    approved_claims = ClaimRequest.query.filter_by(claimer_id=current_user.id, status='accepted').order_by(ClaimRequest.request_date.desc()).all()
    
    # Get found items that need to be surrendered (claimed status)
    items_to_surrender = ItemReport.query.filter_by(
        reporter_id=current_user.id, 
        type='found', 
        status='claimed'
    ).all()
    
    # Get approved claims that haven't been picked up yet (for showing claim codes)
    claims_to_pickup = ClaimRequest.query.filter_by(
        claimer_id=current_user.id, 
        status='accepted',
        pickup_confirmed=False
    ).all()
    
    return render_template('dashboard.html', 
                          lost_reports=lost_reports, 
                          found_reports=found_reports,
                          pending_claims=pending_claims,
                          approved_claims=approved_claims,
                          items_to_surrender=items_to_surrender,
                          claims_to_pickup=claims_to_pickup)

# Routes - Reports
@app.route('/report/new', methods=['GET', 'POST'])
@login_required
def new_report():
    # Admin should not be able to create reports
    if current_user.role == 'admin':
        flash('Admin accounts cannot create reports. Please use a regular user account.', 'warning')
        return redirect(url_for('admin_stats'))
    
    form = ItemReportForm()
    
    # Get report type from the URL parameter
    report_type = request.args.get('type', 'lost')
    if report_type not in ['lost', 'found']:
        report_type = 'lost'  # Default to 'lost' if invalid type
    
    if form.validate_on_submit():
        # Handle location - use custom location if "other" is selected
        if form.location.data == 'other':
            location = form.custom_location.data if form.custom_location.data else 'Unknown Location'
        else:
            location = form.location.data
        
        report = ItemReport(
            reporter_id=current_user.id,
            type=report_type,
            title=form.title.data,
            description=form.description.data,
            location=location,
            date_time=form.date_time.data,
            status='approved'  # Auto-approve reports (no admin review needed)
        )
        
        # Save photo if provided
        if form.photo.data:
            photo_filename = save_picture(form.photo.data)
            report.photo_filename = photo_filename
        
        db.session.add(report)
        db.session.commit()
        
        flash(f'Your {report_type} item report has been submitted successfully!', 'success')
        return redirect(url_for('user_dashboard'))
    
    return render_template('new_report.html', title=f'Report {report_type.capitalize()} Item', form=form, report_type=report_type)

@app.route('/report/<int:report_id>')
def report_detail(report_id):
    report = ItemReport.query.get_or_404(report_id)
    
    # Check if current user has already submitted a claim for this report
    user_claim = None
    can_claim = False
    
    if current_user.is_authenticated:
        user_claim = ClaimRequest.query.filter_by(report_id=report.id, claimer_id=current_user.id).first()
    
    # Determine if user can view this report
    can_view = False
    
    # Public: approved and claimed reports can be viewed by anyone
    if report.status in ['approved', 'claimed']:
        can_view = True
    
    # Authenticated users can view:
    if current_user.is_authenticated:
        # Their own reports (any status)
        if current_user.id == report.reporter_id:
            can_view = True
        # Reports they have claimed
        if user_claim:
            can_view = True
        # Admins can view everything
        if current_user.role == 'admin':
            can_view = True
    
    if not can_view:
        abort(403)
    
    # User can claim if:
    # 1. It's a found item report (user is claiming they lost it)
    # 2. User is not the reporter
    # 3. Report is approved (not pending or already claimed)
    # 4. User hasn't claimed it yet
    if current_user.is_authenticated:
        can_claim = (report.type == 'found' and 
                    current_user.id != report.reporter_id and 
                    report.status == 'approved' and 
                    user_claim is None)
    
    return render_template('report_detail.html', report=report, user_claim=user_claim, can_claim=can_claim)

@app.route('/claim/<int:report_id>/new', methods=['GET', 'POST'])
@login_required
def new_claim(report_id):
    # Admin should not be able to claim items
    if current_user.role == 'admin':
        flash('Admin accounts cannot claim items. Please use a regular user account.', 'warning')
        return redirect(url_for('admin_stats'))
    
    report = ItemReport.query.get_or_404(report_id)
    
    # Verify the report can be claimed
    if report.status != 'approved' or report.type != 'found' or current_user.id == report.reporter_id:
        abort(403)
    
    # Check if user already submitted a claim
    existing_claim = ClaimRequest.query.filter_by(report_id=report.id, claimer_id=current_user.id).first()
    if existing_claim:
        flash('You have already submitted a claim for this item.', 'warning')
        return redirect(url_for('report_detail', report_id=report.id))
    
    # Get user's lost reports for matching
    user_lost_reports = ItemReport.query.filter_by(
        reporter_id=current_user.id, 
        type='lost',
        status='approved'
    ).order_by(ItemReport.created_at.desc()).all()
    
    form = ClaimRequestForm()
    if form.validate_on_submit():
        # Get the selected lost report ID if provided
        lost_report_id = request.form.get('lost_report_id')
        
        claim = ClaimRequest(
            report_id=report.id,
            claimer_id=current_user.id,
            message=form.message.data,
            lost_report_id=lost_report_id if lost_report_id else None
        )
        db.session.add(claim)
        db.session.commit()
        
        flash('Your claim request has been submitted and is awaiting review.', 'success')
        return redirect(url_for('report_detail', report_id=report.id))
    
    return render_template('new_claim.html', title='Submit Claim', form=form, report=report, lost_reports=user_lost_reports)

# New route for direct matching of lost and found items
@app.route('/match/<int:lost_id>/<int:found_id>', methods=['GET', 'POST'])
@login_required
def match_items(lost_id, found_id):
    # Admin should not be able to match items
    if current_user.role == 'admin':
        flash('Admin accounts cannot match items. Please use a regular user account.', 'warning')
        return redirect(url_for('admin_stats'))
    
    lost_report = ItemReport.query.get_or_404(lost_id)
    found_report = ItemReport.query.get_or_404(found_id)
    
    # Verify permissions and report types
    if (lost_report.reporter_id != current_user.id or
        lost_report.type != 'lost' or
        found_report.type != 'found' or
        lost_report.status != 'approved' or
        found_report.status != 'approved'):
        abort(403)
    
    # Check if there's already a claim
    existing_claim = ClaimRequest.query.filter_by(
        report_id=found_report.id, 
        claimer_id=current_user.id
    ).first()
    
    if existing_claim:
        flash('You already have a pending claim for this found item.', 'warning')
        return redirect(url_for('user_dashboard'))
    
    if request.method == 'POST':
        message = request.form.get('message', 'This is my lost item.')
        
        # Create a new claim request that links the lost and found items
        claim = ClaimRequest(
            report_id=found_report.id,
            claimer_id=current_user.id,
            message=message,
            lost_report_id=lost_report.id
        )
        db.session.add(claim)
        db.session.commit()
        
        flash('Your match request has been submitted and is awaiting review.', 'success')
        return redirect(url_for('user_dashboard'))
    
    return render_template('match_items.html', lost_report=lost_report, found_report=found_report)

# Routes - Admin

@app.route('/admin/claims')
@login_required
def admin_claims():
    # Check if user is admin
    if current_user.role != 'admin':
        abort(403)
    
    # Get pending claims
    pending_claims = ClaimRequest.query.filter_by(status='pending').order_by(ClaimRequest.request_date.desc()).all()
    
    return render_template('admin/claims.html', claims=pending_claims)

@app.route('/admin/claim/<int:claim_id>/approve', methods=['POST'])
@login_required
def approve_claim(claim_id):
    # Check if user is admin
    if current_user.role != 'admin':
        abort(403)
    
    claim = ClaimRequest.query.get_or_404(claim_id)
    claim.status = 'accepted'
    
    # Generate a unique claim code for verification
    claim.claim_code = generate_claim_code()
    
    # Save pickup details
    claim.pickup_location = request.form.get('pickup_location', 'SCC OFFICE')
    claim.pickup_contact = request.form.get('pickup_contact', 'SCC Staff')
    claim.pickup_instructions = request.form.get('pickup_instructions', 
        'Office hours: 8:00 AM - 5:00 PM, Monday to Friday. Please bring your student ID and show your claim code for verification.')
    
    # Mark the found report as claimed
    found_report = claim.report
    found_report.status = 'claimed'
    
    # If this claim is linked to a lost report, mark that as claimed too
    if claim.lost_report_id:
        lost_report = ItemReport.query.get(claim.lost_report_id)
        if lost_report:
            lost_report.status = 'claimed'
    
    db.session.commit()
    
    flash(f'Claim has been approved! Claim Code: {claim.claim_code}. The finder will be notified to surrender the item to {claim.pickup_location}.', 'success')
    return redirect(url_for('admin_claims'))

@app.route('/admin/claim/<int:claim_id>/reject', methods=['POST'])
@login_required
def reject_claim(claim_id):
    # Check if user is admin
    if current_user.role != 'admin':
        abort(403)
    
    claim = ClaimRequest.query.get_or_404(claim_id)
    claim.status = 'rejected'
    claim.admin_comment = request.form.get('reason', '')
    db.session.commit()
    
    flash('Claim has been rejected.', 'success')
    return redirect(url_for('admin_claims'))

@app.route('/admin/stats')
@login_required
def admin_stats():
    # Check if user is admin
    if current_user.role != 'admin':
        abort(403)
    
    # ============================================
    # BASIC STATISTICS
    # ============================================
    total_users = User.query.count()
    total_reports = ItemReport.query.count()
    total_lost = ItemReport.query.filter_by(type='lost').count()
    total_found = ItemReport.query.filter_by(type='found').count()
    total_claimed = ClaimRequest.query.filter_by(status='accepted').count()
    
    # Pending claims needing attention
    pending_claims = ClaimRequest.query.filter_by(status='pending').count()
    
    # Recovery rate calculation
    recovery_rate = 0
    if total_found > 0:
        recovery_rate = round((total_claimed / total_found) * 100, 1)
    
    # ============================================
    # TOP LOCATIONS ANALYSIS
    # ============================================
    top_locations = db.session.query(
        ItemReport.location,
        db.func.count(ItemReport.id).label('total'),
        db.func.sum(case((ItemReport.type == 'lost', 1), else_=0)).label('lost_count'),
        db.func.sum(case((ItemReport.type == 'found', 1), else_=0)).label('found_count')
    ).group_by(ItemReport.location).order_by(db.text('total DESC')).limit(8).all()
    
    # ============================================
    # RECENT ACTIVITY (Last 7 days)
    # ============================================
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    recent_reports = ItemReport.query.filter(ItemReport.created_at >= seven_days_ago).count()
    recent_claims = ClaimRequest.query.filter(ClaimRequest.request_date >= seven_days_ago).count()
    
    # ============================================
    # TF-IDF COSINE SIMILARITY ALGORITHM
    # Advanced Data Structure: Sparse Matrix (CSR)
    # Finding potential matches between lost and found items
    # ============================================
    potential_matches = []
    
    # Get approved lost and found items
    lost_items = ItemReport.query.filter_by(type='lost', status='approved').all()
    found_items = ItemReport.query.filter_by(type='found', status='approved').all()
    
    if lost_items and found_items:
        try:
            # Combine title, description, and location for better matching
            lost_texts = [f"{item.title} {item.description} {item.location}" for item in lost_items]
            found_texts = [f"{item.title} {item.description} {item.location}" for item in found_items]
            
            # TF-IDF Vectorizer creates a sparse matrix (Compressed Sparse Row format)
            # This is an advanced data structure for efficient storage and computation
            vectorizer = TfidfVectorizer(
                stop_words='english',
                ngram_range=(1, 2),
                max_features=500,
                min_df=1
            )
            
            # Fit and transform all texts into TF-IDF sparse matrix
            all_texts = lost_texts + found_texts
            tfidf_matrix = vectorizer.fit_transform(all_texts)
            
            # Split matrix back into lost and found
            lost_tfidf = tfidf_matrix[:len(lost_texts)]
            found_tfidf = tfidf_matrix[len(lost_texts):]
            
            # Calculate Cosine Similarity between all lost and found items
            similarity_matrix = cosine_similarity(lost_tfidf, found_tfidf)
            
            # Find matches with similarity > 15%
            for i, lost_item in enumerate(lost_items):
                for j, found_item in enumerate(found_items):
                    score = similarity_matrix[i][j]
                    if score > 0.15:
                        # Calculate location bonus (same location = higher match)
                        location_bonus = 0.1 if lost_item.location == found_item.location else 0
                        final_score = min((score + location_bonus) * 100, 100)
                        
                        potential_matches.append({
                            'lost_item': lost_item,
                            'found_item': found_item,
                            'score': round(final_score, 1),
                            'same_location': lost_item.location == found_item.location
                        })
            
            # Sort by score descending and take top 10
            potential_matches.sort(key=lambda x: x['score'], reverse=True)
            potential_matches = potential_matches[:10]
            
        except Exception as e:
            # If TF-IDF fails, continue without matches
            print(f"TF-IDF Error: {e}")
            potential_matches = []
    
    return render_template(
        'admin/stats.html',
        # Basic Stats
        total_users=total_users,
        total_reports=total_reports,
        total_lost=total_lost,
        total_found=total_found,
        total_claimed=total_claimed,
        pending_claims=pending_claims,
        recovery_rate=recovery_rate,
        # Location Analysis
        top_locations=top_locations,
        # Recent Activity
        recent_reports=recent_reports,
        recent_claims=recent_claims,
        # AI Matching
        potential_matches=potential_matches
    )

# Database initialization function
def init_db():
    """Initialize database tables and create default admin user"""
    db.create_all()
    
    # Check for schema updates by inspecting tables
    inspector = inspect(db.engine)
    
    # Check if lost_report_id column exists in claim_requests table
    try:
        columns = [column['name'] for column in inspector.get_columns('claim_requests')]
        if 'lost_report_id' not in columns:
            print("Database schema needs updating but SQLite doesn't support adding foreign key constraints.")
            print("To apply the new schema, it's recommended to:")
            print("1. Backup your database")
            print("2. Delete the database file (lostnfound.db)")
            print("3. Restart the application to recreate the database with the new schema")
            print("The application will continue to run, but matching functionality might be limited.")
    except Exception:
        pass  # Table doesn't exist yet, will be created
    
    # Create admin user if no users exist
    if not User.query.first():
        hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
        admin = User(name='Admin', email='admin@isu.edu', password_hash=hashed_password, role='admin')
        db.session.add(admin)
        db.session.commit()
        print("Default admin user created: admin@isu.edu / admin123")

# Initialize database on app startup (works with Gunicorn)
with app.app_context():
    init_db()

# Run the app (only for local development)
if __name__ == '__main__':
    app.run(debug=True) 