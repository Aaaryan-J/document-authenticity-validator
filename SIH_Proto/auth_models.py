from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

# ==================== USER MANAGEMENT ====================
class User(db.Model):
    """User model for authentication"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # user, admin, institution
    institution_id = db.Column(db.Integer, db.ForeignKey('institution.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    institution = db.relationship('Institution', backref='users')

    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'institution_id': self.institution_id,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

# ==================== INSTITUTION MANAGEMENT ====================
class Institution(db.Model):
    """Model for educational institutions"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)
    address = db.Column(db.Text)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    website = db.Column(db.String(200))
    is_verified = db.Column(db.Boolean, default=False)  # Admin verification required
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'code': self.code,
            'address': self.address,
            'email': self.email,
            'phone': self.phone,
            'website': self.website,
            'is_verified': self.is_verified,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# ==================== BLACKLIST MANAGEMENT ====================
class BlacklistEntry(db.Model):
    """Model for blacklisted certificates/individuals"""
    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.String(100))
    name = db.Column(db.String(100))
    roll_no = db.Column(db.String(80))
    institution_name = db.Column(db.String(200))
    reason = db.Column(db.Text, nullable=False)
    evidence = db.Column(db.Text)  # Description of evidence
    reported_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    ip_address = db.Column(db.String(45))  # Track repeat offenders
    fraud_type = db.Column(db.String(50))  # 'fake_cert', 'data_manipulation', 'identity_theft'
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    reporter = db.relationship('User', backref='reported_frauds')
    
    def to_dict(self):
        return {
            'id': self.id,
            'certificate_id': self.certificate_id,
            'name': self.name,
            'roll_no': self.roll_no,
            'institution_name': self.institution_name,
            'reason': self.reason,
            'fraud_type': self.fraud_type,
            'severity': self.severity,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# ==================== EXTENDED MODELS ====================
class Certificate(db.Model):
    """Enhanced certificate model"""
    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.String(100), unique=True, nullable=False)
    roll_no = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    marks = db.Column(db.Integer, nullable=False)
    institution_id = db.Column(db.Integer, db.ForeignKey('institution.id'))
    course = db.Column(db.String(100))
    graduation_date = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_verified = db.Column(db.Boolean, default=True)
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # Track who added it
    
    # Relationships
    institution = db.relationship('Institution', backref='certificates')
    added_by_user = db.relationship('User', backref='added_certificates')

    def __repr__(self):
        return f"Certificate(id={self.certificate_id}, name={self.name})"
    
    def to_dict(self):
        return {
            'id': self.id,
            'certificate_id': self.certificate_id,
            'roll_no': self.roll_no,
            'name': self.name,
            'marks': self.marks,
            'institution_id': self.institution_id,
            'course': self.course,
            'graduation_date': self.graduation_date.isoformat() if self.graduation_date else None,
            'is_verified': self.is_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class VerificationLog(db.Model):
    """Enhanced verification log with fraud tracking"""
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    extracted_name = db.Column(db.String(100))
    extracted_roll = db.Column(db.String(80))
    extracted_marks = db.Column(db.Integer)
    extracted_cert_id = db.Column(db.String(100))
    is_valid = db.Column(db.Boolean)
    confidence_score = db.Column(db.Float)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    fraud_indicators = db.Column(db.Text)  # JSON string of detected issues
    risk_score = db.Column(db.Float, default=0.0)  # 0-100 fraud risk score
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'extracted_data': {
                'name': self.extracted_name,
                'roll_no': self.extracted_roll,
                'marks': self.extracted_marks,
                'certificate_id': self.extracted_cert_id
            },
            'is_valid': self.is_valid,
            'confidence_score': self.confidence_score,
            'risk_score': self.risk_score,
            'created_at': self.created_at.isoformat()
        }

class ForgeryTrend(db.Model):
    """Track forgery patterns and trends"""
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    fraud_attempts = db.Column(db.Integer, default=0)
    successful_frauds = db.Column(db.Integer, default=0)
    common_fraud_type = db.Column(db.String(50))
    high_risk_institutions = db.Column(db.Text)  # JSON list of institution names
    suspicious_ips = db.Column(db.Text)  # JSON list of IPs with multiple fraud attempts
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'date': self.date.isoformat(),
            'fraud_attempts': self.fraud_attempts,
            'successful_frauds': self.successful_frauds,
            'common_fraud_type': self.common_fraud_type,
            'created_at': self.created_at.isoformat()
        }

# ==================== BULK UPLOAD TRACKING ====================
class BulkUpload(db.Model):
    """Track bulk uploads from institutions"""
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    institution_id = db.Column(db.Integer, db.ForeignKey('institution.id'), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_records = db.Column(db.Integer, default=0)
    successful_records = db.Column(db.Integer, default=0)
    failed_records = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='processing')  # processing, completed, failed
    error_log = db.Column(db.Text)  # JSON string of errors
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    # Relationships
    institution = db.relationship('Institution', backref='bulk_uploads')
    uploader = db.relationship('User', backref='bulk_uploads')
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'institution_id': self.institution_id,
            'total_records': self.total_records,
            'successful_records': self.successful_records,
            'failed_records': self.failed_records,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }