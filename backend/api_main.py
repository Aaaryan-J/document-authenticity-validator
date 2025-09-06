from flask import Flask
from flask_restful import Api
from flask_cors import CORS
from flask_jwt_extended import JWTManager
import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import routes
from auth_routes import (
    Register, Login, Profile, InstitutionRegister, InstitutionList, InstitutionApproval,
    AdminRegister, CreateFirstAdmin, PromoteToAdmin
)
from admin_dashboard import (
    AdminDashboard, ForgeryTrends, BlacklistManagement,
    BlacklistEntry_API, VerificationHistory as AdminVerificationHistory,
    AdminStats
)
from institution_portal import (
    InstitutionDashboard, BulkCertificateUpload, SingleCertificateUpload,
    InstitutionCertificates, BulkUploadHistory, DownloadTemplate
)

# Import shared db + models
from auth_models import db, User, Institution, Certificate, VerificationLog

app = Flask(__name__)

# ==================== CONFIG ====================
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///certificates.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'fallback-key-change-this')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# ==================== EXTENSIONS ====================  
api = Api(app)
jwt = JWTManager(app)
CORS(app)
db.init_app(app)

# Create upload directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs("uploads/bulk", exist_ok=True)
os.makedirs("uploads/templates", exist_ok=True)

# ==================== REGISTER ROUTES ====================

# ---- Auth Routes ----
api.add_resource(Register, '/api/auth/register')
api.add_resource(Login, '/api/auth/login')
api.add_resource(Profile, '/api/auth/profile')
api.add_resource(InstitutionRegister, '/api/auth/institution/register')
api.add_resource(InstitutionList, '/api/auth/institutions')
api.add_resource(InstitutionApproval, '/api/auth/institutions/<int:institution_id>/approve')

# ---- Secure Admin Auth Routes ----
api.add_resource(AdminRegister, '/api/auth/register-admin')
api.add_resource(CreateFirstAdmin, '/api/auth/create-first-admin')
api.add_resource(PromoteToAdmin, '/api/auth/promote/<int:user_id>')

# ---- Admin Dashboard Routes ----
api.add_resource(AdminDashboard, '/api/admin/dashboard')
api.add_resource(ForgeryTrends, '/api/admin/trends')
api.add_resource(BlacklistManagement, '/api/admin/blacklist')
api.add_resource(BlacklistEntry_API, '/api/admin/blacklist/<int:entry_id>')
api.add_resource(AdminVerificationHistory, '/api/admin/history')
api.add_resource(AdminStats, '/api/admin/stats')

# ---- Institution Portal Routes ----
api.add_resource(InstitutionDashboard, '/api/institution/dashboard')
api.add_resource(BulkCertificateUpload, '/api/institution/upload/bulk')
api.add_resource(SingleCertificateUpload, '/api/institution/upload/single')
api.add_resource(InstitutionCertificates, '/api/institution/certificates')
api.add_resource(BulkUploadHistory, '/api/institution/uploads/history')
api.add_resource(DownloadTemplate, '/api/institution/template')

# ==================== HOME ====================
@app.route('/')
def home():
    return '''
    <h1>Certificate Verification System</h1>
    <h3>API Endpoints:</h3>
    <ul>
        <li><strong>Auth</strong>: /api/auth/*</li>
        <li><strong>Admin</strong>: /api/admin/*</li>
        <li><strong>Institution</strong>: /api/institution/*</li>
    </ul>
    <h3>Environment Status:</h3>
    <ul>
        <li>Admin Key Configured: {'✓' if os.environ.get('ADMIN_SECRET_KEY') else '✗'}</li>
        <li>JWT Key Configured: {'✓' if os.environ.get('JWT_SECRET_KEY') else '✗'}</li>
        <li>Database: {os.environ.get('DATABASE_URL', 'sqlite:///certificates.db')}</li>
    </ul>
    '''

# ==================== INIT DB ====================
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    # Security check
    if not os.environ.get('ADMIN_SECRET_KEY'):
        print("WARNING: ADMIN_SECRET_KEY not set! Admin registration will not work.")
    if not os.environ.get('JWT_SECRET_KEY'):
        print("WARNING: JWT_SECRET_KEY not set! Using fallback key (not secure).")
    
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)