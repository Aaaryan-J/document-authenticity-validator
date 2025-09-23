from flask import Flask, send_from_directory, request
from flask_restful import Api
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
import os
from datetime import timedelta
from user_routes import CertificateUpload

# ===== Import routes =====
from auth_routes import Register, Login, Profile, InstitutionRegister, InstitutionList, InstitutionApproval
from admin_dashboard import (
    AdminDashboard, ForgeryTrends, BlacklistManagement,
    BlacklistEntry_API, VerificationHistory as AdminVerificationHistory,
    AdminStats
)
from institution_portal import (
    InstitutionDashboard, BulkCertificateUpload, SingleCertificateUpload,
    InstitutionCertificates, BulkUploadHistory, DownloadTemplate
)
from auth_models import db
from ocr_service import extract_marksheet_details

# ==================== CONFIG ====================
app = Flask(__name__, static_folder="static")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///certificates.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['JWT_SECRET_KEY'] = 'your-jwt-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# ==================== EXTENSIONS ====================
api = Api(app)
jwt = JWTManager(app)
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)
db.init_app(app)

# ==================== CREATE UPLOAD FOLDERS ====================
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs("uploads/bulk", exist_ok=True)
os.makedirs("uploads/templates", exist_ok=True)

# ==================== REGISTER ROUTES ====================

# ---- Auth ----
api.add_resource(Register, '/api/auth/register')
api.add_resource(Login, '/api/auth/login')
api.add_resource(Profile, '/api/auth/profile')
api.add_resource(InstitutionRegister, '/api/auth/institution/register')
api.add_resource(InstitutionList, '/api/auth/institutions')
api.add_resource(InstitutionApproval, '/api/auth/institutions/<int:institution_id>/approve')

# ---- Admin ----
api.add_resource(AdminDashboard, '/api/admin/dashboard')
api.add_resource(ForgeryTrends, '/api/admin/trends')
api.add_resource(BlacklistManagement, '/api/admin/blacklist')
api.add_resource(BlacklistEntry_API, '/api/admin/blacklist/<int:entry_id>')
api.add_resource(AdminVerificationHistory, '/api/admin/history')
api.add_resource(AdminStats, '/api/admin/stats')

# ---- Institution ----
api.add_resource(InstitutionDashboard, '/api/institution/dashboard')
api.add_resource(BulkCertificateUpload, '/api/institution/upload/bulk')
api.add_resource(SingleCertificateUpload, '/api/institution/upload/single')
api.add_resource(InstitutionCertificates, '/api/institution/certificates')
api.add_resource(BulkUploadHistory, '/api/institution/uploads/history')
api.add_resource(DownloadTemplate, '/api/institution/template')

# ---- User Upload ----
api.add_resource(CertificateUpload, '/api/upload')

# ==================== DOWNLOADS ====================
@app.route('/download/template/<filename>')
def download_template_file(filename):
    return send_from_directory("uploads/templates", filename, as_attachment=True)

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
        <li><strong>Upload</strong>: /api/upload</li>
    </ul>
    '''

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/<path:filename>")
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

# ==================== INIT DB ====================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
