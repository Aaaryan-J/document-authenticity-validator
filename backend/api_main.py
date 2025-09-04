from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy 
from flask_restful import Resource, Api, reqparse, marshal_with, abort, fields
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
from datetime import datetime

# Import your team's OCR module (they'll provide this)
# from ocr_module import extract_certificate_data  # Your team will create this

app = Flask(__name__)

# Basic Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///certificates.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize extensions
db = SQLAlchemy(app)
api = Api(app)
CORS(app)  # Allow frontend to connect

# Create upload directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ==================== DATABASE MODELS ====================
class Certificate(db.Model):
    """Simple certificate model with the 4 fields"""
    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.String(100), unique=True, nullable=False)
    roll_no = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    marks = db.Column(db.Integer, nullable=False)
    # Extra fields for tracking
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_verified = db.Column(db.Boolean, default=True)  # True = real certificate in DB

    def __repr__(self):
        return f"Certificate(id={self.certificate_id}, name={self.name})"

class VerificationLog(db.Model):
    """Track all verification attempts"""
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    extracted_name = db.Column(db.String(100))
    extracted_roll = db.Column(db.String(80))
    extracted_marks = db.Column(db.Integer)
    extracted_cert_id = db.Column(db.String(100))
    is_valid = db.Column(db.Boolean)  # True = found match in DB
    confidence_score = db.Column(db.Float)  # OCR confidence
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==================== REQUEST PARSERS ====================
certificate_parser = reqparse.RequestParser()
certificate_parser.add_argument('certificate_id', type=str, required=True, help="Certificate ID required")
certificate_parser.add_argument('name', type=str, required=True, help="Name required")
certificate_parser.add_argument('roll_no', type=str, required=True, help="Roll number required")
certificate_parser.add_argument('marks', type=int, required=True, help="Marks required")

# ==================== RESPONSE FORMATS ====================
certificate_fields = {
    'id': fields.Integer,
    'certificate_id': fields.String,
    'roll_no': fields.String,
    'name': fields.String,
    'marks': fields.Integer,
    'is_verified': fields.Boolean,
    'created_at': fields.DateTime
}

# ==================== HELPER FUNCTIONS ====================
def allowed_file(filename):
    """Check if uploaded file type is allowed"""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_certificate(extracted_data):
    """Check if extracted data matches any certificate in database"""
    try:
        cert_id = extracted_data.get('certificate_id')
        name = extracted_data.get('name')
        roll_no = extracted_data.get('roll_no')
        marks = extracted_data.get('marks')
        
        # Search database for exact match
        certificate = Certificate.query.filter_by(
            certificate_id=cert_id,
            name=name,
            roll_no=roll_no,
            marks=marks
        ).first()
        
        if certificate:
            return {
                'is_valid': True,
                'message': 'Certificate is AUTHENTIC',
                'confidence': extracted_data.get('confidence', 0),
                'matched_certificate': certificate.id
            }
        else:
            # Check for partial matches to give better error messages
            partial_match = Certificate.query.filter_by(certificate_id=cert_id).first()
            if partial_match:
                return {
                    'is_valid': False,
                    'message': 'Certificate ID exists but other details do not match',
                    'confidence': extracted_data.get('confidence', 0),
                    'issues': 'Data mismatch detected'
                }
            else:
                return {
                    'is_valid': False,
                    'message': 'Certificate NOT FOUND in database',
                    'confidence': extracted_data.get('confidence', 0),
                    'issues': 'Certificate ID not in database'
                }
                
    except Exception as e:
        return {
            'is_valid': False,
            'message': f'Validation error: {str(e)}',
            'confidence': 0
        }

# ==================== API ENDPOINTS ====================

class CertificateList(Resource):
    """Handle certificate CRUD operations"""
    
    @marshal_with(certificate_fields)
    def get(self):
        """Get all certificates in database"""
        certificates = Certificate.query.all()
        return certificates, 200
    
    @marshal_with(certificate_fields)
    def post(self):
        """Add new certificate to database (for institutions)"""
        args = certificate_parser.parse_args()
        
        # Check if certificate already exists
        existing = Certificate.query.filter_by(certificate_id=args["certificate_id"]).first()
        if existing:
            abort(409, message="Certificate with this ID already exists")
        
        # Create new certificate
        certificate = Certificate(
            certificate_id=args["certificate_id"],
            name=args["name"],
            roll_no=args["roll_no"],
            marks=args["marks"],
            is_verified=True
        )
        
        db.session.add(certificate)
        db.session.commit()
        return certificate, 201

class CertificateDetail(Resource):
    """Handle individual certificate operations"""
    
    @marshal_with(certificate_fields)
    def get(self, certificate_id):
        """Get specific certificate"""
        certificate = Certificate.query.filter_by(certificate_id=certificate_id).first()
        if not certificate:
            abort(404, message="Certificate not found")
        return certificate, 200

class VerifyUpload(Resource):
    """Handle certificate upload and verification - MAIN FEATURE"""
    
    def post(self):
        """Upload certificate image/PDF and verify authenticity"""
        try:
            # Check if file was uploaded
            if 'file' not in request.files:
                return {'error': 'No file uploaded'}, 400
            
            file = request.files['file']
            if file.filename == '':
                return {'error': 'No file selected'}, 400
            
            # Validate file type
            if not allowed_file(file.filename):
                return {'error': 'File type not allowed. Use PNG, JPG, JPEG, or PDF'}, 400
            
            # Save uploaded file
            filename = secure_filename(file.filename)
            # Add timestamp to avoid conflicts
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_")
            filename = timestamp + filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # ========== INTEGRATE YOUR TEAM'S OCR HERE ==========
            # This is where your team's OCR code will be called
            # Replace this mock function with their actual implementation
            
            # Mock OCR extraction (replace with actual OCR module)
            extracted_data = mock_ocr_extraction(filepath)
            
            # For now, using mock data. Your team will provide:
            # from ocr_module import extract_certificate_data
            # extracted_data = extract_certificate_data(filepath)
            
            # Validate against database
            validation_result = validate_certificate(extracted_data)
            
            # Log the verification attempt
            log_entry = VerificationLog(
                filename=filename,
                extracted_name=extracted_data.get('name'),
                extracted_roll=extracted_data.get('roll_no'),
                extracted_marks=extracted_data.get('marks'),
                extracted_cert_id=extracted_data.get('certificate_id'),
                is_valid=validation_result['is_valid'],
                confidence_score=extracted_data.get('confidence', 0)
            )
            db.session.add(log_entry)
            db.session.commit()
            
            # Return verification result
            return {
                'verification_result': validation_result,
                'extracted_data': extracted_data,
                'log_id': log_entry.id
            }, 200
            
        except Exception as e:
            return {'error': f'Verification failed: {str(e)}'}, 500

class VerificationHistory(Resource):
    """Get verification history for admin dashboard"""
    #TODO: also return forgery trends and the ability to blacklist offenders 

    def get(self):
        """Get all verification attempts"""
        logs = VerificationLog.query.order_by(VerificationLog.created_at.desc()).all()
        
        history = []
        for log in logs:
            history.append({
                'id': log.id,
                'filename': log.filename,
                'extracted_data': {
                    'name': log.extracted_name,
                    'roll_no': log.extracted_roll,
                    'marks': log.extracted_marks,
                    'certificate_id': log.extracted_cert_id
                },
                'is_valid': log.is_valid,
                'confidence_score': log.confidence_score,
                'created_at': log.created_at.isoformat()
            })
        
        return {'verification_history': history}, 200

# ==================== MOCK FUNCTIONS (REPLACE WITH REAL OCR) ====================
def mock_ocr_extraction(filepath):
    """Mock OCR function - replace with your team's actual OCR code"""
    # This is just for testing - your team will replace this
    return {
        'certificate_id': 'CERT001',
        'name': 'John Doe',
        'roll_no': 'ROLL123',
        'marks': 85,
        'confidence': 92.5
    }

# ==================== REGISTER ROUTES ====================
api.add_resource(CertificateList, '/api/certificates')
api.add_resource(CertificateDetail, '/api/certificates/<string:certificate_id>')
api.add_resource(VerifyUpload, '/api/verify')  # Main verification endpoint
api.add_resource(VerificationHistory, '/api/admin/history')

# ==================== HOME PAGE ====================
@app.route('/')
def home():
    return '''
    <h1>Certificate Verification System</h1>
    <h3>API Endpoints:</h3>
    <ul>
        <li><strong>POST /api/verify</strong> - Upload and verify certificate (main feature)</li>
        <li>GET /api/certificates - List all valid certificates</li>
        <li>POST /api/certificates - Add new certificate to database</li>
        <li>GET /api/certificates/&lt;id&gt; - Get specific certificate</li>
        <li>GET /api/admin/history - View verification history</li>
    </ul>
    '''

# ==================== DATABASE INITIALIZATION ====================
@app.before_request
def create_tables():
    db.create_all()
    
    # Add some sample certificates for testing
    if Certificate.query.count() == 0:
        sample_certs = [
            Certificate(certificate_id='CERT001', name='John Doe', roll_no='ROLL123', marks=85),
            Certificate(certificate_id='CERT002', name='Jane Smith', roll_no='ROLL124', marks=92),
            Certificate(certificate_id='CERT003', name='Bob Johnson', roll_no='ROLL125', marks=78)
        ]
        
        for cert in sample_certs:
            db.session.add(cert)
        
        db.session.commit()
        print("Sample certificates added to database")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)