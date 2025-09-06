from flask import request, jsonify
from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
from auth_models import User, Institution, Certificate, BulkUpload, db
from werkzeug.utils import secure_filename
import pandas as pd
import os
from datetime import datetime
import json

# ==================== REQUEST PARSERS ====================
bulk_upload_parser = reqparse.RequestParser()
bulk_upload_parser.add_argument('institution_id', type=int, required=True, help="Institution ID required")

certificate_upload_parser = reqparse.RequestParser()
certificate_upload_parser.add_argument('certificate_id', type=str, required=True)
certificate_upload_parser.add_argument('name', type=str, required=True)
certificate_upload_parser.add_argument('roll_no', type=str, required=True)
certificate_upload_parser.add_argument('marks', type=int, required=True)
certificate_upload_parser.add_argument('course', type=str, required=False)
certificate_upload_parser.add_argument('graduation_date', type=str, required=False)

# ==================== INSTITUTION PORTAL ENDPOINTS ====================
class InstitutionDashboard(Resource):
    """Dashboard for institution users"""
    
    @jwt_required()
    def get(self):
        """Get institution dashboard data"""
        try:
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or user.role != 'institution':
                return {'error': 'Institution access required'}, 403
            
            if not user.institution_id:
                return {'error': 'User not associated with any institution'}, 400
            
            institution = Institution.query.get(user.institution_id)
            if not institution:
                return {'error': 'Institution not found'}, 404
            
            # Get institution statistics
            total_certificates = Certificate.query.filter_by(institution_id=institution.id).count()
            recent_uploads = BulkUpload.query.filter_by(
                institution_id=institution.id
            ).order_by(BulkUpload.created_at.desc()).limit(10).all()
            
            # Calculate upload statistics
            total_bulk_uploads = BulkUpload.query.filter_by(institution_id=institution.id).count()
            successful_uploads = BulkUpload.query.filter_by(
                institution_id=institution.id,
                status='completed'
            ).count()
            
            return {
                'institution': institution.to_dict(),
                'statistics': {
                    'total_certificates': total_certificates,
                    'total_bulk_uploads': total_bulk_uploads,
                    'successful_uploads': successful_uploads,
                    'success_rate': round((successful_uploads / total_bulk_uploads) * 100, 2) if total_bulk_uploads > 0 else 0
                },
                'recent_uploads': [upload.to_dict() for upload in recent_uploads]
            }, 200
            
        except Exception as e:
            return {'error': f'Dashboard fetch failed: {str(e)}'}, 500

class BulkCertificateUpload(Resource):
    """Handle bulk certificate uploads from institutions"""
    
    @jwt_required()
    def post(self):
        """Process bulk CSV upload"""
        try:
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or user.role != 'institution':
                return {'error': 'Institution access required'}, 403
            
            if not user.institution_id:
                return {'error': 'User not associated with any institution'}, 400
            
            # Check if file was uploaded
            if 'file' not in request.files:
                return {'error': 'No file uploaded'}, 400
            
            file = request.files['file']
            if file.filename == '':
                return {'error': 'No file selected'}, 400
            
            # Validate file type
            if not file.filename.lower().endswith(('.csv', '.xlsx', '.xls')):
                return {'error': 'File must be CSV or Excel format'}, 400
            
            # Save uploaded file
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_")
            filename = timestamp + filename
            filepath = os.path.join('uploads/bulk/', filename)
            
            # Create bulk upload directory if it doesn't exist
            os.makedirs('uploads/bulk/', exist_ok=True)
            file.save(filepath)
            
            # Create bulk upload record
            bulk_upload = BulkUpload(
                filename=filename,
                institution_id=user.institution_id,
                uploaded_by=user_id,
                status='processing'
            )
            db.session.add(bulk_upload)
            db.session.commit()
            
            # Process the file
            result = self._process_bulk_file(filepath, user.institution_id, bulk_upload.id)
            
            # Update bulk upload record
            bulk_upload.total_records = result['total_processed']
            bulk_upload.successful_records = result['successful']
            bulk_upload.failed_records = result['failed']
            bulk_upload.status = 'completed' if result['failed'] == 0 else 'completed_with_errors'
            bulk_upload.error_log = json.dumps(result['errors'])
            bulk_upload.completed_at = datetime.utcnow()
            
            db.session.commit()
            
            # Clean up uploaded file
            os.remove(filepath)
            
            return {
                'message': 'Bulk upload completed',
                'upload_id': bulk_upload.id,
                'results': result
            }, 200
            
        except Exception as e:
            # Update bulk upload status to failed if it exists
            try:
                bulk_upload.status = 'failed'
                bulk_upload.error_log = json.dumps([str(e)])
                db.session.commit()
            except:
                pass
            
            return {'error': f'Bulk upload failed: {str(e)}'}, 500
    
    def _process_bulk_file(self, filepath, institution_id, upload_id):
        """Process CSV/Excel file and add certificates to database"""
        try:
            # Read file based on extension
            if filepath.lower().endswith('.csv'):
                df = pd.read_csv(filepath)
            else:
                df = pd.read_excel(filepath)
            
            # Validate required columns
            required_columns = ['certificate_id', 'name', 'roll_no', 'marks']
            missing_columns = [col for col in required_columns if col not in df.columns]
            
            if missing_columns:
                return {
                    'total_processed': 0,
                    'successful': 0,
                    'failed': 1,
                    'errors': [f'Missing required columns: {", ".join(missing_columns)}']
                }
            
            successful = 0
            failed = 0
            errors = []
            
            for index, row in df.iterrows():
                try:
                    # Validate data
                    if pd.isna(row['certificate_id']) or pd.isna(row['name']) or pd.isna(row['roll_no']):
                        errors.append(f'Row {index + 2}: Missing required data')
                        failed += 1
                        continue
                    
                    # Check if certificate already exists
                    existing = Certificate.query.filter_by(
                        certificate_id=str(row['certificate_id'])
                    ).first()
                    
                    if existing:
                        errors.append(f'Row {index + 2}: Certificate ID {row["certificate_id"]} already exists')
                        failed += 1
                        continue
                    
                    # Parse graduation date if provided
                    graduation_date = None
                    if 'graduation_date' in row and not pd.isna(row['graduation_date']):
                        try:
                            graduation_date = pd.to_datetime(row['graduation_date']).date()
                        except:
                            errors.append(f'Row {index + 2}: Invalid date format for graduation_date')
                    
                    # Create certificate
                    certificate = Certificate(
                        certificate_id=str(row['certificate_id']).strip(),
                        name=str(row['name']).strip(),
                        roll_no=str(row['roll_no']).strip(),
                        marks=int(row['marks']),
                        institution_id=institution_id,
                        course=str(row['course']).strip() if 'course' in row and not pd.isna(row['course']) else None,
                        graduation_date=graduation_date,
                        is_verified=True,
                        added_by=upload_id
                    )
                    
                    db.session.add(certificate)
                    successful += 1
                    
                    # Commit in batches to avoid memory issues
                    if successful % 100 == 0:
                        db.session.commit()
                
                except ValueError as e:
                    errors.append(f'Row {index + 2}: Invalid marks value - {str(e)}')
                    failed += 1
                except Exception as e:
                    errors.append(f'Row {index + 2}: {str(e)}')
                    failed += 1
            
            # Final commit
            db.session.commit()
            
            return {
                'total_processed': len(df),
                'successful': successful,
                'failed': failed,
                'errors': errors[:50]  # Limit errors to first 50
            }
            
        except Exception as e:
            db.session.rollback()
            return {
                'total_processed': 0,
                'successful': 0,
                'failed': 1,
                'errors': [f'File processing error: {str(e)}']
            }

class SingleCertificateUpload(Resource):
    """Upload individual certificates"""
    
    @jwt_required()
    def post(self):
        """Add single certificate"""
        try:
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or user.role != 'institution':
                return {'error': 'Institution access required'}, 403
            
            if not user.institution_id:
                return {'error': 'User not associated with any institution'}, 400
            
            args = certificate_upload_parser.parse_args()
            
            # Check if certificate already exists
            existing = Certificate.query.filter_by(certificate_id=args['certificate_id']).first()
            if existing:
                return {'error': 'Certificate with this ID already exists'}, 409
            
            # Parse graduation date if provided
            graduation_date = None
            if args.get('graduation_date'):
                try:
                    graduation_date = datetime.strptime(args['graduation_date'], '%Y-%m-%d').date()
                except ValueError:
                    return {'error': 'Invalid date format. Use YYYY-MM-DD'}, 400
            
            # Create certificate
            certificate = Certificate(
                certificate_id=args['certificate_id'],
                name=args['name'],
                roll_no=args['roll_no'],
                marks=args['marks'],
                institution_id=user.institution_id,
                course=args.get('course'),
                graduation_date=graduation_date,
                is_verified=True,
                added_by=user_id
            )
            
            db.session.add(certificate)
            db.session.commit()
            
            return {
                'message': 'Certificate added successfully',
                'certificate': certificate.to_dict()
            }, 201
            
        except Exception as e:
            return {'error': f'Certificate creation failed: {str(e)}'}, 500

class InstitutionCertificates(Resource):
    """Manage institution's certificates"""
    
    @jwt_required()
    def get(self):
        """Get institution's certificates"""
        try:
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or user.role != 'institution':
                return {'error': 'Institution access required'}, 403
            
            if not user.institution_id:
                return {'error': 'User not associated with any institution'}, 400
            
            # Pagination
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 20, type=int)
            search = request.args.get('search', '')
            
            query = Certificate.query.filter_by(institution_id=user.institution_id)
            
            # Search functionality
            if search:
                query = query.filter(
                    Certificate.name.ilike(f'%{search}%') |
                    Certificate.certificate_id.ilike(f'%{search}%') |
                    Certificate.roll_no.ilike(f'%{search}%')
                )
            
            certificates = query.order_by(Certificate.created_at.desc()).paginate(
                page=page, per_page=per_page, error_out=False
            )
            
            return {
                'certificates': [cert.to_dict() for cert in certificates.items],
                'pagination': {
                    'page': certificates.page,
                    'pages': certificates.pages,
                    'per_page': certificates.per_page,
                    'total': certificates.total,
                    'has_next': certificates.has_next,
                    'has_prev': certificates.has_prev
                }
            }, 200
            
        except Exception as e:
            return {'error': f'Certificate fetch failed: {str(e)}'}, 500

class BulkUploadHistory(Resource):
    """View bulk upload history"""
    
    @jwt_required()
    def get(self):
        """Get institution's bulk upload history"""
        try:
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or user.role != 'institution':
                return {'error': 'Institution access required'}, 403
            
            if not user.institution_id:
                return {'error': 'User not associated with any institution'}, 400
            
            uploads = BulkUpload.query.filter_by(
                institution_id=user.institution_id
            ).order_by(BulkUpload.created_at.desc()).all()
            
            upload_history = []
            for upload in uploads:
                upload_dict = upload.to_dict()
                
                # Parse error log if exists
                if upload.error_log:
                    try:
                        upload_dict['errors'] = json.loads(upload.error_log)
                    except:
                        upload_dict['errors'] = []
                else:
                    upload_dict['errors'] = []
                
                upload_history.append(upload_dict)
            
            return {'bulk_uploads': upload_history}, 200
            
        except Exception as e:
            return {'error': f'Upload history fetch failed: {str(e)}'}, 500

class DownloadTemplate(Resource):
    """Download CSV template for bulk upload"""
    
    @jwt_required()
    def get(self):
        """Generate and return CSV template"""
        try:
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or user.role != 'institution':
                return {'error': 'Institution access required'}, 403
            
            # Create sample CSV template
            template_data = {
                'certificate_id': ['CERT001', 'CERT002', 'CERT003'],
                'name': ['John Doe', 'Jane Smith', 'Bob Johnson'],
                'roll_no': ['ROLL123', 'ROLL124', 'ROLL125'],
                'marks': [85, 92, 78],
                'course': ['Computer Science', 'Mathematics', 'Physics'],
                'graduation_date': ['2023-06-15', '2023-06-16', '2023-06-17']
            }
            
            df = pd.DataFrame(template_data)
            
            # Save template file
            template_filename = 'certificate_upload_template.csv'
            template_path = os.path.join('uploads/templates/', template_filename)
            
            # Create template directory if it doesn't exist
            os.makedirs('uploads/templates/', exist_ok=True)
            df.to_csv(template_path, index=False)
            
            return {
                'message': 'Template generated successfully',
                'template_url': f'/download/template/{template_filename}',
                'instructions': {
                    'required_columns': ['certificate_id', 'name', 'roll_no', 'marks'],
                    'optional_columns': ['course', 'graduation_date'],
                    'notes': [
                        'certificate_id must be unique across all institutions',
                        'marks should be numeric (0-100)',
                        'graduation_date format: YYYY-MM-DD',
                        'All certificate_id values must be unique',
                        'Names should be full names as they appear on certificates'
                    ]
                }
            }, 200
            
            
        except Exception as e:
            return {'error': f'Template generation failed: {str(e)}'}, 500