import os
import logging
from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from ocr_service import extract_marksheet_details

logger = logging.getLogger(__name__)
UPLOAD_FOLDER = "./uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

class CertificateUpload(Resource):
    """Flask-RESTful Resource for certificate upload and OCR"""

    @jwt_required()
    def post(self):
        try:
            if "uploadedFile" not in request.files:
                return {"error": "No file part in request"}, 400

            file = request.files["uploadedFile"]
            if file.filename == "":
                return {"error": "No file selected"}, 400

            if not allowed_file(file.filename):
                return {"error": "Only PNG, JPG, JPEG allowed"}, 400

            current_user = get_jwt_identity()
            filename = secure_filename(file.filename) or "uploaded_file.jpg"
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)

            ocr_data = extract_marksheet_details(filepath)
            if not isinstance(ocr_data, dict):
                return {"error": "OCR returned invalid data"}, 500

            os.remove(filepath)
            return {"success": True, "message": "File processed", "data": ocr_data}, 200

        except Exception as e:
            return {"error": f"Server error: {str(e)}"}, 500

    def options(self):
        """Handle preflight CORS requests"""
        return {}, 200
