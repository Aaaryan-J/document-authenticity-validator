from datetime import datetime
import random
import os
import logging
from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from auth_models import db  # your DB models
from auth_models import Certificate  # assuming you have a Certificate model

logger = logging.getLogger(__name__)
UPLOAD_FOLDER = "./uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

class CertificateUpload(Resource):
    """Bypass OCR for prototype/demo"""

    @jwt_required()
    def post(self):
        try:
            current_user_id = get_jwt_identity()  # your logged-in user's ID

            # Dummy certificate data
            dummy_data = {
                "certificate_id": f"CERT-{random.randint(1000,9999)}",
                "roll_no": f"ROLL-{random.randint(100,999)}",
                "name": "John Doe",
                "marks": random.randint(50,100),
                "institution_id": 1,  # demo institution
                "course": "Computer Science",
                "graduation_date": datetime.utcnow().date()
            }

            cert = Certificate(
                certificate_id=dummy_data["certificate_id"],
                roll_no=dummy_data["roll_no"],
                name=dummy_data["name"],
                marks=dummy_data["marks"],
                institution_id=dummy_data["institution_id"],
                course=dummy_data["course"],
                graduation_date=dummy_data["graduation_date"],
                is_verified=True,
                added_by=current_user_id
            )

            db.session.add(cert)
            db.session.commit()

            return {
                "success": True,
                "message": "Dummy certificate added successfully",
                "data": cert.to_dict()
            }, 200

        except Exception as e:
            return {"error": f"Server error: {str(e)}"}, 500

    def options(self):
        return {}, 200