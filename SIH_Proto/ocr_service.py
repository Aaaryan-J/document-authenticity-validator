import pytesseract
from PIL import Image, ImageEnhance
import re
import logging

# Configure Tesseract path
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

def extract_marksheet_details(image_path: str) -> dict:
    """
    Extract details from marksheet image with comprehensive error handling
    """
    try:
        # Validate file exists
        import os
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image file not found: {image_path}")
        
        # Load and process image
        img = Image.open(image_path).convert("L")  # grayscale
        enhancer = ImageEnhance.Contrast(img)
        img = enhancer.enhance(2.0)

        # Certificate No crop
        cert_crop = img.crop((0, 0, 400, 150))
        cert_text = pytesseract.image_to_string(cert_crop, config='--psm 6')
        cert_match = re.search(r'\b\d{5,}\b', cert_text)
        certificate_no = cert_match.group(0).zfill(7) if cert_match else None

        # Extract full text
        text = pytesseract.image_to_string(img, config='--psm 6')
        
        # Log extracted text for debugging
        logging.info(f"Extracted text: {text[:200]}...")

        # Extract fields with better patterns
        roll_match = re.search(r'Roll\s*No\.?\s*[:\-]?\s*([A-Z0-9]+)', text, re.IGNORECASE)
        roll_no = roll_match.group(1).strip() if roll_match else None

        name_match = re.search(r'Name\s*[:\-]?\s*([A-Za-z .-]+?)(?:\n|$|Roll|Discipline|CGPA)', text, re.IGNORECASE)
        name = name_match.group(1).strip().title() if name_match else None

        cgpa_match = re.search(r'CGPA\s*[:\-]?\s*([\d.]+)', text, re.IGNORECASE)
        cgpa = cgpa_match.group(1).strip() if cgpa_match else None

        result = {
            "Certificate_No": certificate_no,
            "Roll_No": roll_no,
            "Name": name,
            "CGPA": cgpa
        }
        
        logging.info(f"OCR Result: {result}")
        return result

    except Exception as e:
        logging.error(f"OCR extraction failed: {str(e)}")
        # Return a valid dict with error info instead of raising
        return {
            "Certificate_No": None,
            "Roll_No": None,
            "Name": None,
            "CGPA": None,
            "error": f"OCR failed: {str(e)}"
        }