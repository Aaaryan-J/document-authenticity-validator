import pytesseract
from PIL import Image
import re
import json

# Configure Tesseract path
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

def extract_marksheet_details(image_path: str) -> str:
    """Extract Certificate No, Roll No, Name, and CGPA from degree certificate."""
    img = Image.open(image_path)

    # === Step 1: Crop top-left area for certificate number ===
    cert_crop = img.crop((0, 0, 400, 150))  # Adjust based on resolution
    cert_text = pytesseract.image_to_string(cert_crop)

    # Extract certificate number as a string (preserve leading zeros)
    cert_match = re.search(r'\b\d{5,}\b', cert_text)
    certificate_no = cert_match.group(0).zfill(7) if cert_match else None  # Ensure it stays 7 digits

    # === Step 2: Full image OCR for other details ===
    text = pytesseract.image_to_string(img)

    # Roll No
    roll_match = re.search(r'Roll No\.?:\s*([A-Z0-9]+)', text, re.IGNORECASE)
    roll_no = roll_match.group(1) if roll_match else None

    # Name
    name_match = re.search(r'Name\s*:\s*([A-Za-z ]+?)(?:\s+Discipline|$)', text, re.IGNORECASE)
    name = name_match.group(1).strip().title() if name_match else None

    # CGPA
    cgpa_match = re.search(r'CGPA\s+([\d.]+)', text)
    cgpa = cgpa_match.group(1) if cgpa_match else None

    # === Final JSON ===
    result = {
        "Certificate_No": certificate_no,  # Always a string
        "Roll_No": roll_no,
        "Name": name,
        "CGPA": cgpa
    }
    return result