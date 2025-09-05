# Certificate Verification System Setup Guide

## Quick Start (Basic Version)

### 1. Install Dependencies
```bash
pip install flask flask-sqlalchemy flask-restful flask-cors flask-jwt-extended pandas openpyxl xlrd werkzeug
```

### 2. Run the Basic System
```bash
python api_main.py
```

Your system will work with basic features:
- Certificate verification (main feature)
- Basic authentication 
- File uploads
- Database management

## Full Setup (All Features)

### 1. File Structure
Create these files in your project directory:
```
your-project/
├── api_main.py              # Your main file (updated)
├── auth_routes.py           # Authentication (copy from artifacts)
├── admin_dashboard.py       # Admin features (copy from artifacts) 
├── institution_portal.py    # Institution portal (copy from artifacts)
├── uploads/                 # Upload directories (auto-created)
├── requirements.txt         # Dependencies
└── README.md               # This file
```

### 2. Create the Additional Files

**auth_routes.py** - Copy the content from the "auth_routes.py" artifact I created
**admin_dashboard.py** - Copy from the "admin_dashboard.py" artifact  
**institution_portal.py** - Copy from the "institution_portal.py" artifact

### 3. Test the System

#### A. Start the server:
```bash
python api_main.py
```

#### B. Test authentication:
```bash
# Register a user
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "test123", "email": "test@test.com"}'

# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "test123"}'
```

#### C. Test certificate verification:
```bash
# Upload a certificate image for verification
curl -X POST http://localhost:5000/api/verify \
  -F "file=@certificate.jpg"
```

#### D. Test admin features (use token from login):
```bash
# Get admin dashboard (login as admin/admin123)
curl -X GET http://localhost:5000/api/admin/dashboard \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## Integration with OCR Team

### When your team provides OCR code:

1. **Replace the mock function** in `api_main.py`:
```python
# Find this function and replace it:
def mock_ocr_extraction(filepath):
    # Replace with:
    from your_teams_ocr_file import their_function
    return their_function(filepath)
```

2. **Make sure their function returns**:
```python
{
    'certificate_id': 'CERT123',
    'name': 'John Doe', 
    'roll_no': 'ROLL456',
    'marks': 85,
    'confidence': 92.5  # OCR confidence score
}
```

## Features Overview

### Working Now (Basic Mode):
- User registration/login
- Certificate upload & verification  
- Database management
- Verification logging
- Basic admin panel

### With Full Setup:
- **Admin Dashboard**: Fraud trends, blacklist management, system stats
- **Institution Portal**: Bulk upload, certificate management
- **Enhanced Security**: Role-based access, JWT tokens
- **Advanced Analytics**: Fraud detection, risk scoring

## Testing Endpoints

### Authentication:
```bash
POST /api/auth/register   # Register new user
POST /api/auth/login      # Login user  
GET  /api/auth/profile    # Get user profile (with token)
```

### Main Features:
```bash
POST /api/verify          # Upload & verify certificate
GET  /api/certificates    # List valid certificates
POST /api/certificates    # Add new certificate
```

### Admin (token required):
```bash
GET  /api/admin/dashboard # Dashboard overview
GET  /api/admin/trends    # Forgery trends  
GET  /api/admin/blacklist # Blacklist management
POST /api/admin/blacklist # Add to blacklist
```

### Institution Portal (token required):
```bash
GET  /api/institution/dashboard    # Institution overview
POST /api/institution/bulk-upload  # Upload CSV of certificates
GET  /api/institution/template     # Download CSV template
```

## Troubleshooting

### "Module not found" errors:
- Your system will still work in basic mode even if some files are missing
- You need to create all **4 files** for full features:
  - `auth_models.py` (database models)
  - `auth_routes.py` (authentication endpoints)  
  - `admin_dashboard.py` (admin features)
  - `institution_portal.py` (institution portal)

### Database errors:
- Delete `certificate_system.db` and restart
- Tables will be recreated automatically

### JWT token errors:
- Make sure you're including the token in headers:
  `Authorization: Bearer YOUR_TOKEN`

### File upload errors:
- Check that `uploads/` directory exists
- Verify file types are allowed (PNG, JPG, PDF)

## Demo Ready Features

For your hackathon demo, you'll have:

1. **Certificate Upload** - Works now
2. **Real-time Verification** - Works with OCR integration  
3. **Admin Dashboard** - Fraud detection, analytics
4. **Institution Portal** - Bulk uploads, management
5. **Authentication System** - Secure access control
6. **Blacklist Management** - Block fraudulent certificates

## 🔄 Next Steps

1. **Test basic version** - Run `python api_main.py`
2. **Create additional files** if you want full features  
3. **Integrate OCR** when your team provides it
4. **Test with frontend** - All endpoints return JSON
5. **Deploy for demo** - Everything should work!

Need help with any specific part? Let me know!