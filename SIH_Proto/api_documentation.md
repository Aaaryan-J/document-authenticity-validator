# Certificate Verification System - API Documentation

## Overview
This API provides secure certificate verification services with role-based access control and comprehensive fraud detection capabilities.

**Base URL:** `http://localhost:5000`

## Security Features

### Authentication & Authorization
- **JWT-based authentication** with 24-hour token expiry
- **Role-based access control** (user, institution, admin)
- **Secure admin registration** with secret key protection
- **Password hashing** using Werkzeug security functions
- **Account activation/deactivation** capabilities

### Fraud Prevention
- **Risk scoring system** (0-100) for all verification attempts
- **IP address tracking** to identify repeat offenders
- **Blacklist management** with fraud type classification
- **Suspicious activity monitoring** and alerting
- **Institution verification** required before certificate uploads

### Data Protection
- **Input validation** on all endpoints
- **SQL injection prevention** through ORM usage
- **File upload restrictions** (16MB limit, specific formats)
- **Secure file handling** with filename sanitization

## Authentication Headers
All protected endpoints require JWT token:
```
Authorization: Bearer <jwt_token>
```

---

## Authentication Endpoints

### Register User (Standard)
**POST** `/api/auth/register`

Creates new user account. **Admin registration blocked** - use dedicated admin endpoints.

**Request Body:**
```json
{
  "username": "string (required)",
  "email": "string (required)", 
  "password": "string (required)",
  "role": "user|institution (optional, default: user)",
  "institution_code": "string (required if role=institution)"
}
```

**Security Notes:**
- Admin role registration is explicitly blocked
- Institution users must provide valid, verified institution code
- Email and username uniqueness enforced

### Register Admin (Secure)
**POST** `/api/auth/register-admin`

Creates admin user with secret key verification.

**Request Body:**
```json
{
  "username": "string (required)",
  "email": "string (required)",
  "password": "string (required)",
  "admin_secret_key": "string (required)"
}
```

**Security Requirements:**
- Requires `ADMIN_SECRET_KEY` environment variable
- Secret key must match server configuration
- Only available to authorized personnel

### Create First Admin (Bootstrap)
**POST** `/api/auth/create-first-admin`

Emergency endpoint to create first admin user. **Only works when no admin users exist.**

**Request Body:**
```json
{
  "username": "string (required)",
  "email": "string (required)",
  "password": "string (required)",
  "admin_secret_key": "string (required)"
}
```

**Security Features:**
- Automatically disabled after first admin creation
- Still requires secret key verification
- Used for initial system setup only

### Promote User to Admin
**POST** `/api/auth/promote/{user_id}`
*Admin only*

Promotes existing user to admin role.

**Security Controls:**
- Only existing admins can promote others
- Removes institution association when promoting
- Audit trail maintained

### Login
**POST** `/api/auth/login`

**Request Body:**
```json
{
  "username": "string (required)",
  "password": "string (required)"
}
```

**Security Features:**
- Account status validation (active/inactive)
- Last login timestamp tracking
- Failed login attempt monitoring

### Get Profile
**GET** `/api/auth/profile`
*Requires JWT authentication*

---

## Institution Management

### Register Institution
**POST** `/api/auth/institution/register`

**Security:** Requires admin approval before activation.

**Request Body:**
```json
{
  "name": "string (required)",
  "code": "string (required, unique)",
  "address": "string (optional)",
  "email": "string (optional)",
  "phone": "string (optional)",
  "website": "string (optional)"
}
```

### List Institutions
**GET** `/api/auth/institutions`

Returns only **verified and active** institutions.

### Approve Institution
**POST** `/api/auth/institutions/{institution_id}/approve`
*Admin only*

**Request Body:**
```json
{
  "action": "approve|reject"
}
```

---

## Admin Dashboard Endpoints

### Dashboard Overview
**GET** `/api/admin/dashboard`
*Admin only*

**Query Parameters:**
- `days` (optional): Analysis period (default: 30)

**Response includes:**
```json
{
  "overview": {
    "total_certificates": 1500,
    "fraud_rate": 8.0,
    "active_blacklist_entries": 5,
    "high_risk_verifications": 23
  },
  "fraud_types": [
    {"type": "fake_cert", "count": 8},
    {"type": "identity_theft", "count": 3}
  ],
  "high_risk_verifications": [/* flagged attempts */]
}
```

### Forgery Trends Analysis
**GET** `/api/admin/trends`
*Admin only*

**Advanced fraud analytics:**
- Daily fraud attempt trends
- Most targeted institutions
- Suspicious IP addresses (3+ attempts)
- Common fraud patterns by type and severity

**Query Parameters:**
- `days` (optional): Analysis period (default: 30)

### Blacklist Management
**GET** `/api/admin/blacklist`
*Admin only*

**Security Features:**
- Pagination with filtering
- Fraud type classification
- Severity level tracking
- IP address monitoring

**Query Parameters:**
- `page`, `per_page`: Pagination
- `fraud_type`: Filter by `fake_cert|data_manipulation|identity_theft|institution_impersonation|other`
- `severity`: Filter by `low|medium|high|critical`
- `active_only`: Show active entries only

**POST** `/api/admin/blacklist`
*Admin only*

Add blacklist entry with fraud classification.

**Request Body:**
```json
{
  "certificate_id": "string (optional)",
  "name": "string (optional)",
  "roll_no": "string (optional)", 
  "institution_name": "string (optional)",
  "reason": "string (required)",
  "fraud_type": "fake_cert|data_manipulation|identity_theft|institution_impersonation|other (required)",
  "severity": "low|medium|high|critical (optional, default: medium)",
  "evidence": "string (optional)"
}
```

**Security Tracking:**
- Reporter ID logged
- IP address recorded
- Timestamp tracking

### Manage Blacklist Entry
**PATCH** `/api/admin/blacklist/{entry_id}`
*Admin only*

**DELETE** `/api/admin/blacklist/{entry_id}`
*Admin only*

### Verification History
**GET** `/api/admin/history`
*Admin only*

**Advanced filtering:**
- Validity status
- Risk score thresholds
- Time-based filtering
- Enhanced risk indicators

**Query Parameters:**
- `is_valid` (optional): Filter by validity
- `min_risk_score` (optional): Minimum risk threshold
- `days_back` (optional): Lookback period

**Response includes risk indicators:**
- Very High Risk (score ≥ 80)
- High Risk (score ≥ 60)
- Low OCR Confidence
- Certificate Not Found flags

### System Statistics
**GET** `/api/admin/stats`
*Admin only*

Comprehensive system metrics including fraud detection statistics, user activity, and certificate verification success rates.

---

## Institution Portal Endpoints

### Institution Dashboard
**GET** `/api/institution/dashboard`
*Institution role only*

**Security Validation:**
- User-institution association verified
- Institution verification status checked

### Bulk Certificate Upload
**POST** `/api/institution/upload/bulk`
*Institution role only*

**Security Features:**
- File type validation (CSV/Excel only)
- Filename sanitization
- Batch processing (100 records max)
- Duplicate certificate ID detection
- Comprehensive error logging

**Request:**
- Content-Type: `multipart/form-data`
- File field: `file`
- Max size: 16MB

**Required CSV columns:** `certificate_id`, `name`, `roll_no`, `marks`
**Optional columns:** `course`, `graduation_date`

**Security Validations:**
- Certificate ID uniqueness across all institutions
- Data type validation
- Institution ownership verification

### Single Certificate Upload
**POST** `/api/institution/upload/single`
*Institution role only*

**Request Body:**
```json
{
  "certificate_id": "string (required, globally unique)",
  "name": "string (required)",
  "roll_no": "string (required)",
  "marks": "integer (required, 0-100)",
  "course": "string (optional)",
  "graduation_date": "YYYY-MM-DD (optional)"
}
```

**Security Checks:**
- Certificate ID uniqueness validation
- Institution ownership verification
- Data format validation

### List Institution Certificates
**GET** `/api/institution/certificates`
*Institution role only*

**Security:** Only shows certificates belonging to user's institution.

**Query Parameters:**
- `search`: Search by name, certificate ID, or roll number
- `page`, `per_page`: Pagination

### Bulk Upload History
**GET** `/api/institution/uploads/history`
*Institution role only*

**Includes:**
- Upload success/failure statistics
- Detailed error logs
- Processing timestamps
- User tracking

### Download Template
**GET** `/api/institution/template`
*Institution role only*

Provides secure CSV template with validation instructions.

---

## Additional Security Recommendations

### Environment Variables Required
```bash
# Critical security configuration
export ADMIN_SECRET_KEY="your-super-secret-admin-key-change-this"
export JWT_SECRET_KEY="your-jwt-secret-key"
export DATABASE_URL="your-database-connection-string"

# Optional security enhancements
export MAX_LOGIN_ATTEMPTS="5"
export LOCKOUT_DURATION_MINUTES="30"
export PASSWORD_MIN_LENGTH="8"
```

### Enhanced Security Features to Implement

1. **Rate Limiting:**
   ```python
   # Add to your requirements
   flask-limiter==2.6.2
   ```
   - Login attempt limiting (5 attempts per IP per hour)
   - API endpoint rate limiting
   - Bulk upload frequency limits

2. **Password Security:**
   ```python
   # Add password complexity requirements
   import re
   
   def validate_password(password):
       if len(password) < 8:
           return False
       if not re.search(r"[A-Z]", password):
           return False
       if not re.search(r"[a-z]", password):
           return False
       if not re.search(r"\d", password):
           return False
       return True
   ```

3. **Session Security:**
   - JWT token blacklisting on logout
   - Token refresh mechanism
   - Session timeout handling

4. **Audit Logging:**
   ```python
   # Add comprehensive audit trail
   class AuditLog(db.Model):
       id = db.Column(db.Integer, primary_key=True)
       user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
       action = db.Column(db.String(100), nullable=False)
       resource_type = db.Column(db.String(50))
       resource_id = db.Column(db.String(100))
       ip_address = db.Column(db.String(45))
       user_agent = db.Column(db.Text)
       timestamp = db.Column(db.DateTime, default=datetime.utcnow)
   ```

5. **Input Sanitization:**
   - XSS prevention on all text inputs
   - SQL injection protection (already implemented via ORM)
   - File upload content validation

6. **HTTPS Enforcement:**
   ```python
   # Add to Flask config
   app.config['FORCE_HTTPS'] = True
   ```

## Error Responses

**Security-aware error handling:**
```json
{
  "error": "Generic error message",
  "error_code": "SPECIFIC_ERROR_CODE",
  "request_id": "uuid-for-tracking"
}
```

**Security Status Codes:**
- `401`: Authentication required/invalid
- `403`: Insufficient permissions
- `429`: Rate limit exceeded
- `423`: Account locked due to security policy

---

## Security Monitoring

The system tracks:
- Failed login attempts by IP
- Repeated verification failures
- Suspicious file upload patterns
- Bulk upload anomalies
- Admin action auditing
- Blacklist hit patterns

## Compliance Notes

- **Data Privacy:** User data hashed and secured
- **Audit Trail:** Complete action logging for admins
- **Access Control:** Principle of least privilege enforced
- **Data Retention:** Configurable log retention periods
- **Incident Response:** Automated alerting for suspicious activity