from flask import request, jsonify
from flask_restful import Resource, reqparse
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from auth_models import User, Institution, db
from datetime import datetime

# ==================== REQUEST PARSERS ====================
register_parser = reqparse.RequestParser()
register_parser.add_argument('username', type=str, required=True, help="Username required")
register_parser.add_argument('email', type=str, required=True, help="Email required")
register_parser.add_argument('password', type=str, required=True, help="Password required")
register_parser.add_argument('role', type=str, required=False, default='user', help="Role: user, admin, institution")
register_parser.add_argument('institution_code', type=str, required=False, help="Institution code (if role=institution)")

login_parser = reqparse.RequestParser()
login_parser.add_argument('username', type=str, required=True, help="Username required")
login_parser.add_argument('password', type=str, required=True, help="Password required")

institution_parser = reqparse.RequestParser()
institution_parser.add_argument('name', type=str, required=True, help="Institution name required")
institution_parser.add_argument('code', type=str, required=True, help="Institution code required")
institution_parser.add_argument('address', type=str, required=False, help="Address")
institution_parser.add_argument('email', type=str, required=False, help="Email")
institution_parser.add_argument('phone', type=str, required=False, help="Phone")
institution_parser.add_argument('website', type=str, required=False, help="Website")

# ==================== AUTHENTICATION ENDPOINTS ====================
class Register(Resource):
    """User registration endpoint"""
    
    def post(self):
        """Register new user"""
        try:
            args = register_parser.parse_args()
            
            # Check if username already exists
            if User.query.filter_by(username=args['username']).first():
                return {'error': 'Username already exists'}, 400
            
            # Check if email already exists
            if User.query.filter_by(email=args['email']).first():
                return {'error': 'Email already registered'}, 400
            
            # Validate role
            valid_roles = ['user', 'admin', 'institution']
            if args['role'] not in valid_roles:
                return {'error': 'Invalid role'}, 400
            
            # For institution users, verify institution code
            institution_id = None
            if args['role'] == 'institution' and args.get('institution_code'):
                institution = Institution.query.filter_by(code=args['institution_code']).first()
                if not institution:
                    return {'error': 'Invalid institution code'}, 400
                if not institution.is_verified:
                    return {'error': 'Institution not verified by admin'}, 400
                institution_id = institution.id
            
            # Create new user
            user = User(
                username=args['username'],
                email=args['email'],
                role=args['role'],
                institution_id=institution_id
            )
            user.set_password(args['password'])
            
            db.session.add(user)
            db.session.commit()
            
            # Create access token
            access_token = create_access_token(identity=str(user.id))
            
            return {
                'message': 'User registered successfully',
                'access_token': access_token,
                'user': user.to_dict()
            }, 201
            
        except Exception as e:
            return {'error': f'Registration failed: {str(e)}'}, 500

class Login(Resource):
    """User login endpoint"""
    
    def post(self):
        """Authenticate user and return token"""
        try:
            args = login_parser.parse_args()
            
            # Find user by username
            user = User.query.filter_by(username=args['username']).first()
            
            if not user or not user.check_password(args['password']):
                return {'error': 'Invalid username or password'}, 401
            
            if not user.is_active:
                return {'error': 'Account is deactivated'}, 401
            
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Create access token
            access_token = create_access_token(identity=str(user.id))
            
            return {
                'message': 'Login successful',
                'access_token': access_token,
                'user': user.to_dict()
            }, 200
            
        except Exception as e:
            return {'error': f'Login failed: {str(e)}'}, 500

class Profile(Resource):
    """User profile management"""
    
    @jwt_required()
    def get(self):
        """Get current user profile"""
        try:
            user_id = int(get_jwt_identity())
            user = User.query.get(user_id)
            
            if not user:
                return {'error': 'User not found'}, 404
            
            return {'user': user.to_dict()}, 200
            
        except Exception as e:
            return {'error': f'Failed to get profile: {str(e)}'}, 500

# ==================== INSTITUTION MANAGEMENT ====================
class InstitutionRegister(Resource):
    """Institution registration endpoint"""
    
    def post(self):
        """Register new institution (requires admin approval)"""
        try:
            args = institution_parser.parse_args()
            
            # Check if institution code already exists
            if Institution.query.filter_by(code=args['code']).first():
                return {'error': 'Institution code already exists'}, 400
            
            # Create new institution
            institution = Institution(
                name=args['name'],
                code=args['code'],
                address=args.get('address'),
                email=args.get('email'),
                phone=args.get('phone'),
                website=args.get('website'),
                is_verified=False  # Requires admin approval
            )
            
            db.session.add(institution)
            db.session.commit()
            
            return {
                'message': 'Institution registered successfully. Waiting for admin approval.',
                'institution': institution.to_dict()
            }, 201
            
        except Exception as e:
            return {'error': f'Institution registration failed: {str(e)}'}, 500

class InstitutionList(Resource):
    """List institutions"""
    
    def get(self):
        """Get all verified institutions"""
        try:
            institutions = Institution.query.filter_by(is_verified=True, is_active=True).all()
            
            return {
                'institutions': [inst.to_dict() for inst in institutions]
            }, 200
            
        except Exception as e:
            return {'error': f'Failed to get institutions: {str(e)}'}, 500

class InstitutionApproval(Resource):
    """Admin endpoint to approve institutions"""
    
    @jwt_required()
    def post(self, institution_id):
        """Approve institution (admin only)"""
        try:
            user_id = int(get_jwt_identity())
            user = User.query.get(user_id)
            
            if not user or user.role != 'admin':
                return {'error': 'Admin access required'}, 403
            
            institution = Institution.query.get(institution_id)
            if not institution:
                return {'error': 'Institution not found'}, 404
            
            action = request.json.get('action', 'approve')
            
            if action == 'approve':
                institution.is_verified = True
                message = 'Institution approved successfully'
            elif action == 'reject':
                institution.is_active = False
                message = 'Institution rejected'
            else:
                return {'error': 'Invalid action'}, 400
            
            db.session.commit()
            
            return {
                'message': message,
                'institution': institution.to_dict()
            }, 200
            
        except Exception as e:
            return {'error': f'Institution approval failed: {str(e)}'}, 500

# ==================== UTILITY FUNCTIONS ====================
def require_role(role):
    """Decorator to require specific role"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            user_id = int(get_jwt_identity())
            user = User.query.get(user_id)
            
            if not user or user.role != role:
                return {'error': f'{role} access required'}, 403
            
            return f(*args, **kwargs)
        return wrapper
    return decorator

def get_current_user():
    """Get current user from JWT token"""
    user_id = int(get_jwt_identity())
    return User.query.get(user_id) if user_id else None