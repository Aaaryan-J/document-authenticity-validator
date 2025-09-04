from flask import request, jsonify
from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
from auth_models import User, VerificationLog, BlacklistEntry, ForgeryTrend, Certificate, Institution, db
from datetime import datetime, timedelta
from sqlalchemy import func, desc
import json

# ==================== REQUEST PARSERS ====================
blacklist_parser = reqparse.RequestParser()
blacklist_parser.add_argument('certificate_id', type=str, required=False)
blacklist_parser.add_argument('name', type=str, required=False)
blacklist_parser.add_argument('roll_no', type=str, required=False)
blacklist_parser.add_argument('institution_name', type=str, required=False)
blacklist_parser.add_argument('reason', type=str, required=True, help="Reason for blacklisting required")
blacklist_parser.add_argument('fraud_type', type=str, required=True, help="Fraud type required")
blacklist_parser.add_argument('severity', type=str, required=False, default='medium')
blacklist_parser.add_argument('evidence', type=str, required=False)

date_range_parser = reqparse.RequestParser()
date_range_parser.add_argument('start_date', type=str, required=False)
date_range_parser.add_argument('end_date', type=str, required=False)
date_range_parser.add_argument('days', type=int, required=False, default=30)

# ==================== ADMIN DASHBOARD ENDPOINTS ====================
class AdminDashboard(Resource):
    """Main admin dashboard with key metrics"""
    
    @jwt_required()
    def get(self):
        """Get dashboard overview statistics"""
        try:
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or user.role != 'admin':
                return {'error': 'Admin access required'}, 403
            
            # Get date range (default: last 30 days)
            args = date_range_parser.parse_args()
            days = args.get('days', 30)
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Basic counts
            total_certificates = Certificate.query.count()
            total_verifications = VerificationLog.query.count()
            recent_verifications = VerificationLog.query.filter(
                VerificationLog.created_at >= start_date
            ).count()
            
            # Fraud statistics
            fraud_attempts = VerificationLog.query.filter(
                VerificationLog.is_valid == False,
                VerificationLog.created_at >= start_date
            ).count()
            
            fraud_rate = (fraud_attempts / recent_verifications * 100) if recent_verifications > 0 else 0
            
            # Blacklist statistics
            active_blacklist_entries = BlacklistEntry.query.filter_by(is_active=True).count()
            recent_blacklist_additions = BlacklistEntry.query.filter(
                BlacklistEntry.created_at >= start_date
            ).count()
            
            # Institution statistics
            total_institutions = Institution.query.filter_by(is_active=True).count()
            pending_institutions = Institution.query.filter_by(is_verified=False, is_active=True).count()
            
            # Top fraud types
            fraud_types = db.session.query(
                BlacklistEntry.fraud_type,
                func.count(BlacklistEntry.id).label('count')
            ).filter(
                BlacklistEntry.created_at >= start_date,
                BlacklistEntry.is_active == True
            ).group_by(BlacklistEntry.fraud_type).all()
            
            # Recent high-risk verifications
            high_risk_verifications = VerificationLog.query.filter(
                VerificationLog.risk_score >= 70.0,
                VerificationLog.created_at >= start_date
            ).order_by(desc(VerificationLog.created_at)).limit(10).all()
            
            return {
                'overview': {
                    'total_certificates': total_certificates,
                    'total_verifications': total_verifications,
                    'recent_verifications': recent_verifications,
                    'fraud_attempts': fraud_attempts,
                    'fraud_rate': round(fraud_rate, 2),
                    'active_blacklist_entries': active_blacklist_entries,
                    'recent_blacklist_additions': recent_blacklist_additions,
                    'total_institutions': total_institutions,
                    'pending_institutions': pending_institutions
                },
                'fraud_types': [{'type': ft[0], 'count': ft[1]} for ft in fraud_types],
                'high_risk_verifications': [log.to_dict() for log in high_risk_verifications]
            }, 200
            
        except Exception as e:
            return {'error': f'Dashboard data fetch failed: {str(e)}'}, 500

class ForgeryTrends(Resource):
    """Forgery trends analysis"""
    
    @jwt_required()
    def get(self):
        """Get forgery trends over time"""
        try:
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or user.role != 'admin':
                return {'error': 'Admin access required'}, 403
            
            args = date_range_parser.parse_args()
            days = args.get('days', 30)
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Daily fraud attempts trend
            daily_trends = db.session.query(
                func.date(VerificationLog.created_at).label('date'),
                func.count(VerificationLog.id).label('total_attempts'),
                func.sum(func.case([(VerificationLog.is_valid == False, 1)], else_=0)).label('fraud_attempts'),
                func.avg(VerificationLog.risk_score).label('avg_risk_score')
            ).filter(
                VerificationLog.created_at >= start_date
            ).group_by(
                func.date(VerificationLog.created_at)
            ).order_by('date').all()
            
            # Most targeted institutions (fake certificates claiming to be from them)
            targeted_institutions = db.session.query(
                VerificationLog.extracted_name.label('institution'),
                func.count(VerificationLog.id).label('fraud_count')
            ).filter(
                VerificationLog.is_valid == False,
                VerificationLog.created_at >= start_date
            ).group_by(VerificationLog.extracted_name).order_by(desc('fraud_count')).limit(10).all()
            
            # Suspicious IP addresses (multiple fraud attempts)
            suspicious_ips = db.session.query(
                VerificationLog.ip_address,
                func.count(VerificationLog.id).label('attempt_count'),
                func.sum(func.case([(VerificationLog.is_valid == False, 1)], else_=0)).label('fraud_count')
            ).filter(
                VerificationLog.created_at >= start_date,
                VerificationLog.ip_address.isnot(None)
            ).group_by(VerificationLog.ip_address).having(
                func.count(VerificationLog.id) >= 3  # 3+ attempts from same IP
            ).order_by(desc('fraud_count')).all()
            
            # Common fraud patterns
            fraud_patterns = db.session.query(
                BlacklistEntry.fraud_type,
                BlacklistEntry.severity,
                func.count(BlacklistEntry.id).label('count')
            ).filter(
                BlacklistEntry.created_at >= start_date,
                BlacklistEntry.is_active == True
            ).group_by(BlacklistEntry.fraud_type, BlacklistEntry.severity).all()
            
            return {
                'daily_trends': [{
                    'date': trend[0].isoformat(),
                    'total_attempts': trend[1],
                    'fraud_attempts': trend[2] or 0,
                    'fraud_rate': round((trend[2] or 0) / trend[1] * 100, 2) if trend[1] > 0 else 0,
                    'avg_risk_score': round(float(trend[3] or 0), 2)
                } for trend in daily_trends],
                
                'targeted_institutions': [{
                    'institution': target[0] or 'Unknown',
                    'fraud_count': target[1]
                } for target in targeted_institutions],
                
                'suspicious_ips': [{
                    'ip_address': ip[0],
                    'total_attempts': ip[1],
                    'fraud_attempts': ip[2] or 0,
                    'fraud_rate': round((ip[2] or 0) / ip[1] * 100, 2)
                } for ip in suspicious_ips],
                
                'fraud_patterns': [{
                    'type': pattern[0],
                    'severity': pattern[1],
                    'count': pattern[2]
                } for pattern in fraud_patterns]
            }, 200
            
        except Exception as e:
            return {'error': f'Trends analysis failed: {str(e)}'}, 500

class BlacklistManagement(Resource):
    """Manage blacklisted certificates and offenders"""
    
    @jwt_required()
    def get(self):
        """Get blacklist entries"""
        try:
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or user.role != 'admin':
                return {'error': 'Admin access required'}, 403
            
            # Pagination
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 20, type=int)
            
            # Filters
            fraud_type = request.args.get('fraud_type')
            severity = request.args.get('severity')
            active_only = request.args.get('active_only', 'true').lower() == 'true'
            
            query = BlacklistEntry.query
            
            if fraud_type:
                query = query.filter_by(fraud_type=fraud_type)
            if severity:
                query = query.filter_by(severity=severity)
            if active_only:
                query = query.filter_by(is_active=True)
            
            entries = query.order_by(desc(BlacklistEntry.created_at)).paginate(
                page=page, per_page=per_page, error_out=False
            )
            
            return {
                'blacklist_entries': [entry.to_dict() for entry in entries.items],
                'pagination': {
                    'page': entries.page,
                    'pages': entries.pages,
                    'per_page': entries.per_page,
                    'total': entries.total,
                    'has_next': entries.has_next,
                    'has_prev': entries.has_prev
                }
            }, 200
            
        except Exception as e:
            return {'error': f'Blacklist fetch failed: {str(e)}'}, 500
    
    @jwt_required()
    def post(self):
        """Add entry to blacklist"""
        try:
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or user.role != 'admin':
                return {'error': 'Admin access required'}, 403
            
            args = blacklist_parser.parse_args()
            
            # Validate fraud type
            valid_fraud_types = ['fake_cert', 'data_manipulation', 'identity_theft', 'institution_impersonation', 'other']
            if args['fraud_type'] not in valid_fraud_types:
                return {'error': 'Invalid fraud type'}, 400
            
            # Validate severity
            valid_severities = ['low', 'medium', 'high', 'critical']
            if args['severity'] not in valid_severities:
                return {'error': 'Invalid severity level'}, 400
            
            blacklist_entry = BlacklistEntry(
                certificate_id=args.get('certificate_id'),
                name=args.get('name'),
                roll_no=args.get('roll_no'),
                institution_name=args.get('institution_name'),
                reason=args['reason'],
                evidence=args.get('evidence'),
                fraud_type=args['fraud_type'],
                severity=args['severity'],
                reported_by=user_id,
                ip_address=request.remote_addr
            )
            
            db.session.add(blacklist_entry)
            db.session.commit()
            
            return {
                'message': 'Entry added to blacklist successfully',
                'entry': blacklist_entry.to_dict()
            }, 201
            
        except Exception as e:
            return {'error': f'Blacklist addition failed: {str(e)}'}, 500

class BlacklistEntry_API(Resource):
    """Individual blacklist entry management"""
    
    @jwt_required()
    def patch(self, entry_id):
        """Update blacklist entry (activate/deactivate)"""
        try:
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or user.role != 'admin':
                return {'error': 'Admin access required'}, 403
            
            entry = BlacklistEntry.query.get(entry_id)
            if not entry:
                return {'error': 'Blacklist entry not found'}, 404
            
            action = request.json.get('action')
            
            if action == 'deactivate':
                entry.is_active = False
                message = 'Blacklist entry deactivated'
            elif action == 'activate':
                entry.is_active = True
                message = 'Blacklist entry activated'
            else:
                return {'error': 'Invalid action. Use "activate" or "deactivate"'}, 400
            
            db.session.commit()
            
            return {
                'message': message,
                'entry': entry.to_dict()
            }, 200
            
        except Exception as e:
            return {'error': f'Blacklist update failed: {str(e)}'}, 500
    
    @jwt_required()
    def delete(self, entry_id):
        """Delete blacklist entry"""
        try:
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or user.role != 'admin':
                return {'error': 'Admin access required'}, 403
            
            entry = BlacklistEntry.query.get(entry_id)
            if not entry:
                return {'error': 'Blacklist entry not found'}, 404
            
            db.session.delete(entry)
            db.session.commit()
            
            return {'message': 'Blacklist entry deleted successfully'}, 200
            
        except Exception as e:
            return {'error': f'Blacklist deletion failed: {str(e)}'}, 500

class VerificationHistory(Resource):
    """Enhanced verification history with filtering"""
    
    @jwt_required()
    def get(self):
        """Get detailed verification history"""
        try:
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or user.role != 'admin':
                return {'error': 'Admin access required'}, 403
            
            # Pagination
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 50, type=int)
            
            # Filters
            is_valid = request.args.get('is_valid')
            min_risk_score = request.args.get('min_risk_score', type=float)
            days_back = request.args.get('days_back', 30, type=int)
            
            query = VerificationLog.query
            
            # Date filter
            start_date = datetime.utcnow() - timedelta(days=days_back)
            query = query.filter(VerificationLog.created_at >= start_date)
            
            # Validity filter
            if is_valid is not None:
                is_valid_bool = is_valid.lower() == 'true'
                query = query.filter_by(is_valid=is_valid_bool)
            
            # Risk score filter
            if min_risk_score is not None:
                query = query.filter(VerificationLog.risk_score >= min_risk_score)
            
            logs = query.order_by(desc(VerificationLog.created_at)).paginate(
                page=page, per_page=per_page, error_out=False
            )
            
            # Enhanced log data with risk indicators
            enhanced_logs = []
            for log in logs.items:
                log_dict = log.to_dict()
                
                # Add risk indicators
                risk_indicators = []
                if log.risk_score >= 80:
                    risk_indicators.append('Very High Risk')
                elif log.risk_score >= 60:
                    risk_indicators.append('High Risk')
                elif log.risk_score >= 40:
                    risk_indicators.append('Medium Risk')
                
                if not log.is_valid:
                    risk_indicators.append('Certificate Not Found')
                
                if log.confidence_score < 70:
                    risk_indicators.append('Low OCR Confidence')
                
                log_dict['risk_indicators'] = risk_indicators
                enhanced_logs.append(log_dict)
            
            return {
                'verification_logs': enhanced_logs,
                'pagination': {
                    'page': logs.page,
                    'pages': logs.pages,
                    'per_page': logs.per_page,
                    'total': logs.total,
                    'has_next': logs.has_next,
                    'has_prev': logs.has_prev
                }
            }, 200
            
        except Exception as e:
            return {'error': f'Verification history fetch failed: {str(e)}'}, 500

class AdminStats(Resource):
    """Detailed statistics for admin dashboard"""
    
    @jwt_required()
    def get(self):
        """Get comprehensive system statistics"""
        try:
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or user.role != 'admin':
                return {'error': 'Admin access required'}, 403
            
            # Time-based statistics
            now = datetime.utcnow()
            last_24h = now - timedelta(hours=24)
            last_week = now - timedelta(days=7)
            last_month = now - timedelta(days=30)
            
            stats = {
                'system_overview': {
                    'total_users': User.query.count(),
                    'active_users': User.query.filter_by(is_active=True).count(),
                    'admin_users': User.query.filter_by(role='admin').count(),
                    'institution_users': User.query.filter_by(role='institution').count(),
                },
                'certificates': {
                    'total_certificates': Certificate.query.count(),
                    'verified_certificates': Certificate.query.filter_by(is_verified=True).count(),
                    'certificates_by_institution': db.session.query(
                        Institution.name,
                        func.count(Certificate.id)
                    ).join(Certificate).group_by(Institution.id).all()
                },
                'verifications': {
                    'total_verifications': VerificationLog.query.count(),
                    'last_24h': VerificationLog.query.filter(VerificationLog.created_at >= last_24h).count(),
                    'last_week': VerificationLog.query.filter(VerificationLog.created_at >= last_week).count(),
                    'last_month': VerificationLog.query.filter(VerificationLog.created_at >= last_month).count(),
                    'success_rate': self._calculate_success_rate(),
                },
                'fraud_detection': {
                    'total_fraud_attempts': VerificationLog.query.filter_by(is_valid=False).count(),
                    'fraud_last_24h': VerificationLog.query.filter(
                        VerificationLog.is_valid == False,
                        VerificationLog.created_at >= last_24h
                    ).count(),
                    'high_risk_attempts': VerificationLog.query.filter(
                        VerificationLog.risk_score >= 70
                    ).count(),
                    'blacklisted_entries': BlacklistEntry.query.filter_by(is_active=True).count()
                }
            }
            
            return stats, 200
            
        except Exception as e:
            return {'error': f'Stats calculation failed: {str(e)}'}, 500
    
    def _calculate_success_rate(self):
        """Calculate verification success rate"""
        total = VerificationLog.query.count()
        if total == 0:
            return 100.0
        
        valid = VerificationLog.query.filter_by(is_valid=True).count()
        return round((valid / total) * 100, 2)