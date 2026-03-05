from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_restx import Api, Resource, fields, Namespace
from datetime import datetime, timedelta, timezone
import jwt
import uuid
import string
import random
import os
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///workshop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'workshop-secret-key-not-for-production'

# Initialize extensions
db = SQLAlchemy(app)

# Add root route BEFORE Flask-RESTX initialization
@app.route('/')
def root_endpoint():
    """Welcome message for API Workshop"""
    response = {
        'status': 200,
            'message': {'1':'Welcome to API Workshop! To get started, use your API key to obtain a token at /api/auth/token',
            '2': 'I\'ll help you out with first cURL command...',
            '3': 'curl -X POST \'{"API_HOST"}\'-H "Content-Type: application/json" -d \'{"api_key": "YOUR_API_KEY"}\''}
            }
    return jsonify(response), 200

# Initialize Flask-RESTX with custom docs URL
api = Api(app, 
    title='API Workshop', 
    version='1.0', 
    description='CRUD API for workshop Bayer IA Team Workshop',
    doc='/hidden/swagger/'
)

# Admin password for adding users
ADMIN_PASSWORD = 'workshop_admin_pass'

# Models
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    api_key = db.Column(db.String(64), unique=True, nullable=False)
    task_id = db.Column(db.String(64), unique=True, nullable=True)
    certification_id = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    tokens = db.relationship('Token', backref='user', lazy=True, cascade='all, delete-orphan')

class Token(db.Model):
    __tablename__ = 'tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class Task(db.Model):
    __tablename__ = 'tasks'
    
    task_record_id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(120), db.ForeignKey('users.email'), nullable=False)
    action_id = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(20), default='pending')
    data = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('task_id', 'email', name='_task_email_uc'),)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    task_record_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    endpoint = db.Column(db.String(255), nullable=True)
    method = db.Column(db.String(10), nullable=True)
    request_status = db.Column(db.Integer, nullable=True)
    response_data = db.Column(db.Text, nullable=True)
    request_data = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Utility functions
def generate_random_string(length):
    """Generate a random string of specified length"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_api_key():
    """Generate a unique API key"""
    return str(uuid.uuid4()).replace('-', '')

def generate_task_id():
    """Generate a random 15-character task ID"""
    return generate_random_string(15)

def generate_certification_id():
    """Generate certification ID with 'cert_' prefix"""
    return f"cert_{generate_random_string(20)}"

def generate_action_id():
    """Generate a random action ID"""
    return generate_random_string(10)

def log_audit(user_email=None, action='', task_record_id=None, details='', 
              endpoint='', method='', status=200, response_data='', request_data=''):
    """Log audit information"""
    try:
        audit_log = AuditLog(
            user_email=user_email,
            action=action,
            task_record_id=task_record_id,
            details=details,
            endpoint=endpoint,
            method=method,
            request_status=status,
            response_data=str(response_data),
            request_data=str(request_data),
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent') if request else None
        )
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        print(f"Audit log error: {e}")

def token_required(f):
    """Decorator to require valid token"""
    @wraps(f)
    def decorated(self, *args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                pass
        if not token:
            log_audit(action='Token Missing', endpoint=request.endpoint, method=request.method, status=401)
            return {'status': 401, 'message': 'Token is missing', 'error_code': 'TOKEN_MISSING'}, 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_email = data['email']
            token_obj = Token.query.filter_by(token=token, is_active=True).first()
            if not token_obj:
                log_audit(user_email=current_user_email, action='Invalid Token', endpoint=request.endpoint, method=request.method, status=401)
                return {'status': 401, 'message': 'Token is invalid', 'error_code': 'TOKEN_INVALID'}, 401
            # Ensure both datetimes are timezone-aware for comparison
            expires_at_aware = token_obj.expires_at.replace(tzinfo=timezone.utc) if token_obj.expires_at.tzinfo is None else token_obj.expires_at
            if expires_at_aware < datetime.now(timezone.utc):
                token_obj.is_active = False
                db.session.commit()
                log_audit(user_email=current_user_email, action='Token Expired', endpoint=request.endpoint, method=request.method, status=401)
                return {'status': 401, 'message': 'Token has expired', 'error_code': 'TOKEN_EXPIRED'}, 401
            current_user = User.query.filter_by(email=current_user_email).first()
            if not current_user:
                log_audit(user_email=current_user_email, action='User Not Found', endpoint=request.endpoint, method=request.method, status=401)
                return {'status': 401, 'message': 'User not found', 'error_code': 'USER_NOT_FOUND'}, 401
        except jwt.ExpiredSignatureError:
            # Decode token without verifying expiration to get email
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'], options={"verify_exp": False})
                user_email = data.get('email')
            except Exception:
                user_email = None
            log_audit(user_email=user_email, action='Token Expired (JWT)', endpoint=request.endpoint, method=request.method, status=401)
            return {'status': 401, 'message': 'Your token has expired. Obtain a new one by calling the /auth/token endpoint with your API key.', 'error_code': 'TOKEN_EXPIRED'}, 401
        except jwt.InvalidTokenError:
            # Try to decode to get email, but may fail
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'], options={"verify_exp": False})
                user_email = data.get('email')
            except Exception:
                user_email = None
            log_audit(user_email=user_email, action='Invalid Token (JWT)', endpoint=request.endpoint, method=request.method, status=401)
            return {'status': 401, 'message': 'Token is invalid. Are you sure you got the right token?', 'error_code': 'TOKEN_INVALID'}, 401
        return f(self, current_user=current_user, *args, **kwargs)
    return decorated

# Define API models for Swagger documentation
auth_model = api.model('Auth', {
    'api_key': fields.String(required=True, description='User API key', example='abc123def456')
})

token_response_model = api.model('TokenResponse', {
    'status': fields.Integer(description='HTTP status code', example=200),
    'token': fields.String(description='JWT token', example='eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'),
    'expires_at': fields.String(description='Token expiration time', example='2023-07-18T15:30:00Z'),
    'message': fields.String(description='Success message', example='Token generated successfully'),
    'task 1': fields.String(description='Task 1 endpoint', example='/task1')
})

task1_response_model = api.model('Task1Response', {
    'status': fields.Integer(description='HTTP status code', example=200),
    'task_id': fields.String(description='Generated task ID', example='abcd1234efgh567'),
    'email': fields.String(description='User email', example='user@example.com'),
    'next_endpoint': fields.String(description='Next task endpoint', example='/api/task2'),
    'description': fields.String(description='Task description', example='Use POST request to save this task_id')
})

task2_model = api.model('Task2', {
    'task_id': fields.String(required=True, description='Task ID from task 1', example='abcd1234efgh567')
})

task2_response_model = api.model('Task2Response', {
    'status': fields.Integer(description='HTTP status code', example=201),
    'task_record_id': fields.Integer(description='Generated task record ID', example=123),
    'message': fields.String(description='Success message', example='Task saved successfully'),
    'next_endpoint': fields.String(description='Next task endpoint', example='/api/task3/123'),
    'description': fields.String(description='Task description', example='Use PUT request to update this record')
})

task3_model = api.model('Task3', {
    'data': fields.String(required=True, description='Data to update', example='Updated task data')
})

task3_response_model = api.model('Task3Response', {
    'status': fields.Integer(description='HTTP status code', example=200),
    'action_id': fields.String(description='Generated action ID', example='act123456'),
    'message': fields.String(description='Success message', example='Task updated successfully'),
    'next_endpoint': fields.String(description='Next task endpoint', example='/api/task4'),
    'description': fields.String(description='Task description', example='Use DELETE request with action_id to complete the workflow')
})

task4_model = api.model('Task4', {
    'action_id': fields.String(required=True, description='Action ID from task 3', example='act123456')
})

task4_response_model = api.model('Task4Response', {
    'status': fields.Integer(description='HTTP status code', example=200),
    'certification_id': fields.String(description='User certification ID', example='cert_abcd1234567890123456'),
    'message': fields.String(description='Success message', example='Task completed successfully! You have finished the workshop.')
})

error_model = api.model('Error', {
    'status': fields.Integer(description='HTTP status code', example=400),
    'message': fields.String(description='Error message', example='Error description'),
    'error_code': fields.String(description='Error code', example='ERROR_CODE')
})

# Create namespaces
auth_ns = Namespace('auth', description='Authentication operations')
task_ns = Namespace('tasks', description='Workshop task operations')

api.add_namespace(auth_ns, path='/api')
api.add_namespace(task_ns, path='/api')

# Define response model for home endpoint
home_response_model = api.model('HomeResponse', {
    'status': fields.Integer(description='HTTP status code', example=200),
    'message': fields.String(description='Welcome message', example='Welcome to API Workshop!')
})

# Add welcome endpoint using Flask-RESTX after namespaces
@api.route('/welcome')
class Welcome(Resource):
    @api.marshal_with(home_response_model)
    @api.response(200, 'Success', home_response_model)
    def get(self):
        """Welcome message for API Workshop"""
        response = {
            'status': 200,
            'message': {'1':'Welcome to API Workshop! To get started, use your API key to obtain a token at /api/auth/token',
            '2': 'Below sample cURL command:',
            '3': 'curl -X POST \'{"API_HOST"}\'-H "Content-Type: application/json" -d \'{"api_key": "YOUR_API_KEY"}\''}
        }
        return response, 200

@auth_ns.route('/auth/token')
class AuthToken(Resource):
    @auth_ns.expect(auth_model)
    @auth_ns.response(200, 'Success', token_response_model)
    @auth_ns.response(400, 'Bad Request', error_model)
    @auth_ns.response(401, 'Unauthorized', error_model)
    @auth_ns.response(404, 'User Not Found', error_model)
    def post(self):
        """Get authentication token using API key"""
        try:
            # Check for valid JSON first
            if not request.is_json:
                log_audit(action='Malformed JSON', endpoint='/api/auth/token', method='POST', status=400, details='Request is not a valid JSON format')
                return {'status': 400, 'message': 'Malformed JSON. Please send a valid JSON format, as per initial documentation.', 'error_code': 'MALFORMED_JSON'}, 400

            data = request.get_json(silent=True)
            if not data or 'api_key' not in data:
                log_audit(action='Missing API Key', endpoint='/api/auth/token', method='POST', status=400, request_data=str(data))
                return {'status': 400, 'message': 'API key is required. Please provide your API key in the JSON body as {"api_key": "YOUR_KEY"}', 'error_code': 'API_KEY_REQUIRED'}, 400

            api_key = data['api_key']
            user = User.query.filter_by(api_key=api_key).first()
            if not user:
                log_audit(action='Invalid API Key', endpoint='/api/auth/token', method='POST', status=404, request_data=str(data))
                return {'status': 404, 'message': 'Invalid API key!!! Check if your key is valid. You should\'ve received your key prior to the workshop.', 'error_code': 'INVALID_API_KEY'}, 404

            # Validate user model fields
            if not user.email:
                log_audit(user_email=None, action='User Model Error', endpoint='/api/auth/token', method='POST', status=500, details='User email missing')
                return {'status': 500, 'message': 'User record is corrupted (missing email). Contact workshop admin.', 'error_code': 'USER_MODEL_ERROR'}, 500

            # Deactivate old tokens
            try:
                Token.query.filter_by(user_id=user.id, is_active=True).update({'is_active': False})
                db.session.commit()
            except Exception as db_err:
                log_audit(user_email=user.email, action='DB Error (Deactivate Tokens)', endpoint='/api/auth/token', method='POST', status=500, details=str(db_err))
                return {'status': 500, 'message': 'Database error while deactivating old tokens.', 'error_code': 'DB_ERROR'}, 500

            # Create new token
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
            token_payload = {
                'email': user.email,
                'exp': expires_at
            }
            try:
                token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
            except Exception as jwt_err:
                log_audit(user_email=user.email, action='JWT Encode Error', endpoint='/api/auth/token', method='POST', status=500, details=str(jwt_err))
                return {'status': 500, 'message': 'Error generating token. Tell workshop admin what you\'ve done.', 'error_code': 'JWT_ERROR'}, 500

            # Save token to database
            try:
                token_obj = Token(
                    token=token,
                    user_id=user.id,
                    expires_at=expires_at
                )
                db.session.add(token_obj)
                db.session.commit()
            except Exception as db_err:
                log_audit(user_email=user.email, action='DB Error (Save Token)', endpoint='/api/auth/token', method='POST', status=500, details=str(db_err))
                return {'status': 500, 'message': 'Database error while saving token.', 'error_code': 'DB_ERROR'}, 500

            response = {
                'status': 200,
                'token': token,
                'expires_at': expires_at.isoformat() + 'Z',
                'message': 'Token generated successfully. You have 5 minutes to use it... Tick-tock!',
                'task 1': '/api/task1'
            }

            log_audit(user_email=user.email, action='Token Generated', endpoint='/api/auth/token', method='POST', status=200, response_data=str(response))

            return response

        except Exception as e:
            log_audit(action='Token Generation Error', endpoint='/api/auth/token', method='POST', status=500, details=str(e))
            return {'status': 500, 'message': 'Token generation error, please try again later.', 'error_code': 'SERVER_ERROR'}, 500


########################################### TASK 1 ###########################################
@task_ns.route('/task1')
class Task1(Resource):
    # @task_ns.marshal_with(task1_response_model)
    @task_ns.response(200, 'Success', task1_response_model)
    @task_ns.response(400, 'Bad Request', error_model)
    @task_ns.response(401, 'Unauthorized', error_model)
    @task_ns.response(404, 'Not Found', error_model)
    @task_ns.doc(security='Bearer')
    @token_required
    def get(self, current_user=None):
        """Task 1: Get task ID and next task information"""
        try:
            # Generate task_id if not exists
            if not current_user.task_id:
                current_user.task_id = generate_task_id()
                db.session.commit()
            
            response = {
                'status': 200,
                'task_id': current_user.task_id,
                'email': current_user.email,
                'next_endpoint': '/api/task2',
                'description': 'Use POST request to save this task_id to the tasks table. Refer to API.md for more details or ask Bartek :)'
            }
            
            log_audit(user_email=current_user.email, action='Task 1 Completed', 
                     endpoint='/api/task1', method='GET', status=200, response_data=str(response))
            
            return response
            
        except Exception as e:
            log_audit(user_email=current_user.email, action='Task 1 Error', 
                     endpoint='/api/task1', method='GET', status=500, details=str(e))
            return {'status': 500, 'message': 'Internal server error. Please try again later.', 'error_code': 'SERVER_ERROR'}, 500


########################################### TASK 2 ###########################################
@task_ns.route('/task2')
class Task2(Resource):
    @task_ns.expect(task2_model)
    # @task_ns.marshal_with(task2_response_model)
    @task_ns.response(201, 'Created', task2_response_model)
    @task_ns.response(400, 'Bad Request', error_model)
    @task_ns.response(401, 'Unauthorized', error_model)
    @task_ns.response(404, 'Not Found', error_model)
    @task_ns.doc(security='Bearer')
    @token_required
    def post(self, current_user=None):
        """Task 2: Save task ID to tasks table"""
        try:
            data = request.get_json()
            if not data or 'task_id' not in data:
                log_audit(user_email=current_user.email, action='Task 2 Missing Data', 
                         endpoint='/api/task2', method='POST', status=400, request_data=str(data))
                return {'status': 400, 'message': 'task_id is required! Did you get it from previous task?', 'error_code': 'TASK_ID_REQUIRED'}, 400
            
            task_id = data['task_id']
            
            # Verify task_id belongs to current user
            if current_user.task_id != task_id:
                log_audit(user_email=current_user.email, action='Task 2 Invalid Task ID', 
                         endpoint='/api/task2', method='POST', status=400, request_data=str(data))
                return {'status': 400, 'message': 'This is not your task_id! Naughty, naughty...', 'error_code': 'INVALID_TASK_ID', 'YOUR task_id': current_user.task_id}, 400
            
            # Check if task already exists
            existing_task = Task.query.filter_by(task_id=task_id, email=current_user.email).first()
            if existing_task:
                log_audit(user_email=current_user.email, action='Task 2 Duplicate', 
                         endpoint='/api/task2', method='POST', status=400, request_data=str(data))
                return {'status': 400, 'message': 'Task already exists!', 'error_code': 'TASK_EXISTS', 'task_id': task_id}, 400
            
            # Create new task
            new_task = Task(
                task_id=task_id,
                email=current_user.email,
                status='pending'
            )
            db.session.add(new_task)
            db.session.commit()
            
            response = {
                'status': 201,
                'task_record_id': new_task.task_record_id,
                'message': 'Task saved successfully',
                'next_endpoint': f'/api/task3/{new_task.task_record_id}',
                'description': 'Use PUT request to update this record by task_record_id. Refer to API.md for more details or ask Bartek :)'
            }
            
            log_audit(user_email=current_user.email, action='Task 2 Completed', 
                     task_record_id=new_task.task_record_id, endpoint='/api/task2', 
                     method='POST', status=201, response_data=str(response))
            
            return response, 201
            
        except Exception as e:
            log_audit(user_email=current_user.email, action='Task 2 Error', 
                     endpoint='/api/task2', method='POST', status=500, details=str(e))
            return {'status': 500, 'message': 'Internal server error', 'error_code': 'SERVER_ERROR'}, 500


########################################### TASK 3 ###########################################
@task_ns.route('/task3/<int:task_record_id>')
class Task3(Resource):
    @task_ns.expect(task3_model)
    # @task_ns.marshal_with(task3_response_model)
    @task_ns.response(200, 'Success', task3_response_model)
    @task_ns.response(400, 'Bad Request', error_model)
    @task_ns.response(401, 'Unauthorized', error_model)
    @task_ns.response(404, 'Not Found', error_model)
    @task_ns.doc(security='Bearer')
    @token_required
    def put(self, task_record_id, current_user=None):
        """Task 3: Update task record by task_record_id"""
        try:
            data = request.get_json()
            if not data or 'data' not in data:
                log_audit(user_email=current_user.email, action='Task 3 Missing Data', 
                         task_record_id=task_record_id, endpoint=f'/api/task3/{task_record_id}', 
                         method='PUT', status=400, request_data=str(data))
                return {'status': 400, 'message': 'Data field is required. Did you forget \'task_record_id\'?', 'error_code': 'DATA_REQUIRED'}, 400
            
            # Find task belonging to current user
            task = Task.query.filter_by(task_record_id=task_record_id, email=current_user.email).first()
            if not task:
                log_audit(user_email=current_user.email, action='Task 3 Not Found', 
                         task_record_id=task_record_id, endpoint=f'/api/task3/{task_record_id}', 
                         method='PUT', status=404, request_data=str(data))
                return {'status': 404, 'message': 'Task not found by task_record_id or not owned by you... Check it properly.', 'error_code': 'TASK_NOT_FOUND'}, 404
            
            # Update task
            task.data = data['data']
            task.status = 'updated'
            
            # Generate action_id if not exists
            if not task.action_id:
                task.action_id = generate_action_id()
            
            db.session.commit()
            
            response = {
                'status': 200,
                'action_id': task.action_id,
                'message': 'Task updated successfully',
                'next_endpoint': '/api/task4',
                'description': 'Use DELETE request with the action_id to complete the workshop'
            }
            
            log_audit(user_email=current_user.email, action='Task 3 Completed', 
                     task_record_id=task_record_id, endpoint=f'/api/task3/{task_record_id}', 
                     method='PUT', status=200, response_data=str(response))
            
            return response
            
        except Exception as e:
            log_audit(user_email=current_user.email, action='Task 3 Error', 
                     task_record_id=task_record_id, endpoint=f'/api/task3/{task_record_id}', 
                     method='PUT', status=500, details=str(e))
            return {'status': 500, 'message': 'Internal server error', 'error_code': 'SERVER_ERROR'}, 500


########################################### TASK 4 ###########################################
@task_ns.route('/task4')
class Task4(Resource):
    @task_ns.expect(task4_model)
    # @task_ns.marshal_with(task4_response_model)
    @task_ns.response(200, 'Success', task4_response_model)
    @task_ns.response(400, 'Bad Request', error_model)
    @task_ns.response(401, 'Unauthorized', error_model)
    @task_ns.response(404, 'Not Found', error_model)
    @task_ns.doc(security='Bearer')
    @token_required
    def delete(self, current_user=None):
        """Task 4: Delete task record by action_id"""
        try:
            data = request.get_json()
            if not data or 'action_id' not in data:
                log_audit(user_email=current_user.email, action='Task 4 Missing Data', 
                         endpoint='/api/task4', method='DELETE', status=400, request_data=str(data))
                return {'status': 400, 'message': 'action_id is required', 'error_code': 'ACTION_ID_REQUIRED'}, 400
            
            action_id = data['action_id']
            
            # Find task belonging to current user
            task = Task.query.filter_by(action_id=action_id, email=current_user.email).first()
            if not task:
                log_audit(user_email=current_user.email, action='Task 4 Not Found', 
                         endpoint='/api/task4', method='DELETE', status=404, request_data=str(data))
                return {'status': 404, 'message': 'Task not found or not owned by user', 'error_code': 'TASK_NOT_FOUND'}, 404
            
            # Generate certification_id if not exists
            if not current_user.certification_id:
                current_user.certification_id = generate_certification_id()
            
            # Delete task
            task_record_id = task.task_record_id
            db.session.delete(task)
            db.session.commit()
            
            response = {
                'status': 200,
                'certification_id': current_user.certification_id,
                'message': 'Task completed successfully! You have finished the workshop. Call a bonus endpoint to get your certificate picture! :)'
            }
            
            log_audit(user_email=current_user.email, action='Task 4 Completed', 
                     task_record_id=task_record_id, endpoint='/api/task4', 
                     method='DELETE', status=200, response_data=str(response))
            
            return response
            
        except Exception as e:
            log_audit(user_email=current_user.email, action='Task 4 Error', 
                     endpoint='/api/task4', method='DELETE', status=500, details=str(e))
            return {'status': 500, 'message': 'Internal server error', 'error_code': 'SERVER_ERROR'}, 500

########################################### ADD USER ###########################################
@app.route('/admin/add_user', methods=['POST'])
def add_user():
    """Hidden endpoint to add users (requires admin password)"""
    try:
        # Check admin password
        admin_pass = request.headers.get('X-Admin-Password')
        if admin_pass != ADMIN_PASSWORD:
            return jsonify({'status': 401, 'message': 'Unauthorized', 'error_code': 'UNAUTHORIZED'}), 401
        
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({'status': 400, 'message': 'Email is required', 'error_code': 'EMAIL_REQUIRED'}), 400
        
        email = data['email']
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'status': 400, 'message': 'User already exists', 'error_code': 'USER_EXISTS'}), 400
        
        # Create new user (certification_id is earned by completing all tasks)
        new_user = User(
            email=email,
            api_key=generate_api_key()
        )
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'status': 201,
            'message': 'User created successfully',
            'user_id': new_user.id,
            'email': new_user.email,
            'api_key': new_user.api_key
        }), 201
        
    except Exception as e:
        return jsonify({'status': 500, 'message': 'Internal server error', 'error_code': 'SERVER_ERROR'}), 500

########################################### AUDIT STATISTICS WEBPAGE ###########################################
@app.route('/admin/audit_stats')
def audit_stats_webpage():
    """Admin webpage to show audit log statistics in hierarchical format"""
    try:
        # Get all audit logs ordered by email and timestamp
        audit_logs = AuditLog.query.order_by(AuditLog.user_email, AuditLog.timestamp.desc()).all()
        
        # Build hierarchical structure
        stats = {}
        total_records = len(audit_logs)
        
        for log in audit_logs:
            email = log.user_email or 'Anonymous'
            action = log.action or 'Unknown Action'
            
            # Initialize email structure if not exists
            if email not in stats:
                stats[email] = {
                    'total_actions': 0,
                    'actions': {}
                }
            
            # Initialize action structure if not exists
            if action not in stats[email]['actions']:
                stats[email]['actions'][action] = {
                    'count': 0,
                    'records': []
                }
            
            # Add record details
            record_detail = {
                'id': log.id,
                'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S') if log.timestamp else 'N/A',
                'endpoint': log.endpoint or 'N/A',
                'method': log.method or 'N/A',
                'status': log.request_status or 'N/A',
                'details': log.details or 'N/A',
                'task_record_id': log.task_record_id or 'N/A',
                'ip_address': log.ip_address or 'N/A',
                'user_agent': log.user_agent or 'N/A',
                'request_data': log.request_data or 'N/A',
                'response_data': log.response_data or 'N/A'
            }
            
            stats[email]['actions'][action]['records'].append(record_detail)
            stats[email]['actions'][action]['count'] += 1
            stats[email]['total_actions'] += 1
        
        # Calculate summary statistics
        summary = {
            'total_records': total_records,
            'total_users': len(stats),
            'users_with_actions': sum(1 for email_stats in stats.values() if email_stats['total_actions'] > 0)
        }
        
        # HTML template
        html_template = '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>API Workshop - Audit Log Statistics</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background-color: #f5f5f5;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    padding: 20px;
                }
                h1 {
                    color: #333;
                    text-align: center;
                    margin-bottom: 30px;
                }
                .summary {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 8px;
                    margin-bottom: 30px;
                    display: flex;
                    justify-content: space-around;
                    text-align: center;
                }
                .summary-item h3 {
                    margin: 0;
                    font-size: 2em;
                }
                .summary-item p {
                    margin: 5px 0 0 0;
                    opacity: 0.9;
                }
                .tree {
                    margin: 20px 0;
                }
                .email-node {
                    margin: 10px 0;
                    border: 2px solid #e1e5e9;
                    border-radius: 8px;
                    background: #fafbfc;
                }
                .email-header {
                    padding: 15px;
                    background: linear-gradient(135deg, #4CAF50, #45a049);
                    color: white;
                    cursor: pointer;
                    border-radius: 6px 6px 0 0;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .email-header:hover {
                    background: linear-gradient(135deg, #45a049, #3d8b40);
                }
                .action-node {
                    margin: 5px 15px;
                    border-left: 3px solid #2196F3;
                    background: white;
                    border-radius: 5px;
                }
                .action-header {
                    padding: 10px 15px;
                    background: #f8f9fa;
                    cursor: pointer;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    border-radius: 5px;
                }
                .action-header:hover {
                    background: #e9ecef;
                }
                .records {
                    display: none;
                    padding: 0;
                }
                .record {
                    padding: 10px 15px;
                    border-top: 1px solid #e9ecef;
                    font-size: 0.9em;
                }
                .record:nth-child(even) {
                    background: #f8f9fa;
                }
                .record-detail {
                    margin: 3px 0;
                    display: flex;
                }
                .record-label {
                    font-weight: bold;
                    width: 140px;
                    color: #555;
                }
                .record-value {
                    color: #333;
                    word-break: break-all;
                }
                .badge {
                    background: #007bff;
                    color: white;
                    padding: 2px 8px;
                    border-radius: 12px;
                    font-size: 0.8em;
                    font-weight: bold;
                }
                .toggle-icon {
                    font-size: 1.2em;
                    transition: transform 0.3s;
                }
                .expanded .toggle-icon {
                    transform: rotate(90deg);
                }
                .status-200 { color: #28a745; font-weight: bold; }
                .status-400, .status-404 { color: #ffc107; font-weight: bold; }
                .status-401 { color: #dc3545; font-weight: bold; }
                .status-500 { color: #dc3545; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔍 API Workshop - Audit Log Statistics</h1>
                
                <div class="summary">
                    <div class="summary-item">
                        <h3>''' + str(summary['total_records']) + '''</h3>
                        <p>Total Records</p>
                    </div>
                    <div class="summary-item">
                        <h3>''' + str(summary['total_users']) + '''</h3>
                        <p>Total Users</p>
                    </div>
                    <div class="summary-item">
                        <h3>''' + str(summary['users_with_actions']) + '''</h3>
                        <p>Active Users</p>
                    </div>
                </div>
                
                <div class="tree">
        '''
        
        # Generate user nodes
        for email, email_data in stats.items():
            html_template += f'''
                    <div class="email-node">
                        <div class="email-header" onclick="toggleEmail(this)">
                            <span>👤 {email}</span>
                            <span><span class="badge">{email_data['total_actions']} actions</span> <span class="toggle-icon">▶</span></span>
                        </div>
                        <div class="email-content" style="display: none;">
            '''
            
            # Generate action nodes for this email
            for action, action_data in email_data['actions'].items():
                html_template += f'''
                            <div class="action-node">
                                <div class="action-header" onclick="toggleAction(this)">
                                    <span>🔧 {action}</span>
                                    <span><span class="badge">{action_data['count']} records</span> <span class="toggle-icon">▶</span></span>
                                </div>
                                <div class="records">
                '''
                
                # Generate record details for this action
                for i, record in enumerate(action_data['records']):
                    status_class = f"status-{str(record['status'])[:3]}" if str(record['status']).isdigit() else ""
                    html_template += f'''
                                    <div class="record">
                                        <div class="record-detail">
                                            <span class="record-label">ID:</span>
                                            <span class="record-value">#{record['id']}</span>
                                        </div>
                                        <div class="record-detail">
                                            <span class="record-label">Timestamp:</span>
                                            <span class="record-value">{record['timestamp']}</span>
                                        </div>
                                        <div class="record-detail">
                                            <span class="record-label">Endpoint:</span>
                                            <span class="record-value">{record['endpoint']}</span>
                                        </div>
                                        <div class="record-detail">
                                            <span class="record-label">Method:</span>
                                            <span class="record-value">{record['method']}</span>
                                        </div>
                                        <div class="record-detail">
                                            <span class="record-label">Status:</span>
                                            <span class="record-value {status_class}">{record['status']}</span>
                                        </div>
                                        <div class="record-detail">
                                            <span class="record-label">Details:</span>
                                            <span class="record-value">{record['details']}</span>
                                        </div>
                                        <div class="record-detail">
                                            <span class="record-label">Task Record ID:</span>
                                            <span class="record-value">{record['task_record_id']}</span>
                                        </div>
                                        <div class="record-detail">
                                            <span class="record-label">IP Address:</span>
                                            <span class="record-value">{record['ip_address']}</span>
                                        </div>
                                        <div class="record-detail">
                                            <span class="record-label">User Agent:</span>
                                            <span class="record-value">{record['user_agent']}</span>
                                        </div>
                                    </div>
                    '''
                
                html_template += '''
                                </div>
                            </div>
                '''
            
            html_template += '''
                        </div>
                    </div>
            '''
        
        html_template += '''
                </div>
            </div>
            
            <script>
                function toggleEmail(header) {
                    const content = header.nextElementSibling;
                    const icon = header.querySelector('.toggle-icon');
                    const emailNode = header.parentElement;
                    
                    if (content.style.display === 'none') {
                        content.style.display = 'block';
                        emailNode.classList.add('expanded');
                    } else {
                        content.style.display = 'none';
                        emailNode.classList.remove('expanded');
                    }
                }
                
                function toggleAction(header) {
                    const records = header.nextElementSibling;
                    const icon = header.querySelector('.toggle-icon');
                    const actionNode = header.parentElement;
                    
                    if (records.style.display === 'none') {
                        records.style.display = 'block';
                        actionNode.classList.add('expanded');
                    } else {
                        records.style.display = 'none';
                        actionNode.classList.remove('expanded');
                    }
                }
            </script>
        </body>
        </html>
        '''
        
        return html_template
        
    except Exception as e:
        return f'''
        <html>
        <body>
            <h1>Error loading audit statistics</h1>
            <p>Error: {str(e)}</p>
        </body>
        </html>
        ''', 500

# Add Bearer token authorization to Swagger
authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': 'Add a JWT token to the header with format: Bearer &lt;JWT&gt;'
    }
}

api.authorizations = authorizations

# Custom 404 error handler
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'status': 404,
        'message': 'Not Found',
        'error_code': 'NOT_FOUND'
    }), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
