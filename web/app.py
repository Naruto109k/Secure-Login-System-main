from flask import Flask, request, jsonify, render_template, session, make_response
from functools import wraps
from typing import Callable, Any

from secure_auth_system.auth.auth_manager import AuthManager

app = Flask(__name__)
# We are using our own token-based session management for the auth system
# but Flask needs a secret key for its own session and flash messages if used.
app.secret_key = 'super_secret_key_for_flask_development'

auth_manager = AuthManager()

# --- Decorators ---

def require_auth(f: Callable) -> Callable:
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        # Read the session token from the cookie
        session_token = request.cookies.get('session_token')
        username = request.cookies.get('username')
        
        if not session_token or not username:
            return jsonify({'success': False, 'message': 'Not authenticated'}), 401
            
        is_valid, msg = auth_manager.session_manager.validate_session(username, session_token)
        if not is_valid:
            return jsonify({'success': False, 'message': msg}), 401
            
        # Optional: Inject the user profile or username into kwargs
        return f(username=username, *args, **kwargs)
    return decorated_function

def require_admin(f: Callable) -> Callable:
    @wraps(f)
    @require_auth
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        username = kwargs.get('username')
        if not username:
            return jsonify({'success': False, 'message': 'Not authenticated'}), 401
            
        user = auth_manager.storage.get_user(username)
        if not user or user.get('role') != 'admin':
            return jsonify({'success': False, 'message': 'Access denied. Admin privileges required.'}), 403
            
        return f(*args, **kwargs)
    return decorated_function

# --- Frontend Routes ---

@app.route('/')
def index():
    return render_template('index.html')

# --- API Routes ---

@app.route('/api/status', methods=['GET'])
def get_status():
    session_token = request.cookies.get('session_token')
    username = request.cookies.get('username')
    
    if session_token and username:
        is_valid, _ = auth_manager.session_manager.validate_session(username, session_token)
        if is_valid:
            profile = auth_manager.get_profile(username)
            return jsonify({'success': True, 'authenticated': True, 'profile': profile})
            
    return jsonify({'success': True, 'authenticated': False})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
        
    username = data.get('username', '')
    password = data.get('password', '')
    security_question = data.get('security_question', '')
    security_answer = data.get('security_answer', '')
    role = data.get('role', 'user')
    
    ok, msg = auth_manager.register(username, password, security_question, security_answer, role)
    return jsonify({'success': ok, 'message': msg}), 200 if ok else 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
        
    username = data.get('username', '')
    password = data.get('password', '')
    
    ok, msg = auth_manager.login(username, password)
    
    if ok:
        # After successful login, the session token is in the manager. Let's get it.
        session_info = auth_manager.get_session_info(username)
        user = auth_manager.storage.get_user(username)
        token = user.get('session_token') if user else None
        
        response = make_response(jsonify({'success': True, 'message': msg}))
        
        # Set cookies (HttpOnly in production, but let JS read it for simplicity here if we want)
        # For security, token should be HttpOnly, but our frontend might need username to show status
        response.set_cookie('session_token', token, httponly=True, max_age=3600)
        response.set_cookie('username', username, httponly=False, max_age=3600)
        
        return response
    else:
        return jsonify({'success': False, 'message': msg}), 401

@app.route('/api/logout', methods=['POST'])
@require_auth
def logout(username=None):
    ok, msg = auth_manager.logout(username)
    response = make_response(jsonify({'success': ok, 'message': msg}))
    response.set_cookie('session_token', '', expires=0)
    response.set_cookie('username', '', expires=0)
    return response

@app.route('/api/reset-password/init', methods=['POST'])
def reset_password_init():
    data = request.json
    username = data.get('username')
    ok, result = auth_manager.initiate_password_reset(username)
    if ok:
        return jsonify({'success': True, 'question': result})
    else:
        return jsonify({'success': False, 'message': result}), 400

@app.route('/api/reset-password/complete', methods=['POST'])
def reset_password_complete():
    data = request.json
    username = data.get('username')
    answer = data.get('answer')
    new_password = data.get('new_password')
    
    ok, msg = auth_manager.complete_password_reset(username, answer, new_password)
    return jsonify({'success': ok, 'message': msg}), 200 if ok else 400

@app.route('/api/profile', methods=['GET'])
@require_auth
def get_profile(username=None):
    profile = auth_manager.get_profile(username)
    session_info = auth_manager.get_session_info(username)
    return jsonify({
        'success': True,
        'profile': profile,
        'session': session_info
    })

# --- Admin API Routes ---

@app.route('/api/admin/users', methods=['GET'])
@require_admin
def admin_list_users(username=None):
    ok, result = auth_manager.admin_list_users(username)
    return jsonify({'success': ok, 'users': result if ok else []})

@app.route('/api/admin/stats', methods=['GET'])
@require_admin
def admin_stats(username=None):
    ok, result = auth_manager.admin_failed_login_stats(username)
    return jsonify({'success': ok, 'stats': result if ok else []})

@app.route('/api/admin/unlock', methods=['POST'])
@require_admin
def admin_unlock(username=None):
    target = request.json.get('username')
    ok, msg = auth_manager.admin_unlock_user(username, target)
    return jsonify({'success': ok, 'message': msg})

@app.route('/api/admin/reset-password', methods=['POST'])
@require_admin
def admin_reset_password(username=None):
    target = request.json.get('username')
    new_password = request.json.get('new_password')
    ok, msg = auth_manager.admin_reset_password(username, target, new_password)
    return jsonify({'success': ok, 'message': msg})

if __name__ == '__main__':
    app.run(debug=True)
