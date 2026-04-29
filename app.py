"""
app.py  —  CipherChat Web Backend
Flask + Flask-SocketIO WebSocket relay server.
The server NEVER sees plaintext — it only relays encrypted blobs between browsers.

Install:
    pip install flask flask-socketio flask-sqlalchemy flask-login werkzeug gevent gevent-websocket

Run:
    python app.py
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit, disconnect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os, datetime

app = Flask(__name__)
app.config['SECRET_KEY']                     = os.urandom(32).hex()
app.config['SQLALCHEMY_DATABASE_URI']        = 'sqlite:///securelink.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db            = SQLAlchemy(app)
socketio      = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')
login_manager = LoginManager(app)
login_manager.login_view = 'login_page'

# online users: username → socket id
online_users = {}
sid_to_user  = {}


# ══════════════════════════════════════════════════════════════════════
#  MODELS
# ══════════════════════════════════════════════════════════════════════
class User(UserMixin, db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def set_password(self, pw):   self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)


class Message(db.Model):
    """Stores message history per user pair."""
    id               = db.Column(db.Integer, primary_key=True)
    sender           = db.Column(db.String(64), nullable=False)
    recipient        = db.Column(db.String(64), nullable=False)
    plaintext_content= db.Column(db.Text, nullable=True)   # stored as plaintext for history
    msg_type         = db.Column(db.String(8), default='text')
    filename         = db.Column(db.String(256), nullable=True)
    ts               = db.Column(db.DateTime, default=datetime.datetime.utcnow)


@login_manager.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))


# ══════════════════════════════════════════════════════════════════════
#  HTTP ROUTES
# ══════════════════════════════════════════════════════════════════════
@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/chat')
@login_required
def chat_page():
    return render_template('chat.html', username=current_user.username)

@app.route('/login')
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('chat_page'))
    return render_template('auth.html', mode='login')

@app.route('/register')
def register_page():
    return render_template('auth.html', mode='register')

@app.route('/api/register', methods=['POST'])
def api_register():
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'ok': False, 'msg': 'Username and password required'}), 400
    if len(username) < 3:
        return jsonify({'ok': False, 'msg': 'Username must be at least 3 characters'}), 400
    if len(password) < 6:
        return jsonify({'ok': False, 'msg': 'Password must be at least 6 characters'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'ok': False, 'msg': 'Username already taken'}), 409
    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    login_user(user)
    return jsonify({'ok': True, 'redirect': '/chat'})

@app.route('/api/login', methods=['POST'])
def api_login():
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    user     = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'ok': False, 'msg': 'Invalid username or password'}), 401
    login_user(user)
    return jsonify({'ok': True, 'redirect': '/chat'})

@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    logout_user()
    return jsonify({'ok': True, 'redirect': '/'})

@app.route('/api/users/online')
@login_required
def api_online_users():
    users = [u for u in online_users if u != current_user.username]
    return jsonify({'users': users})

@app.route('/api/history/<peer>')
@login_required
def api_history(peer):
    """Return last 50 encrypted messages between current user and peer."""
    me = current_user.username
    from sqlalchemy import or_, and_
    msgs = Message.query.filter(
        or_(
            and_(Message.sender == me,   Message.recipient == peer),
            and_(Message.sender == peer, Message.recipient == me)
        )
    ).order_by(Message.ts.asc()).limit(100).all()

    result = []
    for m in msgs:
        result.append({
            'from':     m.sender,
            'to':       m.recipient,
            'content':  m.plaintext_content,
            'type':     m.msg_type,
            'filename': m.filename,
            'ts':       m.ts.isoformat(),
        })
    return jsonify({'messages': result})


# ══════════════════════════════════════════════════════════════════════
#  WEBSOCKET EVENTS
# ══════════════════════════════════════════════════════════════════════
@socketio.on('connect')
def on_connect():
    if not current_user.is_authenticated:
        disconnect(); return
    uname = current_user.username
    online_users[uname] = request.sid
    sid_to_user[request.sid] = uname
    emit('user_online',  {'username': uname}, broadcast=True)
    emit('online_list',  {'users': [u for u in online_users if u != uname]})

@socketio.on('disconnect')
def on_disconnect():
    uname = sid_to_user.pop(request.sid, None)
    if uname:
        online_users.pop(uname, None)
        emit('user_offline', {'username': uname}, broadcast=True)

# ── Key exchange relay ─────────────────────────────────────────────────
@socketio.on('key_offer')
def on_key_offer(data):
    target = data.get('to')
    if target in online_users:
        emit('key_offer', {
            'from':      current_user.username,
            'ecdh_pub':  data.get('ecdh_pub'),
            'ecdsa_pub': data.get('ecdsa_pub'),
        }, to=online_users[target])

@socketio.on('key_answer')
def on_key_answer(data):
    target = data.get('to')
    if target in online_users:
        emit('key_answer', {
            'from':      current_user.username,
            'ecdh_pub':  data.get('ecdh_pub'),
            'ecdsa_pub': data.get('ecdsa_pub'),
        }, to=online_users[target])

# ── Text message relay + save to DB ───────────────────────────────────
@socketio.on('encrypted_msg')
def on_encrypted_msg(data):
    target = data.get('to')
    sender = current_user.username
    nonce      = data.get('nonce', '')
    sig        = data.get('sig', '')
    ciphertext = data.get('ciphertext', '')
    ts         = datetime.datetime.utcnow()

    if target in online_users:
        emit('encrypted_msg', {
            'from':       sender,
            'nonce':      nonce,
            'sig':        sig,
            'ciphertext': ciphertext,
            'type':       'text',
            'ts':         ts.isoformat(),
        }, to=online_users[target])

# ── Save plaintext history (called by client after encrypt/decrypt) ───
@app.route('/api/save_message', methods=['POST'])
@login_required
def api_save_message():
    data = request.get_json()
    msg = Message(
        sender    = current_user.username,
        recipient = data.get('to',''),
        plaintext_content = data.get('content',''),
        msg_type  = data.get('type','text'),
        filename  = data.get('filename'),
    )
    db.session.add(msg)
    db.session.commit()
    return jsonify({'ok': True})

# save_received removed — sender saves for both sides

# ── File transfer relay ────────────────────────────────────────────────
@socketio.on('file_meta')
def on_file_meta(data):
    """Relay encrypted file metadata (filename, size) to recipient."""
    target = data.get('to')
    sender = current_user.username
    ts     = datetime.datetime.utcnow()

    if target in online_users:
        emit('file_meta', {
            'from':       sender,
            'nonce':      data.get('nonce'),
            'sig':        data.get('sig'),
            'ciphertext': data.get('ciphertext'),
            'filename':   data.get('filename'),
            'size':       data.get('size'),
            'total_chunks': data.get('total_chunks'),
            'ts':         ts.isoformat(),
        }, to=online_users[target])

@socketio.on('file_chunk')
def on_file_chunk(data):
    """Relay one encrypted file chunk to recipient."""
    target = data.get('to')
    if target in online_users:
        emit('file_chunk', {
            'from':       current_user.username,
            'chunk_idx':  data.get('chunk_idx'),
            'total':      data.get('total'),
            'nonce':      data.get('nonce'),
            'sig':        data.get('sig'),
            'ciphertext': data.get('ciphertext'),
        }, to=online_users[target])

@socketio.on('file_done')
def on_file_done(data):
    target = data.get('to')
    if target in online_users:
        emit('file_done', {
            'from':     current_user.username,
            'filename': data.get('filename'),
        }, to=online_users[target])

# ── Typing relay ──────────────────────────────────────────────────────
@socketio.on('typing')
def on_typing(data):
    target = data.get('to')
    if target in online_users:
        emit('typing', {'from': current_user.username}, to=online_users[target])

@socketio.on('stop_typing')
def on_stop_typing(data):
    target = data.get('to')
    if target in online_users:
        emit('stop_typing', {'from': current_user.username}, to=online_users[target])


# ══════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=5002, debug=False,
                 allow_unsafe_werkzeug=True)