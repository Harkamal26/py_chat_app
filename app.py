from flask import Flask, render_template, request, redirect, session, flash, send_from_directory, jsonify
import sqlite3, hashlib, os, uuid
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'supersecret'

DB_FILE = 'chat_app.db'
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp3', 'wav', 'mp4', 'avi', 'mov', 'pdf', 'txt'}

# ---------- DATABASE ----------
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(p): 
    return hashlib.sha256(p.encode()).hexdigest()

def allowed(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        last_seen TEXT
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        message TEXT,
        file_path TEXT,
        file_type TEXT,
        status TEXT DEFAULT 'sent',
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()

# ---------- HELPERS ----------
@app.before_request
def update_last_seen():
    if 'user' in session:
        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE users SET last_seen=? WHERE username=?",
                  (datetime.now().strftime("%Y-%m-%d %H:%M"), session['user']))
        conn.commit()
        conn.close()

# ---------- ROUTES ---------- 
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u, p = request.form['username'], request.form['password']
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("INSERT INTO users(username,password,last_seen) VALUES (?,?,?)",
                      (u, hash_password(p), "Online"))
            conn.commit()
            conn.close()
            flash("Registered successfully! Please log in.")
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash("Username already exists!")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u, p = request.form['username'], request.form['password']
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (u,))
        user = c.fetchone()
        if user and user['password'] == hash_password(p):
            session['user'] = u
            conn.close()
            return redirect('/users')
        else:
            flash("Invalid username or password.")
        conn.close()
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

@app.route('/users')
def users():
    if 'user' not in session:
        return redirect('/login')
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT username, last_seen FROM users WHERE username != ?", (session['user'],))
    users = c.fetchall()
    conn.close()
    return render_template('users.html', users=users, current=session['user'])

@app.route('/uploads/<path:filename>')
def uploaded(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/chat/<receiver>', methods=['GET', 'POST'])
def chat(receiver):
    if 'user' not in session:
        return redirect('/login')
    user = session['user']

    if request.method == 'POST':
        msg = request.form.get('message')
        f = request.files.get('file')
        fp, ft = None, None

        if f and f.filename and allowed(f.filename):
            fname = str(uuid.uuid4()) + "_" + secure_filename(f.filename)
            path = os.path.join(UPLOAD_FOLDER, fname)
            f.save(path)
            fp = fname
            ext = fname.split('.')[-1]
            if ext in ['png','jpg','jpeg','gif']: ft='image'
            elif ext in ['mp3','wav']: ft='audio'
            elif ext in ['mp4','avi','mov']: ft='video'
            else: ft='file'

        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO messages(sender,receiver,message,file_path,file_type,status) VALUES (?,?,?,?,?,?)",
                  (user, receiver, msg, fp, ft, 'sent'))
        conn.commit()
        conn.close()
        return redirect(f'/chat/{receiver}')

    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE messages SET status='delivered' WHERE receiver=? AND sender=? AND status='sent'",
              (user, receiver))
    conn.commit()

    c.execute("""
        SELECT sender, receiver, message, file_path, file_type, status, timestamp
        FROM messages
        WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
        ORDER BY timestamp
    """, (user, receiver, receiver, user))
    msgs = c.fetchall()
    conn.close()
    return render_template('chat.html', chat=msgs, receiver=receiver, user=user)

@app.route('/mark_seen', methods=['POST'])
def mark_seen():
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'})
    data = request.get_json()
    partner = data.get('partner')
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE messages SET status='seen' WHERE receiver=? AND sender=? AND status!='seen'",
              (session['user'], partner))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})
@app.route('/chat/<receiver>/search')
def search_chat(receiver):
    if 'user' not in session:
        return redirect('/login')
    user = session['user']
    query = request.args.get('q', '').strip()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT sender, receiver, message, file_path, file_type, status, timestamp
        FROM messages
        WHERE ((sender=? AND receiver=?) OR (sender=? AND receiver=?))
        AND message LIKE ?
        ORDER BY timestamp
    """, (user, receiver, receiver, user, f'%{query}%'))
    msgs = cursor.fetchall()
    conn.close()

    return render_template('chat.html', chat=msgs, receiver=receiver, search_query=query)


if __name__ == '__main__':
    init_db()
    app.run(port=5000)
