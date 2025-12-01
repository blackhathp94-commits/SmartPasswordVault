import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, session,
    render_template, flash, jsonify, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet

# -----------------------------
# Basic Config
# -----------------------------
app = Flask(__name__, template_folder="../frontend/templates")
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-change-me'

DB_PATH = os.environ.get('DB_PATH') or 'vault.db'
FERNET_KEY_PATH = os.environ.get('FERNET_KEY_PATH') or 'vault_fernet.key'

UPLOAD_FOLDER = "../uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# -----------------------------
# Encryption Helper
# -----------------------------
def _load_or_create_fernet_key(path: str) -> bytes:
    if os.path.exists(path):
        with open(path, 'rb') as f:
            return f.read()
    key = Fernet.generate_key()
    with open(path, 'wb') as f:
        f.write(key)
    return key

FERNET_KEY = os.environ.get('FERNET_KEY')
if FERNET_KEY:
    fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)
else:
    fernet = Fernet(_load_or_create_fernet_key(FERNET_KEY_PATH))

# -----------------------------
# Database Helpers
# -----------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # USERS
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )

    # PASSWORD ENTRIES
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            site TEXT NOT NULL,
            login TEXT NOT NULL,
            password_encrypted BLOB NOT NULL,
            note TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )

    # CREDIT CARDS
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS credit_cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            card_name TEXT NOT NULL,
            card_number_encrypted BLOB NOT NULL,
            expiry TEXT NOT NULL,
            cvv_encrypted BLOB NOT NULL,
            note TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )

    # DOCUMENTS
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            filename TEXT NOT NULL,
            note TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )

    # BANK INFO
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS bank_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            bank_name TEXT NOT NULL,
            account_number_encrypted BLOB NOT NULL,
            ifsc TEXT NOT NULL,
            branch TEXT,
            note TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )

    conn.commit()
    conn.close()


with app.app_context():
    init_db()

# -----------------------------
# Auth Helpers
# -----------------------------
def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapper

# -----------------------------
# Routes
# -----------------------------
@app.route('/')
@login_required
def vault():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, site, login, note, created_at FROM entries "
        "WHERE user_id = ? ORDER BY created_at DESC",
        (session['user_id'],)
    )
    entries = cur.fetchall()
    conn.close()
    return render_template("vault.html", title='🔐 Password Vault', entries=entries)
# -----------------------------
# SIGNUP
# -----------------------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password required')
            return redirect(url_for('signup'))

        conn = get_db()
        cur = conn.cursor()

        try:
            cur.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), datetime.utcnow().isoformat())
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash('Username already exists')
            conn.close()
            return redirect(url_for('signup'))

        user_id = cur.lastrowid
        conn.close()

        session['user_id'] = user_id
        session['username'] = username
        return redirect(url_for('vault'))

    return render_template("signup.html", title='Create Account')


# -----------------------------
# LOGIN
# -----------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()

        if row and check_password_hash(row['password_hash'], password):
            session['user_id'] = row['id']
            session['username'] = username
            return redirect(url_for('vault'))

        flash('Invalid credentials')
        return redirect(url_for('login'))

    return render_template("login.html", title='Log In')


# -----------------------------
# LOGOUT
# -----------------------------
@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))


# -----------------------------
# PASSWORD ADD
# -----------------------------
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_entry():
    if request.method == 'POST':
        site = request.form.get('site', '').strip()
        login_name = request.form.get('login', '').strip()
        password_plain = request.form.get('password', '')
        note = request.form.get('note', '').strip() or None

        if not site or not login_name or not password_plain:
            flash('All fields except note are required')
            return redirect(url_for('add_entry'))

        enc = fernet.encrypt(password_plain.encode('utf-8'))

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO entries (user_id, site, login, password_encrypted, note, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (session['user_id'], site, login_name, enc, note, datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()

        return redirect(url_for('vault'))

    return render_template("add.html", title='Add Password')
 # Edit   
@app.route('/edit/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def edit_entry(entry_id):
    conn = get_db()
    cur = conn.cursor()

    # Get entry for this user
    cur.execute("""
        SELECT id, site, login, password_encrypted, note
        FROM entries
        WHERE id = ? AND user_id = ?
    """, (entry_id, session['user_id']))

    entry = cur.fetchone()

    if not entry:
        conn.close()
        flash("Entry not found")
        return redirect(url_for('vault'))

    if request.method == 'POST':
        site = request.form.get('site', '').strip()
        login_name = request.form.get('login', '').strip()
        password_plain = request.form.get('password', '')
        note = request.form.get('note', '').strip() or None

        if not site or not login_name:
            flash("Site and login are required")
            return redirect(url_for('edit_entry', entry_id=entry_id))

        # If password was changed, re-encrypt
        if password_plain:
            password_encrypted = fernet.encrypt(password_plain.encode())
        else:
            password_encrypted = entry['password_encrypted']

        cur.execute("""
            UPDATE entries
            SET site = ?, login = ?, password_encrypted = ?, note = ?
            WHERE id = ? AND user_id = ?
        """, (site, login_name, password_encrypted, note, entry_id, session['user_id']))

        conn.commit()
        conn.close()

        return redirect(url_for('vault'))

    # GET request - decrypt password for the form
    password_plain = fernet.decrypt(entry['password_encrypted']).decode()

    conn.close()

    return render_template("edit_entry.html", entry=entry, password=password_plain)

# -----------------------------
# PASSWORD DELETE
# -----------------------------
@app.route('/delete/<int:entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM entries WHERE id = ? AND user_id = ?", (entry_id, session['user_id']))
    conn.commit()
    conn.close()
    return redirect(url_for('vault'))


# -----------------------------
# PASSWORD REVEAL
# -----------------------------
@app.route('/reveal/<int:entry_id>', methods=['POST'])
@login_required
def reveal_password(entry_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT password_encrypted FROM entries WHERE id = ? AND user_id = ?", (entry_id, session['user_id']))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({'error': 'Not found'}), 404

    try:
        plain = fernet.decrypt(row['password_encrypted']).decode('utf-8')
        return jsonify({'password': plain})
    except Exception:
        return jsonify({'error': 'Decrypt failed'}), 500


# ---------------------------------------------------------------------
# CREDIT CARDS
# ---------------------------------------------------------------------
@app.route('/credit_cards')
@login_required
def credit_cards():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM credit_cards WHERE user_id = ? ORDER BY created_at DESC",
                (session['user_id'],))
    cards = cur.fetchall()
    conn.close()
    return render_template("credit_cards.html", title="Credit Cards", cards=cards)


@app.route('/credit_cards/add', methods=['GET', 'POST'])
@login_required
def add_credit_card():
    if request.method == 'POST':
        name = request.form.get('card_name', '')
        number = request.form.get('card_number', '')
        expiry = request.form.get('expiry', '')
        cvv = request.form.get('cvv', '')
        note = request.form.get('note', '')

        if not name or not number or not expiry or not cvv:
            flash("Required fields missing")
            return redirect(url_for('add_credit_card'))

        enc_num = fernet.encrypt(number.encode())
        enc_cvv = fernet.encrypt(cvv.encode())

        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO credit_cards (user_id, card_name, card_number_encrypted, expiry, cvv_encrypted, note, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (session['user_id'], name, enc_num, expiry, enc_cvv, note, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

        return redirect(url_for('credit_cards'))

    return render_template("add_credit_card.html", title="Add Credit Card")


@app.route('/credit_cards/delete/<int:card_id>', methods=['POST'])
@login_required
def delete_credit_card(card_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM credit_cards WHERE id = ? AND user_id = ?", (card_id, session['user_id']))
    conn.commit()
    conn.close()
    return redirect(url_for('credit_cards'))


# ---------------------------------------------------------------------
# DOCUMENTS
# ---------------------------------------------------------------------
@app.route('/documents')
@login_required
def documents():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM documents WHERE user_id = ?", (session['user_id'],))
    docs = cur.fetchall()
    conn.close()
    return render_template("documents.html", docs=docs, title="Documents")


@app.route('/documents/add', methods=['GET', 'POST'])
@login_required
def add_document():
    if request.method == 'POST':
        title = request.form.get('title', '')
        note = request.form.get('note', '')
        file = request.files.get('file')

        if not title or not file:
            flash("Title and file required")
            return redirect(url_for('add_document'))

        filename = secure_filename(file.filename)
        path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(path)

        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO documents (user_id, title, filename, note, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (session['user_id'], title, filename, note, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

        return redirect(url_for('documents'))

    return render_template("add_document.html", title="Add Document")


@app.route('/documents/delete/<int:doc_id>', methods=['POST'])
@login_required
def delete_document(doc_id):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT filename FROM documents WHERE id = ? AND user_id = ?", (doc_id, session['user_id']))
    doc = cur.fetchone()

    if doc:
        try:
            os.remove(os.path.join(app.config["UPLOAD_FOLDER"], doc["filename"]))
        except:
            pass

        cur.execute("DELETE FROM documents WHERE id = ? AND user_id = ?", (doc_id, session['user_id']))
        conn.commit()

    conn.close()
    return redirect(url_for('documents'))


@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ---------------------------------------------------------------------
# BANK INFO
# ---------------------------------------------------------------------
@app.route('/bank_info')
@login_required
def bank_info():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM bank_info WHERE user_id = ?", (session['user_id'],))
    banks = cur.fetchall()
    conn.close()
    return render_template("bank_info.html", title="Bank Info", banks=banks)


@app.route('/bank_info/add', methods=['GET', 'POST'])
@login_required
def add_bank_info():
    if request.method == 'POST':
        bank_name = request.form.get('bank_name', '')
        account_number = request.form.get('account_number', '')
        ifsc = request.form.get('ifsc', '')
        branch = request.form.get('branch', '')
        note = request.form.get('note', '')

        if not bank_name or not account_number or not ifsc:
            flash("Required fields missing")
            return redirect(url_for('add_bank_info'))

        enc = fernet.encrypt(account_number.encode())

        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO bank_info (user_id, bank_name, account_number_encrypted, ifsc, branch, note, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (session['user_id'], bank_name, enc, ifsc, branch, note, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

        return redirect(url_for('bank_info'))

    return render_template("add_bank_info.html", title="Add Bank Info")


@app.route('/bank_info/delete/<int:bank_id>', methods=['POST'])
@login_required
def delete_bank_info(bank_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM bank_info WHERE id = ? AND user_id = ?", (bank_id, session['user_id']))
    conn.commit()
    conn.close()
    return redirect(url_for('bank_info'))


# -----------------------------
# RUN SERVER
# -----------------------------
if __name__ == '__main__':
    app.run(debug=True)
