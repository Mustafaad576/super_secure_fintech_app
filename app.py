
# app.py - Secure FinTech demo (improved)
import streamlit as st
import sqlite3
import bcrypt
import re
from datetime import datetime, timedelta
import html

# --- Config ---
DB_PATH = "users.db"
SESSION_TIMEOUT_MINUTES = 15
USERNAME_MAX_LEN = 50
PASSWORD_MIN_LEN = 8

# --- Helpers ---
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            meta TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def seed_admin():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if not cur.fetchone():
        pw = b"Test@1234"
        ph = bcrypt.hashpw(pw, bcrypt.gensalt())
        cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ("admin", ph))
        conn.commit()
    conn.close()

def log_action(user_id, action, meta=""):
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO audit_logs (user_id, action, meta) VALUES (?, ?, ?)", (user_id, action, meta))
        conn.commit()
        conn.close()
    except Exception:
        # swallow to avoid exposing internal errors to users
        pass

# --- Validation ---
PW_POLICY_RE = re.compile(r'^(?=.*[0-9])(?=.*[A-Z])(?=.*[a-z])(?=.*[!@#\$%\^&\*]).{%d,}$' % PASSWORD_MIN_LEN)

def is_strong_password(pw: str) -> bool:
    return bool(PW_POLICY_RE.match(pw))

def sanitize_for_display(s: str) -> str:
    # sanitize output to prevent XSS when reflecting input back
    return html.escape(s)

# --- DB operations ---
def create_user(username: str, password: str, email: str = None) -> (bool, str):
    username = username.strip()
    if len(username) == 0 or len(username) > USERNAME_MAX_LEN:
        return False, f"Username must be 1..{USERNAME_MAX_LEN} characters."
    if not is_strong_password(password):
        return False, f"Password must be at least {PASSWORD_MIN_LEN} chars and include upper, lower, digit and special char."
    try:
        pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, pw_hash, email))
        conn.commit()
        user_id = cur.lastrowid
        conn.close()
        log_action(user_id, "register", f"username={username}")
        return True, "User registered successfully."
    except sqlite3.IntegrityError:
        return False, "Username already exists."
    except Exception as e:
        # log and return generic error
        log_action(None, "error", f"create_user_error:{str(e)}")
        return False, "An internal error occurred. Please contact the administrator."

def get_user(username: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row

# --- Session helpers ---
def create_session(user_row):
    st.session_state['user'] = {"id": user_row["id"], "username": user_row["username"]}
    st.session_state['last_activity'] = datetime.utcnow()

def is_session_active():
    if 'user' not in st.session_state:
        return False
    if 'last_activity' not in st.session_state:
        return False
    return datetime.utcnow() - st.session_state['last_activity'] <= timedelta(minutes=SESSION_TIMEOUT_MINUTES)

def refresh_activity():
    st.session_state['last_activity'] = datetime.utcnow()

def logout_user():
    user = st.session_state.get('user')
    if user:
        log_action(user.get('id'), "logout", f"user={user.get('username')}")
    for k in list(st.session_state.keys()):
        del st.session_state[k]

# --- Pages ---
def page_login():
    st.header("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        try:
            row = get_user(username)
            if row and bcrypt.checkpw(password.encode('utf-8'), row['password_hash']):
                create_session(row)
                log_action(row['id'], "login", f"user={username}")
                st.success(f"Welcome, {sanitize_for_display(username)}!")
                st.experimental_rerun()
            else:
                log_action(None, "failed_login", f"username={username}")
                st.error("Invalid credentials.")
        except Exception as e:
            log_action(None, "error", f"login_error:{str(e)}")
            st.error("An internal error occurred. The original error has been logged.")

def page_register():
    st.header("🧾 Register")
    new_username = st.text_input("Choose username", key="reg_user")
    new_email = st.text_input("Email (optional)", key="reg_email")
    new_password = st.text_input("Choose password", type="password", key="reg_pw")
    confirm = st.text_input("Confirm password", type="password", key="reg_confirm")
    if st.button("Register"):
        if new_password != confirm:
            st.error("Passwords do not match.")
        else:
            ok, msg = create_user(new_username, new_password, new_email)
            if ok:
                st.success(msg + " You can now log in.")
            else:
                st.error(msg)

def page_dashboard():
    if not is_session_active():
        logout_user()
        st.warning("Session expired or not logged in; please log in.")
        return
    refresh_activity()
    st.header("💼 Dashboard")
    st.subheader(f"Welcome, {sanitize_for_display(st.session_state['user']['username'])}!")
    if st.button("Logout"):
        logout_user()
        st.success("Logged out.")
        st.experimental_rerun()
    st.write("Use the sidebar to access other pages. Audit logs are recorded for actions.")

def page_encrypt():
    if not is_session_active():
        st.warning("Please log in to use this tool.")
        return
    refresh_activity()
    st.header("🔒 Simple Encrypt / Decrypt Demo (Base64)")
    txt = st.text_area("Text to encrypt/decrypt")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Encrypt"):
            if txt:
                enc = txt.encode('utf-8').hex()
                st.code(enc)
                log_action(st.session_state['user']['id'], "encrypt", f"len={len(txt)}")
            else:
                st.warning("Enter text first.")
    with col2:
        if st.button("Decrypt"):
            if txt:
                try:
                    dec = bytes.fromhex(txt).decode('utf-8')
                    st.code(dec)
                    log_action(st.session_state['user']['id'], "decrypt", f"len={len(dec)}")
                except Exception:
                    st.error("Invalid token or cannot decrypt.")

def page_logs():
    if not is_session_active():
        st.warning("Please log in to view logs.")
        return
    refresh_activity()
    st.header("📜 Audit Logs")
    conn = get_conn()
    df = conn.execute("SELECT id, user_id, action, meta, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 200").fetchall()
    conn.close()
    # render safely
    rows = [[r['id'], r['user_id'], sanitize_for_display(str(r['action'])), sanitize_for_display(str(r['meta'])), r['created_at']] for r in df]
    st.table(rows)

def page_about():
    st.header("ℹ️ About")
    st.write("Secure FinTech demo app — input validation, password hashing (bcrypt), session management, and logging.")

# --- Main ---
def main():
    init_db()
    seed_admin()
    st.sidebar.title("Secure FinTech")
    if 'user' in st.session_state and not is_session_active():
        logout_user()
    # menu based on auth status
    if 'user' in st.session_state:
        # logged in
        page = st.sidebar.selectbox("Menu", ["Dashboard", "Encrypt Tool", "Logs", "About", "Logout"])
        if page == "Dashboard":
            page_dashboard()
        elif page == "Encrypt Tool":
            page_encrypt()
        elif page == "Logs":
            page_logs()
        elif page == "About":
            page_abou_
