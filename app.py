import streamlit as st
import sqlite3
import os
import bcrypt
import base64
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import re
import argparse
import hashlib
import pandas as pd
try:
    import magic
except Exception:
    magic = None

DB_PATH = "data/fintech.db"
KEY_PATH = "data/fernet.key"
UPLOAD_DIR = "data/uploads"
def ensure_dirs():
    os.makedirs("data", exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)

def get_conn():
    ensure_dirs()
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    ensure_dirs()
    # ensure schema file is present in same directory
    if not os.path.exists("schema_init.sql"):
        st.error("schema_init.sql not found in repository root.")
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.executescript(open("schema_init.sql").read())
    conn.commit()
    conn.close()
    st.success("DB initialized (data/fintech.db created).")

def load_key():
    ensure_dirs()
    if not os.path.exists(KEY_PATH):
        key = Fernet.generate_key()
        open(KEY_PATH, "wb").write(key)
        return key
    return open(KEY_PATH, "rb").read()

FERNET_KEY = None
FERNET = None

def get_fernet():
    global FERNET_KEY, FERNET
    if FERNET:
        return FERNET
    FERNET_KEY = load_key()
    FERNET = Fernet(FERNET_KEY)
    return FERNET

def hash_password(plain: str) -> bytes:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt())

def verify_password(plain: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed)
    except Exception:
        return False

def log_action(user_id, action, meta=""):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO audit_logs (user_id, action, meta) VALUES (?, ?, ?)", (user_id, action, meta))
    conn.commit()
PASSWORD_REGEX = re.compile(r"^(?=.*[0-9])(?=.*[A-Z])(?=.*[a-z])(?=.*[!@#\$%\^&\*])(?=.{8,})")

def password_is_strong(pw: str) -> bool:
    return bool(PASSWORD_REGEX.match(pw))

def sanitize_text(s: str) -> str:
    # lightweight sanitizer for display safety
    return s.replace("<", "&lt;").replace(">", "&gt;")
def create_user(username, password, email=None):
    conn = get_conn()
    cur = conn.cursor()
    pw_hash = hash_password(password)
    try:
        cur.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, pw_hash, email))
        conn.commit()
        user_id = cur.lastrowid
        log_action(user_id, "register", f"username={username}")
        return user_id
    except sqlite3.IntegrityError:
        return None

def get_user_by_username(username):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    return row
SESSION_TIMEOUT_MINUTES = 1
def create_session(user_row):
    st.session_state["user"] = {"id": user_row["id"], "username": user_row["username"], "login_time": datetime.utcnow().isoformat()}
    st.session_state["last_activity"] = datetime.utcnow()
    log_action(user_row["id"], "login")

def logout():
    user = st.session_state.get("user")
    if user:
        log_action(user["id"], "logout")
    for k in list(st.session_state.keys()):
        del st.session_state[k]

def check_session_timeout():
    if "last_activity" in st.session_state:
        if datetime.utcnow() - st.session_state["last_activity"] > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
            logout()
            st.warning("Session expired due to inactivity.")
def hacker_theme_css():
    st.markdown("""
    <style>
    .stApp { background-color: #0b0f0b; color: #c0ffb3; }
    .neon { color: #39ff14; font-weight:700 }
    .card { background: rgba(0,0,0,0.6); padding: 12px; border-radius:12px; box-shadow: 0 0 8px rgba(57,255,20,0.07); }
    </style>
    """, unsafe_allow_html=True)
def page_register():
    st.header("Register")
    with st.form("register_form"):
        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        confirm = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Create account")
        if submitted:
            if not username:
                st.error("Username required")
            elif password != confirm:
                st.error("Passwords do not match")
            elif not password_is_strong(password):
                st.error("Password not strong enough. Must be 8+ chars, include upper+lower+digit+symbol.")
            else:
                uid = create_user(sanitize_text(username), password, sanitize_text(email))
                if uid:
                    st.success("Account created. You can now log in.")
                else:
                    st.error("Username already exists")

def page_login():
    st.header("Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            row = get_user_by_username(username)
            if not row:
                st.error("Invalid credentials")
            else:
                if verify_password(password, row["password_hash"]):
                    create_session(row)
                    st.experimental_rerun()
                else:
                    st.error("Invalid credentials")

def page_dashboard():
    check_session_timeout()
    st.header(f"Dashboard — {st.session_state['user']['username']}")
    st.write("Welcome to your secure FinTech demo. Use the left menu to navigate features.")

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (st.session_state['user']['id'],))
    user_row = cur.fetchone()
    f = get_fernet()
    balance_enc = user_row["balance_encrypted"]
    if balance_enc:
        try:
            balance = f.decrypt(balance_enc.encode()).decode()
        except Exception:
            balance = "[unreadable]"
    else:
        balance = "0"

    st.metric("Encrypted Balance (decrypted)", balance)

    st.subheader("Update profile")
    with st.form("profile_form"):
        email = st.text_input("Email", value=user_row["email"] or "")
        new_balance = st.text_input("Set balance (numeric)")
        submitted = st.form_submit_button("Update")
        if submitted:
            if new_balance and not re.match(r"^\d+(\.\d{1,2})?$", new_balance):
                st.error("Invalid amount format. Use numbers, optionally with 2 decimals.")
            else:
                if new_balance:
                    enc = f.encrypt(str(new_balance).encode()).decode()
                    cur.execute("UPDATE users SET email=?, balance_encrypted=? WHERE id=?", (sanitize_text(email), enc, st.session_state['user']['id']))
                else:
                    cur.execute("UPDATE users SET email=? WHERE id=?", (sanitize_text(email), st.session_state['user']['id']))
                conn.commit()
                log_action(st.session_state['user']['id'], "profile_update", f"email={email}")
                st.success("Profile updated")

def page_encrypt_tool():
    st.header("Encrypt / Decrypt Tool")
    f = get_fernet()
    txt = st.text_area("Text to encrypt")
    if st.button("Encrypt"):
        st.code(f.encrypt(txt.encode()).decode())
    token = st.text_area("Token to decrypt")
    if st.button("Decrypt"):
        try:
            st.code(f.decrypt(token.encode()).decode())
        except Exception:
            st.error("Invalid token or cannot decrypt")

def page_logs():
    st.header("Activity Logs (audit)")
    conn = get_conn()
    df = pd.read_sql_query("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200", conn)
    st.dataframe(df)

def page_file_upload():
    st.header("File Upload (validated)")
    uploaded = st.file_uploader("Upload snapshot (png, jpg, pdf allowed)", type=["png", "jpg", "jpeg", "pdf"])
    if uploaded:
        raw = uploaded.read()
        mime = None
        if magic:
            try:
                mime = magic.from_buffer(raw, mime=True)
            except Exception:
                mime = None
        if not mime:
            fname = uploaded.name.lower()
            if fname.endswith(".png"):
                mime = "image/png"
            elif fname.endswith(".jpg") or fname.endswith(".jpeg"):
                mime = "image/jpeg"
            elif fname.endswith(".pdf"):
                mime = "application/pdf"
        if mime not in ("image/png", "image/jpeg", "application/pdf"):
            st.error("Disallowed file type")
            return
        filename = sanitize_text(uploaded.name)
        save_path = os.path.join(UPLOAD_DIR, filename)
        with open(save_path, "wb") as f:
            f.write(raw)
        h = hashlib.sha256(raw).hexdigest()
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO files (user_id, filename, content_hash) VALUES (?, ?, ?)", (st.session_state['user']['id'], filename, h))
        conn.commit()
        log_action(st.session_state['user']['id'], "file_upload", filename)
        st.success("File uploaded and validated")
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--init-db", action="store_true")
    args, _ = parser.parse_known_args()
    ensure_dirs()
    if args.init_db:
        init_db()
        return

    get_fernet()
    hacker_theme_css()
    st.sidebar.markdown("<div class='neon'>⚡ Secure FinTech — Demo</div>", unsafe_allow_html=True)

    if "user" not in st.session_state:
        page = st.sidebar.selectbox("Menu", ["Login", "Register", "Encrypt Tool"])
        if page == "Login":
            page_login()
        elif page == "Register":
            page_register()
        elif page == "Encrypt Tool":
            page_encrypt_tool()
    else:
        check_session_timeout()
        page = st.sidebar.selectbox("Menu", ["Dashboard", "Encrypt Tool", "Upload File", "Logs", "Logout"])
        if page == "Dashboard":
            page_dashboard()
        elif page == "Encrypt Tool":
            page_encrypt_tool()
        elif page == "Upload File":
            page_file_upload()
        elif page == "Logs":
            page_logs()
        elif page == "Logout":
            logout()
            st.experimental_rerun()

if __name__ == "__main__":
    main()
