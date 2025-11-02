import streamlit as st
import sqlite3
import bcrypt
import time
from datetime import datetime, timedelta
import base64

DB_PATH = "data/fintech.db"
SESSION_TIMEOUT_MINUTES = 15

def create_tables():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT
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

# ---- SEED DEFAULT ADMIN USER ----
def seed_admin_user():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    password_hash = bcrypt.hashpw(b"Test@1234", bcrypt.gensalt()).decode("utf-8")
    cur.execute("INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)", ("admin", password_hash))
    conn.commit()
    conn.close()
# ---------------------------------

def log_action(user_id, action, meta=""):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO audit_logs (user_id, action, meta) VALUES (?, ?, ?)", (user_id, action, meta))
    conn.commit()
    conn.close()

def get_user_by_username(username):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()
    return user

def insert_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
    conn.commit()
    conn.close()

# ----------------------------------------
# AUTHENTICATION LOGIC
# ----------------------------------------
def login_user(username, password):
    user = get_user_by_username(username)
    if user:
        stored_hash = user[2]
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            return user
    return None

# ----------------------------------------
# SESSION MANAGEMENT
# ----------------------------------------
def is_session_active():
    if "last_activity" not in st.session_state:
        return False
    now = datetime.now()
    if now - st.session_state["last_activity"] > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
        return False
    return True

def update_session_activity():
    st.session_state["last_activity"] = datetime.now()

# ----------------------------------------
# PAGE FUNCTIONS
# ----------------------------------------
def page_login():
    st.title("🔐 Secure FinTech App – Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        try:
            user = login_user(username, password)
            if user:
                st.session_state["user"] = {"id": user[0], "username": user[1]}
                update_session_activity()
                log_action(user[0], "login", f"user={username}")
                st.success("Login successful! Redirecting...")
                time.sleep(1)
                st.experimental_rerun()
            else:
                st.error("Invalid username or password.")
        except Exception:
            st.error("This app has encountered an error. The original error message is redacted to prevent data leaks.")
            log_action(None, "error", "login attempt failed")

def page_dashboard():
    st.title("💻 Dashboard")
    st.write(f"Welcome, **{st.session_state['user']['username']}**!")
    log_action(st.session_state["user"]["id"], "view_dashboard")

def page_logs():
    st.title("📜 Activity Logs")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT a.id, u.username, a.action, a.meta, a.created_at
        FROM audit_logs a
        LEFT JOIN users u ON u.id = a.user_id
        ORDER BY a.created_at DESC
    """)
    rows = cur.fetchall()
    conn.close()
    st.dataframe(rows, use_container_width=True)

def page_encrypt_tool():
    st.title("🔒 Encryption / Decryption Tool")

    mode = st.radio("Select mode:", ["Encrypt", "Decrypt"])
    text = st.text_area("Enter text:")

    if st.button("Run"):
        if not text.strip():
            st.warning("Please enter some text.")
            return
        if mode == "Encrypt":
            encoded = base64.b64encode(text.encode()).decode()
            st.success(f"Encrypted: {encoded}")
        else:
            try:
                decoded = base64.b64decode(text.encode()).decode()
                st.success(f"Decrypted: {decoded}")
            except Exception:
                st.error("Invalid encrypted text!")

    log_action(st.session_state["user"]["id"], "use_encryption_tool", f"mode={mode}")

# ----------------------------------------
# MAIN APP LOGIC
# ----------------------------------------
def main():
    create_tables()
    seed_admin_user()

    st.sidebar.title("🕵️ Hacker-Themed Secure FinTech App")
    st.sidebar.markdown("---")

    if "user" not in st.session_state:
        menu = ["Login"]
    else:
        menu = ["Dashboard", "Encrypt Tool", "Logs", "Logout"]

    choice = st.sidebar.selectbox("Navigate", menu)

    if "user" in st.session_state and not is_session_active():
        st.warning("Session expired due to inactivity. Please log in again.")
        st.session_state.pop("user")
        st.experimental_rerun()
    else:
        if "user" in st.session_state:
            update_session_activity()

    if choice == "Login":
        page_login()
    elif choice == "Dashboard":
        page_dashboard()
    elif choice == "Encrypt Tool":
        page_encrypt_tool()
    elif choice == "Logs":
        page_logs()
    elif choice == "Logout":
        st.session_state.pop("user", None)
        st.success("Logged out successfully.")
        st.experimental_rerun()

if __name__ == "__main__":
    main()
