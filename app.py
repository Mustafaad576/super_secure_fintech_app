import streamlit as st
import re
import hashlib
import html
from datetime import datetime, timedelta
import binascii
SESSION_TIMEOUT_MINUTES = 15
PASSWORD_MIN_LEN = 8
PW_POLICY_RE = re.compile(
    rf'^(?=.*[0-9])(?=.*[A-Z])(?=.*[a-z])(?=.*[!@#\$%\^&\*]).{{{PASSWORD_MIN_LEN},}}$'
)
USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{1,50}$') 
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except Exception:
    BCRYPT_AVAILABLE = False

USERS = {}
AUDIT_LOGS = []
def seed_admin():
    if 'admin' not in USERS:
        pw = "Test@1234"
        if BCRYPT_AVAILABLE:
            ph = bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt())
        else:
            ph = hashlib.sha256(pw.encode('utf-8')).hexdigest()
        USERS['admin'] = {"password_hash": ph, "created_at": datetime.utcnow()}
def now_iso():
    return datetime.utcnow().isoformat()

def log_action(user, action, meta=""):
    AUDIT_LOGS.insert(0, {"ts": now_iso(), "user": user, "action": action, "meta": meta})
    # keep log size reasonable
    if len(AUDIT_LOGS) > 1000:
        AUDIT_LOGS.pop()

def hash_password(password: str):
    if BCRYPT_AVAILABLE:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    else:
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(password: str, stored):
    if BCRYPT_AVAILABLE:
        try:
            return bcrypt.checkpw(password.encode('utf-8'), stored)
        except Exception:
            return False
    else:
        return hashlib.sha256(password.encode('utf-8')).hexdigest() == stored

def sanitize_for_display(s: str) -> str:
    return html.escape(str(s))

def is_valid_username(u: str) -> bool:
    return bool(USERNAME_RE.match(u))

def is_strong_password(pw: str) -> bool:
    return bool(PW_POLICY_RE.match(pw))
def create_session(username: str):
    st.session_state['user'] = username
    st.session_state['last_activity'] = datetime.utcnow()
    log_action(username, "login")

def is_session_active() -> bool:
    if 'user' not in st.session_state:
        return False
    if 'last_activity' not in st.session_state:
        return False
    return datetime.utcnow() - st.session_state['last_activity'] <= timedelta(minutes=SESSION_TIMEOUT_MINUTES)

def refresh_activity():
    st.session_state['last_activity'] = datetime.utcnow()

def logout_session():
    user = st.session_state.get('user')
    if user:
        log_action(user, "logout")
    keys = list(st.session_state.keys())
    for k in keys:
        del st.session_state[k]
def page_login():
    st.header("🔐 Login")
    if not BCRYPT_AVAILABLE:
        st.warning("bcrypt not available in this environment — using SHA256 fallback for demo only.")
    username = st.text_input("Username", key="login_user")
    password = st.text_input("Password", type="password", key="login_pw")

    if st.button("Login"):
        if not username or not password:
            st.error("Enter both username and password.")
            return
        input_username = username.strip()
        user_rec = USERS.get(input_username)
        if user_rec and verify_password(password, user_rec["password_hash"]):
            create_session(input_username)
            st.success(f"Welcome, {sanitize_for_display(input_username)}!")
            st.rerun()
        else:
            log_action(input_username, "failed_login")
            st.error("Invalid credentials.")

def page_register():
    st.header("🧾 Register")
    st.write("Choose a username (letters, numbers, underscore) and a strong password.")
    new_user = st.text_input("Username", key="reg_user")
    new_password = st.text_input("Password", type="password", key="reg_pw")
    confirm_pw = st.text_input("Confirm password", type="password", key="reg_confirm")

    if st.button("Register"):
        if not new_user or not new_password or not confirm_pw:
            st.error("All fields are required.")
            return
        if not is_valid_username(new_user):
            st.error("Username invalid — use letters, numbers, underscore; max 50 chars.")
            return
        if new_password != confirm_pw:
            st.error("Passwords do not match.")
            return
        if not is_strong_password(new_password):
            st.error(f"Password must be >={PASSWORD_MIN_LEN} chars and include upper, lower, digit, and symbol.")
            return
        if new_user in USERS:
            st.error("Username already exists.")
            return
        ph = hash_password(new_password)
        USERS[new_user] = {"password_hash": ph, "created_at": datetime.utcnow()}
        log_action(new_user, "register")
        st.success("Account created. You can now log in.")

def page_dashboard():
    if not is_session_active():
        logout_session()
        st.warning("Session expired or not logged in. Please log in.")
        return
    refresh_activity()
    st.header("💼 Dashboard")
    user = st.session_state['user']
    st.subheader(f"Welcome, {sanitize_for_display(user)}")
    st.write("Quick FinTech demo: simulate a transaction or use the encryption tool.")
    amount = st.number_input("Amount (PKR)", min_value=0.0, step=0.01)
    recipient = st.text_input("Recipient username")
    if st.button("Send"):
        if amount <= 0:
            st.error("Enter a positive amount.")
        elif not recipient or not is_valid_username(recipient):
            st.error("Enter a valid recipient username.")
        else:
            log_action(user, "transfer", f"to={recipient};amount={amount}")
            st.success(f"Sent PKR {amount:.2f} to {sanitize_for_display(recipient)}")

    st.markdown("---")
    if st.button("Logout"):
        logout_session()
        st.success("Logged out.")
        st.experimental_rerun()

def page_encrypt_tool():
    if not is_session_active():
        st.warning("Please log in to use the encryption tool.")
        return
    refresh_activity()
    st.header("🔐 Encrypt / Decrypt Demo (hex encode)")
    txt = st.text_area("Enter text to encrypt/decrypt", height=120)
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Encrypt (to hex)"):
            if not txt:
                st.warning("Enter text to encrypt.")
            else:
                enc = binascii.hexlify(txt.encode('utf-8')).decode('utf-8')
                st.code(enc)
                log_action(st.session_state['user'], "encrypt", f"len={len(txt)}")
    with col2:
        if st.button("Decrypt (from hex)"):
            if not txt:
                st.warning("Enter hex string to decrypt.")
            else:
                try:
                    dec = binascii.unhexlify(txt.encode('utf-8')).decode('utf-8')
                    st.code(dec)
                    log_action(st.session_state['user'], "decrypt", f"len={len(dec)}")
                except Exception:
                    st.error("Invalid hex string.")

def page_logs():
    if not is_session_active():
        st.warning("Please log in to view logs.")
        return
    refresh_activity()
    st.header("📋 Audit Logs (most recent first)")
    if not AUDIT_LOGS:
        st.info("No logs yet.")
        return
    rows = AUDIT_LOGS[:200]
    safe_rows = [
        {
            "ts": r["ts"],
            "user": sanitize_for_display(r["user"]) if r["user"] else "(anon)",
            "action": sanitize_for_display(r["action"]),
            "meta": sanitize_for_display(r["meta"])
        }
        for r in rows
    ]
    st.table(safe_rows)

def page_about():
    st.header("ℹ️ About / Notes")
    st.write("""
    This demo uses **in-memory** storage (no database) to avoid file permission issues on Streamlit Cloud.
    - Default seeded admin: **admin / Test@1234**
    - Password hashing uses bcrypt if available; otherwise SHA256 fallback (note this in your report).
    - Audit logs are kept in memory for demoing test cases.
    """)

def main():
    seed_admin()
    st.sidebar.title("🔒 Secure FinTech Demo (in-memory)")
    if 'user' in st.session_state and not is_session_active():
        logout_session()
        st.warning("Session timed out. Please log in again.")

    if 'user' in st.session_state:
        menu = st.sidebar.selectbox("Menu", ["Dashboard", "Encrypt Tool", "Logs", "About", "Logout"])
        if menu == "Dashboard":
            page_dashboard()
        elif menu == "Encrypt Tool":
            page_encrypt_tool()
        elif menu == "Logs":
            page_logs()
        elif menu == "About":
            page_about()
        elif menu == "Logout":
            logout_session()
            st.success("Logged out.")
            st.experimental_rerun()
    else:
        menu = st.sidebar.selectbox("Menu", ["Login", "Register", "About"])
        if menu == "Login":
            page_login()
        elif menu == "Register":
            page_register()
        elif menu == "About":
            page_about()

if __name__ == "__main__":
    main()
