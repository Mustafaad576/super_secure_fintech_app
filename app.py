import streamlit as st
import re
import hashlib

# ----------------------------
# Security Configuration
# ----------------------------
PASSWORD_MIN_LEN = 8
PW_POLICY_RE = re.compile(
    rf'^(?=.*[0-9])(?=.*[A-Z])(?=.*[a-z])(?=.*[!@#\$%\^&\*]).{{{PASSWORD_MIN_LEN},}}$'
)

# Simple in-memory "database"
USERS = {"admin": hashlib.sha256("Secure@123".encode()).hexdigest()}

# ----------------------------
# Utility Functions
# ----------------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_username(username):
    """Allow only safe usernames"""
    return bool(re.match(r'^[A-Za-z0-9_]+$', username))

def validate_password_strength(password):
    """Check strong password rules"""
    return bool(PW_POLICY_RE.match(password))

def sanitize_input(text):
    """Basic sanitization to avoid script injections"""
    return re.sub(r'[<>"]', '', text)

# ----------------------------
# App Session
# ----------------------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = None

# ----------------------------
# Login Functionality
# ----------------------------
def login():
    st.title("🔐 Secure FinTech App Login")
    username = sanitize_input(st.text_input("Username:"))
    password = st.text_input("Password:", type="password")

    if st.button("Login"):
        if not username or not password:
            st.warning("Please enter both fields.")
            return

        if username in USERS and USERS[username] == hash_password(password):
            st.session_state.authenticated = True
            st.session_state.username = username
            st.success(f"Welcome, {username}!")
            st.experimental_rerun()
        else:
            st.error("Invalid credentials.")

# ----------------------------
# Signup Functionality
# ----------------------------
def signup():
    st.title("🧾 Create an Account")
    username = sanitize_input(st.text_input("New Username:"))
    password = st.text_input("New Password:", type="password")

    if st.button("Sign Up"):
        if not validate_username(username):
            st.error("Username can only contain letters, numbers, and underscores.")
            return

        if not validate_password_strength(password):
            st.error(f"Password must be at least {PASSWORD_MIN_LEN} chars long, with uppercase, lowercase, number, and special character.")
            return

        if username in USERS:
            st.warning("User already exists.")
            return

        USERS[username] = hash_password(password)
        st.success("Account created successfully! Please log in.")

# ----------------------------
# Dashboard
# ----------------------------
def dashboard():
    st.title(f"💼 Welcome, {st.session_state.username}")
    st.markdown("You are now logged into the secure FinTech system.")
    st.info("All actions are logged and monitored for security compliance.")

    st.subheader("Transaction Simulation")
    amount = st.number_input("Enter Amount (PKR):", min_value=0.0, max_value=1000000.0)
    recipient = sanitize_input(st.text_input("Recipient Username:"))

    if st.button("Send Money"):
        if not validate_username(recipient):
            st.error("Invalid recipient name.")
        elif amount <= 0:
            st.warning("Enter a valid amount.")
        else:
            st.success(f"Successfully sent PKR {amount:.2f} to {recipient}!")

    # Logout section
    if st.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.username = None
        st.experimental_rerun()

# ----------------------------
# Navigation
# ----------------------------
st.sidebar.title("🔒 Navigation")
choice = st.sidebar.radio("Select Page", ["Login", "Sign Up"])

if st.session_state.authenticated:
    dashboard()
else:
    if choice == "Login":
        login()
    else:
        signup()
