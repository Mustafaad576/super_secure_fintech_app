import streamlit as st
import sqlite3
import hashlib
import os

# ------------------ Database Setup ------------------
DB_PATH = "users.db"

def create_table():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def insert_default_user():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Insert default admin user if not exists
    cur.execute("SELECT * FROM users WHERE username=?", ("admin",))
    if not cur.fetchone():
        hashed_pw = hashlib.sha256("admin123".encode()).hexdigest()
        cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", hashed_pw))
        conn.commit()
    conn.close()

def add_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    hashed_pw = hashlib.sha256(password.encode()).hexdigest()
    try:
        cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_user_by_username(username):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cur.fetchone()
    conn.close()
    return user

# ------------------ Utility Functions ------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(stored_password, provided_password):
    return stored_password == hash_password(provided_password)

# ------------------ Pages ------------------
def page_login():
    st.title("🔐 Secure FinTech Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = get_user_by_username(username)
        if user and check_password(user[2], password):
            st.session_state["logged_in"] = True
            st.session_state["username"] = username
            st.success(f"Welcome back, {username}!")
        else:
            st.error("Invalid username or password")

def page_register():
    st.title("🧾 Register New Account")

    new_user = st.text_input("Choose a username")
    new_pass = st.text_input("Choose a password", type="password")

    if st.button("Register"):
        if add_user(new_user, new_pass):
            st.success("User registered successfully! You can now log in.")
        else:
            st.error("Username already exists. Try another one.")

def page_encrypt():
    st.title("🔒 Data Encryption Tool")

    data = st.text_area("Enter data to encrypt")
    if st.button("Encrypt"):
        if data:
            encrypted = hashlib.sha256(data.encode()).hexdigest()
            st.success(f"Encrypted Data: {encrypted}")
        else:
            st.warning("Please enter data to encrypt")

def page_about():
    st.title("ℹ️ About This App")
    st.write("""
    This FinTech app demonstrates secure login, password hashing, 
    and encryption — designed for cybersecurity awareness and testing.
    """)

# ------------------ Main App ------------------
def main():
    st.sidebar.title("🔐 Secure FinTech App")
    menu = st.sidebar.radio("Navigation", ["Login", "Register", "Encrypt", "About"])

    if menu == "Login":
        page_login()
    elif menu == "Register":
        page_register()
    elif menu == "Encrypt":
        if st.session_state.get("logged_in"):
            page_encrypt()
        else:
            st.warning("Please login first to access this page.")
    elif menu == "About":
        page_about()

if __name__ == "__main__":
    create_table()
    insert_default_user()
    main()
