import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import json
import os
import time
from datetime import datetime

# Constants
MAX_ATTEMPTS = 20
LOCKOUT_TIME = 300  # 5 minutes
DATA_FILE = "encrypted_data.json"
KEY_FILE = "secret.key"

# Session state initialization
if 'attempts' not in st.session_state:
    st.session_state.attempts = 0
if 'locked_out' not in st.session_state:
    st.session_state.locked_out = False
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = 0
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'page' not in st.session_state:
    st.session_state.page = "home"

# Get or generate encryption key
def get_encryption_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return key

# Fernet instance
cipher = Fernet(get_encryption_key())

# Hash with salt
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16)
    else:
        # Convert hex string back to bytes if that's how it's stored
        salt = bytes.fromhex(salt) if isinstance(salt, str) else salt
    hashed = hashlib.pbkdf2_hmac('sha256', passkey.encode('utf-8'), salt, 100000)
    return f"{salt.hex()}:{hashed.hex()}"

# Verify passkey
def verify_passkey(passkey, stored_hash):
    try:
        salt_hex, hashed_hex = stored_hash.split(':')
        # Pass the salt as hex string to hash_passkey
        new_hash = hash_passkey(passkey, salt_hex)
        return new_hash == stored_hash
    except Exception as e:
        print(f"Verification error: {str(e)}")
        return False
# Encrypt data
def encrypt_data(data, passkey):
    encrypted = cipher.encrypt(data.encode('utf-8'))
    hashed_key = hash_passkey(passkey)
    return encrypted, hashed_key

# Decrypt data
def decrypt_data(encrypted_data):
   
    try:
         
        return cipher.decrypt(encrypted_data).decode('utf-8')
    except:
        return None

# Load JSON data
def load_data():
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

# Save JSON data
def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

# Lockout check
def check_lockout():
    if st.session_state.locked_out:
        current_time = time.time()
        if current_time - st.session_state.lockout_time < LOCKOUT_TIME:
            remaining_time = int(LOCKOUT_TIME - (current_time - st.session_state.lockout_time))
            st.error(f"Too many failed attempts. Try again in {remaining_time} seconds.")
            return True
        else:
            st.session_state.locked_out = False
            st.session_state.attempts = 0
    return False

# Sidebar navigation
def sidebar_nav():
    with st.sidebar:
        st.title("🔒 Navigation")
        if st.session_state.authenticated:
            if st.button("🏠 Home"):
                st.session_state.page = "home"
                st.rerun()
            if st.button("💾 Store Data"):
                st.session_state.page = "store"
                st.rerun()
            if st.button("🔑 Retrieve Data"):
                st.session_state.page = "retrieve"
                st.rerun()
            st.markdown("---")
            if st.button("🚪 Logout"):
                st.session_state.authenticated = False
                st.session_state.current_user = None
                st.session_state.page = "home"
                st.rerun()
        st.markdown("---")
        st.write("### About")
        st.write("Secure Data Vault uses:")
        st.write("- AES-256 encryption")
        st.write("- PBKDF2 key derivation")
        st.write("- Secure session management")

# Login page
def login_page():
    st.title("🔒 Secure Data Vault - Login")
    if check_lockout():
        return
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username and password:
            st.session_state.authenticated = True
            st.session_state.current_user = username
            st.session_state.attempts = 0
            st.session_state.page = "home"
            st.rerun()
        else:
            st.error("Please enter both username and password")

# Home page
def home_page():
    st.title("🔒 Secure Data Vault")
    st.write(f"Welcome back, {st.session_state.current_user}!")
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Store Data")
        st.write("Securely encrypt and store your sensitive information")
        if st.button("Go to Store →"):
            st.session_state.page = "store"
            st.rerun()
    with col2:
        st.subheader("Retrieve Data")
        st.write("Access your encrypted data with your passkey")
        if st.button("Go to Retrieve →"):
            st.session_state.page = "retrieve"
            st.rerun()
    st.markdown("---")
    stored_data = load_data()
    count = len([k for k, v in stored_data.items() if v.get("created_by") == st.session_state.current_user])
    st.write(f"📦 You have {count} stored items")

# Store data page
def store_data_page():
    st.title("💾 Store New Data")
    data_key = st.text_input("Unique identifier (e.g., 'note1')")
    secret_data = st.text_area("Enter the data to encrypt", height=200)
    passkey = st.text_input("Create a strong passkey", type="password")
    confirm_passkey = st.text_input("Confirm your passkey", type="password")
    if st.button("Encrypt & Store"):
        if not data_key or not secret_data or not passkey:
            st.error("Please fill in all fields")
        elif passkey != confirm_passkey:
            st.error("Passkeys don't match!")
        else:
            stored_data = load_data()
            if data_key in stored_data:
                st.error("Identifier already exists. Use a different one.")
            else:
                encrypted_data, hashed_key = encrypt_data(secret_data, passkey)
                stored_data[data_key] = {
                    "encrypted_text": encrypted_data.hex(),
                    "passkey_hash": hashed_key,
                    "created_at": datetime.now().isoformat(),
                    "created_by": st.session_state.current_user
                }
                save_data(stored_data)
                st.success("✅ Data encrypted and stored!")
                st.balloons()

# Retrieve data page
def retrieve_data_page():
    st.title("🔑 Retrieve Stored Data")
    if check_lockout():
       
        return
    
    stored_data = load_data()
    user_data = [k for k, v in stored_data.items() if v.get("created_by") == st.session_state.current_user]
    if not user_data:
        st.warning("You haven't stored any data yet.")
        return
    data_key = st.selectbox("Select data to retrieve", user_data)
    passkey = st.text_input("Enter your passkey", type="password").strip()
    if st.button("Decrypt Data"):
        if data_key in stored_data:
            print(data_key ,"checking data key inside retrieve data in lie 220")
            data = stored_data[data_key]
            print(data , "checking for data after encrypts \n")
            encrypted = bytes.fromhex(data["encrypted_text"])
            print(encrypted ,"data envrypts")
            print(passkey ,"pass key validation")
            if verify_passkey(passkey, data["passkey_hash"]):
                 
                decrypted = decrypt_data(encrypted)
                if decrypted:
                     
                    st.success("🔓 Data decrypted successfully!")
                    st.text_area("Decrypted Data", decrypted, height=200)
                    st.session_state.attempts = 0
                else:
                    
                    st.error("Decryption failed!")
            else:
                st.session_state.attempts += 1
                left = MAX_ATTEMPTS - st.session_state.attempts
                if st.session_state.attempts >= MAX_ATTEMPTS:
                    
                    st.session_state.locked_out = True
                    st.session_state.lockout_time = time.time()
                    st.error("❌ Too many failed attempts. Locked out for 5 minutes.")
                else:
                    st.error(f"Invalid passkey! {left} attempts left.")
    st.write(f"Failed attempts: {st.session_state.attempts}/{MAX_ATTEMPTS}")

# Main
def main():
    
    sidebar_nav()
    if not st.session_state.authenticated:
        login_page()
    else:
        if st.session_state.page == "home":
            home_page()
        elif st.session_state.page == "store":
            store_data_page()
        elif st.session_state.page == "retrieve":
            
            retrieve_data_page()

if __name__ == "__main__":
    main()
