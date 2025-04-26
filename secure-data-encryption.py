import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key (in production, securely store and reuse this)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data storage
stored_data = {}  # Structure: {encrypted_text: {"encrypted_text": str, "passkey": hashed_passkey}}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "is_authenticated" not in st.session_state:
    st.session_state.is_authenticated = False

# Function to hash the passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    if encrypted_text in stored_data:
        stored_entry = stored_data[encrypted_text]
        if stored_entry["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            return decrypted

    st.session_state.failed_attempts += 1
    return None

# Streamlit App
st.title("🛡️ Secure Data Encryption System")

# Sidebar Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigate", menu)

# Pages
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("""
        This is a **secure data storage** system using **encryption and authentication**.
        
        🔹 Store any text securely by setting a passkey.  
        🔹 Retrieve data with the correct passkey.  
        🔹 After 3 failed attempts, login reauthorization is needed.
    """)

elif choice == "Store Data":
    st.subheader("📂 Store New Data")
    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Set a passkey for this data:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_pass = hash_passkey(passkey)
            stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_pass}
            st.success("✅ Data encrypted and stored securely!")
            st.write(f"🔒 **Your Encrypted Data (Save this!):**\n\n`{encrypted_text}`")
        else:
            st.error("⚠️ Please fill in both fields!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")

    # If too many failed attempts, block access
    if st.session_state.failed_attempts >= 3 and not st.session_state.is_authenticated:
        st.warning("🔒 Too many failed attempts! Please login again.")
        st.switch_page("Login")  # Switch to login page (Streamlit 1.20+). Else use rerun.
        st.stop()

    encrypted_text = st.text_area("Enter your encrypted text:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success("✅ Decrypted Successfully!")
                st.write(f"📄 **Your Data:**\n\n{result}")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")

                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    master_password = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master_password == "admin123":  # For demo, in production replace this
            st.session_state.failed_attempts = 0
            st.session_state.is_authenticated = True
            st.success("✅ Login successful! Redirecting...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect Master Password!")
           