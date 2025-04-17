import streamlit as st
from database import init_db, register_user, login_user, get_user_logs, log_action, update_username, update_password
from cryptography.fernet import Fernet, InvalidToken
import base64
import hashlib
import plotly.express as px
import plotly.graph_objects as go
import time

#page styling
st.set_page_config(page_title= "Cryptify", page_icon="🔐", layout="centered")

with open("style.css") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# Initialize database
init_db()

# Session setup
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = ""
if 'fernet_key' not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
    st.session_state.fernet = Fernet(st.session_state.fernet_key)
if 'session_start_time' not in st.session_state:
    st.session_state.session_start_time = time.time()


def generate_fernet_key_from_password(password: str) -> bytes:
    # Hash the password and encode to a Fernet-compatible base64 key
    hashed = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

# Calculate session time
def get_session_duration():
    elapsed_time = time.time() - st.session_state.session_start_time
    minutes, seconds = divmod(int(elapsed_time), 60)
    return f"{minutes} min {seconds} sec"


st.title("🔐 Cryptify – Lock Your Words, Unlock with Trust.")
st.markdown("""
Secure your messages with ease!  
Encrypt and decrypt your text using simple, secure tools powered by **Fernet**.  
""")


# Show menus based on login status
if st.session_state.logged_in:
    st.success(f"Welcome, {st.session_state.username}!")
# Set default page to 'Home' on first load
    if 'page' not in st.session_state:
        st.session_state.page = 'Dashboard'

    # Sidebar buttons
    st.sidebar.title("Menu")
    if st.sidebar.button("📊 Dashboard", key="dashboard_btn", use_container_width=True):
        st.session_state.page = 'Dashboard'
    if st.sidebar.button("🔐 Encrypt Text", key="encrypt_btn", use_container_width=True):
        st.session_state.page = 'Encryption'
    if st.sidebar.button("🔓 Decrypt Text", key="decrypt_btn", use_container_width=True):
        st.session_state.page = 'Decryption'
    if st.sidebar.button("⚙️ User Settings", key="settings_btn", use_container_width=True):
        st.session_state.page = 'Settings'
    if st.sidebar.button("🚪 Logout", key="logout_btn", use_container_width=True):
        st.session_state.page = 'Logout'

    if st.session_state.page == 'Dashboard':
        st.title("📊 Dashboard")

        action_counts, week_data = get_user_logs(st.session_state.username)
        encrypt_count = action_counts.get("encrypt", 0)
        decrypt_count = action_counts.get("decrypt", 0)

        col1, col2, col3 = st.columns(3)
        col1.metric("Encryptions", str(encrypt_count))
        col2.metric("Decryptions", str(decrypt_count))
        col3.metric("Session Time", get_session_duration())

        # Pie Chart
        st.markdown("### 🔄 Encryption vs Decryption")
        pie_data = px.pie(
            names=["Encryptions", "Decryptions"],
            values=[encrypt_count, decrypt_count],
            color_discrete_sequence=px.colors.sequential.RdBu
        )
        st.plotly_chart(pie_data, use_container_width=True)

        # Bar Chart
        st.markdown("### 📈 Weekly Activity")
        days = list(week_data.keys())
        enc_counts = [week_data[day]["encrypt"] for day in days]
        dec_counts = [week_data[day]["decrypt"] for day in days]

        bar_fig = go.Figure()
        bar_fig.add_trace(go.Bar(x=days, y=enc_counts, name='Encryptions'))
        bar_fig.add_trace(go.Bar(x=days, y=dec_counts, name='Decryptions'))
        bar_fig.update_layout(barmode='group')
        st.plotly_chart(bar_fig, use_container_width=True)


    elif st.session_state.page == 'Encryption':
        st.subheader("🔐 Fernet Encryption")
        key_input = st.text_input("Enter Secret Key (used for both encrypt & decrypt)", type="password")
        text = st.text_area("Enter your text:")
        
        if st.button("Encrypt"):
            if not key_input or not text:
                st.warning("Please enter both key and text.")
            else:
                try:
                    key = generate_fernet_key_from_password(key_input)
                    f = Fernet(key)
                    encrypted_text = f.encrypt(text.encode()).decode()
                    st.session_state.last_encrypted = encrypted_text
                    st.session_state.last_key_used = key_input
                    st.success("Encrypt your data successfully!")
                    st.code(encrypted_text)  # Show encrypted text
                    log_action(st.session_state.username, "encrypt")
                except Exception as e:
                    st.error(f"Error during encryption: {e}")
        
    elif st.session_state.page == 'Decryption':
            st.info("Only the passkey is required. We will use the last encrypted data from this session.")

            key_input = st.text_input("🔑 Enter the passkey to decrypt the previous encrypted message", type="password")

            if st.button("Decrypt"):
                if not key_input:
                    st.warning("Please enter the passkey.")
                elif 'last_encrypted' not in st.session_state:
                    st.warning("No encrypted data found in this session. Please encrypt something first.")
                else:
                    try:
                        key = generate_fernet_key_from_password(key_input)
                        f = Fernet(key)
                        decrypted_text = f.decrypt(st.session_state.last_encrypted.encode()).decode()
                        st.success("✅ Your data was decrypted successfully!")
                        st.code(decrypted_text)
                        log_action(st.session_state.username, "decrypt")
                    except InvalidToken:
                        st.error("❌ Invalid passkey or corrupted data. Decryption failed.")
                    except Exception as e:
                        st.error(f"❌ Error during decryption: {e}")    

    elif st.session_state.page == 'Settings':
        st.header("⚙️ User Settings")

        st.subheader("📧 Update User Name")
        new_username = st.text_input("Enter new username")

        if st.button("Update User Name"):
            if new_username:
                update_username(st.session_state.username, new_username)
                st.success("Username updated successfully!")
            else:
                st.warning("Please enter a valid username.")

        st.subheader("🔒 Change Password")
        current_pass = st.text_input("Current Password", type="password")
        new_pass = st.text_input("New Password", type="password")
        confirm_pass = st.text_input("Confirm New Password", type="password")

        if st.button("Update Password"):
            if not current_pass or not new_pass or not confirm_pass:
                st.warning("Please fill out all password fields.")
            elif new_pass != confirm_pass:
                st.warning("New passwords do not match.")
            elif not login_user(st.session_state.username, current_pass):
                st.error("Current password is incorrect.")
            else:
                update_password(st.session_state.username, new_pass)
                st.success("Password updated successfully!")


    elif st.session_state.page == 'Logout':
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.success("Logged out.")
        st.rerun()

else:
    menu = st.sidebar.radio("Get Started", ["Login", "Register"], index=None)

    if menu is None:
        st.subheader("🔒 Features:")
        st.markdown("""
        - **Fernet Encryption:** Advanced encryption using passkey-based security.
        - **Caesar Cipher:** Classic letter-shifting encryption.
        - **Session-Safe:** Your encrypted data stays secure during your session.
        - **Key-Protected:** Decryption requires your secret passkey.
        """)
        st.success("👉 Get started by logging in from the sidebar!")
        st.caption("“If privacy is outlawed, only outlaws will have privacy.” – Phil Zimmermann")


    elif menu == "Login":
        st.subheader("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            if login_user(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
                st.rerun()
            else:
                st.error("User not found. Please register.")

    elif menu == "Register":
        st.subheader("Register")
        new_username = st.text_input("Create Username")
        new_password = st.text_input("Create Password", type="password")

        if st.button("Register"):
            if register_user(new_username, new_password):
                st.success("Registered! Now login.")
            else:
                st.error("Username already exists.")

st.markdown("---")
st.markdown("Created with ❤️ by Urooj Sadiq - [Connect on LinkedIn](https://www.linkedin.com/in/urooj-sadiq-a91031212/)")
