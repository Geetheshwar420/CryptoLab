try:
    import streamlit as st
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import serialization
    import base64
    import os
except ModuleNotFoundError as e:
    print("Error: Required module not found. Ensure you have 'streamlit' and 'cryptography' installed.")
    print("Use: pip install streamlit cryptography")
    raise

# App configuration
st.set_page_config(page_title="Crypto Lab", layout="wide")

# State management
if "page" not in st.session_state:
    st.session_state.page = "intro"

def set_page(selected_page):
    st.session_state.page = selected_page

# Introduction Page
if st.session_state.page == "intro":
    st.title("Virtual Cryptographic Lab")
    st.write("""
        Welcome to the Virtual Cryptographic Lab! This tool allows you to explore and experiment with cryptographic algorithms such as:
        - **Symmetric Encryption** (e.g., AES, DES)
        - **Asymmetric Encryption** (e.g., RSA)
        - **Hash Functions** (e.g., SHA-256, MD5)
    """)

    st.subheader("Choose a Cryptography Category to Start:")
    st.radio(
        "Select a category:",
        ["Symmetric Encryption", "Asymmetric Encryption", "Hashing"],
        key="category_selection",
        on_change=lambda: set_page(st.session_state.category_selection)
    )

# Symmetric Encryption Page
if st.session_state.page == "Symmetric Encryption":
    if st.button("⬅ Back"):
        set_page("intro")
    st.subheader("Symmetric Encryption")
    algorithm = st.selectbox("Choose Algorithm:", ["AES", "DES"])
    message = st.text_input("Enter your plaintext:")
    key = st.text_input("Enter your key (16 bytes for AES):")
    mode = st.selectbox("Choose mode of operation:", ["ECB", "CBC"])
    execute = st.button("Encrypt/Decrypt")

    if execute:
        try:
            if algorithm == "AES":
                cipher = Cipher(algorithms.AES(key.encode()), modes.ECB())
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
                st.success(f"Ciphertext: {base64.b64encode(ciphertext).decode()}")
            else:
                st.warning("DES implementation coming soon!")
        except Exception as e:
            st.error(f"Error: {e}")

# Asymmetric Encryption Page
if st.session_state.page == "Asymmetric Encryption":
    if st.button("⬅ Back"):
        set_page("intro")
    st.subheader("Asymmetric Encryption")
    st.write("Generate a pair of RSA keys:")
    if st.button("Generate RSA Key Pair"):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        st.text("Private Key:")
        st.code(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode())
        st.text("Public Key:")
        st.code(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode())

# Hashing Page
if st.session_state.page == "Hashing":
    if st.button("⬅ Back"):
        set_page("intro")
    st.subheader("Hash Functions")
    algo = st.selectbox("Choose a hashing algorithm:", ["SHA-256", "MD5"])
    message = st.text_input("Enter your plaintext:")
    execute = st.button("Generate Hash")

    if execute:
        if algo == "SHA-256":
            digest = hashes.Hash(hashes.SHA256())
        elif algo == "MD5":
            digest = hashes.Hash(hashes.MD5())
        digest.update(message.encode())
        hash_value = digest.finalize()
        st.success(f"Hash Value: {hash_value.hex()}")
