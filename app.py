import streamlit as st
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
import base64
import os

# App configuration
st.set_page_config(page_title="Crypto Lab", layout="wide")

# Introduction Page
st.title("Virtual Cryptographic Lab")
st.sidebar.header("Navigate")
pages = ["Introduction", "Symmetric Encryption", "Asymmetric Encryption", "Hashing"]
choice = st.sidebar.radio("Choose a category:", pages)

if choice == "Introduction":
    st.subheader("Welcome to the Virtual Cryptographic Lab!")
    st.write("""
        This tool allows you to explore and experiment with cryptographic algorithms such as:
        - Symmetric Encryption (AES, DES)
        - Asymmetric Encryption (RSA)
        - Hash Functions (SHA-256, MD5)
    """)

elif choice == "Symmetric Encryption":
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

elif choice == "Asymmetric Encryption":
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

elif choice == "Hashing":
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
