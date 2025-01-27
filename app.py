import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import b64encode, b64decode
import os

# Helper function for navigation
def navigate_to(page):
    st.session_state.current_page = page

# Helper function for AES encryption
def aes_encrypt(message, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_message) + encryptor.finalize()
    return b64encode(encrypted).decode()

def aes_decrypt(encrypted_message, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_padded = decryptor.update(b64decode(encrypted_message)) + decryptor.finalize()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()

# Introduction Page
def introduction():
    st.title("Virtual Cryptographic Lab")
    st.write("Explore Symmetric Encryption, Asymmetric Encryption, and Hashing Algorithms.")
    
    # Navigation Options
    category = st.radio(
        "Select a Category to Explore:",
        ["Symmetric Encryption", "Asymmetric Encryption", "Hashing"],
        key="category_selection"
    )
    
    if st.button("Go to Selected Category"):
        navigate_to(category)

# Symmetric Encryption Page
def symmetric_encryption():
    st.title("Symmetric Encryption")
    st.write("Perform encryption and decryption using AES.")
    
    # Inputs
    message = st.text_input("Enter your plaintext:")
    key_input = st.text_input("Enter your key (16 characters):", type="password")
    encrypt = st.button("Encrypt")
    decrypt = st.button("Decrypt")
    
    # Back Button
    if st.button("⬅ Back"):
        navigate_to("Introduction")
    
    if key_input and len(key_input) == 16:
        key = key_input.encode()
        if encrypt and message:
            try:
                encrypted_message = aes_encrypt(message, key)
                st.success(f"Encrypted Message: {encrypted_message}")
            except Exception as e:
                st.error(f"Encryption Error: {e}")
        elif decrypt and message:
            try:
                decrypted_message = aes_decrypt(message, key)
                st.success(f"Decrypted Message: {decrypted_message}")
            except Exception as e:
                st.error(f"Decryption Error: {e}")
    elif key_input:
        st.error("Key must be exactly 16 characters.")

# Asymmetric Encryption Page
def asymmetric_encryption():
    st.title("Asymmetric Encryption")
    st.write("Generate RSA key pairs and perform encryption and decryption.")
    
    if "rsa_key" not in st.session_state:
        st.session_state.rsa_key = None
    
    if st.button("Generate RSA Key Pair"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        st.session_state.rsa_key = key
        st.success("RSA Key Pair Generated Successfully.")
        st.text(f"Public Key: {key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()}")
    
    message = st.text_input("Enter message to encrypt:")
    if st.session_state.rsa_key and message and st.button("Encrypt"):
        try:
            public_key = st.session_state.rsa_key.public_key()
            encrypted = public_key.encrypt(
                message.encode(),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=SHA256()),
                    algorithm=SHA256(),
                    label=None
                )
            )
            st.success(f"Encrypted Message: {b64encode(encrypted).decode()}")
        except Exception as e:
            st.error(f"Encryption Error: {e}")

    if st.session_state.rsa_key and st.button("Decrypt"):
        try:
            private_key = st.session_state.rsa_key
            encrypted_message = st.text_area("Enter the encrypted message:")
            decrypted = private_key.decrypt(
                b64decode(encrypted_message),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=SHA256()),
                    algorithm=SHA256(),
                    label=None
                )
            )
            st.success(f"Decrypted Message: {decrypted.decode()}")
        except Exception as e:
            st.error(f"Decryption Error: {e}")
    
    # Back Button
    if st.button("⬅ Back"):
        navigate_to("Introduction")

# Hashing Page
def hashing():
    st.title("Hashing")
    st.write("Generate hashes using SHA-256 or MD5.")
    
    message = st.text_input("Enter the message to hash:")
    algo = st.selectbox("Choose Hash Algorithm:", ["SHA-256", "MD5"])
    
    if st.button("Generate Hash"):
        if message:
            if algo == "SHA-256":
                hash_result = hashes.Hash(hashes.SHA256(), backend=default_backend())
                hash_result.update(message.encode())
                result = hash_result.finalize()
            elif algo == "MD5":
                hash_result = hashes.Hash(hashes.MD5(), backend=default_backend())
                hash_result.update(message.encode())
                result = hash_result.finalize()
            st.success(f"Generated Hash: {result.hex()}")
        else:
            st.error("Please enter a message to hash.")
    
    # Back Button
    if st.button("⬅ Back"):
        navigate_to("Introduction")

# Main App
if "current_page" not in st.session_state:
    st.session_state.current_page = "Introduction"

# Page Routing
if st.session_state.current_page == "Introduction":
    introduction()
elif st.session_state.current_page == "Symmetric Encryption":
    symmetric_encryption()
elif st.session_state.current_page == "Asymmetric Encryption":
    asymmetric_encryption()
elif st.session_state.current_page == "Hashing":
    hashing()
