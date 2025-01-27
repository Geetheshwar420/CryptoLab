import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.hashes import SHA256, MD5
from base64 import b64encode, b64decode
import os

# Helper function for navigation
def navigate_to(page):
    st.session_state.current_page = page

# Symmetric Encryption Algorithms
def symmetric_encrypt(algorithm, message, key):
    if algorithm == "AES":
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    elif algorithm == "DES":
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    else:
        raise ValueError("Unsupported Algorithm")

    encryptor = cipher.encryptor()
    padder = padding.PKCS7(cipher.algorithm.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_message) + encryptor.finalize()
    return b64encode(encrypted).decode()

def symmetric_decrypt(algorithm, encrypted_message, key):
    if algorithm == "AES":
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    elif algorithm == "DES":
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    else:
        raise ValueError("Unsupported Algorithm")

    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(cipher.algorithm.block_size).unpadder()
    decrypted_padded = decryptor.update(b64decode(encrypted_message)) + decryptor.finalize()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()

# Asymmetric Encryption (RSA)
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(public_key, message):
    return b64encode(public_key.encrypt(
        message.encode(),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )).decode()

def rsa_decrypt(private_key, encrypted_message):
    return private_key.decrypt(
        b64decode(encrypted_message),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    ).decode()

# Hashing
def generate_hash(algo, message):
    if algo == "SHA-256":
        hasher = SHA256()
    elif algo == "MD5":
        hasher = MD5()
    else:
        raise ValueError("Unsupported Algorithm")

    digest = hashes.Hash(hasher, backend=default_backend())
    digest.update(message.encode())
    return digest.finalize().hex()

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
    st.write("Perform encryption and decryption using symmetric algorithms like AES and DES.")
    
    # Inputs
    algorithm = st.selectbox("Choose Algorithm:", ["AES", "DES"])
    message = st.text_input("Enter your plaintext:")
    key = st.text_input("Enter your key (16 bytes for AES, 8/24 bytes for DES):", type="password")
    encrypt = st.button("Encrypt")
    decrypt = st.button("Decrypt")
    
    if st.button("⬅ Back"):
        navigate_to("Introduction")
    
    if encrypt:
        try:
            if (algorithm == "AES" and len(key) != 16) or (algorithm == "DES" and len(key) not in [8, 24]):
                st.error(f"Invalid key length for {algorithm}.")
            else:
                encrypted_message = symmetric_encrypt(algorithm, message, key.encode())
                st.success(f"Encrypted Message: {encrypted_message}")
        except Exception as e:
            st.error(f"Encryption Error: {e}")
    
    if decrypt:
        try:
            decrypted_message = symmetric_decrypt(algorithm, message, key.encode())
            st.success(f"Decrypted Message: {decrypted_message}")
        except Exception as e:
            st.error(f"Decryption Error: {e}")

# Asymmetric Encryption Page
def asymmetric_encryption():
    st.title("Asymmetric Encryption")
    st.write("Generate RSA key pairs and perform encryption and decryption.")
    
    if "rsa_keys" not in st.session_state:
        st.session_state.rsa_keys = None
    
    if st.button("Generate RSA Key Pair"):
        private_key, public_key = generate_rsa_key_pair()
        st.session_state.rsa_keys = {"private_key": private_key, "public_key": public_key}
        st.success("RSA Key Pair Generated Successfully.")
    
    message = st.text_input("Enter message to encrypt:")
    if st.session_state.rsa_keys and message and st.button("Encrypt"):
        try:
            public_key = st.session_state.rsa_keys["public_key"]
            encrypted_message = rsa_encrypt(public_key, message)
            st.success(f"Encrypted Message: {encrypted_message}")
        except Exception as e:
            st.error(f"Encryption Error: {e}")

    encrypted_message = st.text_area("Enter the encrypted message to decrypt:")
    if st.session_state.rsa_keys and encrypted_message and st.button("Decrypt"):
        try:
            private_key = st.session_state.rsa_keys["private_key"]
            decrypted_message = rsa_decrypt(private_key, encrypted_message)
            st.success(f"Decrypted Message: {decrypted_message}")
        except Exception as e:
            st.error(f"Decryption Error: {e}")
    
    if st.button("⬅ Back"):
        navigate_to("Introduction")

# Hashing Page
def hashing():
    st.title("Hashing")
    st.write("Generate hashes using SHA-256 or MD5.")
    
    message = st.text_input("Enter the message to hash:")
    algo = st.selectbox("Choose Hash Algorithm:", ["SHA-256", "MD5"])
    
    if st.button("Generate Hash"):
        try:
            hash_value = generate_hash(algo, message)
            st.success(f"Generated Hash: {hash_value}")
        except Exception as e:
            st.error(f"Hashing Error: {e}")
    
    if st.button("⬅ Back"):
        navigate_to("Introduction")

# Main App
if "current_page" not in st.session_state:
    st.session_state.current_page = "Introduction"

if st.session_state.current_page == "Introduction":
    introduction()
elif st.session_state.current_page == "Symmetric Encryption":
    symmetric_encryption()
elif st.session_state.current_page == "Asymmetric Encryption":
    asymmetric_encryption()
elif st.session_state.current_page == "Hashing":
    hashing()
