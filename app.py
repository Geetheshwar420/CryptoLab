import streamlit as st
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from hashlib import sha256, md5

# Helper function for navigation
def navigate_to(page):
    st.session_state.current_page = page

# Helper function for padding (AES and DES require fixed block sizes)
def pad(text, block_size=16):
    padding_length = block_size - len(text) % block_size
    return text + chr(padding_length) * padding_length

def unpad(text):
    padding_length = ord(text[-1])
    return text[:-padding_length]

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
    key = st.text_input("Enter your key (16 bytes for AES, 8 bytes for DES):")
    execute = st.button("Encrypt")
    
    # Back Button
    if st.button("⬅ Back"):
        navigate_to("Introduction")
    
    # Process Encryption
    if execute:
        try:
            if algorithm == "AES" and len(key) != 16:
                st.error("Key must be 16 bytes for AES.")
            elif algorithm == "DES" and len(key) != 8:
                st.error("Key must be 8 bytes for DES.")
            else:
                if algorithm == "AES":
                    cipher = AES.new(key.encode(), AES.MODE_ECB)
                elif algorithm == "DES":
                    cipher = DES.new(key.encode(), DES.MODE_ECB)
                
                encrypted = cipher.encrypt(pad(message).encode())
                st.success(f"Encrypted Message: {encrypted.hex()}")

                if st.button("Decrypt"):
                    decrypted = unpad(cipher.decrypt(bytes.fromhex(encrypted.hex())).decode())
                    st.success(f"Decrypted Message: {decrypted}")
        except Exception as e:
            st.error(f"Error: {e}")

# Asymmetric Encryption Page
def asymmetric_encryption():
    st.title("Asymmetric Encryption")
    st.write("Generate RSA key pairs and perform encryption and decryption.")
    
    if "rsa_key" not in st.session_state:
        st.session_state.rsa_key = None
    
    if st.button("Generate RSA Key Pair"):
        key = RSA.generate(2048)
        st.session_state.rsa_key = key
        st.success("Keys generated successfully.")
        st.text(f"Public Key (PEM):\n{key.publickey().export_key().decode()}")

    message = st.text_input("Enter message to encrypt:")
    if st.session_state.rsa_key and message and st.button("Encrypt"):
        try:
            public_key = st.session_state.rsa_key.publickey()
            cipher = PKCS1_OAEP.new(public_key)
            encrypted = cipher.encrypt(message.encode())
            st.success(f"Encrypted Message: {encrypted.hex()}")

            if st.button("Decrypt"):
                cipher = PKCS1_OAEP.new(st.session_state.rsa_key)
                decrypted = cipher.decrypt(bytes.fromhex(encrypted.hex())).decode()
                st.success(f"Decrypted Message: {decrypted}")
        except Exception as e:
            st.error(f"Error: {e}")
    
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
                hash_result = sha256(message.encode()).hexdigest()
            elif algo == "MD5":
                hash_result = md5(message.encode()).hexdigest()
            st.success(f"Generated Hash: {hash_result}")
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
