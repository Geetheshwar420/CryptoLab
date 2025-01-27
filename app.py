import streamlit as st
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from base64 import b64encode, b64decode

# Helper function for navigation
def navigate_to(page):
    st.session_state.current_page = page

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

# Asymmetric Encryption Algorithms
def rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(public_key, message):
    encrypted = public_key.encrypt(
        message.encode(),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return b64encode(encrypted).decode()

def rsa_decrypt(private_key, encrypted_message):
    decrypted = private_key.decrypt(
        b64decode(encrypted_message),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# Asymmetric Encryption Page
def asymmetric_page():
    # Back button at the top of the page
    if st.button("⬅ Back"):
        navigate_to("Introduction")

    st.title("Asymmetric Encryption")
    
    # Check if keys exist in session state
    if 'private_key' not in st.session_state or 'public_key' not in st.session_state:
        st.warning("You need to generate the RSA key pair first!")
        return

    action = st.radio("Select Action:", ["Generate RSA Key Pair", "Encrypt with RSA", "Decrypt with RSA"])
    
    if action == "Generate RSA Key Pair":
        if st.button("Generate"):
            private_key, public_key = rsa_key_pair()
            st.session_state.private_key = private_key
            st.session_state.public_key = public_key
            st.success("RSA Key Pair Generated!")
            
            # Displaying the public and private keys
            st.subheader("Public Key:")
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            st.text_area("Public Key PEM Format", public_pem)
            
            st.subheader("Private Key:")
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            st.text_area("Private Key PEM Format", private_pem)

    elif action == "Encrypt with RSA":
        message = st.text_input("Enter message to encrypt:")
        if st.button("Encrypt"):
            encrypted_message = rsa_encrypt(st.session_state.public_key, message)
            st.success(f"Encrypted Message: {encrypted_message}")
    
    elif action == "Decrypt with RSA":
        encrypted_message = st.text_input("Enter encrypted message:")
        if st.button("Decrypt"):
            # Check if the private key is present before decryption
            if 'private_key' not in st.session_state:
                st.error("Private key not found! Please generate the RSA key pair first.")
            else:
                decrypted_message = rsa_decrypt(st.session_state.private_key, encrypted_message)
                st.success(f"Decrypted Message: {decrypted_message}")

# Symmetric Encryption Page
def symmetric_page():
    st.title("Symmetric Encryption")
    st.write("Perform encryption and decryption using symmetric algorithms like AES and DES.")
    
    # Inputs
    algorithm = st.selectbox("Choose Algorithm:", ["AES", "DES"])
    message = st.text_input("Enter your plaintext:")
    key = st.text_input("Enter your key (16 bytes for AES):")
    execute = st.button("Encrypt")
    
    # Back Button
    if st.button("⬅ Back"):
        navigate_to("Introduction")
    
    # Process Encryption
    if execute:
        try:
            if len(key) != 16:
                st.error("Key must be 16 bytes for AES.")
            else:
                st.success(f"Encrypted Message: {message[::-1]} (Mocked Encryption)")
        except Exception as e:
            st.error(f"Error: {e}")

# Hashing Page
def hashing_page():
    st.title("Hashing")
    st.write("Generate hashes using SHA-256 or MD5.")
    
    message = st.text_input("Enter the message to hash:")
    algo = st.selectbox("Choose Hash Algorithm:", ["SHA-256", "MD5"])
    
    if st.button("Generate Hash"):
        st.success(f"Generated Hash: {hash(message)} (Mocked Hash)")

# Main
if "current_page" not in st.session_state:
    st.session_state.current_page = "Introduction"

# Page Routing
if st.session_state.current_page == "Introduction":
    introduction()
elif st.session_state.current_page == "Symmetric Encryption":
    symmetric_page()
elif st.session_state.current_page == "Asymmetric Encryption":
    asymmetric_page()
elif st.session_state.current_page == "Hashing":
    hashing_page()
