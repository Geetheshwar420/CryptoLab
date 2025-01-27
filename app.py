import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import padding
import base64

# Function to generate ECDSA Key Pair
def ecdsa_key_pair():
    # Generate ECDSA key pair using SECP256R1 curve
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    public_key = private_key.public_key()
    
    # Serialize the private key and public key (in PEM format)
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key, private_pem, public_pem  # Return all three

# Function to sign a message with ECDSA
def ecdsa_sign(private_key, message):
    signature = private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())  # Using SHA256 as the hash function
    )
    return base64.b64encode(signature).decode()

# Function to verify an ECDSA signature
def ecdsa_verify(public_key_pem, message, signature):
    public_key = load_pem_public_key(public_key_pem, backend=default_backend())
    signature_bytes = base64.b64decode(signature)
    
    try:
        public_key.verify(
            signature_bytes,
            message.encode(),
            ec.ECDSA(hashes.SHA256())  # Using SHA256 as the hash function
        )
        return True
    except:
        return False

# Function to load a PEM public key
def load_pem_public_key(pem_data, backend):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(pem_data, backend=backend)

# Asymmetric Encryption Page (Streamlit UI)
def asymmetric_page():
    # Back button at the top of the page
    if st.button("⬅ Back"):
        navigate_to("Introduction")

    st.title("Asymmetric Encryption (ECDSA)")
    
    action = st.radio("Select Action:", ["Generate ECDSA Key Pair", "Sign with ECDSA", "Verify with ECDSA"])
    
    if action == "Generate ECDSA Key Pair":
        if st.button("Generate"):
            private_key, private_pem, public_pem = ecdsa_key_pair()
            st.session_state.private_key = private_key
            st.session_state.public_key_pem = public_pem
            st.success("ECDSA Key Pair Generated!")
            st.text_area("Public Key:", public_pem.decode())
            st.text_area("Private Key:", private_pem.decode())

    elif action == "Sign with ECDSA":
        message = st.text_input("Enter message to sign:")
        if st.button("Sign"):
            signature = ecdsa_sign(st.session_state.private_key, message)
            st.success(f"Signature: {signature}")

    elif action == "Verify with ECDSA":
        message = st.text_input("Enter message to verify:")
        signature = st.text_input("Enter signature to verify:")
        if st.button("Verify"):
            is_valid = ecdsa_verify(st.session_state.public_key_pem, message, signature)
            if is_valid:
                st.success("Signature is valid!")
            else:
                st.error("Signature is invalid!")

# Main Execution Flow
if "current_page" not in st.session_state:
    st.session_state.current_page = "Introduction"

if st.session_state.current_page == "Introduction":
    introduction()  # Function to show Introduction page
elif st.session_state.current_page == "Symmetric Encryption":
    symmetric_page()  # Function to show Symmetric Encryption page
elif st.session_state.current_page == "Asymmetric Encryption":
    asymmetric_page()  # Function to show Asymmetric Encryption page
elif st.session_state.current_page == "Hashing":
    hashing_page()  # Function to show Hashing page
