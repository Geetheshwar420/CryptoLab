import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
from cryptography.hazmat.primitives.hashes import Hash, SHA256, SHA3_256, MD5, SHA1, SHA224, BLAKE2b, BLAKE2s
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from base64 import b64encode, b64decode
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


# Helper function for navigation
def navigate_to(page):
    st.session_state.current_page = page

# Helper function to derive a key
def derive_key(password, algo="PBKDF2", salt=None):
    if not salt:
        salt = os.urandom(16)
    if algo == "PBKDF2":
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
    elif algo == "scrypt":
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
    else:
        raise ValueError("Unsupported Key Derivation Function")

    key = kdf.derive(password.encode())
    return key, salt

# Symmetric Encryption Algorithms
def symmetric_encrypt(algorithm, mode, message, key, iv=None):
    if algorithm == "AES":
        cipher_algo = algorithms.AES(key)
    elif algorithm == "DES":
        cipher_algo = algorithms.TripleDES(key)
    elif algorithm == "ChaCha20":
        cipher_algo = algorithms.ChaCha20(key, iv)
    elif algorithm == "RC4":
        cipher_algo = algorithms.ARC4(key)
    elif algorithm == "Blowfish":
        cipher_algo = algorithms.Blowfish(key)
    elif algorithm == "CAST5":
        cipher_algo = algorithms.CAST5(key)
    else:
        raise ValueError("Unsupported Algorithm")

    if algorithm == "ChaCha20":
        cipher = Cipher(cipher_algo, mode=None, backend=default_backend())
    else:
        cipher = Cipher(cipher_algo, mode, backend=default_backend())

    encryptor = cipher.encryptor()
    if mode:
        padder = padding.PKCS7(cipher_algo.block_size).padder()
        padded_message = padder.update(message.encode()) + padder.finalize()
        encrypted = encryptor.update(padded_message) + encryptor.finalize()
    else:
        encrypted = encryptor.update(message.encode()) + encryptor.finalize()

    return b64encode(encrypted).decode()

def symmetric_decrypt(algorithm, mode, encrypted_message, key, iv=None):
    if algorithm == "AES":
        cipher_algo = algorithms.AES(key)
    elif algorithm == "DES":
        cipher_algo = algorithms.TripleDES(key)
    elif algorithm == "ChaCha20":
        cipher_algo = algorithms.ChaCha20(key, iv)
    elif algorithm == "RC4":
        cipher_algo = algorithms.ARC4(key)
    elif algorithm == "Blowfish":
        cipher_algo = algorithms.Blowfish(key)
    elif algorithm == "CAST5":
        cipher_algo = algorithms.CAST5(key)
    else:
        raise ValueError("Unsupported Algorithm")

    if algorithm == "ChaCha20":
        cipher = Cipher(cipher_algo, mode=None, backend=default_backend())
    else:
        cipher = Cipher(cipher_algo, mode, backend=default_backend())

    decryptor = cipher.decryptor()
    if mode:
        unpadder = padding.PKCS7(cipher_algo.block_size).unpadder()
        decrypted_padded = decryptor.update(b64decode(encrypted_message)) + decryptor.finalize()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    else:
        decrypted = decryptor.update(b64decode(encrypted_message)) + decryptor.finalize()

    return decrypted.decode()

# Asymmetric Encryption Algorithms (Updated)
def rsa_key_pair():
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Generate the corresponding public key
    public_key = private_key.public_key()
    
    # Serialize the private key (to PEM format)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize the public key (to PEM format)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

def rsa_encrypt(public_key, message):
    # Encrypt message using RSA public key
    encrypted = public_key.encrypt(
        message.encode(),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return b64encode(encrypted).decode()

def rsa_decrypt(private_key, encrypted_message):
    # Decrypt message using RSA private key
    decrypted = private_key.decrypt(
        b64decode(encrypted_message),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def ecdsa_key_pair():
    # Generate ECDSA key pair using SECP256R1 curve
    private_key = generate_private_key(SECP256R1(), backend=default_backend())
    public_key = private_key.public_key()
    
    # Serialize the private key and public key (in PEM format)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

def ecdsa_sign(private_key, message):
    # Sign the message using ECDSA
    signature = private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    return b64encode(signature).decode()

def ecdsa_verify(public_key, message, signature):
    # Verify the signature of the message using ECDSA
    try:
        public_key.verify(
            b64decode(signature),
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return "Signature is valid!"
    except Exception as e:
        return f"Signature verification failed: {str(e)}"

# Hashing Algorithms
def generate_hash(message, algorithm):
    if algorithm == "SHA-256":
        digest = Hash(SHA256(), backend=default_backend())
    elif algorithm == "SHA-3-256":
        digest = Hash(SHA3_256(), backend=default_backend())
    elif algorithm == "MD5":
        digest = Hash(MD5(), backend=default_backend())
    elif algorithm == "SHA1":
        digest = Hash(SHA1(), backend=default_backend())
    elif algorithm == "SHA224":
        digest = Hash(SHA224(), backend=default_backend())
    elif algorithm == "BLAKE2b":
        digest = Hash(BLAKE2b(256), backend=default_backend())
    elif algorithm == "BLAKE2s":
        digest = Hash(BLAKE2s(256), backend=default_backend())
    else:
        raise ValueError("Unsupported Hash Algorithm")

    digest.update(message.encode())
    return digest.finalize().hex()

# Introduction Page
def introduction():
    st.title("Comprehensive Cryptographic Lab")
    st.write("Explore Symmetric Encryption, Asymmetric Encryption, and Hashing Algorithms.")
    
    category = st.radio("Select a Category to Explore:", ["Symmetric Encryption", "Asymmetric Encryption", "Hashing"], key="category")
    if st.button("Go to Selected Category"):
        navigate_to(category)

# Symmetric Encryption Page
def symmetric_page():
    # Back button at the top of the page
    if st.button("⬅ Back"):
        navigate_to("Introduction")

    st.title("Symmetric Encryption")
    algo = st.selectbox("Choose Algorithm:", ["AES", "DES", "ChaCha20", "RC4", "Blowfish", "CAST5"])
    mode = st.selectbox("Choose Mode (if applicable):", ["ECB", "CBC", None])
    message = st.text_input("Enter plaintext:")
    key = st.text_input("Enter key (16 bytes for AES, 8/24 bytes for DES, 32 bytes for ChaCha20):", type="password")
    iv = st.text_input("Enter IV (if needed):", type="password")
    encrypt = st.button("Encrypt")
    decrypt = st.button("Decrypt")

    if encrypt:
        try:
            result = symmetric_encrypt(algo, modes.CBC(b64decode(iv.encode())) if iv else None, message, b64decode(key.encode()))
            st.success(f"Encrypted: {result}")
        except Exception as e:
            st.error(f"Error: {e}")

    if decrypt:
        try:
            result = symmetric_decrypt(algo, modes.CBC(b64decode(iv.encode())) if iv else None, message, b64decode(key.encode()))
            st.success(f"Decrypted: {result}")
        except Exception as e:
            st.error(f"Error: {e}")

# Asymmetric Encryption Page
def asymmetric_page():
    # Back button at the top of the page
    if st.button("⬅ Back"):
        navigate_to("Introduction")

    st.title("Asymmetric Encryption")
    
    action = st.radio("Select Action:", ["Generate RSA Key Pair", "Encrypt with RSA", "Decrypt with RSA", "Generate ECDSA Key Pair", "Sign with ECDSA", "Verify with ECDSA"])
    
    if action == "Generate RSA Key Pair":
        if st.button("Generate"):
            private_pem, public_pem = rsa_key_pair()
            st.session_state.private_key = private_pem
            st.session_state.public_key = public_pem
            st.success("RSA Key Pair Generated!")
            st.text_area("Public Key:", public_pem.decode())
            st.text_area("Private Key:", private_pem.decode())
    
    elif action == "Encrypt with RSA":
        message = st.text_input("Enter message to encrypt:")
        if st.button("Encrypt"):
            encrypted_message = rsa_encrypt(st.session_state.public_key, message)
            st.success(f"Encrypted Message: {encrypted_message}")
    
    elif action == "Decrypt with RSA":
        encrypted_message = st.text_input("Enter encrypted message:")
        if st.button("Decrypt"):
            decrypted_message = rsa_decrypt(st.session_state.private_key, encrypted_message)
            st.success(f"Decrypted Message: {decrypted_message}")

    elif action == "Generate ECDSA Key Pair":
        if st.button("Generate"):
            private_key, private_pem, public_pem = ecdsa_key_pair()
            st.session_state.private_key = private_key
            st.session_state.private_pem = private_pem
            st.session_state.public_key = public_pem
            st.success("ECDSA Key Pair Generated!")
            st.text_area("Public Key:", public_pem.decode())
            st.text_area("Private Key:", private_pem.decode())

    elif action == "Sign with ECDSA":
        message = st.text_input("Enter message to sign:")
        if st.button("Sign"):
            signature = ecdsa_sign(st.session_state.private_key, message)
            st.success(f"Signature: {signature}")

    elif action == "Verify with ECDSA":
        message = st.text_input("Enter message:")
        signature = st.text_input("Enter signature to verify:")
        if st.button("Verify"):
            verification_result = ecdsa_verify(st.session_state.public_key, message, signature)
            st.success(verification_result)

# Hashing Page
def hashing_page():
    # Back button at the top of the page
    if st.button("⬅ Back"):
        navigate_to("Introduction")

    st.title("Hashing")
    algo = st.selectbox("Choose Algorithm:", ["SHA-256", "SHA-3-256", "MD5", "SHA1", "SHA224", "BLAKE2b", "BLAKE2s"])
    message = st.text_input("Enter message:")
    if st.button("Generate Hash"):
        try:
            result = generate_hash(message, algo)
            st.success(f"Hash: {result}")
        except Exception as e:
            st.error(f"Error: {e}")

# Main
if "current_page" not in st.session_state:
    st.session_state.current_page = "Introduction"

if st.session_state.current_page == "Introduction":
    introduction()
elif st.session_state.current_page == "Symmetric Encryption":
    symmetric_page()
elif st.session_state.current_page == "Asymmetric Encryption":
    asymmetric_page()
elif st.session_state.current_page == "Hashing":
    hashing_page()
