import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key


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

    return base64.b64encode(encrypted).decode()


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
        decrypted_padded = decryptor.update(base64.b64decode(encrypted_message)) + decryptor.finalize()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    else:
        decrypted = decryptor.update(base64.b64decode(encrypted_message)) + decryptor.finalize()

    return decrypted.decode()


# RSA Key Generation and Signing
def rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key, private_pem, public_pem


def rsa_sign(private_key, message):
    signature = private_key.sign(
        message.encode(),
        asym_padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def rsa_verify(public_key_pem, message, signature):
    public_key = load_pem_public_key(public_key_pem, backend=default_backend())
    signature_bytes = base64.b64decode(signature)
    
    try:
        public_key.verify(
            signature_bytes,
            message.encode(),
            asym_padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except:
        return False


# ECDSA Key Generation and Signing
def ecdsa_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key, private_pem, public_pem


def ecdsa_sign(private_key, message):
    signature = private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())  # Using SHA256 as the hash function
    )
    return base64.b64encode(signature).decode()


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


# Hashing Algorithms
def generate_hash(message, algorithm):
    if algorithm == "SHA-256":
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    elif algorithm == "SHA-3-256":
        digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    elif algorithm == "MD5":
        digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    elif algorithm == "SHA1":
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    elif algorithm == "SHA224":
        digest = hashes.Hash(hashes.SHA224(), backend=default_backend())
    elif algorithm == "BLAKE2b":
        digest = hashes.Hash(hashes.BLAKE2b(256), backend=default_backend())
    elif algorithm == "BLAKE2s":
        digest = hashes.Hash(hashes.BLAKE2s(256), backend=default_backend())
    else:
        raise ValueError("Unsupported Hash Algorithm")

    digest.update(message.encode())
    return digest.finalize().hex()


# Streamlit UI
def introduction():
    st.title("Comprehensive Cryptography Lab")
    st.write("Explore Symmetric Encryption, Asymmetric Encryption, and Hashing Algorithms.")
    
    category = st.radio("Select a Category to Explore:", ["Symmetric Encryption", "Asymmetric Encryption", "Hashing"], key="category")
    if st.button("Go to Selected Category"):
        st.session_state.current_page = category


def symmetric_page():
    if st.button("Back to Home"):
        st.session_state.current_page = "Introduction"
        
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
            result = symmetric_encrypt(algo, modes.CBC(base64.b64decode(iv.encode())) if iv else None, message, base64.b64decode(key.encode()))
            st.success(f"Encrypted: {result}")
        except Exception as e:
            st.error(f"Error: {e}")

    if decrypt:
        try:
            result = symmetric_decrypt(algo, modes.CBC(base64.b64decode(iv.encode())) if iv else None, message, base64.b64decode(key.encode()))
            st.success(f"Decrypted: {result}")
        except Exception as e:
            st.error(f"Error: {e}")




def asymmetric_page():
    if st.button("Back to Home"):
        st.session_state.current_page = "Introduction"
        
    st.title("Asymmetric Encryption (RSA & ECDSA)")
    action = st.radio("Select Action:", ["Generate RSA Key Pair", "Generate ECDSA Key Pair", "Sign with RSA", "Verify with RSA", "Sign with ECDSA", "Verify with ECDSA"])

    if action == "Generate RSA Key Pair":
        if st.button("Generate"):
            private_key, private_pem, public_pem = rsa_key_pair()
            st.session_state.private_key = private_key
            st.session_state.public_key = public_pem
            st.success("RSA Key Pair Generated!")
            st.text_area("Public Key:", base64.b64encode(public_pem).decode())
            st.text_area("Private Key:", base64.b64encode(private_pem).decode())

    elif action == "Generate ECDSA Key Pair":
        if st.button("Generate"):
            private_key, private_pem, public_pem = ecdsa_key_pair()
            st.session_state.private_key = private_key
            st.session_state.public_key = public_pem
            st.success("ECDSA Key Pair Generated!")
            st.text_area("Public Key:", base64.b64encode(public_pem).decode())
            st.text_area("Private Key:", base64.b64encode(private_pem).decode())

    elif action == "Sign with RSA":
        message = st.text_input("Enter message to sign:")
        if st.button("Sign"):
            signature = rsa_sign(st.session_state.private_key, message)
            st.success(f"Signature: {signature}")

    elif action == "Verify with RSA":
        message = st.text_input("Enter message to verify:")
        signature = st.text_input("Enter signature:")
        if st.button("Verify"):
            if rsa_verify(st.session_state.public_key, message, signature):
                st.success("Signature is valid!")
            else:
                st.error("Signature is invalid!")

    elif action == "Sign with ECDSA":
        message = st.text_input("Enter message to sign:")
        if st.button("Sign"):
            signature = ecdsa_sign(st.session_state.private_key, message)
            st.success(f"Signature: {signature}")

    elif action == "Verify with ECDSA":
        message = st.text_input("Enter message to verify:")
        signature = st.text_input("Enter signature:")
        if st.button("Verify"):
            if ecdsa_verify(st.session_state.public_key, message, signature):
                st.success("Signature is valid!")
            else:
                st.error("Signature is invalid!")

    


def hashing_page():
    if st.button("Back to Home"):
        st.session_state.current_page = "Introduction"
    st.title("Hashing Algorithms")
    hash_algo = st.selectbox("Choose a Hashing Algorithm:", ["SHA-256", "SHA-3-256", "MD5", "SHA1", "SHA224", "BLAKE2b", "BLAKE2s"])
    message = st.text_input("Enter message:")
    if st.button("Generate Hash"):
        hash_value = generate_hash(message, hash_algo)
        st.success(f"Hash ({hash_algo}): {hash_value}")


# Main function to control navigation
def main():
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

# Run the application
if __name__ == "__main__":
    main()
