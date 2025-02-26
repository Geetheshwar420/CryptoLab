import streamlit as st
import io
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES, ChaCha20, ARC4, Blowfish, CAST5, TripleDES
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
import numpy as np
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, UTC
import gnupg
import paramiko
import dns.resolver
import dns.dnssec
import socket
import ssl
import pyperclip  # Add this import at the top of your file

# Symmetric Encryption Algorithms
def symmetric_encrypt(algorithm, mode, message, key, iv=None):
    if algorithm == "AES":
        cipher_algo = AES(key)
    elif algorithm == "DES":
        cipher_algo = TripleDES(key)
    elif algorithm == "ChaCha20":
        cipher_algo = ChaCha20(key, iv)
    elif algorithm == "RC4":
        cipher_algo = ARC4(key)
    elif algorithm == "Blowfish":
        cipher_algo = Blowfish(key)
    elif algorithm == "CAST5":
        cipher_algo = CAST5(key)
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
        cipher_algo = AES(key)
    elif algorithm == "DES":
        cipher_algo = TripleDES(key)
    elif algorithm == "ChaCha20":
        cipher_algo = ChaCha20(key, iv)
    elif algorithm == "RC4":
        cipher_algo = ARC4(key)
    elif algorithm == "Blowfish":
        cipher_algo = Blowfish(key)
    elif algorithm == "CAST5":
        cipher_algo = CAST5(key)
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


# Add new basic crypto algorithms
def caesar_cipher(text: str, shift: int, decrypt: bool = False) -> str:
    if decrypt:
        shift = -shift
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - ascii_offset + shift) % 26
            result += chr(shifted + ascii_offset)
        else:
            result += char
    return result

def vigenere_cipher(text: str, key: str, decrypt: bool = False) -> str:
    result = ""
    key = key.upper()
    key_length = len(key)
    key_as_int = [ord(i) - ord('A') for i in key]
    
    for i, char in enumerate(text):
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            key_idx = i % key_length
            shift = key_as_int[key_idx]
            if decrypt:
                shift = -shift
            shifted = (ord(char) - ascii_offset + shift) % 26
            result += chr(shifted + ascii_offset)
        else:
            result += char
    return result

def playfair_cipher(text: str, key: str, decrypt: bool = False) -> str:
    def create_matrix(key):
        # Remove duplicates from key and create 5x5 matrix
        key = key.upper().replace('J', 'I')
        matrix = []
        seen = set()
        
        # Add key characters first
        for char in key:
            if char.isalpha() and char not in seen:
                seen.add(char)
                matrix.append(char)
                
        # Add remaining alphabet
        for char in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
            if char not in seen:
                matrix.append(char)
                
        return [matrix[i:i+5] for i in range(0, 25, 5)]
    
    def find_position(matrix, char):
        for i, row in enumerate(matrix):
            if char in row:
                return i, row.index(char)
        return None
    
    # Prepare text
    text = text.upper().replace('J', 'I')
    text = ''.join(c for c in text if c.isalpha())
    if len(text) % 2:
        text += 'X'
    
    # Create pairs
    pairs = [text[i:i+2] for i in range(0, len(text), 2)]
    matrix = create_matrix(key)
    result = []
    
    for pair in pairs:
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])
        
        if row1 == row2:  # Same row
            if decrypt:
                col1 = (col1 - 1) % 5
                col2 = (col2 - 1) % 5
            else:
                col1 = (col1 + 1) % 5
                col2 = (col2 + 1) % 5
            result.extend([matrix[row1][col1], matrix[row1][col2]])
        elif col1 == col2:  # Same column
            if decrypt:
                row1 = (row1 - 1) % 5
                row2 = (row2 - 1) % 5
            else:
                row1 = (row1 + 1) % 5
                row2 = (row2 + 1) % 5
            result.extend([matrix[row1][col1], matrix[row2][col2]])
        else:  # Rectangle
            result.extend([matrix[row1][col2], matrix[row2][col1]])
    
    return ''.join(result)

def hill_cipher(text: str, key: str, decrypt: bool = False) -> str:
    # Convert text to numbers (A=0, B=1, etc.)
    text = text.upper()
    text_nums = [ord(c) - ord('A') for c in text if c.isalpha()]
    
    # Ensure text length is multiple of key size
    key_size = int(len(key) ** 0.5)
    while len(text_nums) % key_size:
        text_nums.append(0)
    
    # Convert key to matrix
    key_matrix = np.array([ord(c) - ord('A') for c in key.upper() if c.isalpha()])
    key_matrix = key_matrix.reshape((key_size, key_size))
    
    if decrypt:
        # Calculate inverse matrix for decryption
        det = int(round(np.linalg.det(key_matrix)))
        adj = np.round(det * np.linalg.inv(key_matrix)).astype(int)
        det_inv = pow(det, -1, 26)
        key_matrix = (det_inv * adj) % 26
    
    # Process text in blocks
    result = []
    for i in range(0, len(text_nums), key_size):
        block = np.array(text_nums[i:i+key_size])
        encrypted = np.dot(key_matrix, block) % 26
        result.extend(encrypted)
    
    # Convert numbers back to letters
    return ''.join(chr(int(n) + ord('A')) for n in result)

def autokey_cipher(text: str, key: str, decrypt: bool = False) -> str:
    text = text.upper()
    key = key.upper()
    result = []
    
    if decrypt:
        # Decryption
        for i, char in enumerate(text):
            if not char.isalpha():
                result.append(char)
                continue
            if i == 0:
                shift = ord(key[0]) - ord('A')
            else:
                shift = ord(result[i-1]) - ord('A')
            decrypted = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            result.append(decrypted)
    else:
        # Encryption
        for i, char in enumerate(text):
            if not char.isalpha():
                result.append(char)
                continue
            if i == 0:
                shift = ord(key[0]) - ord('A')
            else:
                shift = ord(text[i-1]) - ord('A')
            encrypted = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            result.append(encrypted)
    
    return ''.join(result)

def rail_fence_cipher(text: str, rails: int, decrypt: bool = False) -> str:
    if rails < 2:
        return text
    
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    
    if not decrypt:
        # Encryption
        for char in text:
            fence[rail].append(char)
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction = -direction
        return ''.join([''.join(rail) for rail in fence])
    else:
        # Decryption
        pattern = []
        rail = 0
        direction = 1
        for _ in text:
            pattern.append(rail)
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction = -direction
        
        # Fill the fence with placeholders
        for i, rail_idx in enumerate(pattern):
            fence[rail_idx].append(text[i])
        
        return ''.join([''.join(rail) for rail in fence])

# Add protocol-related functions
def generate_tls_certificate():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Organization"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(UTC)
    ).not_valid_after(
        datetime.now(UTC) + timedelta(days=365)
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    return {
        'certificate': cert.public_bytes(Encoding.PEM).decode(),
        'private_key': private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption()
        ).decode()
    }

def generate_ssh_keypair():
    key = paramiko.RSAKey.generate(2048)
    private_key_file = io.StringIO()
    key.write_private_key(private_key_file)
    return {
        'public_key': f"ssh-rsa {key.get_base64()}",
        'private_key': private_key_file.getvalue()
    }

def generate_pgp_keypair(name, email):
    gpg = gnupg.GPG()
    input_data = gpg.gen_key_input(
        key_type="RSA",
        key_length=2048,
        name_real=name,
        name_email=email
    )
    key = gpg.gen_key(input_data)
    public_key = gpg.export_keys(str(key))
    private_key = gpg.export_keys(str(key), True)
    return {
        'public_key': public_key,
        'private_key': private_key
    }

def verify_dnssec(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.use_dnssec = True
        answer = resolver.resolve(domain, 'A', want_dnssec=True)
        return {
            'secure': answer.response.flags & dns.flags.AD,
            'authenticated': bool(answer.response.flags & dns.flags.AD)
        }
    except Exception as e:
        return {'error': str(e)}

# Streamlit UI
def introduction():
    st.title("Data Encryption Tool")
    st.write("Explore Symmetric Encryption, Asymmetric Encryption, Hashing, Basic Crypto, and Security Protocols.")
    
    # Rearranged the order to place Basic Crypto first
    category = st.radio(
        "Select a Category to Explore:", 
        ["Basic Crypto", "Symmetric Encryption", "Asymmetric Encryption", "Hashing", "Security Protocols"]
    )
    
    if st.button("Go to Selected Category"):
        st.session_state.current_page = category


def symmetric_page():
    if st.button("Back to Home"):
        st.session_state.current_page = "Introduction"
        
    st.title("Symmetric Encryption")
    algo = st.selectbox("Choose Algorithm:", ["AES", "DES", "ChaCha20", "RC4", "Blowfish", "CAST5"])
    
    # Set mode automatically to CBC for applicable algorithms
    mode = "CBC" if algo in ["AES", "DES", "ChaCha20"] else None
    st.write(f"Mode: {mode}")  # Display the selected mode

    message = st.text_input("Enter plaintext:")
    
    # Initialize key in session state if not already done
    if 'key' not in st.session_state:
        st.session_state.key = ""

    key = st.text_input("Enter key (16 bytes for AES, 8/24 bytes for DES, 32 bytes for ChaCha20):", type="password", value=st.session_state.key)
    
    # Button to generate a random key
    if st.button("Generate Key"):
        if algo == "AES":
            st.session_state.key = base64.b64encode(os.urandom(16)).decode()  # 16 bytes for AES
        elif algo == "DES":
            st.session_state.key = base64.b64encode(os.urandom(8)).decode()   # 8 bytes for DES
        elif algo == "ChaCha20":
            st.session_state.key = base64.b64encode(os.urandom(32)).decode()  # 32 bytes for ChaCha20
        elif algo == "RC4":
            st.session_state.key = base64.b64encode(os.urandom(16)).decode()  # 16 bytes for RC4
        elif algo == "Blowfish":
            st.session_state.key = base64.b64encode(os.urandom(16)).decode()  # 16 bytes for Blowfish
        elif algo == "CAST5":
            st.session_state.key = base64.b64encode(os.urandom(16)).decode()  # 16 bytes for CAST5
        st.success(f"Generated Key: {st.session_state.key}")

    # Display the generated key in the input field
    key = st.session_state.key

    # Generate IV automatically for applicable algorithms
    iv = None
    if algo in ["AES", "DES", "ChaCha20"] and mode == "CBC":
        iv = base64.b64encode(os.urandom(16)).decode()  # Generate a random IV for AES/DES (16 bytes)
        st.write(f"Generated IV: {iv}")  # Display the generated IV

    # Create two columns for Encrypt and Decrypt buttons
    col1, col2 = st.columns(2)

    with col1:
        if st.button("Encrypt"):
            try:
                result = symmetric_encrypt(algo, modes.CBC(base64.b64decode(iv.encode())) if iv else None, message, base64.b64decode(key.encode()))
                encrypted_output = st.text_area("Encrypted Output", result, height=100)  # Output for copying
                if st.button("Copy Encrypted Output"):
                    pyperclip.copy(encrypted_output)  # Copy to clipboard
            except Exception as e:
                st.error(f"Error: {e}")

    with col2:
        if st.button("Decrypt"):
            try:
                result = symmetric_decrypt(algo, modes.CBC(base64.b64decode(iv.encode())) if iv else None, message, base64.b64decode(key.encode()))
                decrypted_output = st.text_area("Decrypted Output", result, height=100)  # Output for copying
                if st.button("Copy Decrypted Output"):
                    pyperclip.copy(decrypted_output)  # Copy to clipboard
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
            st.text_area("Signature Output", signature, height=100)  # Output for copying
            if st.button("Copy Signature Output"):
                pyperclip.copy(signature)  # Copy to clipboard

    elif action == "Verify with RSA":
        message = st.text_input("Enter message to verify:")
        signature = st.text_input("Enter signature:")
        
        # Create two columns for Verify buttons
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Verify"):
                if rsa_verify(st.session_state.public_key, message, signature):
                    st.success("Signature is valid!")
                else:
                    st.error("Signature is invalid!")

    elif action == "Sign with ECDSA":
        message = st.text_input("Enter message to sign:")
        if st.button("Sign"):
            signature = ecdsa_sign(st.session_state.private_key, message)
            st.text_area("Signature Output", signature, height=100)  # Output for copying
            if st.button("Copy Signature Output"):
                pyperclip.copy(signature)  # Copy to clipboard

    elif action == "Verify with ECDSA":
        message = st.text_input("Enter message to verify:")
        signature = st.text_input("Enter signature:")
        
        # Create two columns for Verify buttons
        col1, col2 = st.columns(2)
        with col1:
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
        st.text_area("Hash Output", hash_value, height=100)  # Output for copying
        if st.button("Copy Hash Output"):
            pyperclip.copy(hash_value)  # Copy to clipboard
            st.success("Hash output copied to clipboard!")


def basic_crypto_page():
    if st.button("Back to Home"):
        st.session_state.current_page = "Introduction"
        
    st.title("Basic Cryptographic Algorithms")
    algo = st.selectbox(
        "Choose Algorithm:", 
        ["Caesar", "Vigenère", "Playfair", "Hill", "Autokey", "Rail Fence"]
    )
    
    text = st.text_area("Enter text:")
    
    if algo == "Caesar":
        key = st.number_input("Enter shift (0-25):", min_value=0, max_value=25)
    elif algo == "Rail Fence":
        key = st.number_input("Enter number of rails:", min_value=2)
    else:
        key = st.text_input("Enter key:")
    
    # Create two columns for Encrypt and Decrypt buttons
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Encrypt"):
            try:
                if algo == "Caesar":
                    result = caesar_cipher(text, key, False)
                elif algo == "Vigenère":
                    result = vigenere_cipher(text, key, False)
                elif algo == "Playfair":
                    result = playfair_cipher(text, key, False)
                elif algo == "Hill":
                    result = hill_cipher(text, key, False)
                elif algo == "Autokey":
                    result = autokey_cipher(text, key, False)
                elif algo == "Rail Fence":
                    result = rail_fence_cipher(text, key, False)
                st.text_area("Encrypted Output", result, height=100)  # Output for copying
                if st.button("Copy Encrypted Output"):
                    pyperclip.copy(result)  # Copy to clipboard
            except Exception as e:
                st.error(f"Error: {e}")
    
    with col2:
        if st.button("Decrypt"):
            try:
                if algo == "Caesar":
                    result = caesar_cipher(text, key, True)
                elif algo == "Vigenère":
                    result = vigenere_cipher(text, key, True)
                elif algo == "Playfair":
                    result = playfair_cipher(text, key, True)
                elif algo == "Hill":
                    result = hill_cipher(text, key, True)
                elif algo == "Autokey":
                    result = autokey_cipher(text, key, True)
                elif algo == "Rail Fence":
                    result = rail_fence_cipher(text, key, True)
                st.text_area("Decrypted Output", result, height=100)  # Output for copying
                if st.button("Copy Decrypted Output"):
                    pyperclip.copy(result)  # Copy to clipboard
            except Exception as e:
                st.error(f"Error: {e}")

def protocols_page():
    if st.button("Back to Home"):
        st.session_state.current_page = "Introduction"
        
    st.title("Security Protocols")
    protocol = st.selectbox(
        "Choose Protocol:",
        ["TLS/SSL", "SSH", "OpenPGP", "DNSSEC"]
    )
    
    if protocol == "TLS/SSL":
        if st.button("Generate TLS Certificate"):
            try:
                result = generate_tls_certificate()
                cert_output = st.text_area("Certificate:", result['certificate'])
                private_key_output = st.text_area("Private Key:", result['private_key'])
                if st.button("Copy Certificate"):
                    pyperclip.copy(result['certificate'])  # Copy to clipboard
                    st.success("Certificate copied to clipboard!")
                if st.button("Copy Private Key"):
                    pyperclip.copy(result['private_key'])  # Copy to clipboard
                    st.success("Private key copied to clipboard!")
            except Exception as e:
                st.error(f"Error: {e}")
                
    elif protocol == "SSH":
        if st.button("Generate SSH Key Pair"):
            try:
                result = generate_ssh_keypair()
                public_key_output = st.text_area("Public Key:", result['public_key'])
                private_key_output = st.text_area("Private Key:", result['private_key'])
                if st.button("Copy Public Key"):
                    pyperclip.copy(result['public_key'])  # Copy to clipboard
                    st.success("Public key copied to clipboard!")
                if st.button("Copy Private Key"):
                    pyperclip.copy(result['private_key'])  # Copy to clipboard
                    st.success("Private key copied to clipboard!")
            except Exception as e:
                st.error(f"Error: {e}")
                
    elif protocol == "OpenPGP":
        name = st.text_input("Name:")
        email = st.text_input("Email:")
        if st.button("Generate PGP Key Pair"):
            try:
                result = generate_pgp_keypair(name, email)
                public_key_output = st.text_area("Public Key:", result['public_key'])
                private_key_output = st.text_area("Private Key:", result['private_key'])
                if st.button("Copy Public Key"):
                    pyperclip.copy(result['public_key'])  # Copy to clipboard
                    st.success("Public key copied to clipboard!")
                if st.button("Copy Private Key"):
                    pyperclip.copy(result['private_key'])  # Copy to clipboard
                    st.success("Private key copied to clipboard!")
            except Exception as e:
                st.error(f"Error: {e}")
                
    elif protocol == "DNSSEC":
        domain = st.text_input("Domain:")
        if st.button("Verify DNSSEC"):
            try:
                result = verify_dnssec(domain)
                st.json(result)
            except Exception as e:
                st.error(f"Error: {e}")

# Main function to control navigation
def main():
    # Initialize session state for current_page if it doesn't exist
    if "current_page" not in st.session_state:
        st.session_state["current_page"] = "Introduction"

    if st.session_state.current_page == "Introduction":
        introduction()
    elif st.session_state.current_page == "Basic Crypto":
        basic_crypto_page()
    elif st.session_state.current_page == "Symmetric Encryption":
        symmetric_page()
    elif st.session_state.current_page == "Asymmetric Encryption":
        asymmetric_page()
    elif st.session_state.current_page == "Hashing":
        hashing_page()

    elif st.session_state.current_page == "Security Protocols":
        protocols_page()

# Run the application
if __name__ == "__main__":
    main()
