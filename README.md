# 🔬 CryptoLab: A Web-Based Cryptography Tool

**CryptoLab** is an interactive web application built with [Streamlit](https://streamlit.io/) to demonstrate and perform a wide range of cryptographic operations. This educational tool allows users to explore and visualize how various cryptographic algorithms and security protocols work in a hands-on environment.

## 🚀 Live Demo

Try out the application live: [https://cryptolab.streamlit.app/](https://cryptolab.streamlit.app/)

---

## ✨ Features

CryptoLab is organized into the following major categories:

### 🔐 Basic Crypto (Classical Ciphers)
- ✅ **Caesar Cipher**: Simple substitution cipher.
- ✅ **Vigenère Cipher**: Uses a keyword to apply a series of Caesar ciphers.
- ✅ **Playfair Cipher**: Manual digraph substitution cipher.
- ✅ **Hill Cipher**: Polygraphic cipher based on linear algebra.
- ✅ **Autokey Cipher**: Incorporates plaintext into the key.
- ✅ **Rail Fence Cipher**: Transposition cipher based on zig-zag writing.

### 🔒 Symmetric Encryption
- ✅ AES (Advanced Encryption Standard)
- ✅ DES (Data Encryption Standard)
- ✅ ChaCha20
- ✅ RC4
- ✅ Blowfish
- ✅ CAST5

### 🔑 Asymmetric Encryption
- ✅ RSA: Key generation, signing, and verification
- ✅ ECDSA: Key generation, signing, and verification

### 🧮 Hashing Algorithms
- ✅ SHA-256, SHA-3-256
- ✅ SHA1, SHA224
- ✅ MD5
- ✅ BLAKE2b, BLAKE2s

### 📡 Security Protocols
- ✅ **TLS/SSL**: Self-signed certificate generation
- ✅ **SSH**: RSA key pair generation
- ✅ **OpenPGP**: PGP key pair generation
- ✅ **DNSSEC**: Domain security extension verification

---

## 🏁 Getting Started

Follow these instructions to set up a local development environment.

### ✅ Prerequisites

- Python 3.x installed on your machine ([Download Python](https://www.python.org/downloads/))

### 📦 Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/Geetheshwar420/CryptoLab.git
    ```

2. **Navigate to the project directory:**

    ```bash
    cd CryptoLab
    ```

3. **Create a `requirements.txt` file with the following content:**

    ```txt
    # Web Framework
    streamlit==1.20.0

    # Cryptography Libraries
    cryptography==39.0.1
    python-gnupg==0.5.2
    paramiko>=3.4.0
    dnspython==2.6.1

    # Scientific Computing
    numpy==1.26.4

    # Additional Dependencies
    bcrypt==4.1.2
    pyperclip==1.8.2
    pgpy==0.5.0

    ```

4. **Install the dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

---

## 🎈 Usage

To launch the application locally:

```bash
streamlit run app.py
````

Then open your browser and navigate to: [http://localhost:8501](http://localhost:8501)

---

## 🤝 Contributing

Contributions make the open-source community a fantastic place to learn and grow. If you have a feature request or improvement:

1. **Fork the repository**

2. **Create a new feature branch**

   ```bash
   git checkout -b feature/AmazingFeature
   ```

3. **Commit your changes**

   ```bash
   git commit -m "Add some AmazingFeature"
   ```

4. **Push to the branch**

   ```bash
   git push origin feature/AmazingFeature
   ```

5. **Open a Pull Request**

You can also open an issue with the tag `"enhancement"`. Don’t forget to ⭐ the repo if you like the project!

---

## 📜 License

Distributed under the MIT License. See [`LICENSE.txt`](License.txt) for more details.

---

## 📫 Contact

For questions or feedback, feel free to reach out via GitHub Issues or Pull Requests.

---

```

Let me know if you’d like a badge section, table of contents, or documentation setup (e.g., with `mkdocs` or `Sphinx`) included as well.
```
