import streamlit as st

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
        key="category_selection",
        on_change=lambda: navigate_to(st.session_state.category_selection)
    )

# Symmetric Encryption Page
def symmetric_encryption():
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

# Asymmetric Encryption Page
def asymmetric_encryption():
    st.title("Asymmetric Encryption")
    st.write("Generate RSA key pairs and perform encryption and decryption.")
    
    if st.button("Generate RSA Key Pair"):
        st.success("Keys generated successfully (mocked).")
    
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
        st.success(f"Generated Hash: {hash(message)} (Mocked Hash)")
    
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
