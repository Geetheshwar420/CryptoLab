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
