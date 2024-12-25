# Simulate Ciphertext Tampering Attack
import base64
from cryptography.fernet import Fernet, InvalidToken
import hashlib

# Generate a Fernet key from a passkey
def generate_key_from_password(pass_key: str) -> bytes:
    key = hashlib.sha256(pass_key.encode()).digest()
    return base64.urlsafe_b64encode(key)


def tampering_attack(ciphertext, pass_key):
    print("\n[Ciphertext Tampering Attack]")
    key = generate_key_from_password(pass_key)
    fernet = Fernet(key)

    # Modify the ciphertext (corrupt it)
    tampered_ciphertext = ciphertext[:-1] + b"0"
    try:
        plaintext = fernet.decrypt(tampered_ciphertext).decode('utf-8')
        print(f"Tampering succeeded! Decrypted message: {plaintext}")
    except InvalidToken:
        print("Tampering attack failed: Integrity check failed.")

