import base64
from cryptography.fernet import Fernet, InvalidToken
import hashlib

# Generate a Fernet key from a passkey
def generate_key_from_password(pass_key: str) -> bytes:
    key = hashlib.sha256(pass_key.encode()).digest()
    return base64.urlsafe_b64encode(key)

# Simulate Brute Force Attack
def brute_force_attack(ciphertext, correct_passkey):
    print("\n[Brute Force Attack]")
    for attempt in ["wrongkey1", "wrongkey2", correct_passkey]:  # Add more guesses here
        try:
            key = generate_key_from_password(attempt)
            fernet = Fernet(key)
            plaintext = fernet.decrypt(ciphertext).decode('utf-8')
            print(f"Passkey '{attempt}' succeeded! Decrypted message: {plaintext}")
            return
        except InvalidToken:
            print(f"Passkey '{attempt}' failed.")
    print("Brute force attack failed.")

