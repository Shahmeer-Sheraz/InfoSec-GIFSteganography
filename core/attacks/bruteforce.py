import hashlib
import base64
import string
import random
from PIL import Image
from stegano import lsb
from cryptography.fernet import Fernet

def generate_key_from_password(pass_key: str) -> bytes:
    """Generate a consistent Fernet key from password"""
    key = hashlib.sha256(pass_key.encode()).digest()
    return base64.urlsafe_b64encode(key)

def decrypt_message_from_frame(first_frame, pass_key: str) -> str:
    """Decrypt message from a single frame using pass_key"""
    try:
        # Generate decryption key from pass_key
        key = generate_key_from_password(pass_key)
        fernet = Fernet(key)

        # Extract hidden message from the frame
        hidden_message = lsb.reveal(first_frame)
        if hidden_message is None:
            return None

        # Decrypt the hidden message
        decrypted_message = fernet.decrypt(bytes.fromhex(hidden_message))
        return decrypted_message.decode()
    except Exception:
        return None

def generate_random_password(length=12):
    """Generate a random password of a given length"""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def brute_force_decrypt(first_frame, num_attempts=100000, password_length=12):
    """Brute force attempt to decrypt the hidden message using randomly generated passwords"""
    for attempt in range(num_attempts):
        password = generate_random_password(password_length)
        decrypted_message = decrypt_message_from_frame(first_frame, password)
        if decrypted_message:
            print(f"Password found: {password}")
            print(f"Decrypted message: {decrypted_message}")
            return decrypted_message

        if attempt % 1000 == 0:  # Log progress every 1000 attempts
            print(f"Attempt {attempt}: No match yet...")

    print("Password not found after the given number of attempts.")
    return None

if __name__ == "__main__":
    gif_path = r"D:\stegocrypt\core\attacks\encrypted.gif"

    # Load GIF and extract the first frame
    try:
        with Image.open(gif_path) as gif:
            if not getattr(gif, "is_animated", False):
                raise ValueError("Not an animated GIF")
            gif.seek(0)
            first_frame = gif.copy()
            if first_frame.mode != 'RGB':
                first_frame = first_frame.convert('RGB')

        # Perform brute-force decryption
        brute_force_decrypt(first_frame, num_attempts=10000000, password_length=8)

    except Exception as e:
        print(f"Error: {str(e)}")
