# core/decryption.py
import base64
import hashlib
from PIL import Image
from stegano import lsb
from cryptography.fernet import Fernet
from core.custom_hash import compute_hash

def generate_key_from_password(pass_key: str) -> bytes:
    """Generate a consistent Fernet key from password"""
    key = hashlib.sha256(pass_key.encode()).digest()
    return base64.urlsafe_b64encode(key)
def decrypt_message_from_gif(gif_file, pass_key: str) -> tuple[bool, str]:
    """Extract and decrypt message and its hash from the first frame of a GIF."""
    try:
        # Open GIF and get the first frame
        with Image.open(gif_file) as gif:
            if not getattr(gif, "is_animated", False):
                return False, "Not an animated GIF"

            # Get the first frame
            gif.seek(0)
            first_frame = gif.copy()

            # Convert to RGB if necessary
            if first_frame.mode != 'RGB':
                first_frame = first_frame.convert('RGB')

            try:
                # Extract hidden data
                encrypted_hex = lsb.reveal(first_frame)
                
                if not encrypted_hex:
                    return False, "No hidden data found"

                # Split the extracted data into encrypted message and encrypted hash
                encrypted_message_hex, encrypted_hash_hex = encrypted_hex.split("::")

                # Convert hex to bytes
                encrypted_message = bytes.fromhex(encrypted_message_hex)
                encrypted_hash = bytes.fromhex(encrypted_hash_hex)

                # Generate the same key from pass_key
                key = generate_key_from_password(pass_key)
                fernet = Fernet(key)

                # Decrypt the message and hash
                decrypted_message = fernet.decrypt(encrypted_message).decode('utf-8')
                decrypted_hash = fernet.decrypt(encrypted_hash).decode('utf-8')

                # Verify the hash of the decrypted message
                computed_hash = compute_hash(decrypted_message)
                if computed_hash != decrypted_hash:
                    return False, "Hash mismatch: Message integrity verification failed"

                return True, decrypted_message

            except ValueError:
                return False, "Invalid encrypted data format"
            except Exception as e:
                return False, f"Decryption failed: {str(e)}"

    except Exception as e:
        return False, f"Error processing GIF: {str(e)}"
