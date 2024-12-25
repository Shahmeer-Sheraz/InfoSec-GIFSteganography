import hashlib


def compute_hash(message):
    message_bytes = message.encode('utf-8')
    hash_object = hashlib.sha256()
    
    hash_object.update(message_bytes)
    
    # Get the hexadecimal representation of the hash
    hash_hex = hash_object.hexdigest()
    
    return hash_hex

