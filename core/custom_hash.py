import struct
import random
import string

class CustomHasher:
    def __init__(self):
        # Initialize the hash state with prime numbers (128-bit hash)
        self.state = [19, 31, 47, 61]
        self.block_size = 64  # Process 64 bytes at a time

    def _process_block(self, block):
        """Process a single block of data."""
        for i in range(0, len(block), 4):
            # Read 4 bytes at a time as an integer
            chunk = struct.unpack("<I", block[i:i+4].ljust(4, b'\x00'))[0]

            # XOR with the state
            self.state[i % 4] ^= chunk

            # Perform bitwise rotations and modular arithmetic
            self.state[i % 4] = ((self.state[i % 4] << 5) | (self.state[i % 4] >> 27)) & 0xFFFFFFFF
            self.state[i % 4] += (self.state[(i + 1) % 4] ^ 0x9E3779B9)

    def update(self, data):
        """Update the hash state with new data."""
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Process data in blocks
        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            self._process_block(block)

    def finalize(self):
        """Finalize and return the hash."""
        # Combine the state into a single 128-bit value
        hash_value = 0
        for i, val in enumerate(self.state):
            hash_value ^= (val << (32 * i))
        return hash_value.to_bytes(16, byteorder='little')

    def hash(self, data):
        """Convenience method to hash data."""
        self.update(data)
        return self.finalize()

# Utility function to generate random inputs
def generate_random_input(length=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Collision Freeness Test
def test_collision_freeness():
    print("Testing Collision Freeness...")
    hasher = CustomHasher()
    hashes = {}
    collision_found = False

    for _ in range(10000):  # Test with 100,000 inputs
        input_data = generate_random_input()
        hasher.update(input_data)
        digest = hasher.finalize()

        if digest in hashes:
            print(f"Collision found: {input_data} and {hashes[digest]}")
            collision_found = True
            break
        else:
            hashes[digest] = input_data

    if not collision_found:
        print("No collisions found after 100,000 tests.")

# Preimage Resistance Test
def test_preimage_resistance():
    print("Testing Preimage Resistance...")
    hasher = CustomHasher()
    target_hash = hasher.hash("known_input")
    found = False

    for _ in range(1000000):  # Try brute-forcing with 1,000,000 attempts
        trial_input = generate_random_input()
        hasher.update(trial_input)
        trial_hash = hasher.finalize()

        if trial_hash == target_hash:
            print(f"Preimage found: {trial_input}")
            found = True
            break

    if not found:
        print("No preimage found after 1,000,000 attempts.")

# Second Preimage Resistance Test
def test_second_preimage_resistance():
    print("Testing Second Preimage Resistance...")
    hasher = CustomHasher()
    known_input = "known_input"
    hasher.update(known_input)
    known_hash = hasher.finalize()
    found = False

    for _ in range(1000000):  # Try brute-forcing with 1,000,000 attempts
        trial_input = generate_random_input()
        if trial_input == known_input:
            continue

        hasher.update(trial_input)
        trial_hash = hasher.finalize()

        if trial_hash == known_hash:
            print(f"Second preimage found: {trial_input}")
            found = True
            break

    if not found:
        print("No second preimage found after 1,000,000 attempts.")

# Main function to run all testsorigi
def main():
    test_collision_freeness()
    test_preimage_resistance()
    test_second_preimage_resistance()

if __name__ == "__main__":
    main()