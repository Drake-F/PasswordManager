from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

def get_key(master_password : str, salt : bytes):
    # Generates a key and returns it as bytes - 32 bytes or 256 bits

    # Raise error if user provides empty string for key generation
    if not master_password:
        raise ValueError("Master password must be a non-empty string.")

    # Generate an Argon2id object to generate our "key derivation function" - salt -> random data , length -> 32 bytes = 256 bits
    # iterations -> how many times we iterate over the data, lanes -> how many parallel computes argon2ID can use, memory cost is measured in KiB so 60 * 1024 -> 64 MiB
    kdf = Argon2id(salt = salt, length = 32, iterations = 3, lanes = 4, memory_cost = 64 * 1024)

    return kdf.derive(master_password.encode("UTF-8"))