from pathlib import Path
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from Generate_Encryption_Key import get_key

MAGIC = b"PWENC1"
SALT_SIZE = 16
NONCE_SIZE = 12

def encrypt_file(file_path: str, master_password: str, plaintext: bytes):
    source = Path(file_path)

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)

    key = get_key(master_password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, MAGIC)

    encrypted_data = MAGIC + salt + nonce + ciphertext

    source.write_bytes(encrypted_data)

    return source

def decrypt_file(file_path : str, master_password : str):
    # Decrypt a given file specified by the user with file_path : str with password, master_password : str
    source = Path(file_path)

    # Check if we have an absolute or relative file path
    if not source.is_absolute():
        source = Path(__file__).resolve().parent / source

    # If file does not exist we raise an error
    if not source.is_file():
        raise FileNotFoundError("Encrypted file specified by user does not exist.")

    # Gather the encrypted data
    encrypted_data = source.read_bytes()

    minimum_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE + 16

    if len(encrypted_data) < minimum_size:
        raise ValueError("Encrypted vault is incomplete or corrupted.")

    # Validate file format
    if not encrypted_data.startswith(MAGIC):
        raise ValueError("Invalid encrypted file format.")

    # Extract the salt number
    offset = len(MAGIC)
    salt = encrypted_data[offset:offset + SALT_SIZE]
    offset += SALT_SIZE

    # Extract the nonce
    nonce = encrypted_data[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    # The remaining data now is all of our encrypted data along with our authentication tag
    ciphertext = encrypted_data[offset:]

    # Derive the original encryption key
    key = get_key(master_password, salt)

    # Decrypt and authenticate the data
    try: 
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except InvalidTag:
        raise ValueError("Incorrect password or corrupted encrypted file.")

    return plaintext