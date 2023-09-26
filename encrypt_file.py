from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_hash(u_key, u_salt):
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=u_salt,
    iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(u_key))
    return_key = Fernet(key)
    return return_key

def encrypt_file(file_to_encrypt, key):
    with open(file_to_encrypt, 'rb') as file:
        original_file = file.read()

    encrypted_file = key.encrypt(original_file)

    with open(file_to_encrypt, 'wb') as file:
        file.write(encrypted_file)

def decrypt_file(file_to_decrypt, key):
    with open(file_to_decrypt, 'rb') as file:
        original_file = file.read()

    decrypted_file = key.decrypt(original_file)

    with open(file_to_decrypt, 'wb') as file:
        file.write(decrypted_file)

u_key = input("enter in encryption key: ")
u_key = bytes(u_key, 'utf-8')
u_salt = input("enter in salt key: ")
u_salt = bytes(u_salt, 'utf-8')

file_to_encrypt = input("enter in the name of the file to encrypt/decrypt: ")
choice = input("Enter 0 for encrypt | Enter 1 for decrypt: ")
choice = int(choice)

if choice == 0:
    key = generate_hash(u_key, u_salt)
    encrypt_file(file_to_encrypt, key)      
elif choice == 1:
    key = generate_hash(u_key, u_salt)
    decrypt_file(file_to_encrypt, key)      
else:
    print("invalid choice")




