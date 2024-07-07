import os
import time
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import padding as sym_padding

def generate_aes_key(key_length):
    key = os.urandom(key_length // 8)
    with open(f'aes_key_{key_length}.key', 'wb') as f:
        f.write(key)
    return key

def load_aes_key(key_length):
    with open(f'aes_key_{key_length}.key', 'rb') as f:
        key = f.read()
    return key

def pad_plaintext(plaintext, block_size=128):
    padder = sym_padding.PKCS7(block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    return padded_data
def unpad_plaintext(padded_data, block_size=128):
    unpadder = sym_padding.PKCS7(block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data
def aes_encrypt(key, plaintext, mode):
    if mode == 'ECB':
        plaintext = pad_plaintext(plaintext)
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, None
    elif mode == 'CFB':
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, iv

def aes_decrypt(key, ciphertext, mode, iv=None):
    if mode == 'ECB':
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = unpad_plaintext(padded_plaintext)
        return plaintext
    elif mode == 'CFB':
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    with open('rsa_private_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open('rsa_public_key.pem', 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return private_key, public_key

def load_rsa_keys():
    with open('rsa_private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open('rsa_public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key

def rsa_encrypt(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext
def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext
def rsa_sign(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature
def rsa_verify(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False
def sha256_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()
def measure_execution_time(func, *args):
    start_time = time.time()
    result = func(*args)
    end_time = time.time()
    elapsed_time = end_time - start_time
    return elapsed_time, result


def main():
    while True:
        print("\nCrypto Operations Menu:")
        print("1. AES Encryption/Decryption")
        print("2. RSA Encryption/Decryption")
        print("3. RSA Signature")
        print("4. SHA-256 Hashing")
        print("5. Exit")
        choice = int(input("Enter your choice: "))

        if choice == 1:
            key_length = int(input("Enter AES key length (128 or 256): "))
            mode = input("Enter AES mode (ECB or CFB): ")
            plaintext = input("Enter plaintext: ").encode()

            key = generate_aes_key(key_length)
            elapsed_time, (ciphertext, iv) = measure_execution_time(aes_encrypt, key, plaintext, mode)
            print(f"AES Encryption Time: {elapsed_time} seconds")
            print(f"Ciphertext: {ciphertext}")

            elapsed_time, decrypted_text = measure_execution_time(aes_decrypt, key, ciphertext, mode, iv)
            print(f"AES Decryption Time: {elapsed_time} seconds")
            print(f"Decrypted Text: {decrypted_text.decode()}")

        elif choice == 2:
            plaintext = input("Enter plaintext: ").encode()

            private_key, public_key = generate_rsa_keys()
            elapsed_time, ciphertext = measure_execution_time(rsa_encrypt, public_key, plaintext)
            print(f"RSA Encryption Time: {elapsed_time} seconds")
            print(f"Ciphertext: {ciphertext}")

            elapsed_time, decrypted_text = measure_execution_time(rsa_decrypt, private_key, ciphertext)
            print(f"RSA Decryption Time: {elapsed_time} seconds")
            print(f"Decrypted Text: {decrypted_text.decode()}")

        elif choice == 3:
            message = input("Enter message: ").encode()

            private_key, public_key = generate_rsa_keys()
            elapsed_time, signature = measure_execution_time(rsa_sign, private_key, message)
            print(f"RSA Signature Generation Time: {elapsed_time} seconds")
            print(f"Signature: {signature}")

            elapsed_time, verification = measure_execution_time(rsa_verify, public_key, message, signature)
            print(f"RSA Signature Verification Time: {elapsed_time} seconds")
            print(f"Verification: {'Successful' if verification else 'Failed'}")

        elif choice == 4:
            file_path = input("Enter file path: ")
            elapsed_time, file_hash = measure_execution_time(sha256_hash, file_path)
            print(f"SHA-256 Hashing Time: {elapsed_time} seconds")
            print(f"SHA-256 Hash: {file_hash}")

        elif choice == 5:
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
