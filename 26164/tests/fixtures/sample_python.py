# Synthetic Python test vector for ECDAT scanner
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes, ciphers

def generate_legacy_hashes():
    # Vulnerable hashing
    h1 = hashlib.md5(b"legacy_data").hexdigest()
    h2 = hashlib.sha1(b"legacy_data").hexdigest()
    h3 = hashlib.sha256(b"secure_data").hexdigest()
    return h1, h2, h3

def generate_rsa_key():
    # Static RSA 2048
    key_2048 = RSA.generate(2048)
    
    # Dynamic key size
    dynamic_size = 4096
    key_dynamic = RSA.generate(dynamic_size)
    return key_2048, key_dynamic

def encrypt_data(key, iv, data):
    # AES CBC encryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(data)

def cryptography_hash():
    digest = hashes.Hash(hashes.SHA1())
    digest.update(b"test")
    return digest.finalize()

def non_crypto_function(a, b):
    # This is clean arithmetic code
    result = a + b * 42
    return f"Result: {result}"
