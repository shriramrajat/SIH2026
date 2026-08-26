import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import modes

def test_hashing():
    m = hashlib.md5()
    s1 = hashlib.sha1()
    s256 = hashlib.sha256()
    s512 = hashlib.sha512()

def test_rsa():
    key = RSA.generate(2048)
    key_dynamic = RSA.generate(some_size)

def test_aes():
    cipher1 = AES.new(key, AES.MODE_CBC, iv)
    cipher2 = AES.new(key, AES.MODE_GCM, nonce)

def test_cryptography():
    digest1 = hashes.Hash(hashes.SHA1())
    digest256 = hashes.Hash(hashes.SHA256())
    mode1 = modes.CBC(iv)
    mode2 = modes.GCM(nonce)

def hardcoded_secrets():
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    password = "SuperSecretPassword123!"

# Commented out crypto
# h = hashlib.md5()
# cipher = AES.new(key, AES.MODE_CBC, iv)

def crypto_strings():
    print("This uses hashlib.md5 internally")
    info = "AES.new is used for symmetric encryption"
    doc = """
    You can use RSA.generate(2048)
    """
