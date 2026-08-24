"""
Sample Python file with commented out cryptographic calls to test false-positive filtering.
"""
import hashlib

# Real active call
active_hash = hashlib.sha256(b"active_data")

# Single-line comment false positives
# hashlib.md5(b"commented_out")
# RSA.generate(1024)

# Inline comment after active call
active_sha = hashlib.sha512(b"data")  # hashlib.md5(b"should_not_match")
