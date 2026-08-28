def fake_crypto():
    # Ordinary string, shouldn't trigger
    info = "We might use AES.new or RSA.generate in the future."
    
    # URL shouldn't trigger (wait, does it match the pattern? The pattern is `\bAES\.new\s*\(` so URLs are fine unless they match)
    url = "https://example.com/api/AES.new()"
    
    # Similar function names
    def RSA_generate_something():
        pass
        
    RSA_generate_something()
    
    # Docstring
    """
    AES.new(key, MODE_CBC)
    hashlib.md5()
    """
    pass

class FakeClass:
    def AES_new(self):
        pass
    
    def hashlib_md5(self):
        pass

# Fake variables
hashlib_sha256 = "sha256"
