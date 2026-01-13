"""
###############################################################################
#     STAGE 8.1.3: CRYPTOGRAPHIC VULNERABILITIES                             #
#     Test: Weak crypto, insecure random, hardcoded secrets                  #
###############################################################################

PURPOSE: Detect cryptographic weaknesses and secret management issues.

CATEGORIES:
- Weak hashing algorithms
- Weak encryption
- Insecure random number generation
- Hardcoded secrets
- Insufficient key lengths
- ECB mode usage
"""

import hashlib
import random
import os
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes

# ===========================================================================
# WEAK HASHING ALGORITHMS (CWE-327)
# ===========================================================================

def hash_password_md5(password: str) -> str:
    """VULNERABLE: MD5 for password hashing."""
    return hashlib.md5(password.encode()).hexdigest()

def hash_password_sha1(password: str) -> str:
    """VULNERABLE: SHA-1 for password hashing."""
    return hashlib.sha1(password.encode()).hexdigest()

def hash_data_md5(data: bytes) -> str:
    """VULNERABLE: MD5 for data integrity."""
    return hashlib.md5(data).hexdigest()

# ===========================================================================
# WEAK ENCRYPTION ALGORITHMS
# ===========================================================================

def encrypt_des(plaintext: str, key: bytes) -> bytes:
    """VULNERABLE: DES encryption (56-bit key)."""
    cipher = DES.new(key, DES.MODE_ECB)
    # VULNERABLE: DES and ECB mode
    padded = plaintext + ' ' * (8 - len(plaintext) % 8)
    return cipher.encrypt(padded.encode())

def encrypt_aes_ecb(plaintext: str, key: bytes) -> bytes:
    """VULNERABLE: AES in ECB mode."""
    cipher = AES.new(key, AES.MODE_ECB)
    # VULNERABLE: ECB mode leaks patterns
    padded = plaintext + ' ' * (16 - len(plaintext) % 16)
    return cipher.encrypt(padded.encode())

# ===========================================================================
# INSECURE RANDOM NUMBER GENERATION (CWE-338)
# ===========================================================================

def generate_token_insecure() -> str:
    """VULNERABLE: Predictable PRNG for security token."""
    return str(random.randint(100000, 999999))

def generate_session_id_weak() -> str:
    """VULNERABLE: time-based seed for session ID."""
    import time
    random.seed(time.time())
    return ''.join([str(random.randint(0, 9)) for _ in range(16)])

def generate_password_reset_token() -> str:
    """VULNERABLE: Weak random for password reset."""
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    return ''.join(random.choice(chars) for _ in range(20))

# ===========================================================================
# HARDCODED SECRETS (CWE-798)
# ===========================================================================

# VULNERABLE: Hardcoded API keys
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULNERABLE: Hardcoded database credentials
DB_PASSWORD = "SuperSecret123!"
DB_CONNECTION = "postgresql://admin:password123@localhost/mydb"

# VULNERABLE: Hardcoded encryption key
ENCRYPTION_KEY = b'sixteen byte key'
AES_KEY = "0123456789abcdef0123456789abcdef"

# VULNERABLE: Hardcoded JWT secret
JWT_SECRET = "my-super-secret-jwt-key-12345"

# VULNERABLE: Hardcoded private key (partial)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7RlK...
-----END RSA PRIVATE KEY-----"""

def connect_with_hardcoded_creds():
    """VULNERABLE: Hardcoded credentials in code."""
    import psycopg2
    conn = psycopg2.connect(
        host="localhost",
        database="myapp",
        user="admin",
        password="hardcoded_password_123"  # VULNERABLE
    )
    return conn

# ===========================================================================
# INSUFFICIENT KEY LENGTHS
# ===========================================================================

def generate_weak_key() -> bytes:
    """VULNERABLE: 64-bit key (too short)."""
    return os.urandom(8)  # Only 64 bits

def generate_aes_weak() -> bytes:
    """VULNERABLE: 128-bit AES (should use 256-bit)."""
    return os.urandom(16)  # 128 bits

# ===========================================================================
# NULL CIPHER / NO ENCRYPTION
# ===========================================================================

def store_password_plaintext(username: str, password: str):
    """VULNERABLE: Storing password in plaintext."""
    with open('passwords.txt', 'a') as f:
        f.write(f"{username}:{password}\n")

def log_sensitive_data(credit_card: str):
    """VULNERABLE: Logging sensitive data unencrypted."""
    import logging
    logging.info(f"Processing payment for card: {credit_card}")

# ===========================================================================
# INSECURE SSL/TLS CONFIGURATION
# ===========================================================================

def make_insecure_request(url: str):
    """VULNERABLE: Disabled SSL verification."""
    import requests
    # VULNERABLE: verify=False disables certificate validation
    response = requests.get(url, verify=False)
    return response.text

def use_weak_tls():
    """VULNERABLE: Forcing old TLS version."""
    import ssl
    import socket
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # VULNERABLE: TLS 1.0
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secure_sock = context.wrap_socket(sock, server_hostname="example.com")
    return secure_sock

# ===========================================================================
# WEAK PASSWORD VALIDATION
# ===========================================================================

def validate_password_weak(password: str) -> bool:
    """VULNERABLE: Weak password requirements."""
    # VULNERABLE: Only checks length, no complexity
    return len(password) >= 6

def compare_passwords_timing_attack(input_pw: str, stored_pw: str) -> bool:
    """VULNERABLE: Timing attack on password comparison."""
    # VULNERABLE: Early return leaks information
    if len(input_pw) != len(stored_pw):
        return False
    for i in range(len(input_pw)):
        if input_pw[i] != stored_pw[i]:
            return False
    return True

# ===========================================================================
# CRYPTOGRAPHIC ORACLE
# ===========================================================================

def decrypt_and_return(ciphertext: bytes, key: bytes) -> str:
    """VULNERABLE: Padding oracle attack."""
    cipher = AES.new(key, AES.MODE_CBC, iv=b'0' * 16)
    try:
        plaintext = cipher.decrypt(ciphertext)
        # VULNERABLE: Different error messages leak padding info
        if plaintext[-1] > 16:
            return "Padding error"
        return plaintext.decode()
    except Exception as e:
        return f"Decryption failed: {str(e)}"

"""
EXPECTED DETECTIONS:
1. hash_password_md5 - Weak Crypto (CWE-327)
2. hash_password_sha1 - Weak Crypto (CWE-327)
3. hash_data_md5 - Weak Crypto (CWE-327)
4. encrypt_des - Weak Encryption (CWE-327)
5. encrypt_aes_ecb - ECB Mode (CWE-327)
6. generate_token_insecure - Weak Random (CWE-338)
7. generate_session_id_weak - Weak Random (CWE-338)
8. generate_password_reset_token - Weak Random (CWE-338)
9-14. Hardcoded secrets (6 instances) - Hardcoded Credentials (CWE-798)
15. connect_with_hardcoded_creds - Hardcoded Credentials (CWE-798)
16. store_password_plaintext - Cleartext Storage (CWE-312)
17. log_sensitive_data - Sensitive Data in Log (CWE-532)
18. make_insecure_request - Disabled SSL Verification (CWE-295)
19. use_weak_tls - Weak TLS Version (CWE-327)

PASS CRITERIA: Detect ≥15 out of 19 vulnerabilities (79%)
"""
