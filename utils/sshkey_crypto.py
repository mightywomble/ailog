"""SSH Key encryption/decryption utilities using a master key."""

import os
import hashlib
import hmac
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SSHKeyCryptoError(Exception):
    """Exception raised for SSH key crypto errors."""
    pass


def _get_master_key():
    """Get the master key from environment variable."""
    key = os.environ.get('AILOG_SSHKEY_MASTER_KEY', '').strip()
    if not key:
        return None
    return key.encode() if isinstance(key, str) else key


def is_configured():
    """Check if encryption is configured (master key is set)."""
    return bool(os.environ.get('AILOG_SSHKEY_MASTER_KEY', '').strip())


def generate_master_key():
    """Generate a new random master key (32 bytes, base64-encoded)."""
    import secrets
    import base64
    random_bytes = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(random_bytes).decode('utf-8')


def _derive_fernet_key(master_key):
    """Derive a Fernet-compatible key from the master key."""
    import base64
    
    if isinstance(master_key, str):
        master_key = master_key.encode()
    
    # Use PBKDF2 to derive a 32-byte key from the master key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'ailog_sshkey_crypto',  # Fixed salt for deterministic output
        iterations=100000,
    )
    derived = kdf.derive(master_key)
    return base64.urlsafe_b64encode(derived)


def encrypt_str(plaintext, explicit_key=None):
    """Encrypt a string using the master key or explicit key.
    
    Args:
        plaintext: String to encrypt
        explicit_key: Optional explicit key to use (for testing)
        
    Returns:
        Encrypted string (base64-encoded)
        
    Raises:
        SSHKeyCryptoError: If encryption fails or no key is available
    """
    if not plaintext:
        return ''
    
    # Get the key to use
    key = explicit_key
    if key is None:
        key = _get_master_key()
        if not key:
            raise SSHKeyCryptoError('No master key configured (AILOG_SSHKEY_MASTER_KEY env var not set)')
    
    try:
        # Derive Fernet key
        fernet_key = _derive_fernet_key(key)
        cipher = Fernet(fernet_key)
        
        # Encrypt
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        ciphertext = cipher.encrypt(plaintext)
        
        # Return as string
        import base64
        return base64.urlsafe_b64encode(ciphertext).decode('utf-8')
    except Exception as e:
        raise SSHKeyCryptoError(f'Encryption failed: {str(e)}')


def decrypt_str(ciphertext, explicit_key=None):
    """Decrypt a string using the master key or explicit key.
    
    Args:
        ciphertext: Encrypted string (base64-encoded)
        explicit_key: Optional explicit key to use (for testing)
        
    Returns:
        Decrypted plaintext string
        
    Raises:
        SSHKeyCryptoError: If decryption fails or no key is available
    """
    if not ciphertext:
        return ''
    
    # Get the key to use
    key = explicit_key
    if key is None:
        key = _get_master_key()
        if not key:
            raise SSHKeyCryptoError('No master key configured (AILOG_SSHKEY_MASTER_KEY env var not set)')
    
    try:
        # Derive Fernet key
        fernet_key = _derive_fernet_key(key)
        cipher = Fernet(fernet_key)
        
        # Decode and decrypt
        import base64
        ciphertext_bytes = base64.urlsafe_b64decode(ciphertext)
        plaintext = cipher.decrypt(ciphertext_bytes)
        
        # Return as string
        return plaintext.decode('utf-8')
    except Exception as e:
        raise SSHKeyCryptoError(f'Decryption failed: {str(e)}')


def normalize_ssh_key_text(key_text):
    """Normalize SSH key text (strip whitespace, ensure proper format).
    
    Args:
        key_text: Raw SSH key text
        
    Returns:
        Normalized key text
    """
    if not key_text:
        return ''
    
    # Strip leading/trailing whitespace
    normalized = key_text.strip()
    
    # Ensure Unix line endings
    normalized = normalized.replace('\r\n', '\n').replace('\r', '\n')
    
    return normalized


def compute_key_checksum(key_text):
    """Compute a checksum/hash of the key for verification.
    
    Args:
        key_text: SSH key text (plaintext)
        
    Returns:
        Hex-encoded SHA256 checksum
    """
    if not key_text:
        return ''
    
    if isinstance(key_text, str):
        key_text = key_text.encode('utf-8')
    
    return hashlib.sha256(key_text).hexdigest()


def verify_key_checksum(key_text, stored_checksum):
    """Verify that a key matches its stored checksum.
    
    Args:
        key_text: SSH key text (plaintext)
        stored_checksum: Previously computed checksum
        
    Returns:
        True if checksum matches, False otherwise
    """
    if not key_text or not stored_checksum:
        return False
    
    computed = compute_key_checksum(key_text)
    return hmac.compare_digest(computed, stored_checksum)
