"""
NanoCell Core - Cryptographic primitives
Uses NaCl (libsodium) for all cryptographic operations
"""

import nacl.secret
import nacl.signing
import nacl.bindings
import nacl.utils
from typing import Tuple, Optional
import hashlib


class CryptoBox:
    """End-to-end encryption using NaCl secretbox (XSalsa20 + Poly1305)"""
    
    def __init__(self, secret_key: Optional[bytes] = None):
        if secret_key is None:
            self._secret_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        else:
            if len(secret_key) != nacl.secret.SecretBox.KEY_SIZE:
                raise ValueError(f"Key must be {nacl.secret.SecretBox.KEY_SIZE} bytes")
            self._secret_key = secret_key
        
        self._box = nacl.secret.SecretBox(self._secret_key)
    
    @property
    def secret_key(self) -> bytes:
        return self._secret_key
    
    def encrypt(self, plaintext: bytes, nonce: Optional[bytes] = None) -> bytes:
        """Encrypt message with optional nonce"""
        if nonce is not None and len(nonce) != nacl.secret.SecretBox.NONCE_SIZE:
            raise ValueError(f"Nonce must be {nacl.secret.SecretBox.NONCE_SIZE} bytes")
        return self._box.encrypt(plaintext, nonce)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt message"""
        return self._box.decrypt(ciphertext)


class Identity:
    """Long-term identity using Ed25519 signatures"""
    
    def __init__(self, seed: Optional[bytes] = None):
        if seed is None:
            self._signer = nacl.signing.SigningKey.generate()
        else:
            self._signer = nacl.signing.SigningKey(seed)
        
        self._verify_key = self._signer.verify_key
    
    @property
    def seed(self) -> bytes:
        return bytes(self._signer)
    
    @property
    def public_key(self) -> bytes:
        return bytes(self._verify_key)
    
    @property
    def public_key_hex(self) -> str:
        return self.public_key.hex()
    
    def sign(self, message: bytes) -> bytes:
        """Sign message"""
        signed = self._signer.sign(message)
        return signed.signature
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify signature"""
        try:
            verify_key = nacl.signing.VerifyKey(public_key)
            verify_key.verify(message, signature)
            return True
        except nacl.exceptions.BadSignature:
            return False
    
    def derive_shared_secret(self, their_public_key: bytes) -> bytes:
        """Derive shared secret using ECDH (Curve25519)"""
        # Convert Ed25519 to Curve25519 for key exchange
        curve25519_public = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(their_public_key)
        curve25519_secret = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(bytes(self._signer))
        
        shared = nacl.bindings.crypto_scalarmult(curve25519_secret, curve25519_public)
        return hashlib.sha256(shared).digest()


class KeyExchange:
    """ECDH key exchange protocol"""
    
    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """Generate ephemeral keypair for key exchange"""
        private_key = nacl.utils.random(nacl.bindings.crypto_scalarmult_BYTES)
        public_key = nacl.bindings.crypto_scalarmult_base(private_key)
        return private_key, public_key
    
    @staticmethod
    def compute_shared_secret(private_key: bytes, their_public_key: bytes) -> bytes:
        """Compute shared secret"""
        shared = nacl.bindings.crypto_scalarmult(private_key, their_public_key)
        return hashlib.sha256(shared).digest()


def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Hash password with salt using SHA-256"""
    if salt is None:
        salt = nacl.utils.random(16)
    
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return hashed, salt


def verify_password(password: str, hashed: bytes, salt: bytes) -> bool:
    """Verify password against hash"""
    new_hash, _ = hash_password(password, salt)
    return nacl.bindingcrypto_memcmp(hashed, new_hash) == 0
