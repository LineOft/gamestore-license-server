"""
crypto.py — Sunucu Tarafı Şifreleme
======================================
Offset şifreleme, AES key üretimi, token imzalama.
Client tarafındaki crypto_utils.py'nin sunucu karşılığı.

Son Güncelleme: 2026-02-18
"""

import os
import base64
import json
import hashlib
import hmac
import time
from typing import Dict, Any, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ============================================================
# AES-256-GCM Sunucu Şifreleme
# ============================================================

class ServerCipher:
    """Sunucu tarafı AES-256-GCM şifreleme."""
    
    NONCE_SIZE = 12
    KEY_SIZE = 32
    
    @staticmethod
    def generate_aes_key() -> bytes:
        """Rastgele 32 byte AES-256 key üretir."""
        return os.urandom(32)
    
    @staticmethod
    def generate_aes_key_b64() -> str:
        """Base64 encoded AES key üretir."""
        return base64.urlsafe_b64encode(os.urandom(32)).decode()
    
    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> bytes:
        """AES-256-GCM ile şifreler."""
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ct
    
    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        """AES-256-GCM şifresini çözer."""
        nonce = data[:12]
        ct = data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, None)
    
    @classmethod
    def encrypt_json(cls, obj: dict, key: bytes) -> str:
        """Dict → JSON → AES → Base64."""
        plaintext = json.dumps(obj, separators=(',', ':')).encode('utf-8')
        encrypted = cls.encrypt(plaintext, key)
        return base64.urlsafe_b64encode(encrypted).decode()
    
    @classmethod
    def decrypt_json(cls, b64_data: str, key: bytes) -> dict:
        """Base64 → AES → JSON → Dict."""
        encrypted = base64.urlsafe_b64decode(b64_data)
        plaintext = cls.decrypt(encrypted, key)
        return json.loads(plaintext.decode('utf-8'))


# ============================================================
# TOKEN OLUŞTURMA
# ============================================================

class TokenGenerator:
    """Sunucu tarafı token üretimi ve doğrulama."""
    
    def __init__(self, secret_key: str):
        self._secret = secret_key.encode('utf-8')
    
    def create_signed_token(self, key: str, hwid: str, 
                            plan: str, expires_in: int = 300) -> str:
        """
        İmzalı token oluşturur.
        Token = base64(payload) + "." + base64(signature)
        """
        payload = {
            "key": key,
            "hwid": hwid,
            "plan": plan,
            "iat": int(time.time()),
            "exp": int(time.time()) + expires_in,
            "jti": base64.urlsafe_b64encode(os.urandom(16)).decode()
        }
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode()
        
        signature = hmac.new(
            self._secret, payload_b64.encode(), hashlib.sha256
        ).hexdigest()
        
        return f"{payload_b64}.{signature}"
    
    def verify_signed_token(self, token: str) -> dict:
        """İmzalı token doğrular. Geçersizse None döner."""
        try:
            parts = token.split('.')
            if len(parts) != 2:
                return None
            
            payload_b64, signature = parts
            
            expected_sig = hmac.new(
                self._secret, payload_b64.encode(), hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_sig):
                return None
            
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            
            if payload.get("exp", 0) < time.time():
                return None
            
            return payload
        except Exception:
            return None


# ============================================================
# API SECRET DOĞRULAMA
# ============================================================

def verify_api_secret(provided: str, expected: str) -> bool:
    """Timing-safe API secret karşılaştırma."""
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided.encode(), expected.encode())


def hash_for_integrity(data: bytes) -> str:
    """SHA-256 hash üretir."""
    return hashlib.sha256(data).hexdigest()
