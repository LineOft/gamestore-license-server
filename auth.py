"""
auth.py — Admin Kimlik Doğrulama ve JWT
==========================================
JWT token tabanlı admin auth + brute force koruması.

Son Güncelleme: 2026-02-18
"""

import time
import hashlib
import hmac
import json
import base64
import os
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict
from functools import wraps

from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


# ============================================================
# JWT TOKEN YÖNETİMİ (Basit, bağımlılıksız)
# ============================================================

class JWTManager:
    """Basit JWT implementasyonu (PyJWT bağımlılığı olmadan)."""
    
    def __init__(self, secret_key: str, token_expire_hours: int = 24):
        self._secret = secret_key.encode('utf-8')
        self._expire_hours = token_expire_hours
    
    def create_token(self, username: str, **extra) -> str:
        """JWT token oluşturur."""
        header = {"alg": "HS256", "typ": "JWT"}
        
        payload = {
            "sub": username,
            "iat": int(time.time()),
            "exp": int(time.time()) + (self._expire_hours * 3600),
            "jti": base64.urlsafe_b64encode(os.urandom(16)).decode(),
            **extra
        }
        
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(self._secret, message.encode(), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{message}.{sig_b64}"
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """JWT token doğrular."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header_b64, payload_b64, sig_b64 = parts
            
            # İmza doğrula
            message = f"{header_b64}.{payload_b64}"
            expected_sig = base64.urlsafe_b64encode(
                hmac.new(self._secret, message.encode(), hashlib.sha256).digest()
            ).decode().rstrip('=')
            
            if not hmac.compare_digest(sig_b64, expected_sig):
                return None
            
            # Payload çöz
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += '=' * padding
            
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            
            # Süre kontrolü
            if payload.get("exp", 0) < time.time():
                return None
            
            return payload
        except Exception:
            return None


# ============================================================
# BRUTE FORCE KORUMASI
# ============================================================

class BruteForceProtection:
    """IP bazlı brute force koruması."""
    
    MAX_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15
    
    def __init__(self):
        self._attempts: Dict[str, list] = {}
        self._lock = threading.Lock()
    
    def record_attempt(self, ip: str, success: bool):
        """Giriş denemesi kaydet."""
        with self._lock:
            if ip not in self._attempts:
                self._attempts[ip] = []
            
            self._attempts[ip].append({
                "time": time.time(),
                "success": success
            })
            
            # Eski kayıtları temizle (1 saat öncesi)
            cutoff = time.time() - 3600
            self._attempts[ip] = [a for a in self._attempts[ip] if a["time"] > cutoff]
    
    def is_locked(self, ip: str) -> bool:
        """IP kilitli mi?"""
        with self._lock:
            if ip not in self._attempts:
                return False
            
            # Son LOCKOUT_MINUTES içindeki başarısız denemeleri say
            cutoff = time.time() - (self.LOCKOUT_MINUTES * 60)
            recent_failures = [
                a for a in self._attempts[ip]
                if not a["success"] and a["time"] > cutoff
            ]
            
            return len(recent_failures) >= self.MAX_ATTEMPTS
    
    def get_remaining_lockout(self, ip: str) -> int:
        """Kalan kilit süresi (saniye)."""
        with self._lock:
            if ip not in self._attempts:
                return 0
            
            failures = [a for a in self._attempts[ip] if not a["success"]]
            if len(failures) < self.MAX_ATTEMPTS:
                return 0
            
            last_failure = max(a["time"] for a in failures)
            unlock_time = last_failure + (self.LOCKOUT_MINUTES * 60)
            remaining = unlock_time - time.time()
            return max(0, int(remaining))


# ============================================================
# RATE LIMITER
# ============================================================

class RateLimiter:
    """IP bazlı rate limiting."""
    
    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self._max = max_requests
        self._window = window_seconds
        self._requests: Dict[str, list] = {}
        self._lock = threading.Lock()
    
    def is_allowed(self, ip: str) -> bool:
        """İstek izin veriliyor mu?"""
        with self._lock:
            now = time.time()
            cutoff = now - self._window
            
            if ip not in self._requests:
                self._requests[ip] = []
            
            # Eski kayıtları temizle
            self._requests[ip] = [t for t in self._requests[ip] if t > cutoff]
            
            if len(self._requests[ip]) >= self._max:
                return False
            
            self._requests[ip].append(now)
            return True


# ============================================================
# FASTAPI DEPENDENCY — Admin Auth
# ============================================================

security_scheme = HTTPBearer()

# Global instances
_jwt_manager: Optional[JWTManager] = None
_brute_force = BruteForceProtection()
_rate_limiter = RateLimiter()


def init_auth(secret_key: str):
    """Auth modülünü başlatır."""
    global _jwt_manager
    _jwt_manager = JWTManager(secret_key)


def get_jwt_manager() -> JWTManager:
    if _jwt_manager is None:
        raise RuntimeError("Auth modülü başlatılmamış — init_auth() çağır")
    return _jwt_manager


def get_brute_force() -> BruteForceProtection:
    return _brute_force


def get_rate_limiter() -> RateLimiter:
    return _rate_limiter


async def require_admin(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)) -> Dict:
    """
    FastAPI dependency — Admin JWT doğrulama.
    
    Kullanım:
        @app.get("/admin/endpoint")
        async def endpoint(admin = Depends(require_admin)):
            ...
    """
    jwt = get_jwt_manager()
    payload = jwt.verify_token(credentials.credentials)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Geçersiz veya süresi dolmuş token")
    
    return payload


def get_client_ip(request: Request) -> str:
    """İstemci IP adresini alır (proxy arkasında da çalışır)."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    return request.client.host if request.client else "unknown"
