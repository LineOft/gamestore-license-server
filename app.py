"""
app.py — Lisans API Sunucusu (FastAPI)
========================================
Ana sunucu uygulaması. Tüm endpoint'ler burada.

Endpoint'ler:
  POST /api/verify       → Key + HWID doğrulama + offset dağıtımı
  POST /api/refresh      → Token yenileme
  POST /api/heartbeat    → Heartbeat ping
  POST /api/security-event → Güvenlik olayı bildirimi

  POST /api/admin/login  → Admin girişi
  POST /api/admin/generate → Key üretme
  GET  /api/admin/keys   → Key listeleme
  POST /api/admin/revoke → Key iptal
  POST /api/admin/reset-hwid → HWID sıfırlama
  GET  /api/admin/stats  → İstatistikler
  POST /api/admin/setup  → İlk admin oluşturma

Çalıştırma:
  cd server
  uvicorn app:app --host 0.0.0.0 --port 8000

Son Güncelleme: 2026-02-18
"""

import os
import sys
import time
import logging
import base64
from datetime import datetime
from typing import Optional
from pathlib import Path

# .env dosyasını yükle (server/.env)
try:
    from dotenv import load_dotenv
    _env_path = Path(__file__).parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path)
except ImportError:
    pass

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from pydantic import BaseModel, Field

# Sunucu modülleri (hem lokal 'server.X' hem cloud 'X' import desteği)
try:
    from server.models import get_db, get_key_manager, get_token_store, get_admin_manager
    from server.crypto import ServerCipher, verify_api_secret, TokenGenerator
    from server.auth import (
        init_auth, get_jwt_manager, get_brute_force, get_rate_limiter,
        require_admin, get_client_ip
    )
    from server.offset_provider import get_offset_provider
except ImportError:
    from models import get_db, get_key_manager, get_token_store, get_admin_manager
    from crypto import ServerCipher, verify_api_secret, TokenGenerator
    from auth import (
        init_auth, get_jwt_manager, get_brute_force, get_rate_limiter,
        require_admin, get_client_ip
    )
    from offset_provider import get_offset_provider

# ============================================================
# KONFIGÜRASYON
# ============================================================

# .env'den veya ortam değişkenlerinden oku
API_SECRET = os.environ.get("API_SECRET_TOKEN", "dev_secret_change_me_in_production")
JWT_SECRET = os.environ.get("JWT_SECRET_KEY", "jwt_secret_change_me_in_production")
TOKEN_LIFETIME = int(os.environ.get("TOKEN_LIFETIME", "300"))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "1") == "1"

# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("LicenseServer")

# ============================================================
# FASTAPI UYGULAMA
# ============================================================

app = FastAPI(
    title="GameStore License Server",
    version="1.0.0",
    docs_url="/docs" if DEBUG_MODE else None,   # Üretimde Swagger kapalı
    redoc_url="/redoc" if DEBUG_MODE else None,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if DEBUG_MODE else [],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# Auth modülünü başlat
init_auth(JWT_SECRET)

# Token generator
_token_gen = TokenGenerator(API_SECRET)


# ============================================================
# MIDDLEWARE — Rate Limiting + API Secret Check
# ============================================================

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Rate limit + API secret kontrolü."""
    ip = get_client_ip(request)
    path = request.url.path
    
    # Rate limit
    rate_limiter = get_rate_limiter()
    if not rate_limiter.is_allowed(ip):
        logger.warning(f"Rate limit aşıldı: {ip}")
        return JSONResponse(
            status_code=429,
            content={"detail": "Çok fazla istek. Lütfen bekleyin."}
        )
    
    # API secret kontrolü (admin ve public endpoint'ler için)
    if path.startswith("/api/"):
        # Admin login ve setup hariç, tüm bot endpoint'leri secret gerektirir
        if not path.startswith("/api/admin/"):
            secret = request.headers.get("X-Secret", "")
            if not verify_api_secret(secret, API_SECRET):
                logger.warning(f"Geçersiz API secret: {ip}")
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Erişim reddedildi"}
                )
    
    # Admin paneli ve health endpoint rate-limit hariç geçer
    if path in ("/admin", "/", "/health"):
        response = await call_next(request)
        return response
    
    response = await call_next(request)
    return response


# ============================================================
# REQUEST / RESPONSE MODELLERİ
# ============================================================

class VerifyRequest(BaseModel):
    key: str
    hwid: str
    exe_hash: Optional[str] = None
    app_version: Optional[str] = None
    timestamp: Optional[int] = None

class RefreshRequest(BaseModel):
    token: str
    hwid: str
    timestamp: Optional[int] = None

class HeartbeatRequest(BaseModel):
    token: str
    hwid: str
    timestamp: Optional[int] = None
    exe_hash: Optional[str] = None

class SecurityEventRequest(BaseModel):
    hwid: str
    threat_type: str
    detail: Optional[str] = None
    timestamp: Optional[int] = None

class AdminLoginRequest(BaseModel):
    username: str
    password: str

class GenerateKeysRequest(BaseModel):
    plan: str
    count: int = Field(default=1, ge=1, le=100)
    note: Optional[str] = None

class RevokeKeyRequest(BaseModel):
    key: str
    reason: Optional[str] = None

class ResetHwidRequest(BaseModel):
    key: str

class AdminSetupRequest(BaseModel):
    username: str
    password: str


# ============================================================
# PUBLIC ENDPOINT'LER (Bot İstemci)
# ============================================================

@app.post("/api/verify")
async def verify_key(req: VerifyRequest, request: Request):
    """
    Key + HWID doğrulama.
    Başarılıysa: token + AES key + şifreli offset'ler döner.
    """
    ip = get_client_ip(request)
    logger.info(f"Verify isteği: key={req.key[:8]}..., hwid={req.hwid[:8]}..., ip={ip}")
    
    # Key doğrula
    km = get_key_manager()
    result = km.verify_key(req.key, req.hwid, ip)
    
    if not result["valid"]:
        logger.warning(f"Verify başarısız: {result['reason']} — ip={ip}")
        return {
            "success": False,
            "valid": False,
            "reason": result["reason"]
        }
    
    # Token + AES key oluştur
    offset_provider = get_offset_provider()
    encrypted_offsets, aes_key_b64 = offset_provider.get_encrypted_with_new_key()
    
    # Token'ı DB'ye kaydet
    ts = get_token_store()
    token = ts.create_token(req.key, req.hwid, aes_key_b64, TOKEN_LIFETIME)
    
    logger.info(f"Verify başarılı: plan={result['plan']}, ip={ip}")
    
    return {
        "success": True,
        "valid": True,
        "plan": result["plan"],
        "expires_at": result.get("expires_at"),
        "token": token,
        "aes_key": aes_key_b64,
        "encrypted_offsets": encrypted_offsets,
        "token_lifetime": TOKEN_LIFETIME,
        "offset_version": offset_provider.get_offset_version()
    }


@app.post("/api/refresh")
async def refresh_token(req: RefreshRequest, request: Request):
    """Token yenileme. Eski token → yeni token + yeni AES key."""
    ip = get_client_ip(request)
    
    ts = get_token_store()
    
    # Eski token geçerli mi?
    token_data = ts.validate_token(req.token, req.hwid)
    if not token_data:
        logger.warning(f"Token refresh reddedildi: geçersiz token, ip={ip}")
        return {"success": False, "valid": False, "reason": "TOKEN_EXPIRED"}
    
    # Yeni AES key ve offset'ler
    offset_provider = get_offset_provider()
    encrypted_offsets, new_aes_key_b64 = offset_provider.get_encrypted_with_new_key()
    
    # Yeni token oluştur (eski iptal olur)
    new_token = ts.refresh_token(req.token, req.hwid, new_aes_key_b64, TOKEN_LIFETIME)
    
    if not new_token:
        return {"success": False, "valid": False, "reason": "REFRESH_FAILED"}
    
    # Key'in last_seen güncelle
    km = get_key_manager()
    key_info = km.get_key_info(token_data["key_text"])
    if key_info:
        with get_db().get_cursor() as cursor:
            cursor.execute("UPDATE keys SET last_seen=?, last_ip=? WHERE key=?",
                          (datetime.now().isoformat(), ip, token_data["key_text"]))
    
    logger.debug(f"Token yenilendi: key={token_data['key_text'][:8]}..., ip={ip}")
    
    return {
        "success": True,
        "valid": True,
        "token": new_token,
        "aes_key": new_aes_key_b64,
        "encrypted_offsets": encrypted_offsets,
        "token_lifetime": TOKEN_LIFETIME
    }


@app.post("/api/heartbeat")
async def heartbeat(req: HeartbeatRequest, request: Request):
    """Heartbeat — client hala çalışıyor mu?"""
    ip = get_client_ip(request)
    
    ts = get_token_store()
    token_data = ts.validate_token(req.token, req.hwid)
    
    if not token_data:
        return {"success": False, "alive": False, "reason": "INVALID_TOKEN"}
    
    # last_seen güncelle
    with get_db().get_cursor() as cursor:
        cursor.execute("UPDATE keys SET last_seen=?, last_ip=? WHERE key=?",
                      (datetime.now().isoformat(), ip, token_data["key_text"]))
    
    return {"success": True, "alive": True}


@app.post("/api/security-event")
async def security_event(req: SecurityEventRequest, request: Request):
    """Client'tan güvenlik olayı bildirimi."""
    ip = get_client_ip(request)
    
    logger.warning(f"GÜVENLİK OLAYI: type={req.threat_type}, hwid={req.hwid[:8]}..., ip={ip}")
    
    # DB'ye kaydet
    with get_db().get_cursor() as cursor:
        cursor.execute("""
            INSERT INTO security_events (hwid, event_type, detail, ip_address)
            VALUES (?, ?, ?, ?)
        """, (req.hwid, req.threat_type, req.detail, ip))
    
    return {"received": True}


# ============================================================
# ADMIN ENDPOINT'LER
# ============================================================

@app.post("/api/admin/setup")
async def admin_setup(req: AdminSetupRequest, request: Request):
    """İlk admin hesabı oluşturma (sadece bir kez çalışır)."""
    am = get_admin_manager()
    
    if am.admin_exists():
        raise HTTPException(status_code=400, detail="Admin zaten mevcut")
    
    success = am.create_admin(req.username, req.password)
    if not success:
        raise HTTPException(status_code=400, detail="Admin oluşturulamadı")
    
    logger.info(f"İlk admin oluşturuldu: {req.username}")
    return {"success": True, "message": "Admin hesabı oluşturuldu"}


@app.post("/api/admin/login")
async def admin_login(req: AdminLoginRequest, request: Request):
    """Admin girişi → JWT token."""
    ip = get_client_ip(request)
    bf = get_brute_force()
    
    # Brute force kontrolü
    if bf.is_locked(ip):
        remaining = bf.get_remaining_lockout(ip)
        logger.warning(f"Brute force lock: ip={ip}, remaining={remaining}s")
        raise HTTPException(
            status_code=429,
            detail=f"Çok fazla başarısız deneme. {remaining} saniye bekleyin."
        )
    
    # Doğrulama
    am = get_admin_manager()
    admin = am.verify_admin(req.username, req.password)
    
    if not admin:
        bf.record_attempt(ip, False)
        logger.warning(f"Admin login başarısız: user={req.username}, ip={ip}")
        raise HTTPException(status_code=401, detail="Geçersiz kullanıcı adı veya şifre")
    
    bf.record_attempt(ip, True)
    
    # JWT token oluştur
    jwt = get_jwt_manager()
    token = jwt.create_token(req.username, role="admin")
    
    logger.info(f"Admin login: user={req.username}, ip={ip}")
    
    return {
        "success": True,
        "token": token,
        "username": req.username
    }


@app.post("/api/admin/generate")
async def generate_keys(req: GenerateKeysRequest, admin=Depends(require_admin)):
    """Yeni lisans anahtarları üret."""
    km = get_key_manager()
    
    try:
        keys = km.generate_keys(
            plan=req.plan,
            count=req.count,
            note=req.note,
            created_by=admin.get("sub", "admin")
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    logger.info(f"Key üretildi: {req.count}x {req.plan} by {admin.get('sub')}")
    
    return {
        "success": True,
        "keys": keys,
        "plan": req.plan,
        "count": len(keys)
    }


@app.get("/api/admin/keys")
async def list_keys(status: Optional[str] = None, admin=Depends(require_admin)):
    """Tüm keyleri listele."""
    km = get_key_manager()
    keys = km.get_all_keys(status_filter=status)
    
    # Hassas bilgileri maskele
    for k in keys:
        if k.get("hwid"):
            k["hwid"] = k["hwid"][:8] + "..."
    
    return {"keys": keys, "total": len(keys)}


@app.post("/api/admin/revoke")
async def revoke_key(req: RevokeKeyRequest, admin=Depends(require_admin)):
    """Key iptal et."""
    km = get_key_manager()
    success = km.revoke_key(req.key, req.reason)
    
    if not success:
        raise HTTPException(status_code=404, detail="Key bulunamadı")
    
    logger.info(f"Key iptal: {req.key[:8]}... by {admin.get('sub')}")
    return {"success": True, "message": "Key iptal edildi"}


@app.post("/api/admin/reset-hwid")
async def reset_hwid(req: ResetHwidRequest, admin=Depends(require_admin)):
    """HWID sıfırla (müşteri cihaz değişikliği)."""
    km = get_key_manager()
    success = km.reset_hwid(req.key)
    
    if not success:
        raise HTTPException(status_code=404, detail="Key bulunamadı")
    
    logger.info(f"HWID reset: {req.key[:8]}... by {admin.get('sub')}")
    return {"success": True, "message": "HWID sıfırlandı"}


@app.get("/api/admin/stats")
async def get_stats(admin=Depends(require_admin)):
    """İstatistikler."""
    km = get_key_manager()
    stats = km.get_stats()
    
    return {"stats": stats}


@app.get("/api/admin/security-events")
async def get_security_events(limit: int = 50, admin=Depends(require_admin)):
    """Son güvenlik olayları."""
    with get_db().get_cursor() as cursor:
        cursor.execute("""
            SELECT * FROM security_events 
            ORDER BY created_at DESC LIMIT ?
        """, (limit,))
        events = [dict(row) for row in cursor.fetchall()]
    
    return {"events": events, "total": len(events)}


@app.get("/api/admin/activity")
async def get_activity(limit: int = 100, admin=Depends(require_admin)):
    """Son aktivite logları."""
    with get_db().get_cursor() as cursor:
        cursor.execute("""
            SELECT * FROM activity_logs
            ORDER BY created_at DESC LIMIT ?
        """, (limit,))
        logs = [dict(row) for row in cursor.fetchall()]
    
    return {"logs": logs, "total": len(logs)}


# ============================================================
# SAĞLIK KONTROLÜ
# ============================================================

@app.get("/health")
async def health_check():
    """Sunucu sağlık kontrolü."""
    db = get_db()
    key_count = 0
    try:
        with db.get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as c FROM keys")
            key_count = cursor.fetchone()["c"]
    except Exception:
        pass
    
    return {
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "database": "postgresql" if db._is_postgres else "sqlite",
        "db_path": db.db_path,
        "total_keys": key_count
    }


# ============================================================
# STARTUP & SHUTDOWN
# ============================================================

@app.on_event("startup")
async def startup():
    """Sunucu başlangıcında çalışır."""
    # Veritabanını başlat
    db = get_db()
    db_type = "PostgreSQL (Neon.tech)" if db._is_postgres else "SQLite (EPHEMERAL!)"
    logger.info(f"Veritabanı hazır: {db.db_path} [{db_type}]")
    
    if not db._is_postgres:
        logger.warning("⚠️  DATABASE_URL ortam değişkeni YOK — SQLite kullanılıyor!")
        logger.warning("⚠️  Render.com'da veriler her deploy'da SİLİNECEK!")
    
    # Key sayısını logla
    try:
        with db.get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as c FROM keys")
            count = cursor.fetchone()["c"]
            logger.info(f"Mevcut key sayısı: {count}")
    except Exception as e:
        logger.error(f"Key sayısı okunamadı: {e}")
    
    # Süresi dolmuş tokenları temizle
    ts = get_token_store()
    ts.cleanup_expired()
    
    logger.info("=" * 50)
    logger.info("  GameStore License Server v1.0.0")
    logger.info(f"  Database: {db_type}")
    logger.info(f"  Debug: {DEBUG_MODE}")
    logger.info(f"  Token Lifetime: {TOKEN_LIFETIME}s")
    logger.info("=" * 50)


# ============================================================
# ADMIN PANELİ (Web UI)
# ============================================================

TEMPLATES_DIR = Path(__file__).parent / "templates"

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel():
    """Admin web panelini serve et."""
    html_file = TEMPLATES_DIR / "admin.html"
    if not html_file.exists():
        raise HTTPException(status_code=404, detail="Admin panel dosyası bulunamadı")
    return HTMLResponse(content=html_file.read_text(encoding="utf-8"))

@app.get("/", response_class=HTMLResponse)
async def root_redirect():
    """Kök URL'yi admin paneline yönlendir."""
    return HTMLResponse(content='<html><head><meta http-equiv="refresh" content="0;url=/admin"></head></html>')


# ============================================================
# ÇALIŞTIRMA
# ============================================================

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")
    
    uvicorn.run(
        "server.app:app",
        host=host,
        port=port,
        reload=DEBUG_MODE,
        log_level="debug" if DEBUG_MODE else "info"
    )
