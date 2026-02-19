"""
models.py — Veritabanı Modelleri ve İşlemleri
================================================
SQLite tabanlı lisans veritabanı.
Tablolar: keys, admin_users, security_events, activity_logs

Son Güncelleme: 2026-02-18
"""

import sqlite3
import os
import uuid
import string
import random
import threading
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path
from contextlib import contextmanager

# Veritabanı dosya yolu
DB_DIR = Path(__file__).parent
DB_PATH = DB_DIR / "license.db"

# Bulut PostgreSQL bağlantı adresi (varsa PG, yoksa lokal SQLite)
DATABASE_URL = os.environ.get("DATABASE_URL")


# ============================================================
# CURSOR SARMALAYICI (SQLite ↔ PostgreSQL uyumluluk)
# ============================================================

class _CursorProxy:
    """SQL parametre ve sonuç farkını şeffaf şekilde giderir.
    
    - SQLite: parametre = ?,  tarih = str,  bool = 0/1
    - PostgreSQL: parametre = %s, tarih = datetime obj, bool = True/False
    Bu sınıf farkı şeffaf kapatır — üst katman hiçbir şey değiştirmez.
    
    Ayrıca ISO string parametrelerini datetime nesnesine çevirir,
    böylece PostgreSQL TIMESTAMP sütunlarıyla karşılaştırma doğru çalışır.
    """

    def __init__(self, cursor, is_postgres: bool):
        self._cur = cursor
        self._pg = is_postgres

    @staticmethod
    def _convert_param(value):
        """ISO tarih string'lerini datetime nesnesine çevirir (PostgreSQL uyumluluğu)."""
        if isinstance(value, str) and len(value) >= 19:
            # ISO format: 2026-02-19T16:05:49.123456
            try:
                return datetime.fromisoformat(value)
            except (ValueError, TypeError):
                pass
        return value

    def execute(self, sql, params=None):
        if self._pg:
            sql = sql.replace("?", "%s")
            # ISO string parametreleri datetime'a çevir (PG TIMESTAMP uyumu)
            if params:
                params = tuple(self._convert_param(p) for p in params)
        if params:
            self._cur.execute(sql, params)
        else:
            self._cur.execute(sql)

    def fetchone(self):
        row = self._cur.fetchone()
        if row is None:
            return None
        d = dict(row) if not isinstance(row, dict) else dict(row)
        if self._pg:
            # PostgreSQL datetime → ISO string (mevcut kodla uyumluluk)
            for k, v in d.items():
                if isinstance(v, datetime):
                    d[k] = v.isoformat()
        return d

    def fetchall(self):
        rows = self._cur.fetchall()
        result = []
        for r in rows:
            d = dict(r) if not isinstance(r, dict) else dict(r)
            if self._pg:
                for k, v in d.items():
                    if isinstance(v, datetime):
                        d[k] = v.isoformat()
            result.append(d)
        return result

    @property
    def rowcount(self):
        return self._cur.rowcount

    @property
    def lastrowid(self):
        if self._pg:
            return None
        return self._cur.lastrowid


# ============================================================
# DATABASE BAĞLANTI YÖNETİCİSİ
# ============================================================

class Database:
    """Thread-safe SQLite / PostgreSQL bağlantı yöneticisi.
    
    DATABASE_URL ortam değişkeni varsa → PostgreSQL (bulut, kalıcı)
    Yoksa → SQLite (lokal geliştirme)
    """

    _local = threading.local()

    def __init__(self, db_url: str = None):
        self._db_url = db_url or DATABASE_URL
        self._is_postgres = bool(self._db_url and "postgres" in self._db_url)

        if self._is_postgres:
            self.db_path = "(PostgreSQL Cloud)"
        else:
            self.db_path = str(DB_PATH)

        self._init_db()

    def _get_conn(self):
        """Thread-local bağlantı döndürür."""
        if self._is_postgres:
            import psycopg2
            conn = getattr(self._local, 'conn', None)
            if conn is None or conn.closed:
                self._local.conn = psycopg2.connect(self._db_url)
            else:
                # Neon.tech serverless bağlantı kopma kontrolü
                try:
                    conn.cursor().execute("SELECT 1")
                    conn.commit()
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    self._local.conn = psycopg2.connect(self._db_url)
            return self._local.conn
        else:
            if not hasattr(self._local, 'conn') or self._local.conn is None:
                self._local.conn = sqlite3.connect(self.db_path)
                self._local.conn.row_factory = sqlite3.Row
                self._local.conn.execute("PRAGMA journal_mode=WAL")
                self._local.conn.execute("PRAGMA foreign_keys=ON")
            return self._local.conn

    @contextmanager
    def get_cursor(self):
        """Context manager ile cursor döndürür."""
        conn = self._get_conn()
        if self._is_postgres:
            import psycopg2.extras
            raw_cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            raw_cur = conn.cursor()

        cursor = _CursorProxy(raw_cur, self._is_postgres)
        try:
            yield cursor
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                self._local.conn = None
            raise

    def _init_db(self):
        """Tabloları oluşturur (SQLite veya PostgreSQL)."""
        if self._is_postgres:
            import psycopg2
            conn = psycopg2.connect(self._db_url)
            auto_pk = "SERIAL PRIMARY KEY"
        else:
            conn = sqlite3.connect(self.db_path)
            auto_pk = "INTEGER PRIMARY KEY AUTOINCREMENT"

        cursor = conn.cursor()

        # Keys tablosu
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS keys (
                id {auto_pk},
                key TEXT UNIQUE NOT NULL,
                plan TEXT NOT NULL CHECK(plan IN ('daily','weekly','monthly','lifetime')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                hwid TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                activated_at TIMESTAMP,
                last_seen TIMESTAMP,
                last_ip TEXT,
                note TEXT,
                created_by TEXT DEFAULT 'admin'
            )
        """)

        # Admin kullanıcılar
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS admin_users (
                id {auto_pk},
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        """)

        # Güvenlik olayları
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS security_events (
                id {auto_pk},
                hwid TEXT,
                key_text TEXT,
                event_type TEXT NOT NULL,
                detail TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Aktivite logları
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id {auto_pk},
                key_text TEXT,
                action TEXT NOT NULL,
                detail TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Token tablosu (dönen tokenlar)
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS active_tokens (
                id {auto_pk},
                key_text TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                hwid TEXT NOT NULL,
                aes_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_valid BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (key_text) REFERENCES keys(key)
            )
        """)

        # Deploy takip tablosu — her başlangıçta kayıt eklenir
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS deploy_tracker (
                id {auto_pk},
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                db_type TEXT NOT NULL,
                key_count_at_start INTEGER DEFAULT 0,
                admin_count_at_start INTEGER DEFAULT 0,
                note TEXT
            )
        """)

        # İndeksler
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_keys_hwid ON keys(hwid)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tokens_token ON active_tokens(token)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tokens_key ON active_tokens(key_text)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_hwid ON security_events(hwid)")

        conn.commit()
        conn.close()

    def record_deploy(self):
        """Sunucu başlangıcını deploy_tracker tablosuna kaydeder."""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("SELECT COUNT(*) as c FROM keys")
                key_count = cursor.fetchone()["c"]
                cursor.execute("SELECT COUNT(*) as c FROM admin_users")
                admin_count = cursor.fetchone()["c"]
                db_type = "postgresql" if self._is_postgres else "sqlite"
                cursor.execute(
                    "INSERT INTO deploy_tracker (db_type, key_count_at_start, admin_count_at_start, note) VALUES (?, ?, ?, ?)",
                    (db_type, key_count, admin_count, f"startup-{datetime.now().isoformat()}")
                )
        except Exception as e:
            # deploy_tracker tablosu yoksa sessizce geç (ilk kez)
            print(f"[WARN] Deploy kaydı yazılamadı: {e}")

    def get_db_info(self) -> Dict[str, Any]:
        """Veritabanı hakkında detaylı bilgi döndürür."""
        info = {
            "db_type": "postgresql" if self._is_postgres else "sqlite",
            "db_path": self.db_path,
            "tables": {},
            "deploy_history": [],
        }
        try:
            with self.get_cursor() as cursor:
                # PostgreSQL özel bilgiler
                if self._is_postgres:
                    cursor.execute("SELECT current_database() as db_name")
                    row = cursor.fetchone()
                    info["pg_database"] = row["db_name"] if row else "?"
                    cursor.execute("SELECT current_schema() as schema_name")
                    row = cursor.fetchone()
                    info["pg_schema"] = row["schema_name"] if row else "?"

                # Tablo satır sayıları
                for table in ["keys", "admin_users", "active_tokens", "security_events", "activity_logs", "deploy_tracker"]:
                    try:
                        cursor.execute(f"SELECT COUNT(*) as c FROM {table}")
                        info["tables"][table] = cursor.fetchone()["c"]
                    except Exception:
                        info["tables"][table] = -1  # tablo yok

                # Son 5 deploy kaydı
                try:
                    cursor.execute("SELECT * FROM deploy_tracker ORDER BY id DESC LIMIT 5")
                    info["deploy_history"] = cursor.fetchall()
                except Exception:
                    info["deploy_history"] = []
        except Exception as e:
            info["error"] = str(e)
        return info


# ============================================================
# KEY İŞLEMLERİ
# ============================================================

class KeyManager:
    """Lisans anahtarı CRUD işlemleri."""
    
    # Plan süreleri
    PLAN_DURATIONS = {
        'daily': timedelta(days=1),
        'weekly': timedelta(weeks=1),
        'monthly': timedelta(days=30),
        'lifetime': timedelta(days=36500),  # 100 yıl
    }
    
    def __init__(self, db: Database):
        self.db = db
    
    @staticmethod
    def _generate_key() -> str:
        """XXXX-XXXX-XXXX-XXXX formatında benzersiz key üretir."""
        chars = string.ascii_uppercase + string.digits
        # İlk kısmı UUID'den türet (tahmin edilemezlik)
        uid = uuid.uuid4().hex.upper()
        parts = []
        for i in range(4):
            # UUID karakterleri + random karışımı
            segment = ""
            for j in range(4):
                idx = (i * 4 + j) % len(uid)
                if random.random() > 0.5:
                    segment += uid[idx]
                else:
                    segment += random.choice(chars)
            parts.append(segment)
        return '-'.join(parts)
    
    def generate_keys(self, plan: str, count: int = 1, 
                      note: str = None, created_by: str = "admin") -> List[str]:
        """
        Yeni lisans anahtarları üretir.
        
        Args:
            plan: 'daily', 'weekly', 'monthly', 'lifetime'
            count: Üretilecek key sayısı
            note: Admin notu
            created_by: Oluşturan admin
        
        Returns:
            Üretilen key listesi
        """
        if plan not in self.PLAN_DURATIONS:
            raise ValueError(f"Geçersiz plan: {plan}")
        
        keys = []
        with self.db.get_cursor() as cursor:
            for _ in range(count):
                # Benzersiz key üret
                while True:
                    key = self._generate_key()
                    cursor.execute("SELECT 1 FROM keys WHERE key=?", (key,))
                    if not cursor.fetchone():
                        break
                
                cursor.execute("""
                    INSERT INTO keys (key, plan, note, created_by)
                    VALUES (?, ?, ?, ?)
                """, (key, plan, note, created_by))
                keys.append(key)
        
        return keys
    
    def verify_key(self, key: str, hwid: str, ip: str = None) -> Dict[str, Any]:
        """
        Key + HWID doğrulama.
        
        Returns:
            {"valid": bool, "reason": str, "plan": str, "expires_at": str}
        """
        with self.db.get_cursor() as cursor:
            cursor.execute("SELECT * FROM keys WHERE key=?", (key,))
            record = cursor.fetchone()
            
            if not record:
                self._log_activity(cursor, key, "verify_failed", "KEY_NOT_FOUND", ip)
                return {"valid": False, "reason": "KEY_NOT_FOUND"}
            
            if not record["is_active"]:
                self._log_activity(cursor, key, "verify_failed", "KEY_REVOKED", ip)
                return {"valid": False, "reason": "KEY_REVOKED"}
            
            # Süre kontrolü
            if record["expires_at"]:
                expires = datetime.fromisoformat(record["expires_at"])
                if expires < datetime.now():
                    self._log_activity(cursor, key, "verify_failed", "KEY_EXPIRED", ip)
                    return {"valid": False, "reason": "KEY_EXPIRED"}
            
            # HWID kontrolü
            if record["hwid"] and record["hwid"] != hwid:
                self._log_security(cursor, hwid, key, "HWID_MISMATCH",
                                   f"Kayıtlı: {record['hwid'][:8]}..., Gelen: {hwid[:8]}...", ip)
                return {"valid": False, "reason": "HWID_MISMATCH"}
            
            # İlk aktivasyon → HWID kaydet + süre başlat
            if not record["hwid"]:
                now = datetime.now()
                duration = self.PLAN_DURATIONS[record["plan"]]
                expires_at = now + duration
                
                cursor.execute("""
                    UPDATE keys SET hwid=?, activated_at=?, expires_at=?, 
                                    last_seen=?, last_ip=?
                    WHERE key=?
                """, (hwid, now.isoformat(), expires_at.isoformat(),
                      now.isoformat(), ip, key))
                
                self._log_activity(cursor, key, "activated",
                                   f"HWID={hwid[:8]}..., Plan={record['plan']}", ip)
                
                return {
                    "valid": True,
                    "plan": record["plan"],
                    "expires_at": expires_at.isoformat(),
                    "first_activation": True
                }
            
            # Mevcut key — last_seen güncelle
            cursor.execute("""
                UPDATE keys SET last_seen=?, last_ip=? WHERE key=?
            """, (datetime.now().isoformat(), ip, key))
            
            self._log_activity(cursor, key, "verified", f"HWID={hwid[:8]}...", ip)
            
            return {
                "valid": True,
                "plan": record["plan"],
                "expires_at": record["expires_at"],
                "first_activation": False
            }
    
    def revoke_key(self, key: str, reason: str = None) -> bool:
        """Key'i iptal eder."""
        with self.db.get_cursor() as cursor:
            cursor.execute("UPDATE keys SET is_active=FALSE WHERE key=?", (key,))
            if cursor.rowcount > 0:
                self._log_activity(cursor, key, "revoked", reason)
                # İlgili tokenları da iptal et
                cursor.execute("UPDATE active_tokens SET is_valid=FALSE WHERE key_text=?", (key,))
                return True
            return False
    
    def reset_hwid(self, key: str) -> bool:
        """Key'in HWID'sini sıfırlar (müşteri cihaz değişikliği)."""
        with self.db.get_cursor() as cursor:
            cursor.execute("""
                UPDATE keys SET hwid=NULL, activated_at=NULL, expires_at=NULL 
                WHERE key=?
            """, (key,))
            if cursor.rowcount > 0:
                self._log_activity(cursor, key, "hwid_reset", "Admin tarafından sıfırlandı")
                cursor.execute("UPDATE active_tokens SET is_valid=FALSE WHERE key_text=?", (key,))
                return True
            return False
    
    def get_all_keys(self, status_filter: str = None) -> List[Dict]:
        """Tüm keyleri listeler."""
        with self.db.get_cursor() as cursor:
            query = "SELECT * FROM keys ORDER BY created_at DESC"
            params = []
            
            if status_filter == "active":
                now_str = datetime.now().isoformat()
                query = "SELECT * FROM keys WHERE is_active=TRUE AND (expires_at IS NULL OR expires_at > ?) ORDER BY created_at DESC"
                params = [now_str]
            elif status_filter == "expired":
                now_str = datetime.now().isoformat()
                query = "SELECT * FROM keys WHERE expires_at IS NOT NULL AND expires_at <= ? ORDER BY created_at DESC"
                params = [now_str]
            elif status_filter == "revoked":
                query = "SELECT * FROM keys WHERE is_active=FALSE ORDER BY created_at DESC"
                params = []
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_key_info(self, key: str) -> Optional[Dict]:
        """Tek key bilgisi."""
        with self.db.get_cursor() as cursor:
            cursor.execute("SELECT * FROM keys WHERE key=?", (key,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_stats(self) -> Dict:
        """İstatistikler."""
        with self.db.get_cursor() as cursor:
            stats = {}
            
            cursor.execute("SELECT COUNT(*) as c FROM keys")
            stats["total_keys"] = cursor.fetchone()["c"]
            
            cursor.execute("SELECT COUNT(*) as c FROM keys WHERE is_active=TRUE")
            stats["active_keys"] = cursor.fetchone()["c"]
            
            cursor.execute("SELECT COUNT(*) as c FROM keys WHERE hwid IS NOT NULL")
            stats["activated_keys"] = cursor.fetchone()["c"]
            
            cursor.execute("SELECT COUNT(*) as c FROM keys WHERE is_active=FALSE")
            stats["revoked_keys"] = cursor.fetchone()["c"]
            
            now = datetime.now().isoformat()
            cursor.execute("SELECT COUNT(*) as c FROM keys WHERE expires_at IS NOT NULL AND expires_at <= ?", (now,))
            stats["expired_keys"] = cursor.fetchone()["c"]
            
            # Bu ay aktivasyonlar
            month_start = datetime.now().replace(day=1, hour=0, minute=0, second=0).isoformat()
            cursor.execute("SELECT COUNT(*) as c FROM keys WHERE activated_at >= ?", (month_start,))
            stats["monthly_activations"] = cursor.fetchone()["c"]
            
            # Plan dağılımı
            cursor.execute("SELECT plan, COUNT(*) as c FROM keys GROUP BY plan")
            stats["plan_distribution"] = {row["plan"]: row["c"] for row in cursor.fetchall()}
            
            # Online kullanıcılar (son 4 dk — heartbeat 3 dk'da bir)
            recent = (datetime.now() - timedelta(minutes=4)).isoformat()
            cursor.execute(
                "SELECT COUNT(*) as c FROM keys WHERE last_seen IS NOT NULL AND last_seen >= ?",
                (recent,)
            )
            stats["online_users"] = cursor.fetchone()["c"]
            
            return stats
    
    def _log_activity(self, cursor, key, action, detail=None, ip=None):
        cursor.execute("""
            INSERT INTO activity_logs (key_text, action, detail, ip_address)
            VALUES (?, ?, ?, ?)
        """, (key, action, detail, ip))
    
    def _log_security(self, cursor, hwid, key, event_type, detail=None, ip=None):
        cursor.execute("""
            INSERT INTO security_events (hwid, key_text, event_type, detail, ip_address)
            VALUES (?, ?, ?, ?, ?)
        """, (hwid, key, event_type, detail, ip))


# ============================================================
# TOKEN İŞLEMLERİ
# ============================================================

class TokenStore:
    """Dönen token veritabanı işlemleri."""
    
    TOKEN_LIFETIME = 300  # 5 dakika
    
    def __init__(self, db: Database):
        self.db = db
    
    def create_token(self, key: str, hwid: str, aes_key: str,
                     lifetime: int = None) -> str:
        """Yeni token oluşturur ve eski tokenları iptal eder."""
        token = uuid.uuid4().hex + uuid.uuid4().hex  # 64 char token
        expires = datetime.now() + timedelta(seconds=lifetime or self.TOKEN_LIFETIME)
        
        with self.db.get_cursor() as cursor:
            # Bu key+hwid için eski tokenları iptal et
            cursor.execute("""
                UPDATE active_tokens SET is_valid=FALSE 
                WHERE key_text=? AND hwid=?
            """, (key, hwid))
            
            # Yeni token oluştur
            cursor.execute("""
                INSERT INTO active_tokens (key_text, token, hwid, aes_key, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """, (key, token, hwid, aes_key, expires.isoformat()))
        
        return token
    
    def validate_token(self, token: str, hwid: str) -> Optional[Dict]:
        """Token geçerli mi kontrol eder."""
        with self.db.get_cursor() as cursor:
            cursor.execute("""
                SELECT t.*, k.plan, k.is_active as key_active
                FROM active_tokens t
                JOIN keys k ON t.key_text = k.key
                WHERE t.token=? AND t.hwid=? AND t.is_valid=TRUE
            """, (token, hwid))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            # Süre kontrolü
            expires = datetime.fromisoformat(row["expires_at"])
            if expires < datetime.now():
                cursor.execute("UPDATE active_tokens SET is_valid=FALSE WHERE token=?", (token,))
                return None
            
            # Key hala aktif mi?
            if not row["key_active"]:
                cursor.execute("UPDATE active_tokens SET is_valid=FALSE WHERE token=?", (token,))
                return None
            
            return dict(row)
    
    def refresh_token(self, old_token: str, hwid: str, 
                      new_aes_key: str, lifetime: int = None) -> Optional[str]:
        """Eski token → yeni token. Eski iptal olur."""
        token_data = self.validate_token(old_token, hwid)
        if not token_data:
            return None
        
        # Eski tokeni iptal et
        with self.db.get_cursor() as cursor:
            cursor.execute("UPDATE active_tokens SET is_valid=FALSE WHERE token=?", (old_token,))
        
        # Yeni token oluştur
        return self.create_token(token_data["key_text"], hwid, new_aes_key, lifetime)
    
    def invalidate_token(self, token: str):
        """Tek bir token'ı iptal eder."""
        with self.db.get_cursor() as cursor:
            cursor.execute("UPDATE active_tokens SET is_valid=FALSE WHERE token=?", (token,))
    
    def invalidate_key_tokens(self, key: str):
        """Bir key'e ait tüm tokenları iptal eder."""
        with self.db.get_cursor() as cursor:
            cursor.execute("UPDATE active_tokens SET is_valid=FALSE WHERE key_text=?", (key,))
    
    def cleanup_expired(self):
        """Süresi dolmuş tokenları siler."""
        with self.db.get_cursor() as cursor:
            cursor.execute("""
                DELETE FROM active_tokens 
                WHERE expires_at < ? OR is_valid=FALSE
            """, ((datetime.now() - timedelta(hours=1)).isoformat(),))


# ============================================================
# ADMIN İŞLEMLERİ
# ============================================================

class AdminManager:
    """Admin kullanıcı yönetimi."""
    
    def __init__(self, db: Database):
        self.db = db
    
    def create_admin(self, username: str, password: str) -> bool:
        """Yeni admin oluşturur."""
        from werkzeug.security import generate_password_hash
        
        hashed = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        
        try:
            with self.db.get_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO admin_users (username, password_hash)
                    VALUES (?, ?)
                """, (username, hashed))
            return True
        except sqlite3.IntegrityError:
            return False
    
    def verify_admin(self, username: str, password: str) -> Optional[Dict]:
        """Admin giriş doğrulama."""
        from werkzeug.security import check_password_hash
        
        with self.db.get_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM admin_users WHERE username=? AND is_active=TRUE
            """, (username,))
            
            row = cursor.fetchone()
            if row and check_password_hash(row["password_hash"], password):
                cursor.execute("""
                    UPDATE admin_users SET last_login=? WHERE id=?
                """, (datetime.now().isoformat(), row["id"]))
                return dict(row)
        
        return None
    
    def admin_exists(self) -> bool:
        """En az bir admin var mı?"""
        with self.db.get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as c FROM admin_users WHERE is_active=TRUE")
            return cursor.fetchone()["c"] > 0


# ============================================================
# GLOBAL INSTANCES
# ============================================================

_db: Optional[Database] = None

def get_db() -> Database:
    global _db
    if _db is None:
        _db = Database()
    return _db

def get_key_manager() -> KeyManager:
    return KeyManager(get_db())

def get_token_store() -> TokenStore:
    return TokenStore(get_db())

def get_admin_manager() -> AdminManager:
    return AdminManager(get_db())
