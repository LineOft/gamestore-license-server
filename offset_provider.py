"""
offset_provider.py — Şifreli Offset Dağıtıcı
================================================
Oyun offset'lerini sunucuda tutar, istemciye AES ile şifreli gönderir.
EN KRİTİK CRACK KORUMASI: Offset'ler EXE'de yok, sunucu olmadan bot çalışmaz.

Son Güncelleme: 2026-02-18
"""

import json
import os
from typing import Dict, Any, Optional
from pathlib import Path

try:
    from server.crypto import ServerCipher
except ImportError:
    from crypto import ServerCipher


# ============================================================
# OYUN OFFSETLERİ — SADECE SUNUCUDA
# ============================================================

# Bu veriler ASLA client'a plaintext gönderilmez.
# Her istemciye benzersiz AES key ile şifrelenir.
GAME_OFFSETS = {
    # Ana pointer'lar
    "world_offset": 0x04CE4328,
    
    # Player pozisyon chain
    "player_off1": 0x250,
    "player_off2": 0x138,
    "player_x": 0x1E0,
    "player_y": 0x1E4,
    "player_z": 0x1E8,
    
    # Kamera
    "camera_off1": 0x398,
    "camera_rotation": 0x278,
    
    # Karakter rotation
    "player_rotation": 0x548,
    
    # Entity array
    "entity_array": 0x128,
    "entity_count": 0x130,
    
    # Entity struct
    "entity_x": 0x318,
    "entity_y": 0x31C,
    "entity_z": 0x320,
    "entity_hp": 0x544,
    "entity_max_hp": 0x424,
    "entity_alive": 0x608,
    
    # Target offsets
    "entity_target": 0x0860,
    "go_target_npc": 0x05C0,
    "go_target_attack": 0x05C8,
    "go_target": 0x059C,
    "go_target_pos": 0x05B0,
    
    # GNames
    "gnames_offset": 0x04D81EC0,
    
    # Versiyon (client uyumluluk kontrolü)
    "offset_version": "2026.02.18",
    "min_app_version": "5.1.0",
}


# ============================================================
# OFFSET DAĞITIM
# ============================================================

class OffsetProvider:
    """
    Offset'leri şifreli olarak dağıtır.
    Her istemciye benzersiz AES key ile şifreler.
    """
    
    def __init__(self, offsets: dict = None):
        self._offsets = offsets or GAME_OFFSETS
    
    def get_encrypted_offsets(self, aes_key: bytes) -> str:
        """
        Offset'leri AES-256-GCM ile şifreler.
        
        Args:
            aes_key: 32 byte AES anahtarı (her istemci için benzersiz)
        
        Returns:
            Base64 encoded şifreli offset string
        """
        return ServerCipher.encrypt_json(self._offsets, aes_key)
    
    def get_encrypted_with_new_key(self) -> tuple:
        """
        Yeni AES key üretir ve offset'leri şifreler.
        
        Returns:
            (encrypted_offsets: str, aes_key_b64: str)
        """
        aes_key = ServerCipher.generate_aes_key()
        aes_key_b64 = ServerCipher.generate_aes_key_b64()
        aes_key = __import__('base64').urlsafe_b64decode(aes_key_b64)
        
        encrypted = self.get_encrypted_offsets(aes_key)
        return encrypted, aes_key_b64
    
    def update_offset(self, key: str, value: Any):
        """Tek bir offset'i günceller (oyun güncelleme sonrası)."""
        self._offsets[key] = value
    
    def update_offsets(self, new_offsets: dict):
        """Birden fazla offset günceller."""
        self._offsets.update(new_offsets)
    
    def get_offset_version(self) -> str:
        """Offset versiyon bilgisi."""
        return self._offsets.get("offset_version", "unknown")
    
    def save_to_file(self, path: str = None):
        """Offset'leri dosyaya kaydeder (sunucu backup)."""
        if path is None:
            path = str(Path(__file__).parent / "offsets_backup.json")
        
        with open(path, 'w') as f:
            json.dump(self._offsets, f, indent=2)
    
    def load_from_file(self, path: str = None):
        """Offset'leri dosyadan yükler."""
        if path is None:
            path = str(Path(__file__).parent / "offsets_backup.json")
        
        if os.path.exists(path):
            with open(path, 'r') as f:
                self._offsets = json.load(f)


# ============================================================
# GLOBAL INSTANCE
# ============================================================

_provider: Optional[OffsetProvider] = None

def get_offset_provider() -> OffsetProvider:
    global _provider
    if _provider is None:
        _provider = OffsetProvider()
    return _provider
