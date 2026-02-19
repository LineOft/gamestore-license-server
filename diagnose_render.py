"""
Render.com sunucusu kapsamli diagnoz scripti.
PostgreSQL baglantisi, tablo durumu, key sayilari kontrol eder.
"""
import urllib.request
import json

BASE = "https://gamestore-license-server.onrender.com"

def api_get(path, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{BASE}{path}", headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, json.loads(r.read())

def api_post(path, data=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data else b"{}"
    req = urllib.request.Request(f"{BASE}{path}", data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

def main():
    print("=" * 60)
    print("  RENDER.COM SUNUCU DIAGNOZ")
    print("=" * 60)

    # 1) Health
    print("\n[1] HEALTH CHECK")
    _, h = api_get("/health")
    for k, v in h.items():
        print(f"    {k}: {v}")

    # 2) Admin login (iki sifre dene)
    print("\n[2] ADMIN LOGIN")
    token = None
    for pwd in ["test123", "onudeniz3"]:
        code, resp = api_post("/api/admin/login", {
            "username": "onudeniz3",
            "password": pwd
        })
        if code == 200 and resp.get("token"):
            token = resp["token"]
            print(f"    Login OK (sifre: {pwd})")
            break
        else:
            print(f"    Sifre '{pwd}' basarisiz ({code})")

    if not token:
        print("    Token alinamadi!")
        return

    # 3) Key listesi
    print("\n[3] KEY LISTESI")
    _, resp = api_get("/api/admin/keys", token)
    keys = resp.get("keys", [])
    print(f"    Toplam: {len(keys)}")
    for k in keys:
        key_val = k.get("key", "?")
        plan = k.get("plan", "?")
        active = k.get("is_active", "?")
        note = k.get("note", "-")
        created = k.get("created_at", "?")
        print(f"    - {key_val} | plan={plan} | active={active} | note={note} | created={created}")

    # 4) Stats
    print("\n[4] ISTATISTIKLER")
    _, stats = api_get("/api/admin/stats", token)
    for k, v in stats.items():
        print(f"    {k}: {v}")

    # 5) Kalicilik test keyi
    print("\n[5] KALICILIK TEST KEY")
    code, resp = api_post("/api/admin/generate", {
        "plan": "daily",
        "count": 1,
        "note": "PERSIST_TEST_V2"
    }, token)
    gen_keys = resp.get("keys", [])
    if gen_keys:
        print(f"    Olusturuldu: {gen_keys[0]}")
        print(f"    Deploy sonrasi bu key varsa = PG calisiyor")

    # 6) Son durum
    print("\n[6] SON DURUM")
    _, h2 = api_get("/health")
    print(f"    DB: {h2.get('database')}, Keys: {h2.get('total_keys')}")

    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()
