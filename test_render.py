"""Render.com sunucusunu test et — key kalıcılık testi."""
import urllib.request, json, sys

base = 'https://gamestore-license-server.onrender.com'

def api(method, endpoint, body=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(f'{base}{endpoint}', data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

# 1. Health
print('=== HEALTH ===')
code, data = api('GET', '/health')
print(json.dumps(data, indent=2))
print()

# 2. Admin setup (zaten varsa 400 verir)
print('=== ADMIN SETUP ===')
code, data = api('POST', '/api/admin/setup', {'username':'onudeniz3','password':'test123'})
print(f'{code}: {data}')
print()

# 3. Login
print('=== LOGIN ===')
code, data = api('POST', '/api/admin/login', {'username':'onudeniz3','password':'test123'})
print(f'{code}: success={data.get("success")}')
token = data.get('token', '')
if not token:
    print('TOKEN YOK! Çıkılıyor.')
    sys.exit(1)
print()

# 4. Generate 2 test keys
print('=== GENERATE KEYS ===')
code, data = api('POST', '/api/admin/generate', {'plan':'monthly','count':2,'note':'kalicilik_testi'}, token)
print(f'{code}: {data}')
print()

# 5. List all keys
print('=== LIST KEYS ===')
code, data = api('GET', '/api/admin/keys', token=token)
print(f'Total keys: {data.get("total", 0)}')
for k in data.get('keys', []):
    print(f'  {k["key"]} | plan={k["plan"]} | active={k["is_active"]} | note={k.get("note","-")}')
print()

# 6. Health again
print('=== HEALTH AFTER ===')
code, data = api('GET', '/health')
print(json.dumps(data, indent=2))
