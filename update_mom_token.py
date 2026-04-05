"""
update_mom_token.py — update momCreds.refresh_token in the encrypted config
AND mom.json creds.refresh_token on the Gist, then save back locally.
"""
import base64, json, os, urllib.request

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_dir = os.path.dirname(__file__)

PASSWORD  = b"websteps123"
ITERS     = 100_000

def derive_key(salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERS)
    return kdf.derive(PASSWORD)

def decrypt(blob_b64: str, salt_b64: str, iv_b64: str) -> dict:
    salt = base64.b64decode(salt_b64)
    iv   = base64.b64decode(iv_b64)
    blob = base64.b64decode(blob_b64)
    key  = derive_key(salt)
    plain = AESGCM(key).decrypt(iv, blob, None)
    return json.loads(plain)

def encrypt(data: dict) -> tuple[str, str, str]:
    salt = os.urandom(16)
    iv   = os.urandom(12)
    key  = derive_key(salt)
    blob = AESGCM(key).encrypt(iv, json.dumps(data).encode(), None)
    return base64.b64encode(blob).decode(), base64.b64encode(salt).decode(), base64.b64encode(iv).decode()

def patch_gist(gist_id: str, pat: str, filename: str, content: str):
    body = json.dumps({"files": {filename: {"content": content}}}).encode()
    req  = urllib.request.Request(
        f"https://api.github.com/gists/{gist_id}",
        data=body, method="PATCH",
        headers={"Authorization": f"token {pat}", "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json"},
    )
    urllib.request.urlopen(req)

# ── Load config ───────────────────────────────────────────────────────────────
config_path = os.path.join(_dir, "config.json")
with open(config_path) as f:
    app_config = json.load(f)

# Try loading latest from Gist first (may have newer encrypted blob)
gist_id    = app_config["gistId"]
gist_owner = app_config.get("gistOwner", "michael-tint")
try:
    req = urllib.request.Request(
        f"https://api.github.com/gists/{gist_id}",
        headers={"Accept": "application/vnd.github+json"},
    )
    gist = json.loads(urllib.request.urlopen(req).read())
    if "config.json" in gist["files"]:
        gist_config = json.loads(gist["files"]["config.json"]["content"])
        app_config = {**app_config, **gist_config}
        print("Loaded config from Gist.")
    else:
        print("No config.json in Gist yet, using local.")
except Exception as e:
    print(f"Could not fetch Gist config ({e}), using local.")

# ── Decrypt ───────────────────────────────────────────────────────────────────
print("Decrypting config...")
creds = decrypt(app_config["encryptedBlob"], app_config["salt"], app_config["iv"])
print(f"  momCreds keys: {list(creds.get('momCreds', {}).keys())}")
old_token = creds.get("momCreds", {}).get("refresh_token", "")
print(f"  old token: {old_token[:16]}...")

# ── Swap token ────────────────────────────────────────────────────────────────
new_token_path = os.path.join(_dir, "fitbit_refresh_token.txt")
new_token = open(new_token_path).read().strip()
print(f"  new token: {new_token[:16]}...")

if "momCreds" not in creds:
    raise ValueError("momCreds not found in config — run setup first.")
creds["momCreds"]["refresh_token"] = new_token

# ── Re-encrypt ────────────────────────────────────────────────────────────────
print("Re-encrypting...")
blob, salt, iv = encrypt(creds)
app_config["encryptedBlob"] = blob
app_config["salt"]          = salt
app_config["iv"]            = iv

new_config_str = json.dumps(app_config, indent=2)

# ── Save locally ──────────────────────────────────────────────────────────────
with open(config_path, "w") as f:
    f.write(new_config_str)
print("Local config.json updated.")

# ── Save to Gist ──────────────────────────────────────────────────────────────
pat = creds["gh_pat"]
print("Saving config.json to Gist...")
try:
    patch_gist(gist_id, pat, "config.json", new_config_str)
    print("config.json Gist updated.")
except Exception as e:
    print(f"config.json Gist update failed ({e})")
    print("Local config.json is saved — commit and push it to deploy.")

# ── Also update mom.json creds.refresh_token on the Gist ─────────────────────
print("Updating mom.json on Gist...")
try:
    req = urllib.request.Request(
        f"https://api.github.com/gists/{gist_id}",
        headers={"Authorization": f"token {pat}", "Accept": "application/vnd.github+json"},
    )
    gist = json.loads(urllib.request.urlopen(req).read())
    if "mom.json" in gist["files"]:
        mom_data = json.loads(gist["files"]["mom.json"]["content"])
        old_mom_token = mom_data.get("creds", {}).get("refresh_token", "")
        print(f"  mom.json old token: {old_mom_token[:16]}...")
        mom_data.setdefault("creds", {})["refresh_token"] = new_token
        patch_gist(gist_id, pat, "mom.json", json.dumps(mom_data, indent=2))
        print("mom.json Gist updated.")
    else:
        print("mom.json not found in Gist — skipping.")
except Exception as e:
    print(f"mom.json Gist update failed ({e})")

print("Done.")
