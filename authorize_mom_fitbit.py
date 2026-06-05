"""
authorize_mom_fitbit.py — OAuth flow for mom's Fitbit account using
client_id/secret from the encrypted config.json (momCreds).

Opens the browser, waits for OAuth redirect on localhost:8080.
Updates the encrypted config.json (single source of truth).
"""
import base64, json, os, urllib.request, urllib.parse, webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_dir = os.path.dirname(os.path.abspath(__file__))
PASSWORD = b"websteps123"
ITERS    = 100_000

def derive_key(salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERS)
    return kdf.derive(PASSWORD)

def decrypt(blob_b64, salt_b64, iv_b64):
    key   = derive_key(base64.b64decode(salt_b64))
    plain = AESGCM(key).decrypt(base64.b64decode(iv_b64), base64.b64decode(blob_b64), None)
    return json.loads(plain)

def encrypt(data):
    salt = os.urandom(16)
    iv   = os.urandom(12)
    key  = derive_key(salt)
    blob = AESGCM(key).encrypt(iv, json.dumps(data).encode(), None)
    return base64.b64encode(blob).decode(), base64.b64encode(salt).decode(), base64.b64encode(iv).decode()

def patch_gist(gist_id, pat, filename, content):
    body = json.dumps({"files": {filename: {"content": content}}}).encode()
    req  = urllib.request.Request(
        f"https://api.github.com/gists/{gist_id}",
        data=body, method="PATCH",
        headers={"Authorization": f"token {pat}", "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json"},
    )
    urllib.request.urlopen(req)

# ── Load + decrypt config ──────────────────────────────────────────────────────
config_path = os.path.join(_dir, "config.json")
with open(config_path) as f:
    app_config = json.load(f)

gist_id = app_config["gistId"]
try:
    req  = urllib.request.Request(f"https://api.github.com/gists/{gist_id}",
                                  headers={"Accept": "application/vnd.github+json"})
    gist = json.loads(urllib.request.urlopen(req).read())
    if "config.json" in gist["files"]:
        app_config = {**app_config, **json.loads(gist["files"]["config.json"]["content"])}
        print("Loaded config from Gist.")
except Exception as e:
    print(f"Could not fetch Gist config ({e}), using local.")

creds = decrypt(app_config["encryptedBlob"], app_config["salt"], app_config["iv"])
mom   = creds.get("momCreds", {})
client_id     = mom["client_id"]
client_secret = mom["client_secret"]
pat           = creds["gh_pat"]
print(f"Using mom client_id: {client_id}")

# ── Build auth URL and open browser ───────────────────────────────────────────
REDIRECT_URI = "http://localhost:8080"
SCOPES       = "activity heartrate weight profile"

auth_url = (
    "https://www.fitbit.com/oauth2/authorize"
    f"?response_type=code"
    f"&client_id={client_id}"
    f"&scope={urllib.parse.quote(SCOPES)}"
    f"&redirect_uri={urllib.parse.quote(REDIRECT_URI)}"
    f"&expires_in=604800"
    f"&prompt=login"
)

code_holder = [None]

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        code_holder[0] = params.get("code", [None])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h2>Authorized! You can close this tab.</h2>")
    def log_message(self, fmt, *args):
        pass

server = HTTPServer(("", 8080), Handler)
t = Thread(target=server.handle_request)
t.start()

print("\nOpening browser for mom's Fitbit authorization...")
webbrowser.open(auth_url)
print("Waiting for redirect...")
t.join()
server.server_close()

if not code_holder[0]:
    print("No code received.")
    exit(1)

code = code_holder[0]
print(f"Got code: {code[:16]}...")

# ── Exchange code for tokens ──────────────────────────────────────────────────
print("Exchanging for tokens...")
auth_header = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
req = urllib.request.Request(
    "https://api.fitbit.com/oauth2/token",
    data=urllib.parse.urlencode({
        "grant_type":   "authorization_code",
        "code":         code,
        "redirect_uri": REDIRECT_URI,
    }).encode(),
    headers={"Authorization": f"Basic {auth_header}", "Content-Type": "application/x-www-form-urlencoded"},
)
try:
    tokens = json.loads(urllib.request.urlopen(req).read())
except urllib.error.HTTPError as e:
    print(f"Token exchange failed - HTTP {e.code}: {e.read().decode()}")
    exit(1)

new_token = tokens["refresh_token"]
print(f"New token: {new_token[:16]}...")
print(f"Scopes granted: {tokens.get('scope', 'unknown')}")

# ── Update encrypted config on Gist only (single source of truth) ────────────
creds["momCreds"]["refresh_token"] = new_token
blob, salt, iv = encrypt(creds)
app_config["encryptedBlob"] = blob
app_config["salt"]          = salt
app_config["iv"]            = iv
new_config_str = json.dumps(app_config, indent=2)

try:
    patch_gist(gist_id, pat, "config.json", new_config_str)
    print("config.json Gist updated.")
except Exception as e:
    print(f"config.json Gist update failed ({e})")

print("Done.")
