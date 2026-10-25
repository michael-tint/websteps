"""
authorize_google.py — OAuth flow to get a new Google Health refresh token.

Weight comes from the Google Health API (the scale stopped feeding Fitbit's
weight log on 2026-08-03). That refresh token is long-lived but not immortal:
when it is revoked or expires, every weight fetch returns
`invalid_grant: Token has been expired or revoked` and weight silently stops
updating while steps keep working. This script is the recovery path.

Reads client_id/secret from the encrypted config (googleCreds) and writes the
new refresh token back to the Gist, the single source of truth.

Requires http://localhost:8080 to be an authorized redirect URI on this OAuth
client in the Google Cloud console. If authorization fails with
`redirect_uri_mismatch`, add it there (APIs & Services -> Credentials -> the
client -> Authorized redirect URIs) and re-run.
"""
import base64, json, os, urllib.error, urllib.parse, urllib.request, webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_dir = os.path.dirname(os.path.abspath(__file__))
PASSWORD = b"websteps123"
ITERS    = 100_000

# Ask for the Health scope alone. The old token also carried the legacy
# fitness.body.read, and Google Health rejects any access token holding a Fit
# scope with 403 DISALLOWED_OAUTH_SCOPES.
SCOPES = "https://www.googleapis.com/auth/googlehealth.health_metrics_and_measurements.readonly"

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

creds  = decrypt(app_config["encryptedBlob"], app_config["salt"], app_config["iv"])
google = creds.get("googleCreds") or {}
# Bootstrap path: if googleCreds was wiped from the config (e.g. a stale browser
# tab wrote back a copy that never had it), the client_id/secret can be supplied
# via env vars from a freshly created Google Cloud OAuth client. Kept out of the
# repo — pass them on the command line:
#   GOOGLE_CLIENT_ID=… GOOGLE_CLIENT_SECRET=… python authorize_google.py
CLIENT_ID     = google.get("client_id")     or os.environ.get("GOOGLE_CLIENT_ID")
CLIENT_SECRET = google.get("client_secret") or os.environ.get("GOOGLE_CLIENT_SECRET")
if not CLIENT_ID or not CLIENT_SECRET:
    print("No Google OAuth client_id/client_secret in config or environment.\n"
          "Create an OAuth client in the Google Cloud console (with "
          "http://localhost:8080 as an authorized redirect URI), then re-run:\n"
          "  GOOGLE_CLIENT_ID=… GOOGLE_CLIENT_SECRET=… python authorize_google.py")
    exit(1)
pat           = creds["gh_pat"]
print(f"Using client_id: {CLIENT_ID}")

# ── Build auth URL and open browser ───────────────────────────────────────────
REDIRECT_URI = "http://localhost:8080"

auth_url = (
    "https://accounts.google.com/o/oauth2/v2/auth"
    f"?response_type=code"
    f"&client_id={urllib.parse.quote(CLIENT_ID)}"
    f"&redirect_uri={urllib.parse.quote(REDIRECT_URI)}"
    f"&scope={urllib.parse.quote(SCOPES)}"
    # offline + consent together are what actually return a refresh_token;
    # without prompt=consent Google reissues access tokens only.
    f"&access_type=offline"
    f"&prompt=consent"
    f"&include_granted_scopes=false"
)

code_holder, err_holder = [None], [None]

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        code_holder[0] = params.get("code", [None])[0]
        err_holder[0]  = params.get("error", [None])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        ok = code_holder[0] is not None
        self.wfile.write(b"<h2>Authorized! You can close this tab.</h2>" if ok
                         else b"<h2>Authorization failed. Check the terminal.</h2>")
    def log_message(self, fmt, *args):
        pass

server = HTTPServer(("", 8080), Handler)
t = Thread(target=server.handle_request)
t.start()

print("\nOpening browser for Google authorization...")
webbrowser.open(auth_url)
print("Waiting for redirect...")
t.join()
server.server_close()

if err_holder[0]:
    print(f"Authorization denied: {err_holder[0]}")
    exit(1)
if not code_holder[0]:
    print("No code received.")
    exit(1)

# ── Exchange code for tokens ──────────────────────────────────────────────────
print("Got code, exchanging for tokens...")
req = urllib.request.Request(
    "https://oauth2.googleapis.com/token",
    data=urllib.parse.urlencode({
        "code":          code_holder[0],
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri":  REDIRECT_URI,
        "grant_type":    "authorization_code",
    }).encode(),
    headers={"Content-Type": "application/x-www-form-urlencoded"},
)
try:
    tokens = json.loads(urllib.request.urlopen(req).read())
except urllib.error.HTTPError as e:
    print(f"Token exchange failed - HTTP {e.code}: {e.read().decode()}")
    exit(1)

new_token = tokens.get("refresh_token")
if not new_token:
    print("Google returned no refresh_token. Revoke this app's access at "
          "https://myaccount.google.com/permissions and run this again.")
    exit(1)
print(f"Scopes granted: {tokens.get('scope', 'unknown')}")

# ── Update encrypted config on Gist only (single source of truth) ────────────
# Re-read the Gist first: the browser flow above can take minutes, and another
# writer may have rotated a Fitbit token in the meantime. Writing the copy we
# read at startup would brick it.
try:
    req  = urllib.request.Request(f"https://api.github.com/gists/{gist_id}",
                                  headers={"Accept": "application/vnd.github+json"})
    gist = json.loads(urllib.request.urlopen(req).read())
    fresh_config = json.loads(gist["files"]["config.json"]["content"])
    creds        = decrypt(fresh_config["encryptedBlob"], fresh_config["salt"], fresh_config["iv"])
    app_config   = {**app_config, **fresh_config}
    print("Re-read fresh config from Gist before writing.")
except Exception as e:
    print(f"Could not re-read Gist ({e}); writing the config read at startup.")

# setdefault so a bootstrap run (googleCreds absent from the fresh config) also
# persists the client_id/secret, not just the refresh token.
creds.setdefault("googleCreds", {})
creds["googleCreds"]["client_id"]     = CLIENT_ID
creds["googleCreds"]["client_secret"] = CLIENT_SECRET
creds["googleCreds"]["refresh_token"] = new_token
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

print("Done!")
