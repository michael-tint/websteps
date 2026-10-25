"""
authorize_google.py — OAuth flow to get a new Google Health refresh token.

    python authorize_google.py [me|mom]      (default: me)

Fitbit's Web API is turned off on 2026-11-02; each account's data moves to
Google Health when that account re-consents, and its new data stops appearing
in the legacy Fitbit API from then on. Every user therefore needs their own
Google consent — sign in as THAT person's Google account in the browser window
this opens. `me` is stored as googleCreds (weight + steps), `mom` as
momGoogleCreds (steps only; mom has no weight data).

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
import base64, json, os, sys, urllib.error, urllib.parse, urllib.request, webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_dir = os.path.dirname(os.path.abspath(__file__))
PASSWORD = b"websteps123"
ITERS    = 100_000

# Ask only for what this user's data needs. Google Health rejects an access
# token carrying a disallowed scope (403 DISALLOWED_OAUTH_SCOPES) — the old
# token's legacy fitness.body.read is what broke weight — so the fetchers
# narrow the grant again per request (RFC 6749 §6). Asking for both here is
# safe because of that narrowing.
METRICS_SCOPE  = "https://www.googleapis.com/auth/googlehealth.health_metrics_and_measurements.readonly"
ACTIVITY_SCOPE = "https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly"

USER = (sys.argv[1] if len(sys.argv) > 1 else "me").lower()
if USER not in ("me", "mom"):
    print(f"Unknown user {USER!r}. Usage: python authorize_google.py [me|mom]")
    exit(1)
# mom has no weight data, ever — steps only.
SCOPES   = " ".join([ACTIVITY_SCOPE] if USER == "mom" else [METRICS_SCOPE, ACTIVITY_SCOPE])
CRED_KEY = "googleCreds" if USER == "me" else f"{USER}GoogleCreds"

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
# The OAuth client is the app, shared by both users; only the account that
# consents in the browser differs. Fall back to me's client for a first-time
# mom run, which has no momGoogleCreds yet.
google = creds.get(CRED_KEY) or creds.get("googleCreds") or {}
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
print(f"Authorizing {USER} -> {CRED_KEY}")
print(f"Using client_id: {CLIENT_ID}")
print(f"Scopes requested: {SCOPES}")
print("")
print(f">>> Sign in as {USER.upper()}'s Google account in the browser window. <<<")
print("")

# ── Build auth URL and open browser ───────────────────────────────────────────
REDIRECT_URI = "http://localhost:8080"

auth_url = (
    "https://accounts.google.com/o/oauth2/v2/auth"
    f"?response_type=code"
    f"&client_id={urllib.parse.quote(CLIENT_ID)}"
    f"&redirect_uri={urllib.parse.quote(REDIRECT_URI)}"
    f"&scope={urllib.parse.quote(SCOPES)}"
    # offline + consent together are what actually return a refresh_token;
    # without prompt=consent Google reissues access tokens only. select_account
    # forces the chooser: the default browser is already signed in as me, and
    # without it Google consents as whoever is already signed in and files the
    # token under the other user's key with nothing looking wrong.
    f"&access_type=offline"
    f"&prompt={urllib.parse.quote('select_account consent')}"
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

print("")
print("Opening your default browser. Pick " + USER.upper() + "'s Google account in")
print("the chooser - 'Use another account' if it is not listed.")
print("")
print("To use a private window instead (cleanest when the browser is already")
print("signed in as someone else), paste this URL into it:")
print("")
print(f"  {auth_url}")
print("")
print("Either way it must be a browser on THIS machine - the redirect goes to")
print("http://localhost:8080, which this script is listening on.")
print("")
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
creds.setdefault(CRED_KEY, {})
creds[CRED_KEY]["client_id"]     = CLIENT_ID
creds[CRED_KEY]["client_secret"] = CLIENT_SECRET
creds[CRED_KEY]["refresh_token"] = new_token
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
