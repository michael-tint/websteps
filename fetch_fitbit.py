"""
fetch_fitbit.py — fetch Fitbit data and upsert into me.json.
Window: 2 days before the last date with steps through yesterday, or last 7 days, whichever is larger.
Weight is fetched through today (so today's weigh-in is always captured).
Uses time series endpoints (same as backfill) to avoid permission issues with the daily summary endpoint.

Credentials are read from the encrypted config.json (single source of truth).
"""
import json, os, sys, urllib.request, urllib.parse, base64
from datetime import date, timedelta

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_dir    = os.path.dirname(os.path.abspath(__file__))
GIST_ID = os.environ.get("GIST_ID")
GH_PAT  = os.environ.get("GH_PAT")
_target = sys.argv[1] if len(sys.argv) > 1 else "me.json"
_me_file = os.path.join(_dir, _target)

PASSWORD = b"websteps123"
ITERS    = 100_000

def derive_key(salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERS)
    return kdf.derive(PASSWORD)

def decrypt_config(blob_b64, salt_b64, iv_b64):
    key   = derive_key(base64.b64decode(salt_b64))
    plain = AESGCM(key).decrypt(base64.b64decode(iv_b64), base64.b64decode(blob_b64), None)
    return json.loads(plain)

def encrypt_config(data):
    salt = os.urandom(16)
    iv   = os.urandom(12)
    key  = derive_key(salt)
    blob = AESGCM(key).encrypt(iv, json.dumps(data).encode(), None)
    return base64.b64encode(blob).decode(), base64.b64encode(salt).decode(), base64.b64encode(iv).decode()

def _gist_headers(pat=None):
    return {"Authorization": f"token {pat or GH_PAT}", "Accept": "application/vnd.github+json"}

def _patch_gist(gist_id, pat, files):
    body = json.dumps({"files": files}).encode()
    req = urllib.request.Request(
        f"https://api.github.com/gists/{gist_id}", data=body, method="PATCH",
        headers={**_gist_headers(pat), "Content-Type": "application/json"},
    )
    urllib.request.urlopen(req)

# ── Load config.json and decrypt credentials ─────────────────────────────────
config_path = os.path.join(_dir, "config.json")
with open(config_path) as f:
    app_config = json.load(f)

gist_id = app_config["gistId"]

# Prefer Gist config for latest rotated tokens
if GIST_ID and GH_PAT:
    try:
        req = urllib.request.Request(f"https://api.github.com/gists/{GIST_ID}", headers=_gist_headers())
        gist = json.loads(urllib.request.urlopen(req).read())
        if "config.json" in gist["files"]:
            app_config = {**app_config, **json.loads(gist["files"]["config.json"]["content"])}
            print("Loaded config from Gist.")
    except Exception as e:
        print(f"Could not fetch Gist config ({e}), using local.")

decrypted = decrypt_config(app_config["encryptedBlob"], app_config["salt"], app_config["iv"])
_creds_key = "momCreds" if _target == "mom.json" else "meCreds"
_creds = decrypted[_creds_key]
gh_pat = decrypted["gh_pat"]
client_id     = _creds["client_id"]
client_secret = _creds["client_secret"]
print(f"Loaded {_creds_key} from encrypted config.")

# ── Load user data (data only, no creds) ─────────────────────────────────────
if GIST_ID and GH_PAT:
    _me = json.loads(gist["files"][_target]["content"])
    print(f"Loaded {_target} from Gist.")
else:
    with open(_me_file) as f:
        _me = json.load(f)

# Normalize: strip any leftover creds block, keep only data
_data = _me.get("data", _me if isinstance(_me, list) else [])
if not isinstance(_data, list):
    _data = []
_me = {"data": _data}

# Find the most recent date with a numeric steps value
_records_with_steps = [
    r for r in _me["data"]
    if isinstance(r.get("steps"), (int, float)) and r["steps"] > 0
]
if _records_with_steps:
    _last_steps = date.fromisoformat(max(r["date"] for r in _records_with_steps))
else:
    _last_steps = date.today() - timedelta(days=7)

end_date   = date.today() - timedelta(days=1)
start_date = min(_last_steps - timedelta(days=2), date.today() - timedelta(days=7))
today      = date.today()
print(f"Last steps date: {_last_steps}  |  Updating {start_date} to {end_date} (weight through {today})")

# ── refresh access token ──────────────────────────────────────────────────────
refresh_token = _creds["refresh_token"]

_auth = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
req = urllib.request.Request(
    "https://api.fitbit.com/oauth2/token",
    data=urllib.parse.urlencode({
        "grant_type":    "refresh_token",
        "refresh_token": refresh_token,
    }).encode(),
    headers={
        "Authorization": f"Basic {_auth}",
        "Content-Type":  "application/x-www-form-urlencoded",
    },
)
try:
    tokens = json.loads(urllib.request.urlopen(req).read())
except urllib.error.HTTPError as e:
    print(f"Token refresh failed - HTTP {e.code}: {e.read().decode()}")
    raise
access_token = tokens["access_token"]

# ── Rotate refresh token → save to encrypted config.json only ────────────────
decrypted[_creds_key]["refresh_token"] = tokens["refresh_token"]
blob, salt, iv = encrypt_config(decrypted)
app_config["encryptedBlob"] = blob
app_config["salt"]          = salt
app_config["iv"]            = iv
config_str = json.dumps(app_config, indent=2)

with open(config_path, "w") as f:
    f.write(config_str)

if GIST_ID and GH_PAT:
    _patch_gist(GIST_ID, gh_pat, {"config.json": {"content": config_str}})
print("Refresh token rotated (config.json).")


def fitbit_get(url, skip_errors=False):
    req = urllib.request.Request(url, headers={
        "Authorization":   f"Bearer {access_token}",
        "Accept-Language": "en_US",
    })
    try:
        resp = urllib.request.urlopen(req)
        data = json.loads(resp.read())
        print(f"  {url.split('fitbit.com')[1]} -> OK | rate limit remaining: {resp.headers.get('Fitbit-Rate-Limit-Remaining','?')}/150")
        return data
    except urllib.error.HTTPError as e:
        msg = f"HTTP {e.code}: {e.read().decode()}"
        if skip_errors:
            print(f"  WARNING (skipping): {url.split('fitbit.com')[1]} -> {msg}")
            return {}
        print(f"  ERROR: {url.split('fitbit.com')[1]} -> {msg}")
        raise


by_date = {}

def store(date_str, key, raw_value):
    if raw_value is None:
        return
    try:
        v = int(raw_value)
    except (ValueError, TypeError):
        try:
            v = float(raw_value)
        except (ValueError, TypeError):
            return
    if v == 0 and key not in ("steps", "floors"):
        return
    by_date.setdefault(date_str, {})[key] = v


# ── activity via time series (one call per metric, through yesterday) ─────────
TIMESERIES_METRICS = [
    ("steps",               "steps"),
    ("calories",            "caloriesOut"),
    ("caloriesBMR",         "caloriesBMR"),
    ("activityCalories",    "activityCalories"),
    ("floors",              "floors"),
    ("elevation",           "elevation"),
    ("minutesSedentary",    "sedentaryMinutes"),
    ("minutesLightlyActive","lightlyActiveMinutes"),
    ("minutesFairlyActive", "fairlyActiveMinutes"),
    ("minutesVeryActive",   "veryActiveMinutes"),
]
for resource, field in TIMESERIES_METRICS:
    data = fitbit_get(
        f"https://api.fitbit.com/1/user/-/activities/{resource}/date/{start_date}/{end_date}.json",
        skip_errors=True,
    )
    for entry in data.get(f"activities-{resource}", []):
        store(entry["dateTime"], field, entry["value"])

# ── resting heart rate (through yesterday) ────────────────────────────────────
data = fitbit_get(
    f"https://api.fitbit.com/1/user/-/activities/heart/date/{start_date}/{end_date}.json",
    skip_errors=True,
)
for entry in data.get("activities-heart", []):
    rhr = entry.get("value", {}).get("restingHeartRate")
    if rhr:
        store(entry["dateTime"], "restingHeartRate", rhr)

# ── weight through today (so today's weigh-in is captured) ───────────────────
weight_logs = fitbit_get(
    f"https://api.fitbit.com/1/user/-/body/log/weight/date/{start_date}/{today}.json",
    skip_errors=True,
).get("weight", [])
for e in weight_logs:
    d = e["date"]
    w = round(float(e["weight"]), 1)
    if "weight" not in by_date.get(d, {}) or w < by_date[d]["weight"]:
        by_date.setdefault(d, {})["weight"] = w
print(f"Weight: {len(weight_logs)} entries")

# ── upsert into data ─────────────────────────────────────────────────────────
records = _me["data"]
for date_str, fields in by_date.items():
    existing = next((r for r in records if r.get("date") == date_str), None)
    if existing:
        existing.update(fields)
        print(f"Updated {date_str}")
    else:
        records.append({"date": date_str, **fields})
        print(f"Inserted {date_str}")

records.sort(key=lambda r: r["date"])

# ── Save data only (no creds) ────────────────────────────────────────────────
_save = {"data": records}
if GIST_ID and GH_PAT:
    _patch_gist(GIST_ID, gh_pat, {_target: {"content": json.dumps(_save, indent=2)}})
    print("Saved to Gist.")
else:
    with open(_me_file, "w") as f:
        json.dump(_save, f, indent=2)
    print("Done.")
