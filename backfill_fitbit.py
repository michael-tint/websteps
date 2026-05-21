"""
backfill_fitbit.py — bulk-fill me.json using Fitbit time series endpoints.

Steps:
  1. Seed all dates from weight_data.json into me.json["data"]
  2. Backfill Fitbit activity from ACTIVITY_START to today
  3. Backfill Fitbit weight from the earliest weight_data.json date to today

Credentials are read from the encrypted config.json (single source of truth).
"""
import json, os, sys, urllib.request, urllib.parse, base64
from datetime import date, timedelta

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_dir     = os.path.dirname(os.path.abspath(__file__))
_me_file = os.path.join(_dir, "me.json")
_wt_file = os.path.join(_dir, "weight_data.json")

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

# ── Load config.json and decrypt credentials ─────────────────────────────────
config_path = os.path.join(_dir, "config.json")
with open(config_path) as f:
    app_config = json.load(f)

print("Decrypting config.json for credentials...")
decrypted = decrypt_config(app_config["encryptedBlob"], app_config["salt"], app_config["iv"])
_creds        = decrypted["meCreds"]
client_id     = _creds["client_id"]
client_secret = _creds["client_secret"]

# ── Load data files ──────────────────────────────────────────────────────────
with open(_me_file) as f:
    _me = json.load(f)
with open(_wt_file) as f:
    weight_data = json.load(f)

# Normalize: keep only data
_data = _me.get("data", _me if isinstance(_me, list) else [])
if not isinstance(_data, list):
    _data = []
_me = {"data": _data}

TODAY          = date.today()
ACTIVITY_START = date(2025, 1, 1)
WEIGHT_START   = date.fromisoformat(sorted(weight_data.keys())[0])

print(f"Activity backfill: {ACTIVITY_START} to {TODAY}")
print(f"Weight backfill:   {WEIGHT_START} to {TODAY}")

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
decrypted["meCreds"]["refresh_token"] = tokens["refresh_token"]
blob, salt, iv = encrypt_config(decrypted)
app_config["encryptedBlob"] = blob
app_config["salt"]          = salt
app_config["iv"]            = iv
with open(config_path, "w") as f:
    f.write(json.dumps(app_config, indent=2))
print("Refresh token rotated (config.json).\n")


def fitbit_get(url, skip_errors=False):
    req = urllib.request.Request(url, headers={
        "Authorization":   f"Bearer {access_token}",
        "Accept-Language": "en_US",
    })
    try:
        resp = urllib.request.urlopen(req)
        data = json.loads(resp.read())
        remaining = resp.headers.get("Fitbit-Rate-Limit-Remaining", "?")
        print(f"  {url.split('fitbit.com')[1]} -> OK | remaining: {remaining}/150")
        return data
    except urllib.error.HTTPError as e:
        msg = f"  {url.split('fitbit.com')[1]} -> HTTP {e.code}: {e.read().decode()}"
        if skip_errors:
            print(f"  WARNING (skipping): {msg}")
            return {}
        print(msg)
        raise


def date_chunks(start, end, max_days):
    cur = start
    while cur <= end:
        chunk_end = min(cur + timedelta(days=max_days - 1), end)
        yield cur, chunk_end
        cur = chunk_end + timedelta(days=1)


# ── Step 1: seed all dates from weight_data.json ─────────────────────────────
print("Step 1: seeding dates from weight_data.json...")
records = _me["data"]
existing_dates = {r["date"] for r in records}
inserted = 0
for d in sorted(weight_data.keys()):
    if d not in existing_dates:
        records.append({"date": d})
        inserted += 1
records.sort(key=lambda r: r["date"])
print(f"  Inserted {inserted} new date stubs ({len(records)} total records)")
with open(_me_file, "w") as f:
    json.dump(_me, f, indent=2)
print("  Saved.\n")


# ── collect Fitbit data into flat dict ───────────────────────────────────────
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


# ── Step 2: backfill activity from 2025-01-01 ────────────────────────────────
print("Step 2: fetching activity time series (2025-01-01 to today)...")

TIMESERIES_METRICS = [
    ("steps",               "steps"),
    ("calories",            "caloriesOut"),
    ("caloriesBMR",         "caloriesBMR"),
    ("floors",              "floors"),
    ("elevation",           "elevation"),
    ("minutesSedentary",    "sedentaryMinutes"),
    ("minutesLightlyActive","lightlyActiveMinutes"),
    ("minutesFairlyActive", "fairlyActiveMinutes"),
    ("minutesVeryActive",   "veryActiveMinutes"),
]

for resource, field in TIMESERIES_METRICS:
    data = fitbit_get(
        f"https://api.fitbit.com/1/user/-/activities/{resource}/date/{ACTIVITY_START}/{TODAY}.json"
    )
    for entry in data.get(f"activities-{resource}", []):
        store(entry["dateTime"], field, entry["value"])

print("\nFetching activityCalories (30-day chunks)...")
for s, e in date_chunks(ACTIVITY_START, TODAY, 30):
    data = fitbit_get(
        f"https://api.fitbit.com/1/user/-/activities/activityCalories/date/{s}/{e}.json"
    )
    for entry in data.get("activities-activityCalories", []):
        store(entry["dateTime"], "activityCalories", entry["value"])

print("\nFetching resting heart rate (90-day chunks)...")
for s, e in date_chunks(ACTIVITY_START, TODAY, 90):
    data = fitbit_get(
        f"https://api.fitbit.com/1/user/-/activities/heart/date/{s}/{e}.json",
        skip_errors=True,
    )
    for entry in data.get("activities-heart", []):
        rhr = entry.get("value", {}).get("restingHeartRate")
        if rhr:
            store(entry["dateTime"], "restingHeartRate", rhr)


# ── Step 3: backfill Fitbit weight from earliest date ────────────────────────
print("\nStep 3: fetching Fitbit weight (31-day chunks)...")
for s, e in date_chunks(WEIGHT_START, TODAY, 31):
    weight_logs = fitbit_get(
        f"https://api.fitbit.com/1/user/-/body/log/weight/date/{s}/{e}.json",
        skip_errors=True,
    ).get("weight", [])
    for entry in weight_logs:
        d = entry["date"]
        w = round(float(entry["weight"]), 1)
        if "weight" not in by_date.get(d, {}) or w < by_date[d]["weight"]:
            by_date.setdefault(d, {})["weight"] = w


# ── merge into data ──────────────────────────────────────────────────────────
print(f"\nMerging into me.json...")
updated = 0
for record in records:
    d = record["date"]
    if d in by_date:
        record.update(by_date[d])
        updated += 1

records.sort(key=lambda r: r["date"])
with open(_me_file, "w") as f:
    json.dump(_me, f, indent=2)

print(f"Done. {updated} records updated, {len(records)} total in me.json.")
