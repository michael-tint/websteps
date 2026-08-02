"""
nightly_update.py — headless version of the dashboard's Update button.

Runs in GitHub Actions on a schedule. For each user (me, mom):
  1. Read the live config from the Gist and decrypt it (password from
     WEBSTEPS_PASSWORD env var).
  2. Refresh the Fitbit token (rotates the one-time-use refresh token).
  3. Fetch activity / heart rate / weight and merge into {user}.json.
  4. Write the rotated tokens (re-encrypted config) and both data files
     back to the Gist in a single PATCH.

Mirrors updateFitbit() in index.html — keep the two in sync.
"""
import base64, json, os, sys, urllib.error, urllib.parse, urllib.request
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

GIST_ID  = os.environ.get("WEBSTEPS_GIST_ID", "b35c0da18a580453689ed280fa28c540")
PASSWORD = os.environ["WEBSTEPS_PASSWORD"].encode()
ITERS    = 100_000

METRICS = [
    ("steps", "steps"), ("calories", "caloriesOut"), ("caloriesBMR", "caloriesBMR"),
    ("activityCalories", "activityCalories"), ("floors", "floors"), ("elevation", "elevation"),
    ("minutesSedentary", "sedentaryMinutes"), ("minutesLightlyActive", "lightlyActiveMinutes"),
    ("minutesFairlyActive", "fairlyActiveMinutes"), ("minutesVeryActive", "veryActiveMinutes"),
]


def derive_key(salt):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERS).derive(PASSWORD)


def decrypt(blob_b64, salt_b64, iv_b64):
    key = derive_key(base64.b64decode(salt_b64))
    return json.loads(AESGCM(key).decrypt(base64.b64decode(iv_b64), base64.b64decode(blob_b64), None))


def encrypt(data):
    salt, iv = os.urandom(16), os.urandom(12)
    blob = AESGCM(derive_key(salt)).encrypt(iv, json.dumps(data).encode(), None)
    return (base64.b64encode(blob).decode(), base64.b64encode(salt).decode(), base64.b64encode(iv).decode())


def http_json(url, data=None, method="GET", headers=None):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def today_est():
    return datetime.now(ZoneInfo("America/New_York")).date()


def week_start(d):  # back to Sunday, same as gymWeekStart()
    dow = (d.weekday() + 1) % 7  # Mon=0 → Sun=0 scheme
    return (d - timedelta(days=dow)).isoformat()


def fitbit_get(url, access_token):
    try:
        return http_json(url, headers={"Authorization": f"Bearer {access_token}", "Accept-Language": "en_US"})
    except urllib.error.HTTPError as e:
        print(f"  fitbit GET {url} failed: HTTP {e.code}")
        return {}


def update_user(user, creds, records):
    """Refresh token, fetch data, merge into records. Mutates creds and records."""
    auth = base64.b64encode(f"{creds['client_id']}:{creds['client_secret']}".encode()).decode()
    try:
        tokens = http_json(
            "https://api.fitbit.com/oauth2/token",
            data=urllib.parse.urlencode({
                "grant_type": "refresh_token", "refresh_token": creds["refresh_token"],
            }).encode(),
            method="POST",
            headers={"Authorization": f"Basic {auth}", "Content-Type": "application/x-www-form-urlencoded"},
        )
    except urllib.error.HTTPError as e:
        print(f"  token refresh failed: HTTP {e.code}: {e.read().decode()}")
        return False
    creds["refresh_token"] = tokens["refresh_token"]
    access = tokens["access_token"]

    today = today_est()
    yesterday = today - timedelta(days=1)
    seven_ago = today - timedelta(days=7)
    with_steps = [r["date"] for r in records if r.get("steps", 0) > 0]
    if with_steps:
        two_before = date.fromisoformat(max(with_steps)) - timedelta(days=2)
        start = min(two_before, seven_ago)
    else:
        start = seven_ago

    by_date = {}

    def store(d, k, v):
        try:
            n = float(v)
        except (TypeError, ValueError):
            return
        if n == 0 and k not in ("steps", "floors"):
            return
        by_date.setdefault(d, {})[k] = int(n) if n == int(n) else round(n, 1)

    for resource, field in METRICS:
        data = fitbit_get(
            f"https://api.fitbit.com/1/user/-/activities/{resource}/date/{start}/{yesterday}.json", access)
        for e in data.get(f"activities-{resource}", []):
            store(e["dateTime"], field, e["value"])

    hr = fitbit_get(f"https://api.fitbit.com/1/user/-/activities/heart/date/{start}/{yesterday}.json", access)
    for e in hr.get("activities-heart", []):
        rhr = (e.get("value") or {}).get("restingHeartRate")
        if rhr:
            store(e["dateTime"], "restingHeartRate", rhr)

    wt = fitbit_get("https://api.fitbit.com/1/user/-/body/log/weight/date/today/30d.json", access)
    for e in wt.get("weight", []):
        w = round(float(e["weight"]), 1)
        cur = by_date.get(e["date"], {}).get("weight")
        if cur is None or w < cur:
            by_date.setdefault(e["date"], {})["weight"] = w

    by_date.setdefault(today.isoformat(), {})  # always create today's entry

    by_rec = {r["date"]: r for r in records}
    for d, fields in by_date.items():
        if d in by_rec:
            by_rec[d].update(fields)
            by_rec[d].setdefault("week", week_start(date.fromisoformat(d)))
        else:
            records.append({"date": d, "week": week_start(date.fromisoformat(d)), **fields})
    records.sort(key=lambda r: r["date"])
    print(f"  merged {len(by_date)} day(s), {len(records)} total records")
    return True


def main():
    gist = http_json(f"https://api.github.com/gists/{GIST_ID}",
                     headers={"Accept": "application/vnd.github+json"})
    files = gist["files"]
    app_config = json.loads(files["config.json"]["content"])
    cfg = decrypt(app_config["encryptedBlob"], app_config["salt"], app_config["iv"])
    pat = cfg["gh_pat"]

    def load_records(name):
        try:
            parsed = json.loads(files[name]["content"])
        except (KeyError, ValueError):
            return []
        return parsed.get("data", parsed if isinstance(parsed, list) else [])

    results, payload = {}, {}
    for user, creds_key in (("me", "meCreds"), ("mom", "momCreds")):
        print(f"Updating {user}…")
        creds = cfg.get(creds_key)
        if not creds or not creds.get("client_id"):
            print(f"  no credentials for {user}, skipping")
            results[user] = False
            continue
        records = load_records(f"{user}.json")
        results[user] = update_user(user, creds, records)
        if results[user]:
            payload[f"{user}.json"] = {"content": json.dumps({"data": records}, indent=2)}

    # Always save the config — a successful token refresh rotates the refresh
    # token even if a later fetch step failed, and losing it bricks the token.
    blob, salt, iv = encrypt(cfg)
    app_config.update(encryptedBlob=blob, salt=salt, iv=iv)
    payload["config.json"] = {"content": json.dumps(app_config, indent=2)}

    http_json(
        f"https://api.github.com/gists/{GIST_ID}",
        data=json.dumps({"files": payload}).encode(),
        method="PATCH",
        headers={"Authorization": f"token {pat}", "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json"},
    )
    print(f"Gist updated: {', '.join(sorted(payload))}")

    if not all(results.values()):
        failed = [u for u, ok in results.items() if not ok]
        print(f"FAILED for: {', '.join(failed)}")
        sys.exit(1)
    print("Done!")


if __name__ == "__main__":
    main()
