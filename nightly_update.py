"""
nightly_update.py — headless version of the dashboard's Update button.

Runs in GitHub Actions on a schedule. For each user (me, mom):
  1. Read the live config from the Gist and decrypt it (password from
     WEBSTEPS_PASSWORD env var).
  2. Refresh the Fitbit token (rotates the one-time-use refresh token).
  3. Fetch activity / heart rate from Fitbit, and (for "me") weight from the
     Google Health API, then merge into {user}.json.
  4. Write the rotated tokens (re-encrypted config) and both data files
     back to the Gist in a single PATCH.

Mirrors updateFitbit() in index.html — keep the two in sync.
"""
import base64, json, os, sys, time, urllib.error, urllib.parse, urllib.request
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


GOOGLE_HEALTH_SCOPE = "https://www.googleapis.com/auth/googlehealth.health_metrics_and_measurements.readonly"


def fetch_google_weights(google_creds, start, end):
    """{'YYYY-MM-DD': lb} for [start, end] inclusive, or None if the fetch failed.

    The stored refresh token carries both the Google Health scope and the legacy
    fitness.body.read. Google Health rejects any access token holding a Fit scope
    with 403 DISALLOWED_OAUTH_SCOPES, so this narrows the grant to the Health
    scope alone (RFC 6749 §6). Without the `scope` field below, every weight
    fetch 403s and weight silently stops updating.
    """
    try:
        tokens = http_json(
            "https://oauth2.googleapis.com/token",
            data=urllib.parse.urlencode({
                "client_id": google_creds["client_id"],
                "client_secret": google_creds["client_secret"],
                "refresh_token": google_creds["refresh_token"],
                "grant_type": "refresh_token",
                "scope": GOOGLE_HEALTH_SCOPE,
            }).encode(),
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except urllib.error.HTTPError as e:
        print(f"  google token refresh failed: HTTP {e.code}: {e.read().decode()}")
        return None
    access = tokens["access_token"]

    # civil_time is the weigh-in's local wall-clock date, which is how records
    # are keyed; the upper bound is exclusive, so ask for the day after `end`.
    flt = (f'weight.sample_time.civil_time >= "{start}" AND '
           f'weight.sample_time.civil_time < "{end + timedelta(days=1)}"')
    by_date, page_token = {}, ""
    while True:
        params = {"pageSize": "200", "filter": flt}
        if page_token:
            params["pageToken"] = page_token
        url = ("https://health.googleapis.com/v4/users/me/dataTypes/weight/dataPoints?"
               + urllib.parse.urlencode(params))
        try:
            page = http_json(url, headers={"Authorization": f"Bearer {access}"})
        except urllib.error.HTTPError as e:
            print(f"  google health weight fetch failed: HTTP {e.code}: {e.read().decode()}")
            return None
        for p in page.get("dataPoints", []):
            w = p.get("weight") or {}
            cd = ((w.get("sampleTime") or {}).get("civilTime") or {}).get("date")
            if not cd or w.get("weightGrams") is None:
                continue
            iso = f"{cd['year']:04d}-{cd['month']:02d}-{cd['day']:02d}"
            lb = round(float(w["weightGrams"]) / 453.59237, 1)
            # Several points can share a day (re-weighs, duplicate sources);
            # keep the lowest, matching the old Fitbit weight merge.
            if iso not in by_date or lb < by_date[iso]:
                by_date[iso] = lb
        page_token = page.get("nextPageToken") or ""
        if not page_token:
            return by_date


def update_user(user, creds, records, google_creds=None):
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

    # Weight comes from Google Health, not Fitbit — the scale stopped feeding
    # Fitbit's weight log on 2026-08-03. Only "me" has a Google account. The
    # 30-day window matches the old Fitbit fetch so a run of missed days
    # backfills itself instead of only ever catching the last week.
    if google_creds:
        weights = fetch_google_weights(google_creds, today - timedelta(days=30), today)
        if weights is None:
            print("  weight unavailable this run; activity still merged")
        for d, w in (weights or {}).items():
            cur = by_date.get(d, {}).get("weight")
            if cur is None or w < cur:
                by_date.setdefault(d, {})["weight"] = w

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


def read_gist():
    """Live read. The `cb` param and no-cache header defeat any edge caching, so
    a token another writer stored seconds ago is never read stale."""
    return http_json(
        f"https://api.github.com/gists/{GIST_ID}?cb={int(time.time())}",
        headers={"Accept": "application/vnd.github+json", "Cache-Control": "no-cache"})


def main():
    gist = read_gist()
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
        results[user] = update_user(user, creds, records,
                                    cfg.get("googleCreds") if user == "me" else None)
        if results[user]:
            payload[f"{user}.json"] = {"content": json.dumps({"data": records}, indent=2)}

    # Re-read the Gist before writing. This run takes a while, and another
    # writer (the browser Update button, an authorize script) may have stored a
    # new token meanwhile — writing back the copy read at startup would silently
    # revert it. Only the Fitbit tokens this run actually rotated are carried
    # over; everything else, googleCreds included, comes from the fresh copy.
    try:
        fresh_app = json.loads(read_gist()["files"]["config.json"]["content"])
        fresh_cfg = decrypt(fresh_app["encryptedBlob"], fresh_app["salt"], fresh_app["iv"])
        for user, creds_key in (("me", "meCreds"), ("mom", "momCreds")):
            if results.get(user) and creds_key in fresh_cfg:
                fresh_cfg[creds_key]["refresh_token"] = cfg[creds_key]["refresh_token"]
        cfg, app_config = fresh_cfg, {**app_config, **fresh_app}
        print("Re-read fresh config from Gist before writing.")
    except Exception as e:
        print(f"Could not re-read Gist ({e}); writing the config read at startup.")

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
