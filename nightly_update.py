"""
nightly_update.py — headless version of the dashboard's Update button.

Runs in GitHub Actions on a schedule. For each user (me, mom):
  1. Read the live config from the Gist and decrypt it (password from
     WEBSTEPS_PASSWORD env var).
  2. Refresh the Fitbit token (rotates the one-time-use refresh token). Once
     Fitbit's API is gone this just fails and the run goes on without it.
  3. Fetch activity / heart rate from Fitbit and from the Google Health API,
     and (for "me") weight from Google Health, then merge into {user}.json:
     steps take the higher count, other activity one source per day.
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


GOOGLE_HEALTH_SCOPE   = "https://www.googleapis.com/auth/googlehealth.health_metrics_and_measurements.readonly"
GOOGLE_ACTIVITY_SCOPE = "https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly"


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


def google_access_token(google_creds, scope):
    """Access token narrowed to one scope, or None. Google Health 403s a token
    carrying a scope it doesn't allow, so never ask for more than this call
    needs (RFC 6749 §6 narrowing, which Google honours)."""
    try:
        return http_json(
            "https://oauth2.googleapis.com/token",
            data=urllib.parse.urlencode({
                "client_id": google_creds["client_id"],
                "client_secret": google_creds["client_secret"],
                "refresh_token": google_creds["refresh_token"],
                "grant_type": "refresh_token",
                "scope": scope,
            }).encode(),
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )["access_token"]
    except urllib.error.HTTPError as e:
        print(f"  google token refresh failed: HTTP {e.code}: {e.read().decode()}")
        return None


def google_daily_rollup(access, data_type, start, end):
    """{'YYYY-MM-DD': rollup point} for [start, end] inclusive, or None if the
    fetch failed. dailyRollUp buckets by civil (local wall-clock) date, which is
    how records are keyed, and reconciles DST and timezone moves server-side.
    The caller keeps the range within the type's cap: 90 days for most, 14 for
    total-calories and active-minutes."""
    civil = lambda d, h, m, sec: {"date": {"year": d.year, "month": d.month, "day": d.day},
                                  "time": {"hours": h, "minutes": m, "seconds": sec}}
    body = {"range": {"start": civil(start, 0, 0, 0), "end": civil(end, 23, 59, 59)},
            "windowSizeDays": 1}

    by_date, page_token = {}, ""
    while True:
        payload = dict(body, pageToken=page_token) if page_token else body
        try:
            page = http_json(
                f"https://health.googleapis.com/v4/users/me/dataTypes/{data_type}/dataPoints:dailyRollUp",
                data=json.dumps(payload).encode(), method="POST",
                headers={"Authorization": f"Bearer {access}", "Content-Type": "application/json"})
        except urllib.error.HTTPError as e:
            print(f"  google health {data_type} fetch failed: HTTP {e.code}: {e.read().decode()}")
            return None
        for pt in page.get("rollupDataPoints", []):
            cd = (pt.get("civilStartTime") or {}).get("date")
            if cd:
                by_date[f"{cd['year']:04d}-{cd['month']:02d}-{cd['day']:02d}"] = pt
        page_token = page.get("nextPageToken") or ""
        if not page_token:
            return by_date


def fetch_google_steps(google_creds, start, end):
    """{'YYYY-MM-DD': steps} for [start, end] inclusive, or None if the fetch
    failed — so the caller can tell "walked nowhere" from "the fetch broke".

    Replaces Fitbit's activities/steps time series, which stops serving a user
    once their account migrates to Google Health and dies outright 2026-11-02.
    """
    access = google_access_token(google_creds, GOOGLE_ACTIVITY_SCOPE)
    if not access:
        return None
    start = max(start, end - timedelta(days=89))   # the API caps a rollup range at 90 days
    points = google_daily_rollup(access, "steps", start, end)
    if points is None:
        return None
    return {d: int(p["steps"]["countSum"]) for d, p in points.items()
            if (p.get("steps") or {}).get("countSum") is not None}   # countSum is a string


ACTIVITY_LEVELS = {"LIGHT": "lightlyActiveMinutes", "MODERATE": "fairlyActiveMinutes",
                   "VIGOROUS": "veryActiveMinutes"}


def fetch_google_activity(google_creds, start, end):
    """{'YYYY-MM-DD': {field: value}} for the activity fields Fitbit used to
    supply, read from Google Health; None if no token could be had.

    The fields mean what Fitbit's did (total calories, light/moderate/vigorous
    minutes, sedentary as the rest of the day's 1440, floors, elevation in
    feet), checked day for day against Fitbit, with two exceptions.
    activityCalories is Google's active energy, which leaves out the basal burn
    Fitbit counted, so it runs about half Fitbit's figure; caloriesBMR has no
    Google source at all and isn't set. A zero is None, so it shows as blank
    the way Fitbit's unreported zeros do, and clears a stale value on merge.
    Resting heart rate needs the health-metrics scope; an account consented
    without it goes without.
    """
    access = google_access_token(google_creds, GOOGLE_ACTIVITY_SCOPE)
    if not access:
        return None
    start = max(start, end - timedelta(days=13))   # calories and active minutes cap a rollup at 14 days
    out = {}

    def put(d, field, v):
        if not v and field != "floors":   # Fitbit stored a zero floor count, but no other zero
            v = None
        else:
            v = int(v) if v == int(v) else round(v, 1)
        out.setdefault(d, {})[field] = v

    for d, p in (google_daily_rollup(access, "total-calories", start, end) or {}).items():
        put(d, "caloriesOut", int((p.get("totalCalories") or {}).get("kcalSum", 0)))
    for d, p in (google_daily_rollup(access, "active-energy-burned", start, end) or {}).items():
        put(d, "activityCalories", int((p.get("activeEnergyBurned") or {}).get("kcalSum", 0)))
    for d, p in (google_daily_rollup(access, "active-minutes", start, end) or {}).items():
        levels = {lv.get("activityLevel"): int(lv.get("activeMinutesSum", 0))
                  for lv in (p.get("activeMinutes") or {}).get("activeMinutesRollupByActivityLevel", [])}
        for level, field in ACTIVITY_LEVELS.items():
            put(d, field, levels.get(level, 0))
        put(d, "sedentaryMinutes", 1440 - sum(levels.get(level, 0) for level in ACTIVITY_LEVELS))
    for d, p in (google_daily_rollup(access, "floors", start, end) or {}).items():
        put(d, "floors", int((p.get("floors") or {}).get("countSum", 0)))
    for d, p in (google_daily_rollup(access, "altitude", start, end) or {}).items():
        put(d, "elevation", int((p.get("altitude") or {}).get("gainMillimetersSum", 0)) / 304.8)

    hr_access = google_access_token(google_creds, GOOGLE_HEALTH_SCOPE)
    if hr_access:
        flt = (f'daily_resting_heart_rate.date >= "{start}" AND '
               f'daily_resting_heart_rate.date < "{end + timedelta(days=1)}"')
        page_token = ""
        while True:
            params = {"pageSize": "100", "filter": flt, **({"pageToken": page_token} if page_token else {})}
            try:
                page = http_json("https://health.googleapis.com/v4/users/me/dataTypes/daily-resting-heart-rate/dataPoints?"
                                 + urllib.parse.urlencode(params), headers={"Authorization": f"Bearer {hr_access}"})
            except urllib.error.HTTPError as e:
                print(f"  google health resting heart rate fetch failed: HTTP {e.code}: {e.read().decode()}")
                break
            for p in page.get("dataPoints", []):
                rhr = p.get("dailyRestingHeartRate") or {}
                cd, bpm = rhr.get("date"), rhr.get("beatsPerMinute")
                if cd and bpm:
                    out.setdefault(f"{cd['year']:04d}-{cd['month']:02d}-{cd['day']:02d}", {})["restingHeartRate"] = int(bpm)
            page_token = page.get("nextPageToken") or ""
            if not page_token:
                break
    return out


def active_minutes(fields):
    return sum(fields.get(f) or 0 for f in ACTIVITY_LEVELS.values())


def fitbit_fields(live, stored, google_steps, google_active):
    """Fitbit's activity fields for a day, or None when it has nothing real.

    Fitbit's figures stand where it tracked the day at least as fully as
    Google did. A migrated account gets only placeholders from it (0 steps or
    a few dozen, BMR-only calories, 1440 sedentary minutes), which fall short
    and so count as blank. While Fitbit answers, the test is its step count;
    once it stops, a day it filled before is judged by the stored active
    minutes (stored steps are already the higher of the two sources), and
    Google's own earlier figures count as blank so they refresh.
    """
    if live is not None:
        steps = live.get("steps", 0)
        return live if steps > 0 and steps >= google_steps else None
    if not stored or stored.get("activitySource") == "google":
        return None
    active = active_minutes(stored)
    return stored if active > 0 and active >= google_active else None


def refresh_fitbit(creds):
    """Fitbit access token, rotating creds' one-time refresh token; None when
    Fitbit won't sign in. Expected once its API is turned off, and no reason
    to stop the Google Health fetches, which carry the update from then on."""
    if not (creds and creds.get("client_id")):
        return None
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
        print(f"  fitbit token refresh failed: HTTP {e.code}: {e.read().decode()}")
        return None
    except urllib.error.URLError as e:
        print(f"  fitbit token refresh failed: {e.reason}")
        return None
    creds["refresh_token"] = tokens["refresh_token"]
    return tokens["access_token"]


def update_user(user, creds, records, google_creds=None):
    """Fetch from Fitbit and Google Health, merge into records. Mutates creds
    (a rotated Fitbit token) and records. False only if neither source could
    be reached."""
    access = refresh_fitbit(creds)

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

    if access:
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
    live = {d: dict(f) for d, f in by_date.items()}   # Fitbit's own figures, before anything merges in

    # Weight comes from Google Health, not Fitbit — the scale stopped feeding
    # Fitbit's weight log on 2026-08-03. An account with no scale just has no
    # weigh-ins. The 30-day window matches the old Fitbit fetch so a run of
    # missed days backfills itself instead of only ever catching the last week.
    if google_creds:
        weights = fetch_google_weights(google_creds, today - timedelta(days=30), today)
        if weights is None:
            print("  weight unavailable this run; activity still merged")
        for d, w in (weights or {}).items():
            cur = by_date.get(d, {}).get("weight")
            if cur is None or w < cur:
                by_date.setdefault(d, {})["weight"] = w

    gsteps = gactivity = None
    if google_creds:
        gsteps = fetch_google_steps(google_creds, start, yesterday)
        gactivity = fetch_google_activity(google_creds, start, yesterday)
        if gsteps is None:
            print("  google steps unavailable this run; keeping Fitbit's figures")
        else:
            print(f"  google health: {len(gsteps)} day(s) of steps, {len(gactivity or {})} of activity")

        # Activity fields: Fitbit's where it has them, Google's in the blanks,
        # and the whole day Google's when Fitbit has nothing real for it.
        by_rec = {r["date"]: r for r in records}
        for d, gfields in (gactivity or {}).items():
            fb = fitbit_fields(live.get(d), by_rec.get(d), (gsteps or {}).get(d, 0), active_minutes(gfields))
            if fb is None:
                by_date.setdefault(d, {}).update(gfields, activitySource="google")
            else:
                blanks = {k: v for k, v in gfields.items() if fb.get(k) is None}
                by_date.setdefault(d, {}).update(blanks, activitySource="fitbit")

        # Steps: keep the higher of Fitbit's and Google Health's count. Fitbit's
        # is the watch's own daily total, the figure the Google Health app
        # shows. Google Health only serves the per-minute records, which drop
        # steps (a minute mid-walk reads ~0) and run up to a few percent short.
        # Fitbit serves a migrated account nothing but zeros and is turned off
        # 2026-11-02, so there Google's count wins on its own. A day Fitbit
        # didn't answer for this run is held to its stored count instead.
        for d, n in (gsteps or {}).items():
            fitbit = live[d].get("steps", 0) if d in live else (by_rec.get(d) or {}).get("steps") or 0
            by_date.setdefault(d, {})["steps"] = max(n, fitbit)

    if access is None and gsteps is None and gactivity is None:
        return False
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

    results, payload, rotated = {}, {}, set()
    for user, creds_key in (("me", "meCreds"), ("mom", "momCreds")):
        print(f"Updating {user}…")
        creds = cfg.get(creds_key)
        google_creds = cfg.get("googleCreds" if user == "me" else f"{user}GoogleCreds")
        if not (creds or {}).get("client_id") and not google_creds:
            print(f"  no credentials for {user}, skipping")
            results[user] = False
            continue
        records = load_records(f"{user}.json")
        token_before = (creds or {}).get("refresh_token")
        results[user] = update_user(user, creds, records, google_creds)
        if creds and creds.get("refresh_token") != token_before:
            rotated.add(creds_key)
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
        for creds_key in rotated:
            if creds_key in fresh_cfg:
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
