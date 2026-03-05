"""
fetch_fitbit.py — fetch Fitbit data and upsert into me.json.
Window: 2 days before the last date with steps through yesterday, or last 7 days, whichever is larger.
Weight is fetched through today (so today's weigh-in is always captured).
Uses time series endpoints (same as backfill) to avoid permission issues with the daily summary endpoint.
"""
import json, urllib.request, urllib.parse, base64
from datetime import date, timedelta

_me_file = os.path.join(os.path.dirname(__file__), "me.json")
with open(_me_file) as f:
    _me = json.load(f)
_creds = _me.get("creds", {})
client_id     = _creds["client_id"]
client_secret = _creds["client_secret"]

# Find the most recent date with a numeric steps value
_records_with_steps = [
    r for r in _me.get("data", [])
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

# Rotate refresh token back into me.json
_me["creds"]["refresh_token"] = tokens["refresh_token"]
with open(_me_file, "w") as f:
    json.dump(_me, f, indent=2)
print("Refresh token rotated.")


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

# ── upsert into me.json ───────────────────────────────────────────────────────
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

with open(_me_file, "w") as f:
    json.dump(_me, f, indent=2)
print("Done.")
