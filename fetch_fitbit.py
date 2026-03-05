"""
fetch_fitbit.py — refresh Fitbit token, sync weight + activity data
Refresh token is stored in fitbit_refresh_token.txt (committed to repo).
"""
import json, os, urllib.request, urllib.parse, base64
from datetime import date, timedelta

client_id     = os.environ["FITBIT_CLIENT_ID"]
client_secret = os.environ["FITBIT_CLIENT_SECRET"]

# Read refresh token from file
with open("fitbit_refresh_token.txt") as f:
    refresh_token = f.read().strip()

# 1. Refresh the access token
creds = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
req = urllib.request.Request(
    "https://api.fitbit.com/oauth2/token",
    data=urllib.parse.urlencode({
        "grant_type":    "refresh_token",
        "refresh_token": refresh_token,
    }).encode(),
    headers={
        "Authorization": f"Basic {creds}",
        "Content-Type":  "application/x-www-form-urlencoded",
    },
)
try:
    tokens = json.loads(urllib.request.urlopen(req).read())
except urllib.error.HTTPError as e:
    print(f"Token refresh failed — HTTP {e.code}: {e.read().decode()}")
    raise
access_token = tokens["access_token"]

with open("fitbit_refresh_token.txt", "w") as f:
    f.write(tokens["refresh_token"])
print("Refresh token rotated.")

def fitbit_get(url):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {access_token}"})
    try:
        resp = urllib.request.urlopen(req)
        data = json.loads(resp.read())
        print(f"  {url.split('fitbit.com')[1]} → OK | rate limit remaining: {resp.headers.get('Fitbit-Rate-Limit-Remaining','?')}/150")
        return data
    except urllib.error.HTTPError as e:
        print(f"  {url.split('fitbit.com')[1]} → HTTP {e.code}: {e.read().decode()}")
        raise

TARGET = "2026-03-04"   # TODO: change to rolling window later

# 2. Fetch weight
KG_TO_LBS = 2.20462
weight_logs = fitbit_get(
    f"https://api.fitbit.com/1/user/-/body/log/weight/date/{TARGET}/{TARGET}.json"
).get("weight", [])

with open("weight_data.json", "r") as f:
    weight_data = json.load(f)

# Take the lowest weight for TARGET date from the API only
target_weights = [round(float(e["weight"]) * KG_TO_LBS, 1) for e in weight_logs if e["date"] == TARGET]
daily_weight = min(target_weights) if target_weights else None
if daily_weight is not None:
    if TARGET not in weight_data: weight_data[TARGET] = {}
    weight_data[TARGET]["weight_fitbit"] = daily_weight

with open("weight_data.json", "w") as f:
    json.dump(weight_data, f, indent=2)
print(f"Weight: synced {len(weight_logs)} entries, daily_weight={daily_weight}")

# 3. Fetch activity summary
try:
    summary = fitbit_get(
        f"https://api.fitbit.com/1/user/-/activities/date/{TARGET}.json"
    ).get("summary", {})
except Exception as e:
    print(f"Activity fetch failed ({e}) — skipping activity fields, weight_fitbit still synced")
    summary = {}

fitbit_fields = {
    "steps":                summary.get("steps"),
    "caloriesOut":          summary.get("caloriesOut"),
    "activityCalories":     summary.get("activityCalories"),
    "caloriesBMR":          summary.get("caloriesBMR"),
    "activeScore":          summary.get("activeScore"),
    "floors":               summary.get("floors"),
    "elevation":            summary.get("elevation"),
    "sedentaryMinutes":     summary.get("sedentaryMinutes"),
    "lightlyActiveMinutes": summary.get("lightlyActiveMinutes"),
    "fairlyActiveMinutes":  summary.get("fairlyActiveMinutes"),
    "veryActiveMinutes":    summary.get("veryActiveMinutes"),
    "marginalCalories":     summary.get("marginalCalories"),
    "restingHeartRate":     summary.get("restingHeartRate"),
    "weight_fitbit":        daily_weight,
}

with open("me.json", "r") as f:
    me_data = json.load(f)

existing = next((r for r in me_data if r.get("date") == TARGET), None)
if existing:
    existing.update({k: v for k, v in fitbit_fields.items() if v is not None})
else:
    me_data.append({"date": TARGET, **{k: v for k, v in fitbit_fields.items() if v is not None}})
    me_data.sort(key=lambda r: r["date"])

with open("me.json", "w") as f:
    json.dump(me_data, f, indent=2)
print(f"Activity: synced {TARGET} into me.json — {fitbit_fields.get('steps')} steps")
