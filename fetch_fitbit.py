"""
fetch_fitbit.py — refresh Fitbit token and sync weight data into weight_data.json
Refresh token is stored in fitbit_refresh_token.txt (committed to repo).
"""
import json, os, urllib.request, urllib.parse, base64
from datetime import date

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

# Save new refresh token back to file
with open("fitbit_refresh_token.txt", "w") as f:
    f.write(tokens["refresh_token"])
print("Refresh token rotated.")

# 2. Fetch weight logs (last 1 year)
url = f"https://api.fitbit.com/1/user/-/body/log/weight/date/{date.today().strftime('%Y-%m-%d')}/1y.json"
print(f"Fetching: {url}")
req = urllib.request.Request(url, headers={"Authorization": f"Bearer {access_token}"})
try:
    data = json.loads(urllib.request.urlopen(req).read())
except urllib.error.HTTPError as e:
    print(f"Weight fetch failed — HTTP {e.code}: {e.read().decode()}")
    raise
logs = data.get("weight", [])

# 3. Load existing weight_data.json
with open("weight_data.json", "r") as f:
    weight_data = json.load(f)

# 4. Merge — last log per day wins
for log in logs:
    d = log["date"]
    if d not in weight_data:
        weight_data[d] = {}
    weight_data[d]["weight_fitbit"] = round(log["weight"], 1)

# 5. Save
with open("weight_data.json", "w") as f:
    json.dump(weight_data, f, indent=2)

print(f"Synced {len(logs)} Fitbit weight entries")
