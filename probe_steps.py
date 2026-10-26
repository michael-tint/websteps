"""
probe_steps.py — compare Google Health's daily step totals with the raw step
records behind them, to find where the dashboard and the Google Health app
part ways. Read-only: nothing is written to the Gist or anywhere else.

    python probe_steps.py [me|mom] [YYYY-MM-DD ...]

Defaults to me and the last two full days (ET). For each day it prints the
dailyRollUp total (what the dashboard stores) next to the sum of the raw step
records, broken down by data source.
"""
import base64, json, os, sys, time, urllib.error, urllib.parse, urllib.request
from collections import defaultdict
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_dir     = os.path.dirname(os.path.abspath(__file__))
PASSWORD = os.environ.get("WEBSTEPS_PASSWORD", "websteps123").encode()
ITERS    = 100_000
ACTIVITY_SCOPE = "https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly"
API = "https://health.googleapis.com/v4/users/me/dataTypes/steps/dataPoints"

ARGS = sys.argv[1:]
USER = ARGS.pop(0).lower() if ARGS and ARGS[0].lower() in ("me", "mom") else "me"
today = datetime.now(ZoneInfo("America/New_York")).date()
DAYS = [date.fromisoformat(a) for a in ARGS] or [today - timedelta(days=2), today - timedelta(days=1)]


def http_json(url, data=None, method="GET", headers=None):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def decrypt(blob_b64, salt_b64, iv_b64):
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=base64.b64decode(salt_b64), iterations=ITERS).derive(PASSWORD)
    return json.loads(AESGCM(key).decrypt(base64.b64decode(iv_b64), base64.b64decode(blob_b64), None))


def load_config():
    """The live config from the Gist (API, then raw URL), else the repo copy."""
    with open(os.path.join(_dir, "config.json")) as f:
        local = json.load(f)
    gid, owner = local["gistId"], local.get("gistOwner", "michael-tint")
    sources = [
        ("Gist API", lambda: json.loads(http_json(
            f"https://api.github.com/gists/{gid}?cb={int(time.time())}",
            headers={"Accept": "application/vnd.github+json"})["files"]["config.json"]["content"])),
        ("Gist raw", lambda: http_json(
            f"https://gist.githubusercontent.com/{owner}/{gid}/raw/config.json?cb={int(time.time())}")),
    ]
    for name, fetch in sources:
        try:
            cfg = fetch()
            print(f"Config: {name}")
            return cfg
        except Exception as e:
            print(f"Config: {name} unavailable ({e})")
    print("Config: repo config.json (may be stale)")
    return local


def civil(d, h, m, s):
    return {"date": {"year": d.year, "month": d.month, "day": d.day},
            "time": {"hours": h, "minutes": m, "seconds": s}}


def iso(cd):
    return f"{cd['year']:04d}-{cd['month']:02d}-{cd['day']:02d}"


def rollup(access, start, end):
    """{'YYYY-MM-DD': steps} plus the raw points, exactly as nightly_update asks."""
    body = {"range": {"start": civil(start, 0, 0, 0), "end": civil(end, 23, 59, 59)}, "windowSizeDays": 1}
    out, raw, token = {}, [], ""
    while True:
        page = http_json(f"{API}:dailyRollUp", data=json.dumps(dict(body, pageToken=token) if token else body).encode(),
                         method="POST", headers={"Authorization": f"Bearer {access}", "Content-Type": "application/json"})
        for pt in page.get("rollupDataPoints", []):
            raw.append(pt)
            cd = (pt.get("civilStartTime") or {}).get("date")
            n = (pt.get("steps") or {}).get("countSum")
            if cd and n is not None:
                out[iso(cd)] = int(n)
        token = page.get("nextPageToken") or ""
        if not token:
            return out, raw


def raw_points(access, d):
    """Every step record whose civil start falls on day d."""
    flt = (f'steps.interval.civil_start_time >= "{d}" AND '
           f'steps.interval.civil_start_time < "{d + timedelta(days=1)}"')
    pts, token = [], ""
    while True:
        params = {"pageSize": "1000", "filter": flt}
        if token:
            params["pageToken"] = token
        page = http_json(f"{API}?{urllib.parse.urlencode(params)}", headers={"Authorization": f"Bearer {access}"})
        pts += page.get("dataPoints", [])
        token = page.get("nextPageToken") or ""
        if not token:
            return pts


def main():
    app_config = load_config()
    cfg = decrypt(app_config["encryptedBlob"], app_config["salt"], app_config["iv"])
    google = cfg.get("googleCreds" if USER == "me" else f"{USER}GoogleCreds")
    if not google:
        sys.exit(f"No Google credentials for {USER} in this config.")
    try:
        access = http_json("https://oauth2.googleapis.com/token", method="POST",
                           data=urllib.parse.urlencode({
                               "client_id": google["client_id"], "client_secret": google["client_secret"],
                               "refresh_token": google["refresh_token"], "grant_type": "refresh_token",
                               "scope": ACTIVITY_SCOPE}).encode(),
                           headers={"Content-Type": "application/x-www-form-urlencoded"})["access_token"]
    except urllib.error.HTTPError as e:
        sys.exit(f"Google token refresh failed: HTTP {e.code}: {e.read().decode()}")
    print(f"User: {USER}\n")

    # The nightly's own window, to see which days come back at all.
    start, end = min(DAYS) - timedelta(days=6), today - timedelta(days=1)
    try:
        totals, rraw = rollup(access, start, end)
    except urllib.error.HTTPError as e:
        sys.exit(f"dailyRollUp failed: HTTP {e.code}: {e.read().decode()}")
    print(f"dailyRollUp {start} .. {end}: {len(totals)} day(s) returned")
    for d in sorted(totals):
        print(f"  {d}  {totals[d]:>6}")
    if rraw:
        print("  first rollup point, raw:", json.dumps(rraw[0])[:600])
    print()

    for d in DAYS:
        print(f"── {d} ── dailyRollUp total: {totals.get(d.isoformat(), '(none)')}")
        try:
            pts = raw_points(access, d)
        except urllib.error.HTTPError as e:
            print(f"  raw records failed: HTTP {e.code}: {e.read().decode()[:400]}\n")
            continue
        by_src, total = defaultdict(int), 0
        for p in pts:
            n = int((p.get("steps") or {}).get("count", 0))
            total += n
            by_src[json.dumps(p.get("dataSource"), sort_keys=True)] += n
        print(f"  raw records: {len(pts)}, summing to {total}")
        for src, n in sorted(by_src.items(), key=lambda kv: -kv[1]):
            print(f"    {n:>6}  {src[:200]}")
        if pts:
            print("  first raw record:", json.dumps(pts[0])[:600])
        print()


if __name__ == "__main__":
    main()
