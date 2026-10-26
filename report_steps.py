"""
report_steps.py — print daily steps from Fitbit and Google Health side by side
with what the Gist stores, for me and mom. Read-only for the data files; the
only write is the rotated Fitbit refresh tokens, which must be saved or the
nightly can no longer sign in.

    REPORT_SINCE=2026-10-01 WEBSTEPS_PASSWORD=… python report_steps.py

Runs in GitHub Actions (steps-report.yml, on a push to this branch),
because this needs api.fitbit.com.
"""
import json, os, sys
from datetime import date, timedelta

import nightly_update as N

SINCE = date.fromisoformat(os.environ.get("REPORT_SINCE", "2026-10-01"))
USERS = (("me", "meCreds", "googleCreds"), ("mom", "momCreds", "momGoogleCreds"))


def refresh_fitbit(creds):
    import base64, urllib.parse
    auth = base64.b64encode(f"{creds['client_id']}:{creds['client_secret']}".encode()).decode()
    tokens = N.http_json(
        "https://api.fitbit.com/oauth2/token",
        data=urllib.parse.urlencode({"grant_type": "refresh_token", "refresh_token": creds["refresh_token"]}).encode(),
        method="POST",
        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/x-www-form-urlencoded"})
    creds["refresh_token"] = tokens["refresh_token"]
    return tokens["access_token"]


def save_tokens(rotated):
    """Re-read the live config and carry over only the rotated Fitbit tokens."""
    app_config = json.loads(N.read_gist()["files"]["config.json"]["content"])
    cfg = N.decrypt(app_config["encryptedBlob"], app_config["salt"], app_config["iv"])
    for key, token in rotated.items():
        cfg[key]["refresh_token"] = token
    blob, salt, iv = N.encrypt(cfg)
    app_config.update(encryptedBlob=blob, salt=salt, iv=iv)
    N.http_json(
        f"https://api.github.com/gists/{N.GIST_ID}",
        data=json.dumps({"files": {"config.json": {"content": json.dumps(app_config, indent=2)}}}).encode(),
        method="PATCH",
        headers={"Authorization": f"token {cfg['gh_pat']}", "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json"})
    print(f"Saved rotated Fitbit tokens: {', '.join(rotated)}")


def main():
    gist = N.read_gist()
    files = gist["files"]
    app_config = json.loads(files["config.json"]["content"])
    cfg = N.decrypt(app_config["encryptedBlob"], app_config["salt"], app_config["iv"])
    today = N.today_est()

    # Refresh every Fitbit token first and save them at once, so nothing that
    # follows can strand a rotated token.
    access, rotated = {}, {}
    for user, ck, _ in USERS:
        try:
            access[user] = refresh_fitbit(cfg[ck])
            rotated[ck] = cfg[ck]["refresh_token"]
        except Exception as e:
            print(f"{user}: Fitbit token refresh failed ({e})")
    if rotated:
        save_tokens(rotated)

    cols = {}
    for user, ck, gk in USERS:
        stored = files.get(f"{user}.json", {}).get("content")
        recs = json.loads(stored) if stored else []
        recs = recs.get("data", recs) if isinstance(recs, dict) else recs
        cols[f"{user} stored"] = {r["date"]: r.get("steps") for r in recs}
        cols[f"{user} manual"] = {r["date"]: r.get("manualSteps") for r in recs}
        if user in access:
            for resource in ("steps", "tracker/steps"):
                data = N.fitbit_get(f"https://api.fitbit.com/1/user/-/activities/{resource}/date/{SINCE}/{today}.json",
                                    access[user])
                cols[f"{user} " + ("fitbit" if resource == "steps" else "tracker")] = {
                    e["dateTime"]: int(float(e["value"])) for e in data.get(f"activities-{resource.replace('/', '-')}", [])}
        g = N.fetch_google_steps(cfg[gk], SINCE, today) if cfg.get(gk) else None
        cols[f"{user} google"] = g or {}

    names = list(cols)
    print("\n" + "date      " + "".join(f"{n:>13}" for n in names))
    d = SINCE
    while d <= today:
        k = d.isoformat()
        print(k + "".join(f"{'' if cols[n].get(k) is None else cols[n][k]:>13}" for n in names))
        d += timedelta(days=1)


if __name__ == "__main__":
    main()
