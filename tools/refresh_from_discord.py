# tools/refresh_from_discord.py
import os
import requests

API_BASE = os.getenv("COOKIE_API_BASE", "http://localhost:8000")
API_KEY = os.getenv("COOKIE_API_KEY")


def load_refresh_file(path: str, default_vps: str | None = None):
    accounts = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            parts = line.split(":")
            if len(parts) < 3:
                continue
            username, password, cookie = parts[0], parts[1], ":".join(parts[2:])
            accounts.append(
                {
                    "username": username.strip(),
                    "password": password.strip(),
                    "cookie": cookie.strip(),
                    "vps_node": default_vps,
                }
            )
    return accounts


def refresh_from_file(path: str, default_vps: str | None = None):
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"

    accounts = load_refresh_file(path, default_vps=default_vps)
    payload = {"accounts": accounts}
    r = requests.post(f"{API_BASE}/cookie-accounts/refresh", json=payload, headers=headers)
    print(r.status_code, r.text)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python refresh_from_discord.py refreshed.txt [VPS-NODE]")
        raise SystemExit(1)

    path = sys.argv[1]
    vps_node = sys.argv[2] if len(sys.argv) >= 3 else None
    refresh_from_file(path, default_vps=vps_node)
