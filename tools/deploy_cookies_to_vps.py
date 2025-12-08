# tools/deploy_cookies_to_vps.py
import os
import requests
from pathlib import Path

API_BASE = os.getenv("COOKIE_API_BASE", "http://localhost:8000")
API_KEY = os.getenv("COOKIE_API_KEY")

EXPORT_DIR = Path(os.getenv("COOKIE_EXPORT_DIR", "exports"))


def export_for_vps(vps_node: str, status: str = "live"):
    headers = {}
    if API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"

    params = {"vps_node": vps_node, "status": status}
    r = requests.get(f"{API_BASE}/cookie-accounts/export/vps", params=params, headers=headers)
    r.raise_for_status()

    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EXPORT_DIR / f"{vps_node}.txt"
    out_path.write_text(r.text, encoding="utf-8")
    print(f"Exported {vps_node} -> {out_path}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python deploy_cookies_to_vps.py VPS-1 [VPS-2 VPS-3 ...]")
        raise SystemExit(1)

    for vps in sys.argv[1:]:
        export_for_vps(vps)
