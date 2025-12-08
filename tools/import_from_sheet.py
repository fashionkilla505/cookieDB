# tools/import_from_sheet.py
import csv
import os
import requests

API_BASE = os.getenv("COOKIE_API_BASE", "http://localhost:8000")
API_KEY = os.getenv("COOKIE_API_KEY")  # if you use one


def import_csv(path: str):
    headers = {}
    if API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            payload = {
                "username": row["username"],
                "password": row["password"],
                "cookie": row["cookie"],
                "status": row.get("status", "new"),
                "vps_node": row.get("vps_node") or None,
            }
            r = requests.post(f"{API_BASE}/cookie-accounts", json=payload, headers=headers)
            print(row["username"], r.status_code, r.text)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python import_from_sheet.py path/to/file.csv")
        raise SystemExit(1)

    import_csv(sys.argv[1])
