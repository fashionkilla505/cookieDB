# tools/apply_checker_results.py
import os
import requests

API_BASE = os.getenv("COOKIE_API_BASE", "http://localhost:8000")
API_KEY = os.getenv("COOKIE_API_KEY")


def load_results(path: str):
    results = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            username, status = line.split(":", 1)
            username = username.strip()
            status = status.strip().lower()
            results.append({"username": username, "status": status})
    return results


def send_results(path: str):
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"

    results = load_results(path)
    payload = {"results": results}
    r = requests.post(f"{API_BASE}/cookie-accounts/check-results", json=payload, headers=headers)
    print(r.status_code, r.text)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python apply_checker_results.py path/to/checker_output.txt")
        raise SystemExit(1)

    send_results(sys.argv[1])
