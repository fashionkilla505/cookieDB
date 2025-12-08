from pathlib import Path
import os
import subprocess
from typing import Dict, List
from sqlalchemy.orm import Session

from app import models

# You can move these to a proper settings module / env vars
COOKIE_CHECKER_EXE = os.getenv("COOKIE_CHECKER_EXE", r"C:\Users\junio\Downloads\Main\RMT\VSCODE\cookieDB\check cookie\checkcookie.exe")
COOKIE_CHECKER_OUTPUT_DIR = Path(os.getenv("COOKIE_CHECKER_OUTPUT_DIR", r"C:\Users\junio\Downloads\Main\RMT\VSCODE\cookieDB\check cookie\data"))

STATUS_FILES = {
    "live": "live.txt",
    "dead": "dead.txt",
    "banned": "banned.txt",
}


def _run_checker_exe() -> None: 
    """
    Run the external .exe that checks cookies.
    Adjust arguments if your tool needs extra flags.
    """
    # Example: CookieChecker.exe --out "C:\cookie-tools\out"
    result = subprocess.run(
        [COOKIE_CHECKER_EXE, "--out", str(COOKIE_CHECKER_OUTPUT_DIR)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Cookie checker failed (code {result.returncode}): {result.stderr.strip()}"
        )


def _read_status_file(path: Path) -> List[str]:
    """
    Reads a status .txt file and returns a list of usernames.
    Lines expected in format: username:password:cookie
    """
    if not path.exists():
        return []

    usernames: List[str] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split(":", 2)  # username:password:cookie
            if not parts:
                continue

            username = parts[0].strip()
            if username:
                usernames.append(username)

    return usernames


def collect_checker_results() -> Dict[str, List[str]]:
    """
    Runs the exe and parses live/dead/banned usernames.
    Returns: {"live": [...], "dead": [...], "banned": [...]}
    """
    _run_checker_exe()

    results: Dict[str, List[str]] = {}
    COOKIE_CHECKER_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for status, filename in STATUS_FILES.items():
        file_path = COOKIE_CHECKER_OUTPUT_DIR / filename
        results[status] = _read_status_file(file_path)

    return results


def apply_checker_results_to_db(db: Session, results: Dict[str, List[str]]) -> Dict[str, int]:
    """
    Given {"live": [...], "dead": [...], "banned": [...]}, update DB.
    Returns summary counts of updated rows.
    """
    summary: Dict[str, int] = {}

    # Map text status -> your Enum (adjust names if needed)
    from app.models import CookieStatus  # adjust to your real enum

    STATUS_MAPPING = {
        "live": CookieStatus.LIVE,
        "dead": CookieStatus.DEAD,
        "banned": CookieStatus.BANNED,
    }

    for text_status, usernames in results.items():
        if not usernames:
            summary[text_status] = 0
            continue

        db_status = STATUS_MAPPING[text_status]

        q = (
            db.query(models.CookieAccount)
            .filter(models.CookieAccount.username.in_(usernames))
        )

        updated = 0
        for acc in q.all():
            acc.status = db_status
            updated += 1

        summary[text_status] = updated

    db.commit()
    return summary
