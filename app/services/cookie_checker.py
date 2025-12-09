# app/services/cookie_checker.py

from __future__ import annotations

import os, time, tempfile
from datetime import datetime
from typing import Dict, List, Set
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.models.cookie_accounts import CookieAccount
from app.models.vps_node import VPSNode
from app.utils.crypto import decrypt_text
from app.vps.connection import VPSConnection


# VPS fixa
VPS_CHECK_NODE = "VPS1"

# Diretórios REAIS dentro da VPS
REMOTE_BASE_DIR = r"C:\Users\admin\Documents\check cookie"
REMOTE_DATA_DIR = fr"{REMOTE_BASE_DIR}\data"

# Arquivo de entrada
COOKIE_FILE = "cookie.txt"
REMOTE_COOKIE_PATH = fr"{REMOTE_BASE_DIR}\{COOKIE_FILE}"

# Arquivos de saída
STATUS_FILES = {
    "live": fr"{REMOTE_DATA_DIR}\live.txt",
    "dead": fr"{REMOTE_DATA_DIR}\dead.txt",
    "locked": fr"{REMOTE_DATA_DIR}\banned.txt",
}

# Task e processo do checker
COOKIE_CHECK_TASK_NAME = "CookieChecker"      # nome da task no Windows
COOKIE_CHECK_PROCESS_NAME = "checkcookie.exe" # nome exato do EXE
COOKIE_CHECK_WAIT_SECONDS = 8


def _get_vps1(db: Session) -> VPSNode:
    node = db.query(VPSNode).filter(VPSNode.name == VPS_CHECK_NODE).first()
    if not node:
        raise ValueError("VPS1 não encontrada na database.")
    return node


def _build_cookie_txt_content(db: Session, status_filter: str) -> str:
    stmt = select(CookieAccount).where(CookieAccount.status == status_filter)
    accounts = db.scalars(stmt).all()

    lines = []
    for acc in accounts:
        try:
            plain_pass = decrypt_text(acc.pass_enc)
            plain_cookie = decrypt_text(acc.cookie_enc)
        except:
            continue

        lines.append(f"{acc.username}:{plain_pass}:{plain_cookie}")

    return "\n".join(lines) + "\n" if lines else ""


def _upload_cookie_txt(conn: VPSConnection, content: str):
    # Upload para: C:\Users\admin\Documents\check cookie\cookie.txt """
    with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        conn.upload(tmp_path, REMOTE_COOKIE_PATH)
    finally:
        try:
            os.remove(tmp_path)
        except:
            pass


def _read_remote_file(conn: VPSConnection, remote_path: str) -> List[str]:
    """
    Lê qualquer arquivo remoto via comando: type <path>
    """
    cmd = f'if exist "{remote_path}" type "{remote_path}"'
    out, err = conn.run(cmd)

    if not out.strip():
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def _extract_usernames(lines: List[str]) -> Set[str]:
    users = set()
    for line in lines:
        parts = line.split(":", 1)
        if parts:
            users.add(parts[0].strip())
    return users


def _update_statuses(db: Session, mapped: Dict[str, Set[str]]) -> Dict[str, int]:
    stats = {"live": 0, "dead": 0, "locked": 0}


    for status, users in mapped.items():
        if not users:
            continue

        updated = (
            db.query(CookieAccount)
            .filter(CookieAccount.username.in_(users))
            .update({CookieAccount.status: status}, synchronize_session=False)
        )

        stats[status] = updated

    db.commit()
    return stats


def run_cookie_checker(db: Session, status_filter: str = "live"):


    """
    NOVA FUNÇÃO:
    - sempre VPS1
    - path REAL do Windows
    - entrada: cookie.txt na pasta raiz
    - saída: live/dead/banned.txt dentro de /data
    """
    node = _get_vps1(db)
    password = decrypt_text(node.password_enc) if node.password_enc else None

    cookie_text = _build_cookie_txt_content(db, status_filter)

    status_map = {"live": set(), "dead": set(), "locked": set()}


    try:
        with VPSConnection(
            host=node.host,
            port=node.port,
            username=node.username,
            password=password,
            keyfile=node.keyfile_path,
            working_directory=node.working_directory,
        ) as conn:

            # Upload do cookie.txt
            _upload_cookie_txt(conn, cookie_text)

            # Executar a scheduled task
            conn.run(f'schtasks /RUN /TN "{COOKIE_CHECK_TASK_NAME}"')

            # Aguarda processamento
            time.sleep(COOKIE_CHECK_WAIT_SECONDS)

            # Mata o processo (failsafe)
            conn.run(f'taskkill /IM "{COOKIE_CHECK_PROCESS_NAME}" /F')

            # Lê outputs
            live_lines = _read_remote_file(conn, STATUS_FILES["live"])
            dead_lines = _read_remote_file(conn, STATUS_FILES["dead"])
            banned_lines = _read_remote_file(conn, STATUS_FILES["locked"])


    except Exception as e:
        node.last_sync = datetime.utcnow()
        node.last_sync_status = f"cookie-check error: {e}"
        db.add(node)
        db.commit()
        raise

    status_map["live"] = _extract_usernames(live_lines)
    status_map["dead"] = _extract_usernames(dead_lines)
    status_map["locked"] = _extract_usernames(banned_lines)


    stats = _update_statuses(db, status_map)

    node.last_sync = datetime.utcnow()
    node.last_sync_status = (
        f"check ok: live={stats['live']} dead={stats['dead']} locked={stats['locked']}"
    )
    db.add(node)
    db.commit()

    return {
        "stats": stats,
        "last_sync": node.last_sync,
        "status": node.last_sync_status,
    }
