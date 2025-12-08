# app/routers/vps_nodes.py
from app.models.cookie_accounts import CookieAccount
import tempfile
import os

from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select
from datetime import datetime

from app.dependencies import get_db
from app.models.vps_node import VPSNode
from app.schemas.vps_node import VPSNodeCreate, VPSNodeUpdate, VPSNodeOut
from app.utils.crypto import encrypt_text, decrypt_text
from app.vps.connection import VPSConnection

YUMMY_PROCESS_NAME = "WebRB.exe"
YUMMY_TASK_NAME = "YummyWebRB"
YUMMY_START_EXE = "WebRB.exe"


router = APIRouter(prefix="/vps-nodes", tags=["vps-nodes"])


def _get_by_name(db: Session, name: str) -> VPSNode | None:
    stmt = select(VPSNode).where(VPSNode.name == name)
    return db.scalar(stmt)


@router.get("/", response_model=List[VPSNodeOut])
def list_vps_nodes(db: Session = Depends(get_db)):
    stmt = select(VPSNode)
    nodes = db.scalars(stmt).all()
    return nodes


@router.get("/{name}", response_model=VPSNodeOut)
def get_vps_node(name: str, db: Session = Depends(get_db)):
    node = _get_by_name(db, name)
    if not node:
        raise HTTPException(status_code=404, detail="VPS node not found")
    return node


@router.post("/", response_model=VPSNodeOut)
def create_vps_node(payload: VPSNodeCreate, db: Session = Depends(get_db)):
    existing = _get_by_name(db, payload.name)
    if existing:
        raise HTTPException(status_code=400, detail="VPS node with this name already exists")

    password_enc = encrypt_text(payload.password) if payload.password else None

    node = VPSNode(
        name=payload.name,
        host=payload.host,
        port=payload.port,
        username=payload.username,
        password_enc=password_enc,
        keyfile_path=payload.keyfile_path,
        working_directory=payload.working_directory,
    )
    db.add(node)
    db.commit()
    db.refresh(node)
    return node


@router.patch("/{name}", response_model=VPSNodeOut)
def update_vps_node(name: str, payload: VPSNodeUpdate, db: Session = Depends(get_db)):
    node = _get_by_name(db, name)
    if not node:
        raise HTTPException(status_code=404, detail="VPS node not found")

    if payload.host is not None:
        node.host = payload.host
    if payload.port is not None:
        node.port = payload.port
    if payload.username is not None:
        node.username = payload.username
    if payload.working_directory is not None:
        node.working_directory = payload.working_directory
    if payload.keyfile_path is not None:
        node.keyfile_path = payload.keyfile_path
    if payload.password is not None:
        node.password_enc = encrypt_text(payload.password)

    db.add(node)
    db.commit()
    db.refresh(node)
    return node


@router.delete("/{name}")
def delete_vps_node(name: str, db: Session = Depends(get_db)):
    node = _get_by_name(db, name)
    if not node:
        raise HTTPException(status_code=404, detail="VPS node not found")

    db.delete(node)
    db.commit()
    return {"deleted": True, "name": name}


# ---------- TEST CONNECTION (SSH + opcional command) ----------
from paramiko.ssh_exception import (
    NoValidConnectionsError,
    AuthenticationException,
    SSHException,
)
import socket
from datetime import datetime
@router.post("/{name}/test-connection")
def test_connection(name: str, db: Session = Depends(get_db)):
    node = _get_by_name(db, name)
    if not node:
        raise HTTPException(status_code=404, detail="VPS node not found")

    password = decrypt_text(node.password_enc) if node.password_enc else None

    try:
        with VPSConnection(
            host=node.host,
            port=node.port,
            username=node.username,
            password=password,
            keyfile=node.keyfile_path,
            working_directory=node.working_directory,
        ) as conn:
            out, err = conn.run("echo TEST && cd")
    except NoValidConnectionsError as e:
        node.last_sync = datetime.utcnow()
        node.last_sync_status = "network_error"
        db.add(node)
        db.commit()
        raise HTTPException(
            status_code=502,
            detail={
                "error_type": "network",
                "message": f"No valid TCP connection: {e}",
            },
        )
    except AuthenticationException as e:
        node.last_sync = datetime.utcnow()
        node.last_sync_status = "auth_error"
        db.add(node)
        db.commit()
        raise HTTPException(
            status_code=401,
            detail={
                "error_type": "auth",
                "message": f"Authentication failed: {e}",
            },
        )
    except SSHException as e:
        node.last_sync = datetime.utcnow()
        node.last_sync_status = "ssh_error"
        db.add(node)
        db.commit()
        raise HTTPException(
            status_code=500,
            detail={
                "error_type": "ssh",
                "message": f"SSH protocol error: {e}",
            },
        )
    except socket.timeout as e:
        node.last_sync = datetime.utcnow()
        node.last_sync_status = "timeout"
        db.add(node)
        db.commit()
        raise HTTPException(
            status_code=504,
            detail={
                "error_type": "timeout",
                "message": f"Socket timeout: {e}",
            },
        )
    except Exception as e:
        node.last_sync = datetime.utcnow()
        node.last_sync_status = f"generic_error: {e}"
        db.add(node)
        db.commit()
        raise HTTPException(
            status_code=500,
            detail={
                "error_type": "generic",
                "message": f"Unexpected error: {e}",
            },
        )

    node.last_sync = datetime.utcnow()
    node.last_sync_status = "ok (test-connection)"
    db.add(node)
    db.commit()

    return {
        "status": "ok",
        "stdout": out,
        "stderr": err,
        "last_sync": node.last_sync,
        "last_sync_status": node.last_sync_status,
    }   
@router.post("/{name}/deploy-cookies")
def deploy_cookies_to_vps(
    name: str,
    status: str = "live",  # por padrão só contas LIVE
    db: Session = Depends(get_db),
):
    """
    Gera um .txt com user:pass:cookie das contas daquele VPS
    e faz upload via SFTP para o caminho remoto (cookie.txt).

    - Filtra por vps_node == name
    - Filtra por status (default: 'live')
    """

    # 1) Buscar o VPS
    node = _get_by_name(db, name)
    if not node:
        raise HTTPException(status_code=404, detail="VPS node not found")

    # 2) Buscar as contas do VPS
    stmt = select(CookieAccount).where(CookieAccount.vps_node == name)
    if status:
        stmt = stmt.where(CookieAccount.status == status)

    accounts = db.scalars(stmt).all()

    # 3) Montar o conteúdo do .txt
    lines: list[str] = []
    for acc in accounts:
        try:
            plain_pass = decrypt_text(acc.pass_enc)
            plain_cookie = decrypt_text(acc.cookie_enc)
        except Exception:
            # Se der pau pra descriptografar alguma conta, pula ela
            continue

        # FORMATO: username:password:cookie
        lines.append(f"{acc.username}:{plain_pass}:{plain_cookie}")

    # Conteúdo final (pode ser vazio, para "zerar" cookies no VPS)
    content = ""
    if lines:
        content = "\n".join(lines) + "\n"

    # 4) Criar arquivo temporário no container
    with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    # 5) Caminho remoto no VPS
    # Aqui assumimos que o manager lê em: C:/RobloxFarm/cookie.txt
    # (working_directory + "/cookie.txt")
    base = node.working_directory.replace("\\", "/").rstrip("/")
    remote_path = f"{base}/cookie.txt"

    # 6) Conectar via SSH/SFTP e subir o arquivo
    password = decrypt_text(node.password_enc) if node.password_enc else None

    try:
        with VPSConnection(
            host=node.host,
            port=node.port,
            username=node.username,
            password=password,
            keyfile=node.keyfile_path,
            working_directory=node.working_directory,
        ) as conn:
            conn.upload(tmp_path, remote_path)
    except Exception as e:
        # limpa o arquivo temporário
        try:
            os.remove(tmp_path)
        except Exception:
            pass

        node.last_sync = datetime.utcnow()
        node.last_sync_status = f"deploy-cookies error: {e}"
        db.add(node)
        db.commit()

        raise HTTPException(status_code=500, detail=f"Deploy failed: {e}")

    # 7) Sucesso → atualizar last_sync
    try:
        os.remove(tmp_path)
    except Exception:
        pass

    node.last_sync = datetime.utcnow()
    node.last_sync_status = f"deploy-cookies ok ({len(lines)} accounts → {remote_path})"
    db.add(node)
    db.commit()

    return {
        "status": "ok",
        "vps": name,
        "accounts_count": len(lines),
        "remote_path": remote_path,
    }
@router.post("/{name}/kill-yummy")
@router.post("/{name}/kill-yummy")
def kill_yummy(
    name: str,
    db: Session = Depends(get_db),
):
    """
    Mata o processo do yummy manager (WebRB.exe) no VPS.
    Usa taskkill /IM WebRB.exe /F.
    """
    node = _get_by_name(db, name)
    if not node:
        raise HTTPException(status_code=404, detail="VPS node not found")

    password = decrypt_text(node.password_enc) if node.password_enc else None

    stop_cmd = f'taskkill /IM "{YUMMY_PROCESS_NAME}" /F'

    try:
        with VPSConnection(
            host=node.host,
            port=node.port,
            username=node.username,
            password=password,
            keyfile=node.keyfile_path,
            working_directory=node.working_directory,
        ) as conn:
            out_stop, err_stop = conn.run(stop_cmd)
    except Exception as e:
        node.last_sync = datetime.utcnow()
        node.last_sync_status = f"kill-yummy error: {e}"
        db.add(node)
        db.commit()
        raise HTTPException(status_code=500, detail=f"kill-yummy failed: {e}")

    node.last_sync = datetime.utcnow()
    node.last_sync_status = (
        f'kill-yummy ok ({YUMMY_PROCESS_NAME}) | stdout={out_stop!r} | stderr={err_stop!r}'
    )
    db.add(node)
    db.commit()

    return {
        "status": "ok",
        "action": "kill-yummy",
        "vps": name,
        "process_name": YUMMY_PROCESS_NAME,
        "command": stop_cmd,
        "stdout": out_stop,
        "stderr": err_stop,
    }

@router.post("/{name}/start-yummy")
def start_yummy(
    name: str,
    db: Session = Depends(get_db),
):
    """
    Inicia o yummy manager via Scheduled Task.
    Supõe que exista uma task agendada chamada YUMMY_TASK_NAME (ex.: "YummyWebRB")
    configurada para rodar o WebRB.exe com o usuário logado.
    """
    node = _get_by_name(db, name)
    if not node:
        raise HTTPException(status_code=404, detail="VPS node not found")

    password = decrypt_text(node.password_enc) if node.password_enc else None

    # Comando simples: dispara a tarefa agendada
    start_cmd = f'schtasks /run /tn "{YUMMY_TASK_NAME}"'

    try:
        with VPSConnection(
            host=node.host,
            port=node.port,
            username=node.username,
            password=password,
            keyfile=node.keyfile_path,
            working_directory=node.working_directory,
        ) as conn:
            out_start, err_start = conn.run(start_cmd)
    except Exception as e:
        node.last_sync = datetime.utcnow()
        node.last_sync_status = f"start-yummy error: {e}"
        db.add(node)
        db.commit()
        raise HTTPException(status_code=500, detail=f"start-yummy failed: {e}")

    node.last_sync = datetime.utcnow()
    node.last_sync_status = (
        f"start-yummy ok (task={YUMMY_TASK_NAME}) | stdout={out_start!r} | stderr={err_start!r}"
    )
    db.add(node)
    db.commit()

    return {
        "status": "ok",
        "action": "start-yummy",
        "vps": name,
        "task_name": YUMMY_TASK_NAME,
        "command": start_cmd,
        "stdout": out_start,
        "stderr": err_start,
    }

@router.post("/{name}/restart-yummy")
def restart_yummy(
    name: str,
    db: Session = Depends(get_db),
):
    """
    Reinicia o yummy manager:
    - taskkill /IM WebRB.exe /F
    - schtasks /run /tn "YummyWebRB"
    """
    node = _get_by_name(db, name)
    if not node:
        raise HTTPException(status_code=404, detail="VPS node not found")

    password = decrypt_text(node.password_enc) if node.password_enc else None

    stop_cmd = f'taskkill /IM "{YUMMY_PROCESS_NAME}" /F'
    start_cmd = f'schtasks /run /tn "{YUMMY_TASK_NAME}"'

    stdout_steps: list[str] = []
    stderr_steps: list[str] = []

    try:
        with VPSConnection(
            host=node.host,
            port=node.port,
            username=node.username,
            password=password,
            keyfile=node.keyfile_path,
            working_directory=node.working_directory,
        ) as conn:
            # STOP
            out_stop, err_stop = conn.run(stop_cmd)
            stdout_steps.append(f"[STOP]\n{out_stop}")
            stderr_steps.append(f"[STOP]\n{err_stop}")

            # START
            out_start, err_start = conn.run(start_cmd)
            stdout_steps.append(f"[START]\n{out_start}")
            stderr_steps.append(f"[START]\n{err_start}")

    except Exception as e:
        node.last_sync = datetime.utcnow()
        node.last_sync_status = f"restart-yummy error: {e}"
        db.add(node)
        db.commit()
        raise HTTPException(status_code=500, detail=f"restart-yummy failed: {e}")

    node.last_sync = datetime.utcnow()
    node.last_sync_status = (
        f"restart-yummy ok ({YUMMY_PROCESS_NAME} -> task {YUMMY_TASK_NAME})"
    )
    db.add(node)
    db.commit()

    return {
        "status": "ok",
        "action": "restart-yummy",
        "vps": name,
        "process_name": YUMMY_PROCESS_NAME,
        "task_name": YUMMY_TASK_NAME,
        "stop_command": stop_cmd,
        "start_command": start_cmd,
        "stdout": "\n".join(stdout_steps),
        "stderr": "\n".join(stderr_steps),
    }

@router.get("/{name}/check-yummy")
def check_yummy(
    name: str,
    db: Session = Depends(get_db),
):
    """
    Verifica se o processo do yummy manager (WebRB.exe) está rodando no VPS.
    Usa tasklist /FI "IMAGENAME eq WebRB.exe".
    """
    node = _get_by_name(db, name)
    if not node:
        raise HTTPException(status_code=404, detail="VPS node not found")

    password = decrypt_text(node.password_enc) if node.password_enc else None

    check_cmd = (
        f'tasklist /FI "IMAGENAME eq {YUMMY_PROCESS_NAME}" /FO CSV /NH'
    )

    try:
        with VPSConnection(
            host=node.host,
            port=node.port,
            username=node.username,
            password=password,
            keyfile=node.keyfile_path,
            working_directory=node.working_directory,
        ) as conn:
            out_check, err_check = conn.run(check_cmd)
    except Exception as e:
        node.last_sync = datetime.utcnow()
        node.last_sync_status = f"check-yummy error: {e}"
        db.add(node)
        db.commit()
        raise HTTPException(status_code=500, detail=f"check-yummy failed: {e}")

    # Interpreta saída do tasklist
    running = False
    raw = (out_check or "").strip()

    if raw and "No tasks are running" not in raw:
        # Quando encontra, a primeira linha costuma ser algo tipo:
        # "WebRB.exe","1234","Console","1","50.000 K"
        first_line = raw.splitlines()[0]
        if YUMMY_PROCESS_NAME.lower() in first_line.lower():
            running = True

    node.last_sync = datetime.utcnow()
    node.last_sync_status = (
        f"check-yummy ok ({YUMMY_PROCESS_NAME} running={running})"
    )
    db.add(node)
    db.commit()

    return {
        "status": "ok",
        "action": "check-yummy",
        "vps": name,
        "process_name": YUMMY_PROCESS_NAME,
        "running": running,
        "command": check_cmd,
        "stdout": out_check,
        "stderr": err_check,
    }
