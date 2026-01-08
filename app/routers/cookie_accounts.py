# app/routers/cookie_accounts.py
from typing import List, Optional, Dict

import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.models.cookie_accounts import CookieAccount
from app.models.vps_node import VPSNode

from app.schemas.cookie_accounts import (
    CookieAccountCreate,
    CookieAccountUpdate,
    CookieAccountOut,
    BulkCheckResults,
    BulkRefreshPayload,
)
from app.utils.crypto import encrypt_text, decrypt_text
from app.dependencies import get_db
    
from app.services.cookie_checker import run_cookie_checker


router = APIRouter(prefix="/cookie-accounts", tags=["cookie-accounts"])


# ---- Schemas (local) ----

class CookieCheckSummary(BaseModel):
    updated: Dict[str, int]


# ---- Helpers ----

def _get_account_by_username(db: Session, username: str) -> Optional[CookieAccount]:
    stmt = select(CookieAccount).where(CookieAccount.username == username)
    return db.scalar(stmt)


def _decrypt_row(row: CookieAccount):
    """Return (username, password, cookie) decrypted for exports."""
    username = row.username
    password = decrypt_text(row.pass_enc) or ""
    cookie = decrypt_text(row.cookie_enc) or ""
    return username, password, cookie


# ---- Endpoints ----

from fastapi.responses import PlainTextResponse

@router.get("/cookie/password/{username}", response_class=PlainTextResponse)
def get_plain_password(
    username: str,
    db: Session = Depends(get_db),
):
    """
    TEMPORÁRIO:
    Retorna SOMENTE a senha em texto puro.
    Sem JSON, sem metadata.
    """
    acc = _get_account_by_username(db, username)
    if not acc:
        return PlainTextResponse("NOT_FOUND", status_code=404)

    plain_password = decrypt_text(acc.pass_enc) or ""

    return PlainTextResponse(plain_password)


@router.get("/cookie", response_model=List[CookieAccountOut])
def list_cookie_accounts(
    status: Optional[str] = Query(None),
    vps_node: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    stmt = select(CookieAccount)
    if status:
        stmt = stmt.where(CookieAccount.status == status)
    if vps_node:
        stmt = stmt.where(CookieAccount.vps_node == vps_node)

    result = db.scalars(stmt).all()
    return result


@router.post("/cookie", response_model=CookieAccountOut)
def create_or_upsert_cookie_account(
    payload: CookieAccountCreate,
    db: Session = Depends(get_db),
):
    existing = _get_account_by_username(db, payload.username)

    pass_enc = encrypt_text(payload.password)
    cookie_enc = encrypt_text(payload.cookie)

    if existing:
        existing.pass_enc = pass_enc
        existing.cookie_enc = cookie_enc
        existing.status = payload.status
        existing.vps_node = payload.vps_node
        existing.note = payload.note
        if payload.stock is not None:
            existing.stock = payload.stock
        db.add(existing)
        db.commit()
        db.refresh(existing)
        return existing

    obj = CookieAccount(
        username=payload.username,
        pass_enc=pass_enc,
        cookie_enc=cookie_enc,
        status=payload.status,
        vps_node=payload.vps_node,
        note=payload.note,
        stock=payload.stock,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.patch("/cookie/{username}", response_model=CookieAccountOut)
def update_cookie_account(
    username: str,
    payload: CookieAccountUpdate,
    db: Session = Depends(get_db),
):
    acc = _get_account_by_username(db, username)
    if not acc:
        raise HTTPException(status_code=404, detail="Cookie account not found")

    if payload.password is not None:
        acc.pass_enc = encrypt_text(payload.password)

    if payload.cookie is not None:
        acc.cookie_enc = encrypt_text(payload.cookie)

    if payload.status is not None:
        acc.status = payload.status

    if payload.vps_node is not None:
        acc.vps_node = payload.vps_node

    if payload.note is not None:
        acc.note = payload.note

    # stock can only be set when status is "done"
    if payload.stock is not None:
        final_status = payload.status if payload.status is not None else acc.status
        if final_status != "done":
            raise HTTPException(
                status_code=400,
                detail="stock can only be set when status is 'done'",
            )
        acc.stock = payload.stock

    db.add(acc)
    db.commit()
    db.refresh(acc)
    return acc

@router.get("/cookie/{username}", response_model=CookieAccountOut)
def get_cookie_account(
    username: str,
    db: Session = Depends(get_db),
):
    """
    Retorna todos os dados da conta especificada pelo username.
    """
    acc = _get_account_by_username(db, username)
    if not acc:
        raise HTTPException(status_code=404, detail="Cookie account not found")
    return acc

## --- setar o status da conta

# -- SECTION: DONE
@router.delete("/done", response_model=CookieAccountOut)
def get_cookie_account(
    username: str,
    db: Session = Depends(get_db),
):
    """
    SECTION: DONE.
    """
   

    return {}

@router.patch("/done/set-done/{username}", response_model=CookieAccountOut)
def set_cookie_done(
    username: str,
    db: Session = Depends(get_db),
):
    """
    Marca a conta especificada como 'done'.
    Usado pela API externa para indicar finalização do kaitun.
    """

    acc = _get_account_by_username(db, username)
    if not acc:
        raise HTTPException(status_code=404, detail="Cookie account not found")

    acc.status = "done"

    db.add(acc)
    db.commit()
    db.refresh(acc)
    return acc

from fastapi import Body
from fastapi.responses import JSONResponse

@router.post(
    "/done/set-done-bulk",
    response_class=JSONResponse
)
def set_cookie_done_bulk(
    raw_text: str = Body(
        ...,
        media_type="text/plain",
        example="username1\nusername2\nusername3"
    ),
    db: Session = Depends(get_db),
):
    """
    BULK: Marca várias contas como 'done' via text/plain.

        username1
        username2
        username3
    """

    raw_text = raw_text.strip()

    if not raw_text:
        raise HTTPException(status_code=400, detail="Empty payload")

    usernames = [line.strip() for line in raw_text.splitlines() if line.strip()]

    updated = 0
    updated_usernames = []
    not_found = []

    for username in usernames:
        acc = _get_account_by_username(db, username)
        if not acc:
            not_found.append(username)
            continue

        acc.status = "done"
        db.add(acc)
        updated += 1
        updated_usernames.append(username)

    db.commit()

    return {
        "total_received": len(usernames),
        "updated": updated,
        "updated_usernames": updated_usernames,
        "not_found": not_found,
    }

from pydantic import BaseModel
from typing import List

# ---- Schema de resposta ----
class UsernamesResponse(BaseModel):
    usernames: List[str]


@router.get(
    "/done/done-no-stock/usernames",
    response_model=UsernamesResponse
)
def list_done_without_stock_usernames(
    db: Session = Depends(get_db),
):
    """
    Retorna SOMENTE usernames das contas com:
    - status = 'done'
    - stock NULL ou vazio

    Formato:
    {
        "usernames": ["aaaa", "bbbb", "ccccc"]
    }
    """

    stmt = (
        select(CookieAccount.username)
        .where(CookieAccount.status == "done")
        .where(
            (CookieAccount.stock.is_(None)) |
            (CookieAccount.stock == "")
        )
    )

    usernames = db.scalars(stmt).all()

    return {"usernames": usernames}


@router.get("/done/done-no-stock", response_model=List[CookieAccountOut])
def list_done_without_stock(
    db: Session = Depends(get_db),
):
    """
    Retorna todas as contas com:
    - status = 'done'
    - stock vazio ou null
    """
    stmt = (
        select(CookieAccount)
        .where(CookieAccount.status == "done")
        .where(
            (CookieAccount.stock == None) | (CookieAccount.stock == "")
        )
    )

    rows = db.scalars(stmt).all()
    return rows

# --- SECTION: NOTE

@router.delete("/note", response_model=CookieAccountOut)
def update_note_single(
):
    """
    SECTION: NOTE.
    """

    return {}

from pydantic import BaseModel

class NoteUpdate(BaseModel):
    note: str


@router.patch("/note/set-note/{username}", response_model=CookieAccountOut)
def update_note_single(
    username: str,
    payload: NoteUpdate,
    db: Session = Depends(get_db),
):
    """
    Atualiza o note de uma conta específica.
    """
    acc = _get_account_by_username(db, username)
    if not acc:
        raise HTTPException(status_code=404, detail="Cookie account not found")

    acc.note = payload.note

    db.add(acc)
    db.commit()
    db.refresh(acc)
    return acc
    
class NoteBulkUpdate(BaseModel):
    usernames: List[str]
    note: str


@router.patch("/note/set-note-bulk")
def update_note_bulk(
    payload: NoteBulkUpdate,
    db: Session = Depends(get_db),
):
    """
    Atualiza o note de várias contas ao mesmo tempo.
    Todas recebem a MESMA note.
    """
    updated = 0
    not_found = []

    for username in payload.usernames:
        acc = _get_account_by_username(db, username)
        if not acc:
            not_found.append(username)
            continue

        acc.note = payload.note
        db.add(acc)
        updated += 1

    db.commit()

    return {
        "updated": updated,
        "not_found": not_found,
        "applied_note": payload.note
    }

from fastapi.responses import PlainTextResponse

@router.get("/note/by-note/txt", response_class=PlainTextResponse)
def get_accounts_by_note_txt(
    note: str = Query(...),
    db: Session = Depends(get_db),
):
    """
    Retorna username:password (plaintext) por linha das contas com a note informada.
    """
    stmt = (
        select(CookieAccount)
        .where(CookieAccount.note == note)
    )

    rows = db.scalars(stmt).all()

    lines = []
    for row in rows:
        password = decrypt_text(row.pass_enc) or ""
        lines.append(f"{row.username}:{password}")

    return "\n".join(lines)


@router.get("/note/notes", response_model=List[str])
def list_all_notes(
    db: Session = Depends(get_db),
):
    """
    Lista valores DISTINCT de notes,
    mas SOMENTE de contas onde o stock é NULL ou "".
    """
    stmt = (
        select(CookieAccount.note)
        .where(CookieAccount.note.isnot(None))
        .where(CookieAccount.note != "")
        .where((CookieAccount.stock.is_(None)) | (CookieAccount.stock == ""))
    )

    notes = db.scalars(stmt).all()

    unique_notes = list(dict.fromkeys(notes))
    return [str(s) for s in unique_notes]

@router.get("/by-note")
def get_accounts_by_note(
    note: str = Query(...),
    db: Session = Depends(get_db),
):
    """
    Retorna username + senha plaintext de todas as contas com a note informada.
    """
    stmt = (
        select(CookieAccount)
        .where(CookieAccount.note == note)
    )

    rows = db.scalars(stmt).all()

    results = []
    for row in rows:
        password = decrypt_text(row.pass_enc) or ""
        results.append({
            "username": row.username,
            "password": password
        })

    return results

from pydantic import BaseModel
from typing import List
from fastapi.responses import JSONResponse


class NoteBulkJSON(BaseModel):
    usernames: List[str]
    note: str

from pydantic import BaseModel
from typing import List
from fastapi.responses import JSONResponse
from sqlalchemy import select


class NoteBulkJSON(BaseModel):
    usernames: List[str]
    note: str


@router.patch(
    "/note/set-noteaaaaaaaa",
    response_class=JSONResponse
)
def update_note_bulk_json(
    payload: NoteBulkJSON,
    db: Session = Depends(get_db),
):
    """
    BULK (JSON): Atualiza o note de várias contas.
    Nunca falha por username inexistente.
    """

    if not payload.usernames:
        return {
            "updated": 0,
            "not_found": [],
            "note_applied": payload.note,
            "message": "Empty usernames list"
        }

    # 🔹 buscar todas de uma vez
    stmt = (
        select(CookieAccount)
        .where(CookieAccount.username.in_(payload.usernames))
    )
    accounts = db.scalars(stmt).all()

    found_usernames = set()
    updated_usernames = []

    for acc in accounts:
        acc.note = payload.note
        db.add(acc)
        found_usernames.add(acc.username)
        updated_usernames.append(acc.username)

    db.commit()

    not_found = [
        u for u in payload.usernames
        if u not in found_usernames
    ]

    return {
        "note_applied": payload.note,
        "total_received": len(payload.usernames),
        "updated": len(updated_usernames),
        "updated_usernames": updated_usernames,
        "not_found": not_found,
    }




# --- SECTION: STOCK

@router.delete("/stock", response_model=CookieAccountOut)
def update_stock_single(

):
    """
    SECTION: STOCK
    """

    return {}

class StockUpdate(BaseModel):
    stock: int | str

@router.patch("/stock/set-stock/{username}", response_model=CookieAccountOut)
def update_stock_single(
    username: str,
    payload: StockUpdate,
    db: Session = Depends(get_db),
):
    """
    Atualiza apenas o campo 'stock' de uma conta específica.
    Usado para registrar quantidade/estoque/valor do item gerado pela conta.
    """

    acc = _get_account_by_username(db, username)
    if not acc:
        raise HTTPException(status_code=404, detail="Cookie account not found")

    acc.stock = payload.stock

    db.add(acc)
    db.commit()
    db.refresh(acc)
    return acc

from fastapi import Body
from fastapi.responses import JSONResponse

from fastapi import Request

@router.patch(
    "/stock/set-stock-bulk",
    response_class=JSONResponse
)
async def update_stock_bulk(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    BULK: Atualiza stock de várias contas via text/plain.

        STOCK_AQUI
        username1
        username2
        ...
    """

    raw_text = (await request.body()).decode("utf-8").strip()

    if not raw_text:
        raise HTTPException(status_code=400, detail="Empty payload")

    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]

    stock_value = lines[0]
    usernames = lines[1:]

    if not usernames:
        raise HTTPException(status_code=400, detail="No usernames found after stock line")

    updated = 0
    not_found = []
    updated_list = []

    for username in usernames:
        acc = _get_account_by_username(db, username)
        if not acc:
            not_found.append(username)
            continue

        acc.stock = stock_value
        db.add(acc)
        updated += 1
        updated_list.append(username)

    db.commit()

    return {
        "stock_assigned": stock_value,
        "updated": updated,
        "updated_usernames": updated_list,
        "not_found": not_found,
        "total_received": len(usernames)
    }


@router.get("/stock/stocks", response_model=List[str])
def list_all_stocks(
    db: Session = Depends(get_db),
):
    """
    Lista todos os valores de stock registrados (DISTINCT),
    ignorando NULL ou string vazia.
    """
    stmt = (
        select(CookieAccount.stock)
        .where(CookieAccount.stock.isnot(None))
        .where(CookieAccount.stock != "")
    )

    stocks = db.scalars(stmt).all()

    # Remover duplicados mantendo ordem
    unique_stocks = list(dict.fromkeys(stocks))

    # Converter tudo para string para o response_model
    return [str(s) for s in unique_stocks]





# --- EXPORT: per VPS (for deploying to each node) ---
# --- SECTION: EXPORT

@router.delete("/export", response_class=PlainTextResponse)
def export_for_vps(
):
    """
    SECTION: EXPORT
    """

    return {}


@router.get("/export/vps", response_class=PlainTextResponse)
def export_for_vps(
    vps_node: str = Query(...),
    status: str = Query("live"),
    db: Session = Depends(get_db),
):
    """
    Export `username:password:cookie` lines for a given VPS and status.
    Intended to be saved as VPS-X.txt.
    """
    stmt = (
        select(CookieAccount)
        .where(CookieAccount.vps_node == vps_node)
        .where(CookieAccount.status == status)
    )
    rows = db.scalars(stmt).all()

    lines = []
    for row in rows:
        username, password, cookie = _decrypt_row(row)
        if not username or not cookie:
            continue
        lines.append(f"{username}:{password}:{cookie}")

    return "\n".join(lines)


# --- EXPORT: dead cookies for renewal ---

@router.get("/export/dead", response_class=PlainTextResponse)
def export_dead_cookies(
    db: Session = Depends(get_db),
):
    """
    Export ALL `username:password:cookie` with status = dead.
    Independent of vps_node.
    """
    stmt = select(CookieAccount).where(CookieAccount.status == "dead")
    rows = db.scalars(stmt).all()

    lines = []
    for row in rows:
        username, password, cookie = _decrypt_row(row)
        if not username or not cookie:
            continue
        lines.append(f"{username}:{password}:{cookie}")

    return "\n".join(lines)

@router.get("/export/live", response_class=PlainTextResponse)
def export_dead_cookies(
    db: Session = Depends(get_db),
):
    """
    Export ALL `username:password:cookie` with status = live.
    Independent of vps_node.
    """
    stmt = select(CookieAccount).where(CookieAccount.status == "live")
    rows = db.scalars(stmt).all()

    lines = []
    for row in rows:
        username, password, cookie = _decrypt_row(row)
        if not username or not cookie:
            continue
        lines.append(f"{username}:{password}:{cookie}")

    return "\n".join(lines)

@router.get("/export/locked", response_class=PlainTextResponse)
def export_dead_cookies(
    db: Session = Depends(get_db),
):
    """
    Export ALL `username:password:cookie` with status = locked.
    Independent of vps_node.
    """
    stmt = select(CookieAccount).where(CookieAccount.status == "locked")
    rows = db.scalars(stmt).all()

    lines = []
    for row in rows:
        username, password, cookie = _decrypt_row(row)
        if not username or not cookie:
            continue
        lines.append(f"{username}:{password}:{cookie}")

    return "\n".join(lines)

# --- EXPORT: CSV for spreadsheet sync ---

@router.get("/export/csv", response_class=StreamingResponse)
def export_cookie_accounts_csv(
    status: Optional[str] = Query(None),
    vps_node: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """
    Export all cookie accounts as CSV with headers:

        user, pass_current, cookie_current, status, vps_node, stock
    """
    stmt = select(CookieAccount)
    if status:
        stmt = stmt.where(CookieAccount.status == status)
    if vps_node:
        stmt = stmt.where(CookieAccount.vps_node == vps_node)

    rows = db.scalars(stmt).all()

    def generate():
        buffer = io.StringIO()
        writer = csv.writer(buffer)

        # Header exactly as your sheet:
        writer.writerow(["user", "pass_current", "cookie_current", "status", "vps_node", "stock"])
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)

        for row in rows:
            username, password, cookie = _decrypt_row(row)

            writer.writerow([
                username,               # user
                password,               # pass_current
                cookie,                 # cookie_current
                row.status or "",       # status
                row.vps_node or "",     # vps_node
                row.stock or 0,         # stock
            ])

            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)

    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="cookie_accounts_export.csv"'
        },
    )


from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi import Query
from app.utils.crypto import decrypt_text

@router.get("/export/ggmax", response_class=PlainTextResponse)
def export_marketplace_ggmax(
    note: str = Query(..., description="Filtrar contas pelo campo note"),
    db: Session = Depends(get_db),
):
    """
    Exportação para GGMAX.
    - Apenas contas com status='done'
    - stock = NULL
    - note == <param>
    """

    stmt = (
        select(CookieAccount)
        .where(CookieAccount.status == "done")
        .where((CookieAccount.stock.is_(None)) | (CookieAccount.stock == ""))
        .where(CookieAccount.note == note)
    )

    rows = db.scalars(stmt).all()

    if not rows:
        return ""

    output_lines = []
    for row in rows:
        password = decrypt_text(row.pass_enc) or ""
        output_lines.append(f"Usuário: {row.username}")
        output_lines.append(f"Senha: {password}")
        output_lines.append("-=-=-=-")

    return "\n".join(output_lines)

ELDORADO_TEMPLATE = (
    "Hello, thanks for the purchase! 💖\n"
    "Account details 👇\n\n"
    "Username: {username}\n"
    "Password: {password}\n\n"
    "Account Unverified Email 📩❌\n"
    "Please add your own email to the account for preventing losses.\n\n"
    "If you can leave a review help so much! ✨"
)

@router.get("/export/eldorado", response_class=PlainTextResponse)
def export_marketplace_eldorado(
    note: str = Query(..., description="Filtrar contas pelo campo note"),
    db: Session = Depends(get_db),
):
    """
    Exportação para Eldorado.
    - Resposta em texto puro
    - Apenas contas com status='done'
    - stock = NULL
    - note == <param>
    - Cada conta separada por -------
    """

    stmt = (
        select(CookieAccount)
        .where(CookieAccount.status == "done")
        .where((CookieAccount.stock.is_(None)) | (CookieAccount.stock == ""))
        .where(CookieAccount.note == note)
    )

    rows = db.scalars(stmt).all()

    if not rows:
        return ""

    output_lines = []

    for row in rows:
        password = decrypt_text(row.pass_enc) or ""

        formatted = (
            "Hello, thanks for the purchase! 💖\n"
            "Account details 👇\n\n"
            f"Username: {row.username}\n"
            f"Password: {password}\n\n"
            "Account Unverified Email 📩❌\n"
            "Please add your own email to the account for preventing losses.\n\n"
            "If you can leave a review help so much! ✨"
        )

        output_lines.append(formatted)
        output_lines.append("-------")  # separador para você apagar depois

    return "\n".join(output_lines)


@router.post("/export/set-stock-after-export")
def bulk_set_stock_after_export(
    note: str = Query(..., description="Filtrar contas pelo campo note"),
    marketplace: str = Query(..., description="Nome do marketplace ex: ggmax, eldorado, etc."),
    db: Session = Depends(get_db),
):
    """
    Atualiza o campo 'stock' de todas as contas exportadas para marketplace.
    Regras:
    - status = 'done'
    - stock = NULL
    - note = <note>
    """

    # Query de contas elegíveis
    stmt = (
        select(CookieAccount)
        .where(CookieAccount.status == "done")
        .where((CookieAccount.stock.is_(None)) | (CookieAccount.stock == ""))
        .where(CookieAccount.note == note)
    )

    accounts = db.scalars(stmt).all()

    if not accounts:
        return {
            "updated": 0,
            "marketplace": marketplace,
            "note": note,
            "message": "Nenhuma conta elegível encontrada."
        }

    updated_users = []

    for acc in accounts:
        acc.stock = marketplace  # marca o marketplace onde foi vendida/registrada
        db.add(acc)
        updated_users.append(acc.username)

    db.commit()

    return {
        "updated": len(updated_users),
        "marketplace": marketplace,
        "note": note,
        "affected_usernames": updated_users
    }

## -- 

## -- SECTION: NODE

@router.delete(
    "/node",
    response_class=JSONResponse
)   
def set_cookie_done_bulk(

):
    """
    SECTION: NODE
    """

    return {}



ACTIVE_STATUSES = ["live", "dead", "locked", "new"]


@router.get("/node/vps-node/none", response_model=List[CookieAccountOut])
def list_accounts_without_vpsnode(
    db: Session = Depends(get_db),
):
    """
    Lista TODAS as contas sem vps_node,
    mas APENAS se o status for: live, dead ou locked.
    """
    stmt = (
        select(CookieAccount)
        .where(
            (CookieAccount.vps_node.is_(None)) |
            (CookieAccount.vps_node == "")
        )
        .where(CookieAccount.status.in_(ACTIVE_STATUSES))
    )

    rows = db.scalars(stmt).all()
    return rows


@router.get("/node/vps-node/none/count")
def count_accounts_without_vpsnode(
    db: Session = Depends(get_db),
):
    """
    Conta contas SEM vps_node, mas APENAS se estiverem com status:
    live, dead ou locked.
    """
    stmt = (
        select(CookieAccount)
        .where(
            (CookieAccount.vps_node.is_(None)) |
            (CookieAccount.vps_node == "")
        )
        .where(CookieAccount.status.in_(ACTIVE_STATUSES))
    )

    total = db.scalars(stmt).all()
    return {"count": len(total)}

## -- assign vps

class VPSAssignRequest(BaseModel):
    username: str

@router.patch("/node/assign-vps-balanced")
def assign_vps_balanced(
    payload: VPSAssignRequest,
    db: Session = Depends(get_db),
):
    """
    Atribui um vps_node balanceado para uma conta SEM vps_node
    com base na menor carga (live/dead/locked).
    """

    ACTIVE_STATUSES = ["live", "dead", "locked"]

    # Buscar conta alvo
    acc = _get_account_by_username(db, payload.username)
    if not acc:
        raise HTTPException(status_code=404, detail="Cookie account not found")

    # Se já tem vps_node, não mexe
    if acc.vps_node not in [None, ""]:
        raise HTTPException(
            status_code=400,
            detail=f"Account already has vps_node '{acc.vps_node}'"
        )

    # Buscar lista de VPS nodes registrados
    vps_nodes = db.execute(select(VPSNode)).scalars().all()
    if not vps_nodes:
        raise HTTPException(status_code=400, detail="No VPS nodes registered")

    # Contar quantas contas cada VPS já possui
    usage = {}
    for node in vps_nodes:
        count_stmt = (
            select(CookieAccount)
            .where(CookieAccount.vps_node == node.name)
            .where(CookieAccount.status.in_(ACTIVE_STATUSES))
        )
        count = len(db.scalars(count_stmt).all())
        usage[node.name] = count

    # Escolher VPS com menor carga
    chosen_vps = min(usage, key=usage.get)

    # Aplicar
    acc.vps_node = chosen_vps
    db.add(acc)
    db.commit()
    db.refresh(acc)

    return {
        "assigned_to": chosen_vps,
        "usage_before": usage,
        "updated_account": acc.username
    }

@router.patch("/node/assign-vps-balanced/bulk")
def assign_vps_balanced_bulk(
    db: Session = Depends(get_db),
):
    """
    Atribui vps_node balanceado para TODAS as contas sem vps_node.
    Considera status: live, dead, locked.
    Retorna balanço antes/depois e contas atualizadas.
    """

    ACTIVE_STATUSES = ["live", "dead", "locked"]

    # Buscar todos os VPS nodes registrados
    vps_nodes = db.execute(select(VPSNode)).scalars().all()
    if not vps_nodes:
        raise HTTPException(status_code=400, detail="No VPS nodes registered")

    # ---- CONTAGEM ANTERIOR ----
    usage_before = {}
    for node in vps_nodes:
        stmt = (
            select(CookieAccount)
            .where(CookieAccount.vps_node == node.name)
            .where(CookieAccount.status.in_(ACTIVE_STATUSES))
        )
        usage_before[node.name] = len(db.scalars(stmt).all())

    # ---- BUSCAR CONTAS SEM vps_node ----
    stmt_missing = (
        select(CookieAccount)
        .where((CookieAccount.vps_node.is_(None)) | (CookieAccount.vps_node == ""))
        .where(CookieAccount.status.in_(ACTIVE_STATUSES))
    )
    missing_accounts = db.scalars(stmt_missing).all()

    updated_accounts = []

    # Fazer uma cópia da contagem para usar durante a distribuição
    usage_dynamic = usage_before.copy()

    # ---- ATRIBUIR VPS PARA CADA CONTA ----
    for acc in missing_accounts:

        # Escolher VPS com menor carga atual
        chosen_vps = min(usage_dynamic, key=usage_dynamic.get)

        # Aplicar no objeto
        acc.vps_node = chosen_vps
        db.add(acc)

        # Atualizar contador dinâmico
        usage_dynamic[chosen_vps] += 1

        updated_accounts.append(acc.username)

    db.commit()

    # ---- CONTAGEM FINAL ----
    usage_after = {}
    for node in vps_nodes:
        stmt = (
            select(CookieAccount)
            .where(CookieAccount.vps_node == node.name)
            .where(CookieAccount.status.in_(ACTIVE_STATUSES))
        )
        usage_after[node.name] = len(db.scalars(stmt).all())

    return {
        "total_updated": len(updated_accounts),
        "accounts_updated": updated_accounts,
        "usage_before": usage_before,
        "usage_after": usage_after,
    }

class VPSNodeReset(BaseModel):
    vps_node: str


@router.patch("/node/vps-node/reset")
def reset_vpsnode_to_null(
    payload: VPSNodeReset,
    db: Session = Depends(get_db),
):
    """
    TEMPORÁRIO:
    Seta vps_node = NULL para todas as contas que possuem o vps_node especificado.
    """
    target_node = payload.vps_node

    stmt = (
        db.query(CookieAccount)
        .filter(CookieAccount.vps_node == target_node)
    )

    affected = stmt.update(
        {CookieAccount.vps_node: None},
        synchronize_session=False
    )

    db.commit()

    return {
        "cleared": affected,
        "target_node": target_node
    }

## -- SECTION: MISC

@router.delete(
    "/misc",
    response_class=JSONResponse
)   
def set_cookie_done_bulk(

):
    """
    SECTION: MISC
    """

    return {}

# --- Bulk checker results (manual JSON push from some tool, if needed) ---

@router.post("/misc/check-results")
def apply_check_results(
    payload: BulkCheckResults,
    db: Session = Depends(get_db),
):
    updated = 0
    for item in payload.results:
        acc = _get_account_by_username(db, item.username)
        if not acc:
            continue
        acc.status = item.status
        db.add(acc)
        updated += 1
    db.commit()
    return {"updated": updated, "total": len(payload.results)}


# --- Bulk refresh (new cookies from Discord bot /login) ---

from fastapi import Body

@router.post("/misc/refresh", response_model=dict)
def refresh_from_txt(
    raw_text: str = Body(..., media_type="text/plain"),
    db: Session = Depends(get_db),
):
    """
    Refresh cookies from raw TXT.
    Format required:
        username:password:cookie
    """

    inserted = 0
    updated = 0
    ignored_duplicates = 0
    errors = []

    processed_usernames = set()

    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]

    for idx, line in enumerate(lines, start=1):
        # -------------------------------
        # Duplicate line check
        # -------------------------------
        if line in processed_usernames:
            ignored_duplicates += 1
            continue
        processed_usernames.add(line)

        # -------------------------------
        # Format validation
        # -------------------------------
        parts = line.split(":")

        if len(parts) < 3:
            errors.append(
                {"line": idx, "content": line, "error": "Invalid format (expected username:password:cookie)"}
            )
            continue

        username = parts[0].strip()
        password = parts[1].strip()
        cookie = ":".join(parts[2:]).strip()  # cookie can include extra ':' safely

        # -------------------------------
        # Field validation
        # -------------------------------
        if not username:
            errors.append({"line": idx, "content": line, "error": "Missing username"})
            continue

        if not password:
            errors.append({"line": idx, "content": line, "error": "Missing password"})
            continue

        if not cookie:
            errors.append({"line": idx, "content": line, "error": "Missing cookie"})
            continue

        # -------------------------------
        # Process normal refresh logic
        # -------------------------------
        acc = _get_account_by_username(db, username)
        pass_enc = encrypt_text(password)
        cookie_enc = encrypt_text(cookie)

        final_status = "live"

        if acc:
            acc.pass_enc = pass_enc
            acc.cookie_enc = cookie_enc
            acc.status = final_status
            db.add(acc)
            updated += 1
        else:
            acc = CookieAccount(
                username=username,
                pass_enc=pass_enc,
                cookie_enc=cookie_enc,
                status=final_status,
                note="",
                vps_node=None,
            )
            db.add(acc)
            inserted += 1

    db.commit()
    return {
        "inserted": inserted,
        "updated": updated,
        "ignored_duplicates": ignored_duplicates,
        "errors": errors,
        "total_lines": len(lines),
        "processed": len(lines) - len(errors),
    }

@router.post("/misc/refreshjson")
def bulk_refresh_cookies_json(
    payload: BulkRefreshPayload,
    db: Session = Depends(get_db),
):
    inserted = 0
    updated = 0

    for item in payload.accounts:
        acc = _get_account_by_username(db, item.username)
        pass_enc = encrypt_text(item.password)
        cookie_enc = encrypt_text(item.cookie)

        final_status = item.status or "live"

        if acc:
            acc.pass_enc = pass_enc
            acc.cookie_enc = cookie_enc
            acc.status = final_status

            if item.vps_node is not None:
                acc.vps_node = item.vps_node
            if item.note is not None:
                acc.note = item.note
            if item.stock is not None:
                acc.stock = item.stock

            db.add(acc)
            updated += 1

        else:
            acc = CookieAccount(
                username=item.username,
                pass_enc=pass_enc,
                cookie_enc=cookie_enc,
                status=final_status,
                vps_node=item.vps_node,
                note=item.note or "",
                stock=item.stock,
            )
            db.add(acc)
            inserted += 1

    db.commit()
    return {"updated": updated, "inserted": inserted}





@router.post("/misc/check-cookies")
def check_cookies(
    status: str | None = "live",
    db: Session = Depends(get_db)
):
    """
    Checa cookies da VPS1.

    - Sem parâmetro => usa status="live"
    - Com parâmetro => usa o status passado no query param ?status=
    """

    try:
        result = run_cookie_checker(db, status_filter=status)
        return {
            "detail": "Verificação concluída",
            "status_filter": status,
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@router.post(
    "/misc/set-banned-bulk",
    response_class=JSONResponse
)   
def set_cookie_done_bulk(
    raw_text: str = Body(
        ...,
        media_type="text/plain",
        example="username1\nusername2\nusername3"
    ),
    db: Session = Depends(get_db),
):
    """
    BULK: Marca várias contas como 'banned' via text/plain.

        username1
        username2
        username3
    """

    raw_text = raw_text.strip()

    if not raw_text:
        raise HTTPException(status_code=400, detail="Empty payload")

    usernames = [line.strip() for line in raw_text.splitlines() if line.strip()]

    updated = 0
    updated_usernames = []
    not_found = []

    for username in usernames:
        acc = _get_account_by_username(db, username)
        if not acc:
            not_found.append(username)
            continue

        acc.status = "banned"
        db.add(acc)
        updated += 1
        updated_usernames.append(username)

    db.commit()

    return {
        "total_received": len(usernames),
        "updated": updated,
        "updated_usernames": updated_usernames,
        "not_found": not_found,
    }

@router.post(
    "/misc/set-live-bulk",
    response_class=JSONResponse
)   
def set_cookie_done_bulk(
    raw_text: str = Body(
        ...,
        media_type="text/plain",
        example="username1\nusername2\nusername3"
    ),
    db: Session = Depends(get_db),
):
    """
    BULK: Marca várias contas como 'live' via text/plain.

        username1
        username2
        username3
    """

    raw_text = raw_text.strip()

    if not raw_text:
        raise HTTPException(status_code=400, detail="Empty payload")

    usernames = [line.strip() for line in raw_text.splitlines() if line.strip()]

    updated = 0
    updated_usernames = []
    not_found = []

    for username in usernames:
        acc = _get_account_by_username(db, username)
        if not acc:
            not_found.append(username)
            continue

        acc.status = "live"
        db.add(acc)
        updated += 1
        updated_usernames.append(username)

    db.commit()

    return {
        "total_received": len(usernames),
        "updated": updated,
        "updated_usernames": updated_usernames,
        "not_found": not_found,
    }

@router.post(
    "/misc/set-oldstock-bulk",
    response_class=JSONResponse
)   
def set_cookie_done_bulk(
    raw_text: str = Body(
        ...,
        media_type="text/plain",
        example="username1\nusername2\nusername3"
    ),
    db: Session = Depends(get_db),
):
    """
    BULK: Marca várias contas como 'oldstock' via text/plain.

        username1
        username2
        username3
    """

    raw_text = raw_text.strip()

    if not raw_text:
        raise HTTPException(status_code=400, detail="Empty payload")

    usernames = [line.strip() for line in raw_text.splitlines() if line.strip()]

    updated = 0
    updated_usernames = []
    not_found = []

    for username in usernames:
        acc = _get_account_by_username(db, username)
        if not acc:
            not_found.append(username)
            continue

        acc.status = "oldstock"
        db.add(acc)
        updated += 1
        updated_usernames.append(username)

    db.commit()

    return {
        "total_received": len(usernames),
        "updated": updated,
        "updated_usernames": updated_usernames,
        "not_found": not_found,
    }