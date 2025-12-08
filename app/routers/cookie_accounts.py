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
from app.schemas.cookie_accounts import (
    CookieAccountCreate,
    CookieAccountUpdate,
    CookieAccountOut,
    BulkCheckResults,
    BulkRefreshPayload,
)
from app.utils.crypto import encrypt_text, decrypt_text
from app.dependencies import get_db
from app.services.cookie_checker import (
    collect_checker_results,
    apply_checker_results_to_db,
)

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

@router.get("/", response_model=List[CookieAccountOut])
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


@router.post("/", response_model=CookieAccountOut)
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
        # first_seen auto by DB
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.patch("/{username}", response_model=CookieAccountOut)
def update_cookie_account(
    username: str,
    payload: CookieAccountUpdate,
    db: Session = Depends(get_db),
):
    acc = _get_account_by_username(db, username)
    if not acc:
        raise HTTPException(status_code=404, detail="Cookie account not found")

    # password & cookie
    if payload.password is not None:
        acc.pass_enc = encrypt_text(payload.password)

    if payload.cookie is not None:
        acc.cookie_enc = encrypt_text(payload.cookie)

    # status and vps
    if payload.status is not None:
        acc.status = payload.status

    if payload.vps_node is not None:
        acc.vps_node = payload.vps_node

    # note
    if payload.note is not None:
        acc.note = payload.note

    # stock (only allowed when status is "done")
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


# --- EXPORT: per VPS (for deploying to each node) ---

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
    vps_node: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """
    Export `username:password:cookie` for status = dead (optionally filtered by vps_node).
    """
    stmt = select(CookieAccount).where(CookieAccount.status == "dead")
    if vps_node:
        stmt = stmt.where(CookieAccount.vps_node == vps_node)

    rows = db.scalars(stmt).all()
    lines = []
    for row in rows:
        username, password, cookie = _decrypt_row(row)
        if not username or not cookie:
            continue
        lines.append(f"{username}:{password}:{cookie}")

    return "\n".join(lines)


# --- Bulk checker results (manual JSON push from some tool, if needed) ---

@router.post("/check-results")
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

@router.post("/refresh")
def bulk_refresh_cookies(
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


# --- NEW: endpoint that runs the .exe and updates statuses ---

@router.post("/check-cookies", response_model=CookieCheckSummary)
def check_cookies_and_update_statuses(
    db: Session = Depends(get_db),
):
    """
    Runs the external .exe, parses live/dead/banned cookies,
    and updates their status in the DB.
    """
    try:
        results = collect_checker_results()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"cookie checker failed: {e}")

    summary = apply_checker_results_to_db(db, results)
    return {"updated": summary}
