# app/schemas/cookie_accounts.py
from typing import Optional, Literal, List, Annotated, Dict
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict, BeforeValidator

StatusLiteral = Literal["new", "live", "dead", "banned", "expired", "invalid", "locked", "recovered", "done"]

def _normalize_status(value: str) -> str:
    if value is None:
        return value
    # if someone sends non-string, let pydantic complain later
    if not isinstance(value, str):
        return value
    v = value.lower()
    allowed = {"new", "live", "dead", "banned", "expired", "invalid", "locked", "recovered", "done",}
    if v not in allowed:
        # will become a validation error
        raise ValueError(f"Invalid status '{value}'. Allowed: {sorted(allowed)}")
    return v

# Reusable type: accepts ANY case but stores/validates as lowercase StatusLiteral
StatusType = Annotated[StatusLiteral, BeforeValidator(_normalize_status)]

class CookieAccountBase(BaseModel):
    status: StatusType = Field(default="new")
    vps_node: Optional[str] = None
    note: str = ""  # default empty note
    stock: Optional[str] = None  # ⬅ ADD THIS if not present yet



class CookieAccountCreate(CookieAccountBase):
    username: str
    password: str
    cookie: str


class CookieAccountUpdate(BaseModel):
    password: Optional[str] = None
    cookie: Optional[str] = None
    status: Optional[StatusType] = None
    vps_node: Optional[str] = None
    note: Optional[str] = None
    stock: Optional[str] = None   # only valid when status is "done"



class CookieAccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    status: StatusType
    vps_node: Optional[str] = None
    first_seen: Optional[datetime] = None
    note: str = ""
    stock: Optional[str] = None
    updated_at: Optional[datetime] = None



class CheckResultItem(BaseModel):
    username: str
    status: StatusType


class RefreshItem(BaseModel):
    username: str
    password: str
    cookie: str
    vps_node: Optional[str] = None
    status: Optional[StatusType] = None
    note: Optional[str] = None
    stock: Optional[str] = None



class BulkCheckResults(BaseModel):
    results: List[CheckResultItem]


class BulkRefreshPayload(BaseModel):
    accounts: List[RefreshItem]