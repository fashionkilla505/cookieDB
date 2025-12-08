# app/models/cookie_accounts.py
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func

from app.db import Base


class CookieAccount(Base):
    __tablename__ = "cookie_accounts"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    pass_enc = Column(String, nullable=False)
    cookie_enc = Column(String, nullable=False)
    status = Column(String, nullable=False)  # new/live/dead/banned/expired/locked/done
    vps_node = Column(String, nullable=True)

    # NEW FIELDS
    first_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    note = Column(String, nullable=True, server_default="")
    stock = Column(String, nullable=True)

    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
