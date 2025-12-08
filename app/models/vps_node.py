# app/models/vps_node.py
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func

from app.db import Base


class VPSNode(Base):
    __tablename__ = "vps_nodes"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    host = Column(String, nullable=False)
    port = Column(Integer, nullable=False, default=22)
    username = Column(String, nullable=False)
    password_enc = Column(String, nullable=True)
    keyfile_path = Column(String, nullable=True)
    working_directory = Column(String, nullable=False)

    last_sync = Column(DateTime(timezone=True), nullable=True)
    last_sync_status = Column(String, nullable=True)
