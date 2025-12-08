# app/schemas/vps_node.py
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class VPSNodeBase(BaseModel):
    host: str
    port: int = 22
    username: str
    working_directory: str
    # NÃO expomos password_enc; trabalhamos com plain password aqui
    keyfile_path: Optional[str] = None


class VPSNodeCreate(VPSNodeBase):
    name: str
    password: Optional[str] = Field(default=None, description="Plain password; será criptografada")


class VPSNodeUpdate(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    working_directory: Optional[str] = None
    keyfile_path: Optional[str] = None
    password: Optional[str] = Field(default=None, description="Plain password; será criptografada")


class VPSNodeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    host: str
    port: int
    username: str
    working_directory: str
    keyfile_path: Optional[str] = None
    last_sync: Optional[datetime] = None
    last_sync_status: Optional[str] = None
