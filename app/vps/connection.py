# app/vps/connection.py
from __future__ import annotations

from typing import Optional, Tuple

import paramiko


class VPSConnection:
    """
    Reusable VPS connection layer:
    - SSH (remote commands)
    - SFTP (upload/download)
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str] = None,
        keyfile: Optional[str] = None,
        working_directory: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.keyfile = keyfile
        self.working_directory = working_directory

        self.client: Optional[paramiko.SSHClient] = None
        self.sftp: Optional[paramiko.SFTPClient] = None

    def __enter__(self) -> "VPSConnection":
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # ---------- SSH Connection ----------
    def connect(self) -> "VPSConnection":
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if self.keyfile:
            key = paramiko.RSAKey.from_private_key_file(self.keyfile)
            self.client.connect(
                self.host,
                port=self.port,
                username=self.username,
                pkey=key,
                timeout=10,
            )
        else:
            self.client.connect(
                self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10,
            )
        return self

    # ---------- Run command ----------
    def run(self, command: str) -> Tuple[str, str]:
        """
        Run remote command and return (stdout, stderr).
        """
        if not self.client:
            raise RuntimeError("Not connected")

        if self.working_directory:
            command = f"cd {self.working_directory} && {command}"

        stdin, stdout, stderr = self.client.exec_command(command)
        out = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        return out, err

    # ---------- SFTP Upload ----------
    def upload(self, local_path: str, remote_path: str) -> None:
        if not self.client:
            raise RuntimeError("Not connected")
        if not self.sftp:
            self.sftp = self.client.open_sftp()
        self.sftp.put(local_path, remote_path)

    # ---------- Close ----------
    def close(self) -> None:
        if self.sftp:
            try:
                self.sftp.close()
            except Exception:
                pass
            self.sftp = None

        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None
