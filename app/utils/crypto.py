# app/utils/crypto.py
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken


_COOKIE_SECRET_KEY_ENV = "COOKIE_DB_SECRET_KEY"


def _get_fernet() -> Fernet:
    key = os.getenv(_COOKIE_SECRET_KEY_ENV)
    if not key:
        raise RuntimeError(
            f"{_COOKIE_SECRET_KEY_ENV} is not set. Generate one with "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode() if not key.startswith("gAAAA") else key)  # if you paste raw key, it's fine


def encrypt_text(plain: str) -> str:
    f = _get_fernet()
    token = f.encrypt(plain.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_text(token: str) -> Optional[str]:
    f = _get_fernet()
    try:
        return f.decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return None
