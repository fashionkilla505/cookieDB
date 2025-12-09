# app/main.py
from fastapi import FastAPI

from app.db import Base, engine
from app.routers import cookie_accounts, vps_nodes


def create_app() -> FastAPI:
    app = FastAPI(
        title="Collector API + Cookie DB + VPS Layer",
        version="1.1.0",
    )

    # Create tables (auto migrate)
    Base.metadata.create_all(bind=engine)

    # Register routes
    app.include_router(cookie_accounts.router)
    app.include_router(vps_nodes.router)

    @app.get("/")
    def root():
        return {
            "status": "ok",
            "message": "Collector API / Cookie DB / VPS online",
        }

    return app


app = create_app()
