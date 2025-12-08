# app/main.py
from fastapi import FastAPI
from apscheduler.schedulers.background import BackgroundScheduler

from app.db import Base, engine, SessionLocal
from app.routers import cookie_accounts, vps_nodes
from app.services.cookie_checker import (
    collect_checker_results,
    apply_checker_results_to_db,
)


def create_app() -> FastAPI:
    app = FastAPI(
        title="Collector API + Cookie DB + VPS Layer",
        version="1.1.0",
    )

    # Create tables
    Base.metadata.create_all(bind=engine)

    # Routers
    app.include_router(cookie_accounts.router)
    app.include_router(vps_nodes.router)

    @app.get("/")
    def read_root():
        return {"status": "ok", "message": "Collector API / Cookie DB / VPS online"}

    return app


scheduler = BackgroundScheduler()
app = create_app()


def _scheduled_cookie_check():
    db = SessionLocal()
    try:
        results = collect_checker_results()
        apply_checker_results_to_db(db, results)
    except Exception as e:
        # Optional: add proper logging here
        print(f"[cookie-checker] error: {e}")
    finally:
        db.close()


@app.on_event("startup")
def start_scheduler():
    # Run every 3 hours
    scheduler.add_job(
        _scheduled_cookie_check,
        "interval",
        hours=3,
        id="cookie_checker_3h",
        replace_existing=True,
    )
    scheduler.start()


@app.on_event("shutdown")
def shutdown_scheduler():
    scheduler.shutdown()
