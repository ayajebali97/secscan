"""API v1 routers."""
from fastapi import APIRouter

from app.api.v1 import auth, scans, users, reports

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
