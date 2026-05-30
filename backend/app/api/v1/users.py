"""User management endpoints."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from app.api.deps import CurrentUser, DBSession, require_role
from app.core.security import hash_password
from app.models.user import User, UserRole
from app.schemas.user import UserPublic, UserUpdate

router = APIRouter()


@router.get("/me", response_model=UserPublic)
async def get_me(current_user: CurrentUser) -> User:
    return current_user


@router.patch("/me", response_model=UserPublic)
async def update_me(
    payload: UserUpdate, current_user: CurrentUser, db: DBSession
) -> User:
    if payload.full_name is not None:
        current_user.full_name = payload.full_name
    if payload.password is not None:
        current_user.hashed_password = hash_password(payload.password)
    await db.commit()
    await db.refresh(current_user)
    return current_user


@router.get(
    "",
    response_model=list[UserPublic],
    dependencies=[Depends(require_role(UserRole.ADMIN))],
)
async def list_users(db: DBSession) -> list[User]:
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return list(result.scalars().all())
