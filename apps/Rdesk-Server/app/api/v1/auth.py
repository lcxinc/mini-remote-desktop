from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    create_access_token,
    hash_password,
    password_needs_rehash,
    verify_password,
)
from app.core.response_security import no_store_sensitive_response
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, LoginResponse, RegisterRequest

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
    dependencies=[Depends(no_store_sensitive_response)],
)


@router.post("/register", response_model=LoginResponse)
async def register(
    payload: RegisterRequest, db: AsyncSession = Depends(get_db)
) -> LoginResponse:
    username = payload.username.strip()
    email = payload.email.strip().lower()
    password = payload.password

    if len(username) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username must be at least 3 characters",
        )
    if "@" not in email or "." not in email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email",
        )
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters",
        )

    existed = await db.scalar(
        select(User).where(or_(User.username == username, User.email == email))
    )
    if existed:
        if existed.username == username:
            detail = "Username already exists"
        else:
            detail = "Email already exists"
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role="user",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    token = create_access_token(user.id, user.username, user.role)
    return LoginResponse(
        access_token=token,
        user_id=user.id,
        username=user.username,
        role=user.role,
    )


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)) -> LoginResponse:
    user = await db.scalar(select(User).where(User.username == payload.username))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    token = create_access_token(user.id, user.username, user.role)
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)
        await db.commit()
    return LoginResponse(
        access_token=token,
        user_id=user.id,
        username=user.username,
        role=user.role,
    )
