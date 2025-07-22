from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import EmailStr
from sqlalchemy.orm import Session
from app.models.auth import UserCreate, UserLogin, Token, UserOut, ResetPasswordRequest, ResetPassword
from app.services.auth import signup_user, authenticate_user, create_access_token, get_current_user, forgot_password_token, reset_password
from app.core.database import get_db

router = APIRouter(prefix="/auth", tags=["auth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

@router.post("/signup", response_model=UserOut)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    return signup_user(user, db)

from pydantic import BaseModel

class LoginRequest(BaseModel):
    username: str
    password: str

from app.services.auth import create_refresh_token
from app.models.auth import RefreshTokenRequest

@router.post("/login", response_model=Token)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(data.username, data.password, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token({"sub": user.email})
    refresh_token = create_refresh_token({"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}

@router.post("/refresh", response_model=Token)
def refresh_token(request: RefreshTokenRequest):
    from jose import jwt, JWTError
    import os
    SECRET_KEY = os.getenv("SECRET_KEY")
    ALGORITHM = os.getenv("ALGORITHM", "HS256")
    try:
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token type")
        email = payload.get("sub")
        access_token = create_access_token({"sub": email})
        new_refresh_token = create_refresh_token({"sub": email})
        return {"access_token": access_token, "token_type": "bearer", "refresh_token": new_refresh_token}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

@router.post("/forgot-password")
def forgot_password(request: ResetPasswordRequest):
    token = forgot_password_token(request.email)
    # In production, send token via email
    return {"reset_token": token}

@router.post("/reset-password")
def reset_password_endpoint(request: ResetPassword):
    reset_password(request.token, request.new_password)
    return {"msg": "Password reset successful"}

@router.get("/me", response_model=UserOut)
def read_profile(current_user: dict = Depends(get_current_user)):
    return current_user
