from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.models.auth import UserCreate, UserLogin, Token, UserOut, ResetPasswordRequest, ResetPassword, RefreshTokenRequest
from app.models.db_models import User
from app.services.auth import signup_user, authenticate_user, create_access_token, create_refresh_token, get_current_user, forgot_password_token, reset_password
from app.core.database import get_db
from app.models.refresh_token import RefreshToken
from datetime import datetime, timedelta
import hashlib
from jose import jwt, JWTError
import os

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/signup", response_model=UserOut)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    return signup_user(user, db)

from fastapi.security import OAuth2PasswordRequestForm

@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Accept either username or email in the username field
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)
    # Store refresh token in DB (hash for security)
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    expires_at = datetime.utcnow() + timedelta(days=7)
    db_token = RefreshToken(user_id=user.id, token_hash=token_hash, expires_at=expires_at, revoked=False)
    db.add(db_token)
    db.commit()
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}

@router.post("/refresh", response_model=Token)
def refresh_token(request: RefreshTokenRequest, db: Session = Depends(get_db)):
    SECRET_KEY = os.getenv("SECRET_KEY")
    ALGORITHM = os.getenv("ALGORITHM", "HS256")
    try:
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token type")
        user_id = payload.get("sub")
        token_hash = hashlib.sha256(request.refresh_token.encode()).hexdigest()
        db_token = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash, RefreshToken.user_id == int(user_id), RefreshToken.revoked == False).first()
        if not db_token:
            raise HTTPException(status_code=401, detail="Refresh token revoked or not found")
        user = db.query(User).filter(User.id == int(user_id)).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        new_access_token = create_access_token(user)
        new_refresh_token = create_refresh_token(user)
        # Optionally, revoke old refresh token and save new one
        db_token.revoked = True
        new_token_hash = hashlib.sha256(new_refresh_token.encode()).hexdigest()
        expires_at = datetime.utcnow() + timedelta(days=7)
        db.add(RefreshToken(user_id=user.id, token_hash=new_token_hash, expires_at=expires_at, revoked=False))
        db.commit()
        return {"access_token": new_access_token, "token_type": "bearer", "refresh_token": new_refresh_token}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

@router.post("/forgot-password")
def forgot_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    token = forgot_password_token(request.email, db)
    # In production, send token via email
    return {"reset_token": token}

@router.post("/reset-password")
def reset_password_endpoint(request: ResetPassword, db: Session = Depends(get_db)):
    reset_password(request.token, request.new_password, db)
    return {"msg": "Password reset successful"}

@router.post("/logout")
def logout(request: RefreshTokenRequest, db: Session = Depends(get_db)):
    SECRET_KEY = os.getenv("SECRET_KEY")
    ALGORITHM = os.getenv("ALGORITHM", "HS256")
    try:
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        token_hash = hashlib.sha256(request.refresh_token.encode()).hexdigest()
        db_token = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
        if not db_token or db_token.revoked:
            raise HTTPException(status_code=401, detail="Invalid or already revoked refresh token")
        db_token.revoked = True
        db.commit()
        return {"msg": "Logged out successfully"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

@router.get("/me", response_model=UserOut)
def read_profile(current_user: User = Depends(get_current_user)):
    return UserOut(username=current_user.username, email=current_user.email)
