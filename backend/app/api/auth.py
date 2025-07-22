from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import EmailStr
from sqlalchemy.orm import Session
from app.models.auth import UserCreate, UserLogin, Token, UserOut, ResetPasswordRequest, ResetPassword, RefreshTokenRequest
from app.services.auth import signup_user, authenticate_user, create_access_token, get_current_user, forgot_password_token, reset_password, create_refresh_token
from app.core.database import get_db
from app.models.refresh_token import RefreshToken
from jose import jwt, JWTError
from datetime import datetime, timedelta
import os
import hashlib
from pydantic import BaseModel

router = APIRouter(prefix="/auth", tags=["auth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

@router.post("/signup", response_model=UserOut)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    return signup_user(user, db)

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login", response_model=Token)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(data.username, data.password, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token({"sub": user.email})
    refresh_token = create_refresh_token({"sub": user.email})
    # Store refresh token in DB
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    expires_at = datetime.utcnow() + timedelta(days=7)
    db_token = RefreshToken(user_id=user.id, token_hash=token_hash, expires_at=expires_at, revoked=False)
    db.add(db_token)
    db.commit()
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

@router.post("/logout")
def logout(request: RefreshTokenRequest, db: Session = Depends(get_db)):
    SECRET_KEY = os.getenv("SECRET_KEY")
    ALGORITHM = os.getenv("ALGORITHM", "HS256")
    try:
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        token_hash = hashlib.sha256(request.refresh_token.encode()).hexdigest()
        # Find the refresh token in DB and revoke it
        db_token = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
        if not db_token or db_token.revoked:
            raise HTTPException(status_code=401, detail="Invalid or already revoked refresh token")
        db_token.revoked = True
        db.commit()
        return {"msg": "Logged out successfully"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

@router.get("/me", response_model=UserOut)
def read_profile(current_user: dict = Depends(get_current_user)):
    return current_user
