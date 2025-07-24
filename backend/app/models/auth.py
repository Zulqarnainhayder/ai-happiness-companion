from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str = None
    email: EmailStr = None
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class UserOut(BaseModel):
    username: str
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    token: str
    new_password: str
