from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional
from datetime import datetime, timedelta, timezone
import bcrypt
import jwt


app = FastAPI(title="Student Authentication API")


# 1. CẤU HÌNH JWT
SECRET_KEY = "asjkhgdjkabccjhasgcjvasckjb"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# 2. DATABASE GIẢ LẬP
users = []

next_user_id = 1


# 3. SECURITY
security = HTTPBearer()


# 4. SCHEMA
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        if not any(char.isupper() for char in value):
            raise ValueError("Mật khẩu phải có ít nhất một chữ hoa")

        if not any(char.islower() for char in value):
            raise ValueError("Mật khẩu phải có ít nhất một chữ thường")

        if not any(char.isdigit() for char in value):
            raise ValueError("Mật khẩu phải có ít nhất một chữ số")

        return value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool


# 5. HASH PASSWORD
def hash_password(password: str) -> str:
    """
    Băm password bằng Bcrypt
    """
    hashed = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    )

    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """
    Kiểm tra password với password_hash
    """
    return bcrypt.checkpw(
        password.encode("utf-8"),
        password_hash.encode("utf-8")
    )


# 6. JWT
def create_access_token(
    data: dict,
    expires_minutes: int
) -> str:

    payload = data.copy()

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expires_minutes
    )

    payload["exp"] = expire

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


def decode_access_token(token: str) -> dict:

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token đã hết hạn"
        )

    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token không hợp lệ"
        )


# 7. TÌM USER
def find_user_by_email(email: str) -> Optional[dict]:

    for user in users:

        if user["email"] == email:
            return user

    return None


def find_user_by_id(user_id: int) -> Optional[dict]:

    for user in users:

        if user["id"] == user_id:
            return user

    return None


# 8. LẤY USER HIỆN TẠI TỪ JWT
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):

    # Lấy token từ:
    # Authorization: Bearer <token>

    token = credentials.credentials

    # Decode và kiểm tra JWT
    payload = decode_access_token(token)

    # Lấy user_id từ Payload
    user_id = payload.get("user_id")

    if user_id is None:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token không hợp lệ"
        )

    # Quan trọng:
    # Không tin hoàn toàn dữ liệu trong JWT
    # -> truy vấn lại database

    user = find_user_by_id(user_id)

    if user is None:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Người dùng không tồn tại"
        )

    # Kiểm tra tài khoản còn hoạt động
    if not user["is_active"]:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tài khoản đã bị khóa"
        )

    return user


# 9. REGISTER
@app.post("/auth/register")
def register(request: RegisterRequest):

    global next_user_id

    # Kiểm tra email đã tồn tại
    existing_user = find_user_by_email(request.email)

    if existing_user:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email đã được đăng ký"
        )

    # Hash password
    password_hash = hash_password(request.password)

    # Tạo user
    new_user = {
        "id": next_user_id,
        "email": request.email,
        "password_hash": password_hash,
        "full_name": request.full_name,
        "role": "student",
        "is_active": True
    }

    users.append(new_user)

    next_user_id += 1

    # Không trả password/password_hash
    return {
        "message": "Đăng ký tài khoản thành công",
        "data": {
            "id": new_user["id"],
            "email": new_user["email"],
            "full_name": new_user["full_name"],
            "role": new_user["role"],
            "is_active": new_user["is_active"]
        }
    }


# 10. LOGIN
@app.post("/auth/login")
def login(request: LoginRequest):

    # Tìm user
    user = find_user_by_email(request.email)

    # Không thông báo quá chi tiết
    if user is None:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email hoặc mật khẩu không chính xác"
        )

    # Kiểm tra tài khoản có bị khóa không
    if not user["is_active"]:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tài khoản đã bị khóa"
        )

    # Verify password bằng Bcrypt
    password_correct = verify_password(
        request.password,
        user["password_hash"]
    )

    if not password_correct:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email hoặc mật khẩu không chính xác"
        )

    # Tạo JWT
    access_token = create_access_token(
        data={
            "sub": user["email"],
            "user_id": user["id"],
            "role": user["role"]
        },
        expires_minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    # Response
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }


# 11. GET CURRENT USER
@app.get("/auth/me", response_model=UserResponse)
def get_me(
    current_user: dict = Depends(get_current_user)
):

    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "full_name": current_user["full_name"],
        "role": current_user["role"],
        "is_active": current_user["is_active"]
    }


# 12. TEST
@app.get("/")
def home():
    return {
        "message": "Student Authentication API is running"
    }