#main.py
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import os
import mysql.connector
from dotenv import load_dotenv

# 환경변수 로드
load_dotenv()

app = FastAPI()

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 개발 중 전체 허용. 배포 시 제한 권장
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# DB 연결 함수
def get_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='5048',
        database='test'
    )

# 비밀번호 해싱 설정
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT 설정
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "supersecret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 모델
class UserCreate(BaseModel):
    nickname: str
    email: str
    password: str

# 유틸 함수
def hash_password(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# 회원가입 엔드포인트
@app.post("/register")
def register(user: UserCreate):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE email = %s", (user.email,))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail="이미 존재하는 이메일입니다.")

    hashed_pw = hash_password(user.password)
    now = datetime.now()
    cursor.execute("""
        INSERT INTO users (nickname, email, password_hash, created_at)
        VALUES (%s, %s, %s, %s)
    """, (user.nickname, user.email, hashed_pw, now))
    conn.commit()

    cursor.close()
    conn.close()
    return {"msg": "회원가입의 성공했습니다."}

# 로그인 엔드포인트
@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email = %s", (form_data.username,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="이메일 또는 비밀번호가 틀렸습니다.")

    token_data = {"sub": user["email"], "id": user["id"]}
    token = create_access_token(token_data)

    return {"access_token": token, "token_type": "bearer"}

# 사용자정보 엔드포인트
@app.get("/profile")
def get_profile(Authorization: str = Header(...)):
    token = Authorization.split(" ")[1]  # "Bearer {token}"
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다.")

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT nickname, email FROM users WHERE email = %s", (user_email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    return user  # {"nickname": "...", "email": "..."}