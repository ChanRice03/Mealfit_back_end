#main.py
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
from passlib.context import CryptContext
from datetime import datetime, timedelta
from random import randint
from email.message import EmailMessage
import random
import redis
import aiosmtplib
import jwt
import os
import mysql.connector
from dotenv import load_dotenv

# Redis 클라이언트 설정
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    decode_responses=True
)

# 이메일 환경 변수
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT"))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")


# 환경변수 로드
load_dotenv()

app = FastAPI()

# 모델 정의
class EmailRequest(BaseModel):
    email: EmailStr

class CodeVerifyRequest(BaseModel):
    email: EmailStr
    code: str

class PasswordResetRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str

# 이메일 전송 함수
async def send_email(to_email: str, code: str):
    message = EmailMessage()
    message["From"] = EMAIL_USER
    message["To"] = to_email
    message["Subject"] = " 비밀번호 재설정 인증 코드"
    message.set_content(f"요청하신 인증 코드는 다음과 같습니다:\n\n 인증 코드: {code}\n\n10분 이내에 입력해주세요.")

    await aiosmtplib.send(
        message,
        hostname=EMAIL_HOST,
        port=EMAIL_PORT,
        start_tls=True,
        username=EMAIL_USER,
        password=EMAIL_PASS,
    )

# 인증 코드 생성
def generate_code():
    return str(random.randint(100000, 999999))

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


class UserProfile(BaseModel):
    height_cm: int
    weight_kg: int
    birth_year: int
    gender: str = Field(pattern="^(M|F)$")



verification_codes = {}  # 임시 저장소: 실서비스에서는 Redis 또는 DB

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

#사용자 신체정보 엔드포인트
@app.get("/profile-info")
def get_profile_info(Authorization: str = Header(...)):
    token = Authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰이다냥!")

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))
    result = cursor.fetchone()
    if not result:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없다냥!")

    user_id = result["id"]
    cursor.execute("SELECT height_cm, weight_kg, birth_year, gender FROM user_profiles WHERE user_id = %s", (user_id,))
    profile = cursor.fetchone()

    cursor.close()
    conn.close()

    if not profile:
        return {}

    return profile

@app.post("/profile-info")
def save_profile_info(profile: UserProfile, Authorization: str = Header(...)):
    token = Authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다.")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))
    result = cursor.fetchone()
    if not result:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    user_id = result[0]
    now = datetime.now()

    cursor.execute("""
        INSERT INTO user_profiles (user_id, height_cm, weight_kg, birth_year, gender, created_at)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
          height_cm = VALUES(height_cm),
          weight_kg = VALUES(weight_kg),
          birth_year = VALUES(birth_year),
          gender = VALUES(gender),
          created_at = VALUES(created_at)
    """, (user_id, profile.height_cm, profile.weight_kg, profile.birth_year, profile.gender, now))

    conn.commit()
    cursor.close()
    conn.close()

    return {"msg": "프로필이 저장되었습니다."}

# 1. 인증 코드 전송
@app.post("/send-verification-code")
async def send_verification_code(req: EmailRequest):
    code = generate_code()
    redis_client.setex(f"verify:{req.email}", 600, code)  # 10분 유효
    await send_email(req.email, code)
    return {"msg": "인증 코드가 이메일로 전송되었습니다."}

# 2. 인증 코드 검증
@app.post("/verify-code")
def verify_code(req: CodeVerifyRequest):
    saved_code = redis_client.get(f"verify:{req.email}")
    if not saved_code:
        raise HTTPException(status_code=400, detail="인증 코드가 만료되었거나 존재하지 않습니다.")
    if saved_code != req.code:
        raise HTTPException(status_code=400, detail="인증 코드가 일치하지 않습니다.")
    return {"msg": "인증 코드가 확인되었습니다."}

# 3. 비밀번호 재설정
@app.post("/reset-password")
def reset_password(req: PasswordResetRequest):
    saved_code = redis_client.get(f"verify:{req.email}")
    if not saved_code or saved_code != req.code:
        raise HTTPException(status_code=400, detail="인증 코드가 올바르지 않습니다.")

    conn = get_connection()
    cursor = conn.cursor()
    hashed_pw = pwd_context.hash(req.new_password)

    cursor.execute("UPDATE users SET password_hash = %s WHERE email = %s", (hashed_pw, req.email))
    conn.commit()
    cursor.close()
    conn.close()

    redis_client.delete(f"verify:{req.email}")  # 인증 코드 삭제
    return {"msg": "비밀번호가 성공적으로 재설정되었습니다!"}