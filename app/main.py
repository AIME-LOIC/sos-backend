import os
import uuid
from datetime import datetime, timedelta
from typing import List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, String, Float, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from passlib.context import CryptContext
from jose import jwt, JWTError
from pydantic import BaseModel

# ---------------- CONFIG ----------------

# Render provides DATABASE_URL. We fix it for SQLAlchemy compatibility.
DATABASE_URL = os.getenv("postgresql://neondb_owner:npg_jiyeGI6W5Lfl@ep-winter-feather-a41vs75x-pooler.us-east-1.aws.neon.tech/SOS?sslmode=require&channel_binding=require")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
else:
    # Fallback for local testing if no env var is set
    DATABASE_URL = "sqlite:///./test.db"

SECRET_KEY = os.getenv("SECRET_KEY", "SUPER_SECRET_KEY_CHANGE_ME")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # 24 hours

# ---------------- DATABASE ----------------

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ---------------- MODELS ----------------

class User(Base):
    __tablename__ = "users"

    # Fixed: Removed as_uuid=True for SQLAlchemy 2.0+
    id = Column(UUID, primary_key=True, default=uuid.uuid4)
    full_name = Column(String, nullable=False)
    blood_type = Column(String, nullable=False)
    phone = Column(String, unique=True, nullable=False)
    emergency_contact = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user")


class SOSAlert(Base):
    __tablename__ = "sos_alerts"

    id = Column(UUID, primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID, ForeignKey("users.id"))
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    status = Column(String, default="active")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

# Create tables
Base.metadata.create_all(bind=engine)

# ---------------- SCHEMAS ----------------

class UserCreate(BaseModel):
    full_name: str
    blood_type: str
    phone: str
    emergency_contact: str
    password: str

class SOSCreate(BaseModel):
    latitude: float
    longitude: float

class Token(BaseModel):
    access_token: str
    token_type: str

# ---------------- SECURITY ----------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(password, hashed):
    return pwd_context.verify(password, hashed)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user

# ---------------- APP ----------------

app = FastAPI(title="SOS Backend")

# IMPORTANT: CORS middleware for Flutter connectivity
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- ROUTES ----------------

@app.get("/")
def health_check():
    return {"status": "online", "system": "SOS Emergency"}

@app.post("/auth/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.phone == user.phone).first():
        raise HTTPException(status_code=400, detail="Phone already registered")

    new_user = User(
        full_name=user.full_name,
        blood_type=user.blood_type,
        phone=user.phone,
        emergency_contact=user.emergency_contact,
        hashed_password=hash_password(user.password)
    )
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.phone == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": str(user.id)})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/sos/create")
def create_sos(sos: SOSCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    alert = SOSAlert(
        user_id=user.id,
        latitude=sos.latitude,
        longitude=sos.longitude
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert

@app.get("/sos/my-alerts")
def my_alerts(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(SOSAlert).filter(SOSAlert.user_id == user.id).all()
