import os
import uuid
from datetime import datetime, timedelta
from typing import List

from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, String, Float, ForeignKey, DateTime, TypeDecorator
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.sql import func
from passlib.context import CryptContext
from jose import jwt, JWTError
from pydantic import BaseModel

# --- ADDED: GEMINI IMPORT ---
from google import genai
from google.genai import types

# ---------------- CONFIG ----------------

DEFAULT_DB = "postgresql://neondb_owner:npg_jiyeGI6W5Lfl@ep-winter-feather-a41vs75x-pooler.us-east-1.aws.neon.tech/SOS?sslmode=require"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DB)

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

SECRET_KEY = os.getenv("SECRET_KEY", "SUPER_SECRET_KEY_CHANGE_ME")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 

# --- ADDED: GEMINI CONFIG ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "AIzaSyDFOvK8Y863TiKYjTnhD4oB0tfbSisiAhs")
client = genai.Client(api_key=GEMINI_API_KEY)

# ---------------- DATABASE ----------------

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ---------------- MODELS ----------------

class User(Base):
    __tablename__ = "users"
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    full_name = Column(String, nullable=False)
    blood_type = Column(String, nullable=False)
    phone = Column(String, unique=True, nullable=False)
    emergency_contact = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user")

class SOSAlert(Base):
    __tablename__ = "sos_alerts"
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey("users.id"))
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    status = Column(String, default="active")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

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
        user_id_str: str = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception
        user_id = uuid.UUID(user_id_str)
    except (JWTError, ValueError):
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user

# ---------------- APP ----------------

app = FastAPI(title="SOS Backend")

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

# ---------------- ADMIN ROUTES ----------------

@app.get("/admin/all-alerts")
def get_all_alerts(db: Session = Depends(get_db)):
    return db.query(SOSAlert).order_by(SOSAlert.created_at.desc()).all()

# --- ADDED: GEMINI ANALYSIS ROUTE ---

import time # Add at top

@app.post("/admin/analyze-location")
async def analyze_location(data: dict = Body(...)):
    lat = data.get("latitude")
    lon = data.get("longitude")
    
    if not lat or not lon:
        raise HTTPException(status_code=400, detail="Latitude and Longitude required")

    prompt = f"Emergency SOS at Lat {lat}, Lon {lon}. List 2 nearest hospitals and 1 police station."
    
    try:
        # Using the new SDK's generation method
        response = client.models.generate_content(
            model='gemini-2.5-flash-lite',
            contents=prompt
)
        return {"analysis": response.text}
    except Exception as e:
        print(f"AI Error: {e}")
        return {"analysis": "AI System Refreshing. Please use the 'Map' button for manual coordinate check."}