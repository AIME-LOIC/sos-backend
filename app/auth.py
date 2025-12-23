import os
import google.generativeai as genai
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, Body
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import User

# ----------------------
# Gemini AI Configuration
# ----------------------
# Replace with your key or use environment variables for safety
GEMINI_API_KEY = "AIzaSyDFOvK8Y863TiKYjTnhD4oB0tfbSisiAhs"
genai.configure(api_key=GEMINI_API_KEY)
ai_model = genai.GenerativeModel('gemini-1.5-flash')

# ----------------------
# Config & JWT Settings
# ----------------------
SECRET_KEY = "CHANGE_THIS_SECRET"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ----------------------
# Password Hashing
# ----------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# ----------------------
# JWT Token Creation
# ----------------------
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ----------------------
# DB & Auth Dependencies
# ----------------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ----------------------
# AI ANALYSIS ROUTE
# ----------------------
# Add this to your main FastAPI app instance (usually in main.py)
# If this code is in a separate file, import 'app' or use an APIRouter.

def add_ai_routes(app):
    @app.post("/admin/analyze-location")
    async def analyze_location(data: dict = Body(...)):
        lat = data.get("latitude")
        lon = data.get("longitude")
        
        if not lat or not lon:
            raise HTTPException(status_code=400, detail="Latitude and Longitude required")

        # The Prompt: instructing Gemini to act as an emergency dispatcher
        prompt = f"""
        Emergency SOS triggered at: Lat {lat}, Lon {lon}.
        Please provide:
        1. Names of the 2 nearest hospitals and 1 police station.
        2. A description of the geographical area (urban, highway, residential, etc.).
        3. A critical recommendation for emergency dispatchers.
        
        Format the response in short, clear bullet points for an admin dashboard.
        """
        
        try:
            response = ai_model.generate_content(prompt)
            return {"analysis": response.text}
        except Exception as e:
            # Fallback if the AI fails or the key is restricted
            return {"analysis": "AI Analysis is currently unavailable. Please proceed with manual dispatch."}