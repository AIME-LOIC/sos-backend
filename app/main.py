import os
import uuid
import base64
import hashlib
import hmac
import secrets
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List

from fastapi import FastAPI, Depends, HTTPException, status, Body, Request, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, String, Float, ForeignKey, DateTime, TypeDecorator
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.sql import func
from passlib.context import CryptContext
from jose import jwt, JWTError
from pydantic import BaseModel
import requests

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
    source_type = Column(String, default="app")  # web | phone | device | app
    source_device_uid = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Device(Base):
    __tablename__ = "devices"
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_uid = Column(String, unique=True, nullable=False, index=True)
    device_name = Column(String, nullable=True)
    device_token = Column(String, nullable=False)
    owner_user_id = Column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_seen_at = Column(DateTime(timezone=True), nullable=True)

class DeviceCommand(Base):
    __tablename__ = "device_commands"
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_uid = Column(String, nullable=False, index=True)
    owner_user_id = Column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    status = Column(String, default="pending")  # pending | delivered
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    delivered_at = Column(DateTime(timezone=True), nullable=True)

Base.metadata.create_all(bind=engine)

# Keep production DB compatible without external migration tooling.
with engine.begin() as conn:
    conn.exec_driver_sql("ALTER TABLE sos_alerts ADD COLUMN IF NOT EXISTS source_type VARCHAR")
    conn.exec_driver_sql("ALTER TABLE sos_alerts ADD COLUMN IF NOT EXISTS source_device_uid VARCHAR")

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

class DeviceLinkRequest(BaseModel):
    device_uid: str
    device_name: str | None = None

class DeviceUnlinkRequest(BaseModel):
    device_uid: str

class DeviceSOSCreate(BaseModel):
    device_uid: str
    device_token: str
    latitude: float
    longitude: float
    battery: str | None = None

class AdminDeviceUnlinkRequest(BaseModel):
    device_uid: str
    rotate_token: bool = True

class DeviceCoordinateCommandCreate(BaseModel):
    device_uid: str
    latitude: float
    longitude: float

class DeviceCommandPullRequest(BaseModel):
    device_uid: str
    device_token: str

def normalize_phone_number(value: str | None) -> str:
    if not value:
        return ""
    return "".join(ch for ch in value if ch.isdigit())

def connected_user_ids_for_emergency(owner: User, db: Session) -> list:
    """
    Connectivity rule:
    1) Same emergency number group: users sharing owner.emergency_contact
    2) Users who set owner's phone as their emergency contact
    """
    owner_phone = normalize_phone_number(owner.phone)
    owner_emergency = normalize_phone_number(owner.emergency_contact)
    connected_ids = {owner.id}

    users = db.query(User.id, User.phone, User.emergency_contact).all()
    for u in users:
        if u.id == owner.id:
            continue
        user_emergency = normalize_phone_number(u.emergency_contact)
        if not user_emergency:
            continue

        if owner_phone and user_emergency == owner_phone:
            connected_ids.add(u.id)
            continue
        if owner_emergency and user_emergency == owner_emergency:
            connected_ids.add(u.id)

    return list(connected_ids)

# ---------------- SECURITY ----------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")
PBKDF2_PREFIX = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 390000

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str):
    # Use stdlib PBKDF2 to avoid bcrypt backend/runtime incompatibilities.
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    digest_b64 = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"{PBKDF2_PREFIX}${PBKDF2_ITERATIONS}${salt_b64}${digest_b64}"

def generate_device_token() -> str:
    return secrets.token_urlsafe(24)

def infer_source_type(user_agent: str | None) -> str:
    ua = (user_agent or "").lower()
    if "mozilla" in ua:
        return "web"
    if "dart" in ua or "okhttp" in ua or "android" in ua or "iphone" in ua or "ios" in ua:
        return "phone"
    return "app"

def verify_password(password, hashed):
    if isinstance(hashed, str) and hashed.startswith(f"{PBKDF2_PREFIX}$"):
        try:
            _, iterations, salt_b64, digest_b64 = hashed.split("$", 3)
            pad = lambda s: s + "=" * (-len(s) % 4)
            salt = base64.urlsafe_b64decode(pad(salt_b64))
            expected = base64.urlsafe_b64decode(pad(digest_b64))
            computed = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt,
                int(iterations),
            )
            return hmac.compare_digest(computed, expected)
        except Exception:
            return False

    # Backward compatibility for existing bcrypt hashes in DB.
    try:
        return pwd_context.verify(password, hashed)
    except Exception:
        return False

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

def require_admin(user: User):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

# ---------------- APP ----------------

app = FastAPI(title="SOS Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
app.mount("/web", StaticFiles(directory=str(WEB_DIR), html=True), name="web")

_keep_awake_started = False

def keep_awake():
    base = os.environ.get("RENDER_URL", "").strip()
    if not base:
        # Optional: only run if explicit URL is configured.
        return
    url = base.rstrip("/") + "/healthz"
    while True:
        try:
            requests.get(url, timeout=10)
        except Exception:
            pass
        time.sleep(10 * 60)  # ping every 10 minutes

@app.on_event("startup")
def start_keep_awake():
    global _keep_awake_started
    if _keep_awake_started:
        return
    _keep_awake_started = True
    threading.Thread(target=keep_awake, daemon=True).start()

# ---------------- ROUTES ----------------

@app.get("/")
def health_check():
    return {"status": "online", "system": "SOS Emergency"}

@app.get("/healthz")
def healthz():
    return {"ok": True, "ts": datetime.utcnow().isoformat() + "Z"}


class NotificationHub:
    def __init__(self):
        self._by_user_id: dict[str, list[WebSocket]] = {}

    async def connect(self, user_id: str, ws: WebSocket):
        await ws.accept()
        self._by_user_id.setdefault(user_id, []).append(ws)

    def disconnect(self, user_id: str, ws: WebSocket):
        conns = self._by_user_id.get(user_id, [])
        self._by_user_id[user_id] = [c for c in conns if c is not ws]
        if not self._by_user_id[user_id]:
            self._by_user_id.pop(user_id, None)

    async def notify_user(self, user_id: str, payload: dict):
        conns = list(self._by_user_id.get(user_id, []))
        for ws in conns:
            try:
                await ws.send_json(payload)
            except Exception:
                self.disconnect(user_id, ws)


hub = NotificationHub()


def user_from_token_or_401(token: str, db: Session) -> User:
    cred_exc = HTTPException(status_code=401, detail="Invalid websocket token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_str: str = payload.get("sub")
        if not user_id_str:
            raise cred_exc
        user_id = uuid.UUID(user_id_str)
    except Exception:
        raise cred_exc
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise cred_exc
    return user


@app.websocket("/ws/notifications")
async def ws_notifications(websocket: WebSocket, token: str = Query(...)):
    db = SessionLocal()
    user: User | None = None
    try:
        user = user_from_token_or_401(token, db)
        user_id = str(user.id)
        await hub.connect(user_id, websocket)
        await hub.notify_user(
            user_id,
            {"type": "ws_connected", "message": "Notification channel connected"},
        )
        while True:
            # Receive keepalive pings from client.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await websocket.close(code=1008)
        except Exception:
            pass
    finally:
        if user is not None:
            hub.disconnect(str(user.id), websocket)
        db.close()

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
async def create_sos(
    sos: SOSCreate,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    source_type = infer_source_type(request.headers.get("user-agent"))
    alert = SOSAlert(
        user_id=user.id,
        latitude=sos.latitude,
        longitude=sos.longitude,
        source_type=source_type,
        source_device_uid=None,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    await hub.notify_user(
        str(user.id),
        {
            "type": "sos_created",
            "sos_id": str(alert.id),
            "user_id": str(user.id),
            "source_type": alert.source_type or "app",
            "source_device_uid": alert.source_device_uid,
            "latitude": alert.latitude,
            "longitude": alert.longitude,
            "status": alert.status,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        },
    )
    return alert

@app.get("/sos/my-alerts")
def my_alerts(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return (
        db.query(SOSAlert)
        .filter(SOSAlert.user_id == user.id)
        .order_by(SOSAlert.created_at.desc())
        .all()
    )

@app.post("/devices/link")
def link_device(data: DeviceLinkRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    device_uid = data.device_uid.strip()
    if not device_uid:
        raise HTTPException(status_code=400, detail="device_uid is required")

    device = db.query(Device).filter(Device.device_uid == device_uid).first()
    if device:
        if device.owner_user_id and device.owner_user_id != user.id:
            raise HTTPException(status_code=409, detail="Device is already linked to another user")
        device.owner_user_id = user.id
        if data.device_name:
            device.device_name = data.device_name
        if not device.device_token:
            device.device_token = generate_device_token()
    else:
        device = Device(
            device_uid=device_uid,
            device_name=data.device_name,
            device_token=generate_device_token(),
            owner_user_id=user.id,
        )
        db.add(device)

    db.commit()
    db.refresh(device)
    return {
        "device_uid": device.device_uid,
        "device_name": device.device_name,
        "device_token": device.device_token,
        "owner_user_id": device.owner_user_id,
        "last_seen_at": device.last_seen_at,
    }

@app.get("/devices/my")
def my_devices(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    devices = db.query(Device).filter(Device.owner_user_id == user.id).order_by(Device.created_at.desc()).all()
    return [
        {
            "device_uid": d.device_uid,
            "device_name": d.device_name,
            "device_token": d.device_token,
            "last_seen_at": d.last_seen_at,
            "created_at": d.created_at,
        }
        for d in devices
    ]

@app.post("/devices/send-coordinates")
async def send_coordinates_to_device(
    payload: DeviceCoordinateCommandCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    device_uid = payload.device_uid.strip()
    if not device_uid:
        raise HTTPException(status_code=400, detail="device_uid is required")

    device = db.query(Device).filter(Device.device_uid == device_uid).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.owner_user_id != user.id:
        raise HTTPException(status_code=403, detail="You can only command your own device")

    # Keep queue small: keep only latest pending command per device.
    (
        db.query(DeviceCommand)
        .filter(
            DeviceCommand.device_uid == device_uid,
            DeviceCommand.owner_user_id == user.id,
            DeviceCommand.status == "pending",
        )
        .delete(synchronize_session=False)
    )

    cmd = DeviceCommand(
        device_uid=device_uid,
        owner_user_id=user.id,
        latitude=payload.latitude,
        longitude=payload.longitude,
        status="pending",
    )
    db.add(cmd)
    db.commit()
    db.refresh(cmd)

    await hub.notify_user(
        str(user.id),
        {
            "type": "device_command_created",
            "command_id": str(cmd.id),
            "device_uid": device_uid,
            "latitude": cmd.latitude,
            "longitude": cmd.longitude,
            "status": cmd.status,
        },
    )

    return {
        "message": "Coordinates queued for device",
        "command_id": str(cmd.id),
        "device_uid": device_uid,
        "latitude": cmd.latitude,
        "longitude": cmd.longitude,
        "status": cmd.status,
    }

@app.post("/devices/unlink")
def unlink_my_device(data: DeviceUnlinkRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    device_uid = data.device_uid.strip()
    if not device_uid:
        raise HTTPException(status_code=400, detail="device_uid is required")

    device = db.query(Device).filter(Device.device_uid == device_uid).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.owner_user_id != user.id:
        raise HTTPException(status_code=403, detail="You can only unlink your own device")

    device.owner_user_id = None
    device.device_token = generate_device_token()
    db.commit()
    db.refresh(device)

    return {
        "message": "Device disconnected",
        "device_uid": device.device_uid,
        "new_device_token": device.device_token,
    }

@app.post("/device/commands/next")
def get_next_device_command(
    payload: DeviceCommandPullRequest,
    db: Session = Depends(get_db),
):
    device_uid = payload.device_uid.strip()
    device = db.query(Device).filter(Device.device_uid == device_uid).first()
    if not device:
        raise HTTPException(status_code=404, detail="Unknown device")
    if device.device_token != payload.device_token:
        raise HTTPException(status_code=401, detail="Invalid device token")
    if not device.owner_user_id:
        raise HTTPException(status_code=400, detail="Device is not linked to a user")

    cmd = (
        db.query(DeviceCommand)
        .filter(DeviceCommand.device_uid == device_uid, DeviceCommand.status == "pending")
        .order_by(DeviceCommand.created_at.asc())
        .first()
    )
    if not cmd:
        return {"has_command": False}

    cmd.status = "delivered"
    cmd.delivered_at = datetime.utcnow()
    db.commit()
    db.refresh(cmd)

    return {
        "has_command": True,
        "command": {
            "id": str(cmd.id),
            "latitude": cmd.latitude,
            "longitude": cmd.longitude,
            "created_at": cmd.created_at.isoformat() if cmd.created_at else None,
        },
    }

@app.post("/device/alerts/device-active")
def get_active_device_alert_state(
    payload: DeviceCommandPullRequest,
    db: Session = Depends(get_db),
):
    device_uid = payload.device_uid.strip()
    device = db.query(Device).filter(Device.device_uid == device_uid).first()
    if not device:
        raise HTTPException(status_code=404, detail="Unknown device")
    if device.device_token != payload.device_token:
        raise HTTPException(status_code=401, detail="Invalid device token")
    if not device.owner_user_id:
        raise HTTPException(status_code=400, detail="Device is not linked to a user")

    owner_user = db.query(User).filter(User.id == device.owner_user_id).first()
    if not owner_user:
        raise HTTPException(status_code=404, detail="Device owner not found")

    connected_user_ids = connected_user_ids_for_emergency(owner_user, db)
    alert = (
        db.query(SOSAlert)
        .filter(
            SOSAlert.user_id.in_(connected_user_ids),
            SOSAlert.status == "active",
        )
        .order_by(SOSAlert.created_at.desc())
        .first()
    )

    if not alert:
        return {
            "has_active_device_alert": False,
            "has_active_alert": False,
            "connected_users_count": len(connected_user_ids),
            "alert": None,
        }

    return {
        "has_active_device_alert": True,
        "has_active_alert": True,
        "connected_users_count": len(connected_user_ids),
        "alert": {
            "id": str(alert.id),
            "user_id": str(alert.user_id) if alert.user_id else None,
            "source_device_uid": alert.source_device_uid,
            "source_type": alert.source_type or "app",
            "latitude": alert.latitude,
            "longitude": alert.longitude,
            "status": alert.status,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
            "is_from_this_device": (alert.source_device_uid or "") == device.device_uid,
        },
    }

@app.post("/device/sos")
async def create_sos_from_device(payload: DeviceSOSCreate, db: Session = Depends(get_db)):
    device_uid = payload.device_uid.strip()
    device = db.query(Device).filter(Device.device_uid == device_uid).first()
    if not device:
        raise HTTPException(status_code=404, detail="Unknown device")
    if device.device_token != payload.device_token:
        raise HTTPException(status_code=401, detail="Invalid device token")
    if not device.owner_user_id:
        raise HTTPException(status_code=400, detail="Device is not linked to a user")

    alert = SOSAlert(
        user_id=device.owner_user_id,
        latitude=payload.latitude,
        longitude=payload.longitude,
        source_type="device",
        source_device_uid=device.device_uid,
    )
    db.add(alert)
    device.last_seen_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)

    await hub.notify_user(
        str(device.owner_user_id),
        {
            "type": "sos_created",
            "sos_id": str(alert.id),
            "user_id": str(device.owner_user_id),
            "source_type": "device",
            "source_device_uid": device.device_uid,
            "latitude": alert.latitude,
            "longitude": alert.longitude,
            "status": alert.status,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        },
    )

    return {
        "message": "SOS received from device",
        "sos_id": alert.id,
        "user_id": device.owner_user_id,
        "device_uid": device.device_uid,
        "source_type": "device",
    }

# ---------------- ADMIN ROUTES ----------------

@app.get("/admin/all-alerts")
def get_all_alerts(
    admin_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_admin(admin_user)
    rows = (
        db.query(SOSAlert, User)
        .join(User, SOSAlert.user_id == User.id)
        .order_by(SOSAlert.created_at.desc())
        .all()
    )
    return [
        {
            "id": alert.id,
            "user_id": alert.user_id,
            "full_name": user.full_name,
            "phone": user.phone,
            "user": {
                "id": user.id,
                "full_name": user.full_name,
                "blood_type": user.blood_type,
                "phone": user.phone,
                "emergency_contact": user.emergency_contact,
                "role": user.role,
            },
            "latitude": alert.latitude,
            "longitude": alert.longitude,
            "source_type": alert.source_type or "app",
            "source_device_uid": alert.source_device_uid,
            "status": alert.status,
            "created_at": alert.created_at,
        }
        for alert, user in rows
    ]

@app.put("/admin/alerts/{alert_id}/deactivate")
def deactivate_alert(
    alert_id: str,
    admin_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_admin(admin_user)
    try:
        alert_uuid = uuid.UUID(alert_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert id")

    alert = db.query(SOSAlert).filter(SOSAlert.id == alert_uuid).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = "inactive"
    db.commit()
    db.refresh(alert)
    return {"message": "Alert deactivated", "id": alert.id, "status": alert.status}

@app.delete("/admin/alerts/{alert_id}")
def delete_alert(
    alert_id: str,
    admin_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_admin(admin_user)
    try:
        alert_uuid = uuid.UUID(alert_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert id")

    alert = db.query(SOSAlert).filter(SOSAlert.id == alert_uuid).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    db.delete(alert)
    db.commit()
    return {"message": "Alert deleted", "id": str(alert_uuid)}

@app.post("/admin/devices/unlink")
def admin_unlink_device(
    data: AdminDeviceUnlinkRequest,
    admin_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_admin(admin_user)

    device_uid = data.device_uid.strip()
    if not device_uid:
        raise HTTPException(status_code=400, detail="device_uid is required")

    device = db.query(Device).filter(Device.device_uid == device_uid).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    previous_owner = str(device.owner_user_id) if device.owner_user_id else None
    device.owner_user_id = None
    if data.rotate_token:
        device.device_token = generate_device_token()
    db.commit()
    db.refresh(device)

    return {
        "message": "Device unlinked",
        "device_uid": device.device_uid,
        "previous_owner_user_id": previous_owner,
        "rotate_token": data.rotate_token,
        "device_token": device.device_token,
    }

@app.get("/admin/user/{user_id}")
def get_user_for_admin(
    user_id: str,
    admin_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_admin(admin_user)
    try:
        user_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user id")

    user = db.query(User).filter(User.id == user_uuid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "id": user.id,
        "full_name": user.full_name,
        "blood_type": user.blood_type,
        "phone": user.phone,
        "emergency_contact": user.emergency_contact,
        "role": user.role,
    }

# --- ADDED: GEMINI ANALYSIS ROUTE ---

import time # Add at top

@app.post("/admin/analyze-location")
async def analyze_location(
    data: dict = Body(...),
    admin_user: User = Depends(get_current_user),
):
    require_admin(admin_user)
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
