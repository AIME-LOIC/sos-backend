from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel
from app.database import SessionLocal
from app.models import SOSAlert
from app.auth import get_current_user
from app.routes.ws import manager 
router = APIRouter()

# -------------------
# Schemas
# -------------------
class SOSCreate(BaseModel):
    latitude: float
    longitude: float

class SOSUpdateStatus(BaseModel):
    status: str  # e.g., "active", "resolved"

# -------------------
# DB Dependency
# -------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -------------------
# Trigger SOS (authenticated users)
# -------------------
 # import ConnectionManager

import asyncio
# ConnectionManager

@router.post("/trigger")
def trigger_sos(
    alert: SOSCreate,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    sos = SOSAlert(
        user_id=current_user.id,
        latitude=alert.latitude,
        longitude=alert.longitude
    )
    db.add(sos)
    db.commit()
    db.refresh(sos)

    asyncio.create_task(manager.broadcast({
        "sos_id": str(sos.id),
        "user_id": str(current_user.id),
        "latitude": sos.latitude,
        "longitude": sos.longitude,
        "status": sos.status,
        "created_at": str(sos.created_at)
    }))

    return {"status": "SOS triggered", "sos_id": sos.id}



# -------------------
# Get all SOS (admin only)
# -------------------
@router.get("/all", response_model=List[dict])
def get_all_sos_alerts(
    status: str = Query(default=None, description="Filter by status: active/resolved"),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    query = db.query(SOSAlert)
    if status:
        query = query.filter(SOSAlert.status == status)
    alerts = query.all()

    return [
        {
            "sos_id": a.id,
            "user_id": a.user_id,
            "latitude": a.latitude,
            "longitude": a.longitude,
            "status": a.status,
            "created_at": a.created_at
        } for a in alerts
    ]

# -------------------
# Update SOS Status (admin only)
# -------------------
@router.put("/update/{sos_id}")
def update_sos_status(
    sos_id: str,
    update: SOSUpdateStatus,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    sos = db.query(SOSAlert).filter(SOSAlert.id == sos_id).first()
    if not sos:
        raise HTTPException(status_code=404, detail="SOS alert not found")

    sos.status = update.status
    db.commit()
    db.refresh(sos)
    return {"msg": "SOS status updated", "sos_id": sos.id, "new_status": sos.status}

# -------------------
# Get SOS for Current User
# -------------------
@router.get("/my-alerts", response_model=List[dict])
def get_my_sos_alerts(
    status: str = Query(default=None, description="Filter by status: active/resolved"),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(SOSAlert).filter(SOSAlert.user_id == current_user.id)
    if status:
        query = query.filter(SOSAlert.status == status)
    alerts = query.all()

    return [
        {
            "sos_id": a.id,
            "latitude": a.latitude,
            "longitude": a.longitude,
            "status": a.status,
            "created_at": a.created_at
        } for a in alerts
    ]
