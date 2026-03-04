from sqlalchemy import Column, String, Float, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    full_name = Column(String, nullable=False)
    blood_type = Column(String, nullable=False)
    phone = Column(String, nullable=False)
    emergency_contact = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="normal")  # new field for roles
# <- new

class SOSAlert(Base):
    __tablename__ = "sos_alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    status = Column(String, default="active")
    source_type = Column(String, default="app")
    source_device_uid = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Device(Base):
    __tablename__ = "devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_uid = Column(String, unique=True, nullable=False)
    device_name = Column(String, nullable=True)
    device_token = Column(String, nullable=False)
    owner_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
