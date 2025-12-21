from pydantic import BaseModel
from uuid import UUID

class UserCreate(BaseModel):
    full_name: str
    blood_type: str
    phone: str
    emergency_contact: str
    password: str  # <- new

class UserLogin(BaseModel):
    phone: str
    password: str


class SOSCreate(BaseModel):
    latitude: float
    longitude: float
