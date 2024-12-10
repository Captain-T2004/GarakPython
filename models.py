from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from database import Base
from typing import List, Optional
import datetime

class Scan(BaseModel):
    model_type: str
    model_name: str
    probe_list: List[str] = None
    report_name: Optional[str] = None
    scan_id: Optional[str] = None

# SQLAlchemy User Model
class UserModel(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    scans = relationship("ScanHistoryModel", back_populates="user")

# SQLAlchemy Scan History Model
class ScanHistoryModel(Base):
    __tablename__ = "scan_history"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, unique=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    model_type = Column(String)
    model_name = Column(String)
    probe_list = Column(JSON)
    status = Column(String)
    results = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    report_name = Column(String)
    
    user = relationship("UserModel", back_populates="scans")

# Pydantic Models for Request/Response
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str

class ScanCreate(Scan):
    user_id: int

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    model_type: str
    model_name: str