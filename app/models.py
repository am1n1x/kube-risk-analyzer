from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from .database import Base

class RiskRule(Base):
    __tablename__ = "risk_rules"

    id = Column(Integer, primary_key=True, index=True)
    description = Column(String)
    dangerous_verbs = Column(String, nullable=True)
    dangerous_resources = Column(String, nullable=True)
    category = Column(String, default="rbac")
    key = Column(String, nullable=True)
    severity = Column(String, default="MEDIUM")
    is_enabled = Column(Boolean, default=True)
    remediation = Column(String, nullable=True)


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    scan_date = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    target_name = Column(String)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_history.id"))
    subject = Column(String)
    role = Column(String)
    risk_description = Column(String)
    severity = Column(String, default="MEDIUM")
    remediation = Column(String, nullable=True)

    scan = relationship("ScanHistory", back_populates="findings")


class BasScript(Base):
    __tablename__ = "bas_scripts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String, nullable=True)
    script_content = Column(String)
    is_default = Column(Boolean, default=False)
    is_enabled = Column(Boolean, default=True)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)

    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")


class Session(Base):
    __tablename__ = "sessions"

    session_id = Column(String, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="sessions")
