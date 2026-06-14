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

    scan = relationship("ScanHistory", back_populates="findings")


class BasScript(Base):
    __tablename__ = "bas_scripts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String, nullable=True)
    script_content = Column(String)
    is_default = Column(Boolean, default=False)
    is_enabled = Column(Boolean, default=True)
