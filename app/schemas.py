from datetime import datetime
from pydantic import BaseModel, ConfigDict
from typing import Optional, List


# ── RiskRule ──────────────────────────────────────────────────────────────────

class RiskRuleBase(BaseModel):
    description: str
    dangerous_verbs: Optional[str] = None
    dangerous_resources: Optional[str] = None
    category: str = "rbac"
    key: Optional[str] = None
    severity: str = "MEDIUM"

class RiskRuleCreate(RiskRuleBase):
    pass

class RiskRuleUpdate(BaseModel):
    description: Optional[str] = None
    dangerous_verbs: Optional[str] = None
    dangerous_resources: Optional[str] = None
    category: Optional[str] = None
    key: Optional[str] = None
    severity: Optional[str] = None

class RiskRuleSchema(RiskRuleBase):
    id: int
    model_config = ConfigDict(from_attributes=True)


# ── Finding ───────────────────────────────────────────────────────────────────

class FindingBase(BaseModel):
    subject: str
    role: str
    risk_description: str
    severity: str = "MEDIUM"

class FindingCreate(FindingBase):
    pass

class FindingSchema(FindingBase):
    id: int
    scan_id: int
    model_config = ConfigDict(from_attributes=True)


# ── ScanHistory ───────────────────────────────────────────────────────────────

class ScanHistoryBase(BaseModel):
    target_name: str

class ScanHistoryCreate(ScanHistoryBase):
    pass

class ScanHistorySchema(ScanHistoryBase):
    id: int
    scan_date: datetime
    findings: List[FindingSchema] = []
    model_config = ConfigDict(from_attributes=True)


# ── BasScript ─────────────────────────────────────────────────────────────────

class BasScriptBase(BaseModel):
    name: str
    description: Optional[str] = None
    script_content: str

class BasScriptCreate(BasScriptBase):
    pass

class BasScriptUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    script_content: Optional[str] = None

class BasScriptSchema(BasScriptBase):
    id: int
    model_config = ConfigDict(from_attributes=True)


# ── BAS simulate request ──────────────────────────────────────────────────────

class BASSimulateRequest(BaseModel):
    script_id: Optional[int] = None
