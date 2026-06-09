from datetime import datetime
from pydantic import BaseModel, ConfigDict
from typing import Optional, List

class RiskRuleBase(BaseModel):
    description: str
    dangerous_verbs: Optional[str] = None
    dangerous_resources: Optional[str] = None
    category: str = "rbac"
    key: Optional[str] = None

class RiskRuleCreate(RiskRuleBase):
    pass

class RiskRuleSchema(RiskRuleBase):
    id: int
    model_config = ConfigDict(from_attributes=True)


class FindingBase(BaseModel):
    subject: str
    role: str
    risk_description: str

class FindingCreate(FindingBase):
    pass

class FindingSchema(FindingBase):
    id: int
    scan_id: int
    model_config = ConfigDict(from_attributes=True)


class ScanHistoryBase(BaseModel):
    target_name: str

class ScanHistoryCreate(ScanHistoryBase):
    pass

class ScanHistorySchema(ScanHistoryBase):
    id: int
    scan_date: datetime
    findings: List[FindingSchema] = []
    model_config = ConfigDict(from_attributes=True)
