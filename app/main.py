from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from . import models, schemas
from .database import engine, SessionLocal, get_db
from .rules import sync_rules_to_db

models.Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    db = SessionLocal()
    try:
        sync_rules_to_db(db)
        yield
    finally:
        db.close()

app = FastAPI(title="Kube Risk Analyzer API", lifespan=lifespan)

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/rules", response_model=list[schemas.RiskRuleSchema])
def get_rules(db: Session = Depends(get_db)):
    rules = db.query(models.RiskRule).all()
    return rules
