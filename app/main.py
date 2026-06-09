from fastapi import FastAPI
from . import models
from .database import engine

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Kube Risk Analyzer API")

@app.get("/health")
def health_check():
    return {"status": "ok"}
