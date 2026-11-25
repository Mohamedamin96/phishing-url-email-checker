from app.api.routes import router
from fastapi import FastAPI

app=FastAPI(title="Phishing URL & Email Checker")
app.include_router(router,prefix="/api")
