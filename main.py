from fastapi import FastAPI
from app.api.routes import router
app=FastAPI(title="Phishing URL & Email Checker")
app.include_router(router,prefix="/api")
