from app.models.schemas import EmailRequest, URLRequest
from app.services.analyzer import analyze_email, analyze_url
from fastapi import APIRouter

router=APIRouter()
@router.get('/health')
def health(): return {'status':'ok'}
@router.post('/analyze/url')
def url(req: URLRequest): return analyze_url(req.url)
@router.post('/analyze/email')
def email(req: EmailRequest): return analyze_email(req.headers)
