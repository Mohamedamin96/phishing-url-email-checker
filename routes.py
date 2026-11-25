from fastapi import APIRouter
from app.models.schemas import URLRequest,EmailRequest
from app.services.analyzer import analyze_url, analyze_email
router=APIRouter()
@router.get('/health')
def health(): return {'status':'ok'}
@router.post('/analyze/url')
def url(req: URLRequest): return analyze_url(req.url)
@router.post('/analyze/email')
def email(req: EmailRequest): return analyze_email(req.headers)
