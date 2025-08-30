from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from itsdangerous import URLSafeSerializer
from uuid import uuid4


CSRF_SESSION_KEY = "csrf_token"




def get_csrf_token_for_session(request: Request) -> str:
    token = request.session.get(CSRF_SESSION_KEY)
    if not token:
        token = uuid4().hex
    request.session[CSRF_SESSION_KEY] = token
    return token




def validate_csrf(request: Request):
    session_token = request.session.get(CSRF_SESSION_KEY)
    form_token = (request.form and request.form().get("csrf_token")) if hasattr(request, "form") else None
    
    if not session_token or not form_token or session_token != form_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "frame-ancestors 'none'"
        )
        return response