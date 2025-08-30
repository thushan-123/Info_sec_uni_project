# security.py
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from uuid import uuid4

CSRF_SESSION_KEY = "csrf_token"


def get_csrf_token_for_session(request: Request) -> str:
    """
    Generate or retrieve a CSRF token for the current session.
    """
    token = request.session.get(CSRF_SESSION_KEY)
    if not token:
        token = uuid4().hex
        request.session[CSRF_SESSION_KEY] = token
    return token


async def validate_csrf(request: Request):
    """
    Validate CSRF token from form data against session token.
    Should be called in POST endpoints.
    """
    session_token = request.session.get(CSRF_SESSION_KEY)

    # Ensure form is awaited and parsed
    form = await request.form()
    form_token = form.get("csrf_token")

    if not session_token or not form_token or session_token != form_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security-related headers to all responses.
    """
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
            "frame-ancestors 'none';"
        )
        return response
