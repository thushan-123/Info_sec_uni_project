from fastapi import APIRouter, Request, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth
from starlette.datastructures import URL
from .config import settings
from .db import get_session
from .models import User
from sqlmodel import select
from urllib.parse import urlencode


router = APIRouter()


oauth = OAuth()
oauth.register(
    name="auth0",
    client_id=settings.AUTH0_CLIENT_ID,
    client_secret=settings.AUTH0_CLIENT_SECRET,
    client_kwargs={"scope": "openid profile email"},
    server_metadata_url=f"https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration",
)

@router.get("/login")
async def login(request: Request):
    redirect_uri = str(settings.AUTH0_CALLBACK_URL)
    return await oauth.auth0.authorize_redirect(request, redirect_uri)





@router.get("/callback")
async def callback(request: Request, session = Depends(get_session)):
    token = await oauth.auth0.authorize_access_token(request)
    userinfo = token.get("userinfo") or await oauth.auth0.parse_id_token(request, token)


    # Save minimal user record into DB (safe via ORM) — prevents SQL injection
    auth0_sub = userinfo.get("sub")
    email = userinfo.get("email")


    from datetime import datetime
    db_user = session.exec(select(User).where(User.auth0_sub == auth0_sub)).first()
    if not db_user:
        db_user = User(auth0_sub=auth0_sub, email=email)
        session.add(db_user)
    else:
        db_user.email = email or db_user.email
        db_user.updated_at = datetime.utcnow()
    session.commit()



    request.session["user"] = {
    "sub": auth0_sub,
    "email": email,
    "name": userinfo.get("name"),
    "picture": userinfo.get("picture"),
    }
    return RedirectResponse(url="/profile", status_code=302)




@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    params = {
        "client_id": settings.AUTH0_CLIENT_ID,
        "returnTo": str(request.url_for("index"))
    }
    url = f"https://{settings.AUTH0_DOMAIN}/v2/logout?{urlencode(params)}"
    return RedirectResponse(url=url)





def require_user(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Login required")
    return user