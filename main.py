from fastapi import FastAPI, Request, Depends, Form
from fastapi.concurrency import asynccontextmanager
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from .config import settings
from .db import init_db, get_session
from .models import User
from .auth import router as auth_router, require_user
from .security import SecurityHeadersMiddleware, get_csrf_token_for_session
from sqlmodel import select

@asynccontextmanager
async def lifespan(app: FastAPI):     #cret the db tables
    await init_db()
    yield
    


app = FastAPI(title="FastAPI + Auth0 (SQLite)", version="1.0.0", lifespan=lifespan)

# addin middlewere
app.add_middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET, same_site="lax", https_only=False)
app.add_middleware(SecurityHeadersMiddleware)


#html sttic file jinja template

app.mount("/static", StaticFiles(directory="./static"), name="static")
templates = Jinja2Templates(directory="./templates")

app.include_router(auth_router)

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = request.session.get("user")
    return templates.TemplateResponse("index.html", {"request": request, "user": user})


@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request, session=Depends(get_session), user=Depends(require_user)):
    
    db_user = session.exec(select(User).where(User.auth0_sub == user["sub"])).first()
    csrf_token = get_csrf_token_for_session(request)
    return templates.TemplateResponse(
        "profile.html",
        {
        "request": request,
        "auth": user,
        "db_user": db_user,
        "csrf_token": csrf_token,
        },
    )




