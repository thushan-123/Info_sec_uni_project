from fastapi import FastAPI, HTTPException, Request, Depends, Form
from fastapi.concurrency import asynccontextmanager
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from .config import settings
from .db import init_db, get_session
from .models import User
from .auth import router as auth_router, require_user
from .security import validate_csrf, csrf_token_dependency
from sqlmodel import select
from datetime import datetime
import os, pathlib
from sqlmodel import SQLModel
from fastapi_csrf_protect import CsrfProtect


@asynccontextmanager
async def lifespan(app: FastAPI):
    
    init_db() 
    yield
    

app = FastAPI(title="FastAPI + Auth0 (SQLite)", version="1.0.0", lifespan=lifespan)

# addin middlewere
app.add_middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET, same_site="lax", https_only=False)



app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

app.include_router(auth_router)

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, session= Depends(get_session)):
    user = request.session.get("user")

    db_user = None
    if user:
        db_user = session.exec(select(User).where(User.auth0_sub == user.get("sub"))).first()

    safe_user = {
        "name": f"{db_user.first_name} {db_user.last_name}" if db_user else user.get("name") if user else None,
        "email": user.get("email") if user else None,
        "picture": user.get("picture") if user else None
    } if user else None

    return templates.TemplateResponse("index.html", {"request": request, "user": safe_user})


@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request, session=Depends(get_session), csrf_token: str = Depends(csrf_token_dependency)):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")

    db_user = session.exec(select(User).where(User.auth0_sub == user.get("sub"))).first()

    safe_user = {
        "name": f"{db_user.first_name} {db_user.last_name}" if db_user else user.get("name"),
        "email": user.get("email"),
        "picture": user.get("picture"),
        "csrf_token": csrf_token
    }

    return templates.TemplateResponse(
        "profile.html",
        {"request": request, "user": safe_user}
    )


@app.post("/profile/update")
async def update_profile(
    request: Request,
    first_name: str = Form(...),
    last_name: str = Form(...),
    session = Depends(get_session)
):
    await validate_csrf(request)

    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")

    auth0_sub = user.get("sub")
    db_user = session.exec(select(User).where(User.auth0_sub == auth0_sub)).first()

    if not db_user:
        db_user = User(auth0_sub=auth0_sub, email=user.get("email"))

    db_user.first_name = first_name
    db_user.last_name = last_name
    db_user.updated_at = datetime.utcnow()

    session.add(db_user)
    session.commit()

    request.session["user"]["first_name"] = first_name
    request.session["user"]["last_name"] = last_name

    return RedirectResponse(url="/profile", status_code=303)



base_html = r"""



<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{% block title %}SE/2021/011 H.T.Madhusankha + Auth0{% endblock %}</title>
    <link rel="stylesheet" href="/static/style.css" />
</head>

<body>
    <header class="container">
        <h1>SE/2021/011 H.T.Madhusankha Auth0 + SQLite</h1>
        <nav>
            <a href="/">Home</a>
            {% if user %}
            <a href="/profile">Profile</a>
            <a href="/logout">Logout</a>
            {% else %}
            <a href="/login">Login</a>
            {% endif %}
        </nav>
    </header>
    <main class="container">
        {% block content %}{% endblock %}
    </main>
</body>

</html>
"""

with open("app/templates/index.html", "r") as f:
    index_html =f.read()

with open("app/templates/profile.html", "r") as f:
    profile_html =f.read()


style_css = r"""
    :root { font-family: system-ui, Arial, sans-serif; }
    .container { max-width: 860px; margin: 1rem auto; padding: 0 1rem; }
    header { display: flex; align-items: center; justify-content: space-between; }
    nav a { margin-right: 1rem; }
    form { display: grid; gap: 0.75rem; max-width: 420px; }
    label { display: grid; gap: 0.25rem; }
    input, button { padding: 0.5rem; font-size: 1rem; }
    button { cursor: pointer; }
    .error { color: #b00020; }
    .success { color: #0a7d00; }
    img { box-shadow: 0 2px 8px rgba(0,0,0,.15); }
"""


PORT = settings.PORT
if __name__ == "__main__":

    base = pathlib.Path(__file__).resolve().parent
    (base / "templates").mkdir(parents=True, exist_ok=True)
    (base / "static").mkdir(parents=True, exist_ok=True)
    (base / "templates" / "base.html").write_text(base_html, encoding="utf-8")
    (base / "templates" / "index.html").write_text(index_html, encoding="utf-8")
    (base / "templates" / "profile.html").write_text(profile_html, encoding="utf-8")
    (base / "static" / "style.css").write_text(style_css, encoding="utf-8")

    print(f"run server in 127.0.0.1:{PORT}")
    
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=PORT, reload=True)




