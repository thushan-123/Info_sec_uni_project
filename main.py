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
from datetime import datetime
import os, pathlib
import uvicorn

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


@app.post("/profile/update")
async def update_profile(
        request: Request,
        first_name: str = Form(""),
        last_name: str = Form(""),
        age: int | None = Form(None),
        csrf_token: str = Form(...),
        session=Depends(get_session),
        user=Depends(require_user),
    ):
    #chek csrf tkn
    expected = request.session.get("csrf_token")
    if not expected or expected != csrf_token:
        return RedirectResponse("/profile?e=csrf", status_code=303)


    def sanitize(s: str) -> str:
        return s.strip()[:100]


    first_name = sanitize(first_name)
    last_name = sanitize(last_name)
    age = age if age is None else max(0, min(150, age))



    db_user = session.exec(select(User).where(User.auth0_sub == user["sub"])).first()
    if not db_user:
        db_user = User(auth0_sub=user["sub"], email=user.get("email"))
    session.add(db_user)


    db_user.first_name = first_name
    db_user.last_name = last_name
    db_user.age = age
    db_user.updated_at = datetime.utcnow()


    session.add(db_user)
    session.commit()


    return RedirectResponse("/profile?s=1", status_code=303)

base_html = r"""
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{% block title %}FastAPI + Auth0{% endblock %}</title>
    <link rel="stylesheet" href="/static/style.css" />
</head>

<body>
    <header class="container">
        <h1>FastAPI + Auth0 + SQLite</h1>
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
index_html = r"""
{% extends 'base.html' %}
{% block title %}Home — FastAPI + Auth0{% endblock %}
{% block content %}
{% if user %}
<p>Welcome, {{ user.name or user.email }}!</p>
<img src="{{ user.picture }}" alt="avatar" style="max-height:64px;border-radius:50%" />
{% else %}
<p>Please <a href="/login">log in</a> to manage your profile.</p>
{% endif %}
{% endblock %}
"""

profile_html = r"""

    {% extends 'base.html' %}
{% block title %}Your Profile{% endblock %}
{% block content %}
<h2>Authenticated User</h2>
<ul>
    <li><strong>Auth0 sub:</strong> {{ auth.sub }}</li>
    <li><strong>Email:</strong> {{ auth.email }}</li>
</ul>


<h2>Local Profile</h2>
{% if request.query_params.get('e') == 'csrf' %}
<p class="error">CSRF validation failed. Please try again.</p>
{% elif request.query_params.get('s') %}
<p class="success">Profile updated.</p>
{% endif %}


<form method="post" action="/profile/update">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
    <label>First name
        <input type="text" name="first_name" value="{{ db_user.first_name if db_user else '' }}" maxlength="100"
            required />
    </label>
    <label>Last name
        <input type="text" name="last_name" value="{{ db_user.last_name if db_user else '' }}" maxlength="100"
            required />
    </label>
    <label>Age
        <input type="number" name="age" value="{{ db_user.age if db_user and db_user.age is not none else '' }}" min="0"
            max="150" />
    </label>
    <button type="submit">Save</button>
</form>


<details>
    <summary>Raw DB row (for debugging)</summary>
    <pre>{{ db_user | tojson(indent=2) }}</pre>
</details>
{% endblock %}
"""

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


if __name__ == "__main__":

    base = pathlib.Path(__file__).resolve().parent
    (base / "templates").mkdir(parents=True, exist_ok=True)
    (base / "static").mkdir(parents=True, exist_ok=True)
    (base / "templates" / "base.html").write_text(base_html, encoding="utf-8")
    (base / "templates" / "index.html").write_text(index_html, encoding="utf-8")
    (base / "templates" / "profile.html").write_text(profile_html, encoding="utf-8")
    (base / "static" / "style.css").write_text(style_css, encoding="utf-8")
    
    print("run server in 127.0.0.1:8000 ")
    uvicorn.run(port=8000,host="127.0.0.1", reload=True)



