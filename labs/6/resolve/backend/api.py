import os
from pathlib import Path

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

import jwt as auth

CAT = Path("/app/data/cat.jpg")
REFRESH_COOKIE = "refresh_token"
FRONTEND_ORIGINS = [
    o.strip()
    for o in os.getenv("FRONTEND_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
    if o.strip()
]
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"

app = FastAPI(title="Lab6 JWT")
app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AuthIn(BaseModel):
    username: str
    password: str


class RevokeIn(BaseModel):
    username: str


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        REFRESH_COOKIE,
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=auth.REFRESH_SEC,
        path="/",
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(REFRESH_COOKIE, path="/")


@app.on_event("startup")
def startup() -> None:
    auth.init_admin()


def bearer(authorization: str | None = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Нужна авторизация")
    p = auth.verify(authorization[7:], "access")
    if not p:
        raise HTTPException(401, "Токен недействителен")
    return p


def admin(user: dict = Depends(bearer)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(403, "Только админ")
    return user


@app.post("/register")
def register(body: AuthIn) -> dict:
    try:
        auth.register(body.username, body.password)
    except ValueError:
        raise HTTPException(400, "Пользователь уже существует")
    return {"ok": True}


@app.post("/login")
def login(body: AuthIn, response: Response) -> dict:
    role = auth.auth(body.username, body.password)
    if not role:
        raise HTTPException(401, "Неверный логин или пароль")
    access, refresh = auth.issue(body.username, role)
    _set_refresh_cookie(response, refresh)
    return {"access": access, "role": role}


@app.post("/refresh")
def refresh_token(
    response: Response,
    refresh_token: str | None = Cookie(None, alias=REFRESH_COOKIE),
) -> dict:
    if not refresh_token:
        raise HTTPException(401, "Refresh cookie отсутствует")
    pair = auth.refresh(refresh_token)
    if not pair:
        _clear_refresh_cookie(response)
        raise HTTPException(401, "Refresh недействителен")
    access, refresh = pair
    _set_refresh_cookie(response, refresh)
    p = auth.verify(access, "access")
    return {"access": access, "role": p["role"] if p else "user"}


@app.post("/logout")
def logout(
    response: Response,
    user: dict = Depends(bearer),
    refresh_token: str | None = Cookie(None, alias=REFRESH_COOKIE),
) -> dict:
    if refresh_token:
        auth.blacklist(refresh_token, "refresh")
    _clear_refresh_cookie(response)
    return {"ok": True}


@app.get("/me")
def me(user: dict = Depends(bearer)) -> dict:
    return {"username": user["sub"], "role": user["role"]}


@app.get("/cat")
def cat(_user: dict = Depends(bearer)) -> FileResponse:
    if not CAT.exists():
        raise HTTPException(500, "Картинка не найдена")
    return FileResponse(CAT, media_type="image/jpeg")


@app.get("/admin/users")
def users(_admin: dict = Depends(admin)) -> dict:
    return {"users": auth.list_users()}


@app.post("/admin/revoke")
def revoke(body: RevokeIn, _admin: dict = Depends(admin)) -> dict:
    auth.revoke_user(body.username)
    return {"ok": True, "username": body.username}
