from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

import jwt as auth

CAT = Path("/app/data/cat.jpg")
app = FastAPI(title="Lab6 JWT")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AuthIn(BaseModel):
    username: str
    password: str


class RefreshIn(BaseModel):
    refresh: str


class RevokeIn(BaseModel):
    username: str


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
def login(body: AuthIn) -> dict:
    role = auth.auth(body.username, body.password)
    if not role:
        raise HTTPException(401, "Неверный логин или пароль")
    access, refresh = auth.issue(body.username, role)
    return {"access": access, "refresh": refresh, "role": role}


@app.post("/refresh")
def refresh_token(body: RefreshIn) -> dict:
    pair = auth.refresh(body.refresh)
    if not pair:
        raise HTTPException(401, "Refresh недействителен")
    access, refresh = pair
    return {"access": access, "refresh": refresh}


@app.post("/logout")
def logout(body: RefreshIn, user: dict = Depends(bearer)) -> dict:
    auth.blacklist(body.refresh, "refresh")
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
