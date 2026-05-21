import os
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import redis
from jose import JWTError, jwt

REDIS = os.getenv("REDIS_URL", "redis://redis:6379/0")
SECRET = os.getenv("JWT_SECRET", "lab6-jwt-secret")
ACCESS_SEC = int(os.getenv("ACCESS_TTL_SEC", "60"))
REFRESH_SEC = int(os.getenv("REFRESH_TTL_SEC", "604800"))

db = redis.from_url(REDIS, decode_responses=True)


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def _uk(u: str) -> str:
    return f"user:{u}"


def _bl(jti: str) -> str:
    return f"bl:{jti}"


def _rt(jti: str) -> str:
    return f"rt:{jti}"


def _at(jti: str) -> str:
    return f"at:{jti}"


def init_admin() -> None:
    if not db.exists(_uk("creator")):
        db.hset(_uk("creator"), mapping={"password": _hash("1124816"), "role": "admin"})


def register(username: str, password: str) -> None:
    if db.exists(_uk(username)):
        raise ValueError("exists")
    db.hset(_uk(username), mapping={"password": _hash(password), "role": "user"})


def auth(username: str, password: str) -> str | None:
    u = db.hgetall(_uk(username))
    if not u or not _verify(password, u["password"]):
        return None
    return u["role"]


def _encode(sub: str, role: str, typ: str, jti: str, ttl: timedelta) -> str:
    exp = datetime.now(timezone.utc) + ttl
    return jwt.encode(
        {"sub": sub, "role": role, "type": typ, "jti": jti, "exp": exp},
        SECRET,
        algorithm="HS256",
    )


def issue(sub: str, role: str) -> tuple[str, str]:
    db.delete(f"revoked:{sub}")
    aj, rj = uuid.uuid4().hex, uuid.uuid4().hex
    access = _encode(sub, role, "access", aj, timedelta(seconds=ACCESS_SEC))
    refresh = _encode(sub, role, "refresh", rj, timedelta(seconds=REFRESH_SEC))
    db.setex(_at(aj), ACCESS_SEC + 30, sub)
    db.setex(_rt(rj), REFRESH_SEC, sub)
    return access, refresh


def verify(token: str, typ: str) -> dict | None:
    try:
        p = jwt.decode(token, SECRET, algorithms=["HS256"])
    except JWTError:
        return None
    if p.get("type") != typ:
        return None
    jti = p.get("jti")
    if not jti or db.exists(_bl(jti)):
        return None
    key = _at(jti) if typ == "access" else _rt(jti)
    if not db.exists(key) or db.get(key) != p.get("sub"):
        return None
    if db.exists(f"revoked:{p['sub']}"):
        return None
    return p


def refresh(token: str) -> tuple[str, str] | None:
    p = verify(token, "refresh")
    if not p:
        return None
    db.setex(_bl(p["jti"]), REFRESH_SEC, "1")
    db.delete(_rt(p["jti"]))
    return issue(p["sub"], p["role"])


def blacklist(token: str, typ: str) -> None:
    p = verify(token, typ)
    if not p:
        return
    ttl = ACCESS_SEC + 30 if typ == "access" else REFRESH_SEC
    db.setex(_bl(p["jti"]), ttl, "1")
    db.delete(_at(p["jti"]) if typ == "access" else _rt(p["jti"]))


def list_users() -> list[dict]:
    users = []
    for key in db.scan_iter("user:*"):
        username = key.split(":", 1)[1]
        role = db.hget(key, "role") or "user"
        users.append({"username": username, "role": role})
    return sorted(users, key=lambda u: u["username"])


def revoke_user(username: str) -> None:
    db.setex(f"revoked:{username}", REFRESH_SEC, "1")
    for key in list(db.scan_iter("rt:*")) + list(db.scan_iter("at:*")):
        if db.get(key) == username:
            jti = key.split(":", 1)[1]
            db.setex(_bl(jti), REFRESH_SEC, "1")
            db.delete(key)
