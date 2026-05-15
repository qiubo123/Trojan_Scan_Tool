from datetime import datetime, timedelta
from fastapi import APIRouter, Request
from pydantic import BaseModel

from server.core.database import (
    get_conn, hash_password, verify_password, generate_token,
    verify_session, add_audit_log, SESSION_EXPIRE_HOURS
)

router = APIRouter(prefix="/api/v1", tags=["认证"])


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


@router.post("/login")
async def login(req: LoginRequest, request: Request):
    username = req.username.strip()
    password = req.password.strip()
    if not username or not password:
        return {"code": 400, "message": "用户名和密码不能为空"}

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password_hash, role FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()
    conn.close()

    if not row or not verify_password(password, row[0]):
        add_audit_log("", "登录失败", f"用户名: {username}", request.client.host)
        return {"code": 401, "message": "用户名或密码错误"}

    pw_hash, role = row
    token = generate_token()
    now = datetime.now()
    expires = now + timedelta(hours=SESSION_EXPIRE_HOURS)
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    expires_str = expires.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO sessions (token, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token, username, now_str, expires_str)
    )
    conn.commit()
    conn.close()

    add_audit_log(username, "登录成功", "", request.client.host)

    return {
        "code": 0,
        "data": {
            "token": token,
            "username": username,
            "role": role,
            "expires_at": expires_str
        }
    }


@router.post("/change_password")
async def change_password(req: ChangePasswordRequest, request: Request):
    token = request.headers.get("X-Auth-Token", "")
    username = verify_session(token)
    if not username:
        return {"code": 401, "message": "未登录或会话已过期"}

    if not req.old_password or not req.new_password:
        return {"code": 400, "message": "旧密码和新密码不能为空"}
    if len(req.new_password) < 6:
        return {"code": 400, "message": "新密码长度不能少于6位"}

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if not row or not verify_password(req.old_password, row[0]):
        conn.close()
        return {"code": 401, "message": "旧密码错误"}

    cursor.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (hash_password(req.new_password), username)
    )
    cursor.execute("DELETE FROM sessions WHERE username = ?", (username,))
    conn.commit()
    conn.close()

    add_audit_log(username, "修改密码", "", request.client.host)
    return {"code": 0, "message": "密码修改成功，请重新登录"}
