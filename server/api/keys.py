from datetime import datetime
from fastapi import APIRouter, Request
from pydantic import BaseModel

from server.core.database import get_conn, dict_fetch_all, add_audit_log
from server.core.auth import require_auth


router = APIRouter(prefix="/api/v1/keys", tags=["密钥管理"])
MAX_KEYS = 20


class AddKeyRequest(BaseModel):
    purpose: str
    api_key: str = ""


class UpdateKeyRequest(BaseModel):
    purpose: str = ""
    api_key: str = ""


@router.get("/")
async def list_keys(request: Request):
    await require_auth(request)
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM api_keys ORDER BY id DESC")
    keys = dict_fetch_all(cursor)
    conn.close()
    return {"code": 0, "data": {"keys": keys, "total": len(keys), "max": MAX_KEYS}}


@router.post("/")
async def add_key(req: AddKeyRequest, request: Request):
    username = await require_auth(request)

    purpose = req.purpose.strip()
    if not purpose:
        return {"code": 400, "message": "用途不能为空"}

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM api_keys")
    count = cursor.fetchone()[0]
    if count >= MAX_KEYS:
        conn.close()
        return {"code": 400, "message": f"密钥数量已达上限（{MAX_KEYS}个），请先删除其他密钥再添加"}

    new_key = req.api_key.strip()
    if not new_key:
        import secrets
        import string
        alphabet = string.ascii_lowercase + string.digits
        new_key = "".join(secrets.choice(alphabet) for _ in range(10))

    if len(new_key) != 10:
        conn.close()
        return {"code": 400, "message": "密钥长度必须为10位"}

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO api_keys (purpose, api_key, created_at) VALUES (?, ?, ?)",
        (purpose, new_key, now)
    )
    key_id = cursor.lastrowid
    conn.commit()
    conn.close()

    client_ip = request.client.host if request.client else ""
    add_audit_log(username, "添加API密钥", f"用途: {purpose}, ID: {key_id}", client_ip)

    return {"code": 0, "data": {"id": key_id, "api_key": new_key, "purpose": purpose, "created_at": now}, "message": "密钥添加成功"}


@router.put("/{key_id}")
async def update_key(key_id: int, req: UpdateKeyRequest, request: Request):
    username = await require_auth(request)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        return {"code": 404, "message": "密钥不存在"}

    purpose = req.purpose.strip()
    new_key = req.api_key.strip()

    if not purpose and not new_key:
        conn.close()
        return {"code": 400, "message": "用途和密钥不能同时为空"}

    if purpose and new_key:
        if len(new_key) != 10:
            conn.close()
            return {"code": 400, "message": "密钥长度必须为10位"}
        cursor.execute(
            "UPDATE api_keys SET purpose = ?, api_key = ? WHERE id = ?",
            (purpose, new_key, key_id)
        )
        detail = f"用途: {purpose}, 密钥已更新"
    elif purpose:
        cursor.execute(
            "UPDATE api_keys SET purpose = ? WHERE id = ?",
            (purpose, key_id)
        )
        detail = f"用途: {purpose}"
    else:
        if len(new_key) != 10:
            conn.close()
            return {"code": 400, "message": "密钥长度必须为10位"}
        cursor.execute(
            "UPDATE api_keys SET api_key = ? WHERE id = ?",
            (new_key, key_id)
        )
        detail = "密钥已重置"

    conn.commit()
    conn.close()

    client_ip = request.client.host if request.client else ""
    add_audit_log(username, "更新API密钥", f"ID: {key_id}, {detail}", client_ip)

    return {"code": 0, "message": "密钥更新成功"}


@router.delete("/{key_id}")
async def delete_key(key_id: int, request: Request):
    username = await require_auth(request)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT purpose, api_key FROM api_keys WHERE id = ?", (key_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return {"code": 404, "message": "密钥不存在"}

    purpose, api_key = row
    cursor.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()

    client_ip = request.client.host if request.client else ""
    add_audit_log(username, "删除API密钥", f"ID: {key_id}, 用途: {purpose}", client_ip)

    return {"code": 0, "message": "密钥已删除"}


@router.post("/generate")
async def generate_key(request: Request, body: AddKeyRequest):
    username = await require_auth(request)

    purpose = body.purpose.strip()
    if not purpose:
        return {"code": 400, "message": "用途不能为空"}

    import secrets
    import string
    alphabet = string.ascii_lowercase + string.digits
    new_key = "".join(secrets.choice(alphabet) for _ in range(10))

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM api_keys")
    count = cursor.fetchone()[0]
    if count >= MAX_KEYS:
        conn.close()
        return {"code": 400, "message": f"密钥数量已达上限（{MAX_KEYS}个），请先删除其他密钥再添加"}

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO api_keys (purpose, api_key, created_at) VALUES (?, ?, ?)",
        (purpose, new_key, now)
    )
    key_id = cursor.lastrowid
    conn.commit()
    conn.close()

    client_ip = request.client.host if request.client else ""
    add_audit_log(username, "生成API密钥", f"用途: {purpose}, ID: {key_id}", client_ip)

    return {"code": 0, "data": {"id": key_id, "api_key": new_key, "purpose": purpose, "created_at": now}, "message": "密钥生成成功"}
