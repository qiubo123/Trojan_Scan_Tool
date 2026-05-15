from datetime import datetime
from fastapi import APIRouter, Request
from pydantic import BaseModel

from server.core.database import get_conn, dict_fetch_all, add_audit_log
from server.core.auth import require_client_auth

router = APIRouter(prefix="/api/v1", tags=["客户端管理"])


class RegisterRequest(BaseModel):
    client_id: str
    hostname: str = ""
    version: str = ""
    os: str = ""
    sign: str = ""
    t: str = ""


class IPSyncItem(BaseModel):
    ip: str
    port: int = 0
    threat_type: str = ""
    description: str = ""
    source: str = ""
    status: str = "active"
    location: str = ""
    tags: str = ""
    related_virus: str = ""


class SyncRequest(BaseModel):
    client_id: str
    since_id: int = 0
    local_ips: list[IPSyncItem] = []
    sign: str = ""
    t: str = ""
    full_sync: bool = False
    hostname: str = ""
    version: str = ""
    os: str = ""


def _verify_sign(sign, fields):
    import hashlib, hmac
    sorted_keys = sorted(fields.keys())
    raw = "&".join(f"{k}={fields[k]}" for k in sorted_keys)
    try:
        from server.core.database import get_conn, dict_fetch_all
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT api_key FROM api_keys")
        rows = dict_fetch_all(cursor)
        conn.close()
        if not rows:
            return True
        for row in rows:
            expected = hmac.new(
                row["api_key"].encode("utf-8"),
                raw.encode("utf-8"),
                hashlib.sha256
            ).hexdigest()
            if sign == expected:
                return True
        return False
    except Exception:
        return False


def _require_sign(sign, fields):
    if not sign:
        from server.core.database import get_conn
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM api_keys")
        count = cursor.fetchone()[0]
        conn.close()
        if count > 0:
            from fastapi import HTTPException
            raise HTTPException(status_code=401, detail="需要提供API密钥签名")
        return
    if not _verify_sign(sign, fields):
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="API密钥验证失败")


@router.get("/clients")
async def get_clients(request: Request):
    from server.core.auth import require_auth
    await require_auth(request)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM clients ORDER BY last_seen DESC")
    clients = dict_fetch_all(cursor)
    conn.close()

    return {"code": 0, "data": {"clients": clients}}


@router.post("/register")
async def register(req: RegisterRequest, request: Request):
    _require_sign(req.sign, {"client_id": req.client_id, "hostname": req.hostname, "version": req.version, "os": req.os, "t": req.t})

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT client_id FROM clients WHERE client_id = ?", (req.client_id,))
    is_new = cursor.fetchone() is None
    if is_new:
        cursor.execute("""
            INSERT INTO clients (client_id, hostname, version, os, ip_address, last_seen, registered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            req.client_id, req.hostname, req.version, req.os,
            request.client.host, now, now
        ))
    else:
        cursor.execute("""
            UPDATE clients SET hostname=?, version=?, os=?, ip_address=?, last_seen=?
            WHERE client_id=?
        """, (
            req.hostname, req.version, req.os,
            request.client.host, now, req.client_id
        ))
    conn.commit()
    conn.close()

    client_ip = request.client.host if request.client else ""
    action = "客户端注册" if is_new else "客户端更新"
    add_audit_log(req.client_id, action, f"主机名: {req.hostname}, IP: {client_ip}", client_ip)

    return {"code": 0, "message": "注册成功"}


@router.post("/sync")
async def sync(req: SyncRequest, request: Request):
    _require_sign(req.sign, {"client_id": req.client_id, "since_id": str(req.since_id), "full_sync": str(req.full_sync), "t": req.t})

    conn = get_conn()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    import uuid
    batch_id = f"{req.client_id}_{uuid.uuid4().hex[:8]}"

    pushed_count = 0
    new_pending_count = 0
    if req.local_ips:
        for item in req.local_ips:
            if not item.ip:
                continue

            cursor.execute("SELECT id FROM ips WHERE ip = ? AND port = ?", (item.ip, item.port))
            existing = cursor.fetchone()
            if existing:
                cursor.execute("""
                    UPDATE ips SET threat_type=?, description=?, source=?, status=?, location=?, tags=?, related_virus=?, update_time=?
                    WHERE id=?
                """, (
                    item.threat_type, item.description, item.source or "client",
                    item.status, item.location, item.tags, item.related_virus,
                    now, existing[0]
                ))
                pushed_count += 1
                continue

            cursor.execute(
                "SELECT id, review_status FROM pending_ips WHERE ip = ? AND port = ?",
                (item.ip, item.port)
            )
            pending_row = cursor.fetchone()
            if pending_row:
                if pending_row[1] == "pending":
                    continue
                cursor.execute("""
                    UPDATE pending_ips SET threat_type=?, description=?, source=?, location=?, tags=?, related_virus=?, review_status='pending', client_id=?, batch_id=?, update_time=?
                    WHERE id=?
                """, (
                    item.threat_type, item.description, item.source or "client",
                    item.location, item.tags, item.related_virus,
                    req.client_id, batch_id, now, pending_row[0]
                ))
                new_pending_count += 1
                continue

            cursor.execute("""
                INSERT INTO pending_ips (ip, port, threat_type, description, source, location, tags, related_virus, client_id, batch_id, review_status, create_time, update_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
            """, (
                item.ip, item.port, item.threat_type, item.description,
                item.source or "client", item.location, item.tags,
                item.related_virus, req.client_id, batch_id, now, now
            ))
            new_pending_count += 1

    if req.full_sync:
        cursor.execute("SELECT * FROM ips WHERE status = 'active' ORDER BY id ASC")
    else:
        cursor.execute("SELECT * FROM ips WHERE id > ? AND status = 'active' ORDER BY id ASC", (req.since_id,))
    ips = dict_fetch_all(cursor)

    cursor.execute("SELECT MAX(id) FROM ips")
    max_id = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(*) FROM ips")
    total = cursor.fetchone()[0]

    cursor.execute("""
        UPDATE clients SET hostname=?, version=?, os=?, ip_address=?, last_seen=? WHERE client_id=?
    """, (req.hostname, req.version, req.os, request.client.host, now, req.client_id))

    conn.commit()
    conn.close()

    client_ip = request.client.host if request.client else ""
    sync_type = "全量同步" if req.full_sync else "增量同步"
    add_audit_log(req.client_id, f"客户端{sync_type}",
                  f"拉取 {len(ips)} 条IP, 推送更新 {pushed_count} 条, 待审核 {new_pending_count} 条, 本机: {request.client.host}",
                  client_ip)

    return {
        "code": 0,
        "data": {
            "ips": ips,
            "max_id": max_id,
            "count": len(ips),
            "total": total,
            "server_time": now
        }
    }
