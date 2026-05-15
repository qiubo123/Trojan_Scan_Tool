from datetime import datetime
from fastapi import APIRouter, Request, Query
from pydantic import BaseModel
import re

from server.core.database import get_conn, dict_fetch_all, add_audit_log
from server.core.auth import require_auth, require_client_auth

router = APIRouter(prefix="/api/v1", tags=["IP管理"])

def is_valid_ip(ip):
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip)
    if not match:
        return False
    for part in match.groups():
        if int(part) > 255:
            return False
    return True


class AddIPRequest(BaseModel):
    ip: str
    port: int = 0
    threat_type: str = ""
    description: str = ""
    source: str = "web"
    location: str = ""
    tags: str = ""
    related_virus: str = ""


class BatchImportRequest(BaseModel):
    ips: list
    source: str = "web"


class UpdateIPRequest(BaseModel):
    ip: str = None
    port: int = None
    threat_type: str = None
    description: str = None
    source: str = None
    status: str = None
    location: str = None
    tags: str = None
    related_virus: str = None


@router.get("/ips")
async def get_ips(
    request: Request,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    status: str = Query("")
):
    sign = request.query_params.get("sign", "")
    is_client_sync = False
    if sign:
        if not await require_client_auth(request):
            return {"code": 401, "message": "API密钥验证失败"}
        is_client_sync = True
    elif request.query_params.get("since_id"):
        if not await require_client_auth(request):
            return {"code": 401, "message": "API密钥验证失败"}
        is_client_sync = True
    else:
        await require_auth(request)

    conn = get_conn()
    cursor = conn.cursor()
    offset = (page - 1) * size

    if status:
        cursor.execute("SELECT COUNT(*) FROM ips WHERE status = ?", (status,))
        total = cursor.fetchone()[0]
        cursor.execute(
            "SELECT * FROM ips WHERE status = ? ORDER BY id DESC LIMIT ? OFFSET ?",
            (status, size, offset)
        )
    else:
        cursor.execute("SELECT COUNT(*) FROM ips")
        total = cursor.fetchone()[0]
        cursor.execute(
            "SELECT * FROM ips ORDER BY id DESC LIMIT ? OFFSET ?",
            (size, offset)
        )

    ips = dict_fetch_all(cursor)
    conn.close()

    if is_client_sync:
        client_ip = request.client.host if request.client else ""
        add_audit_log("客户端", "客户端拉取IP", f"获取 {len(ips)} 条IP, since_id: {request.query_params.get('since_id', '0')}", client_ip)

    return {"code": 0, "data": {"ips": ips, "total": total, "page": page, "size": size}}


@router.get("/ips/search")
async def search_ips(request: Request, keyword: str = Query("")):
    await require_auth(request)

    if not keyword.strip():
        return await get_ips(request)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM ips WHERE
            ip LIKE ? OR threat_type LIKE ? OR description LIKE ?
            OR location LIKE ? OR tags LIKE ? OR related_virus LIKE ?
        ORDER BY id DESC LIMIT 200
    """, tuple(f"%{keyword}%" for _ in range(6)))
    ips = dict_fetch_all(cursor)
    conn.close()

    return {"code": 0, "data": {"ips": ips, "total": len(ips)}}


@router.get("/ips/statistics")
async def get_statistics(request: Request):
    await require_auth(request)

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT threat_type, COUNT(*) as cnt FROM ips GROUP BY threat_type ORDER BY cnt DESC")
    by_type = [{"threat_type": r[0], "count": r[1]} for r in cursor.fetchall()]

    cursor.execute("SELECT COUNT(*) FROM ips WHERE status = 'expired'")
    expired = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM ips WHERE status = 'active'")
    active = cursor.fetchone()[0]
    conn.close()

    return {"code": 0, "data": {"by_type": by_type, "expired": expired, "active": active, "total": active + expired}}


@router.get("/ips/{ip_id}")
async def get_ip(ip_id: int, request: Request):
    await require_auth(request)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ips WHERE id = ?", (ip_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return {"code": 404, "message": "记录不存在"}

    columns = [d[0] for d in cursor.description]
    return {"code": 0, "data": dict(zip(columns, row))}


@router.post("/ips")
async def add_ip(req: AddIPRequest, request: Request):
    username = await require_auth(request)

    if not req.ip.strip():
        return {"code": 400, "message": "IP地址不能为空"}

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO ips (ip, port, threat_type, description, source, status, location, tags, related_virus, create_time, update_time)
        VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
    """, (
        req.ip, req.port, req.threat_type, req.description, req.source,
        req.location, req.tags, req.related_virus, now, now
    ))
    ip_id = cursor.lastrowid
    conn.commit()
    conn.close()

    add_audit_log(username, "添加IP", f"IP: {req.ip}, 类型: {req.threat_type}", request.client.host)
    return {"code": 0, "data": {"id": ip_id}, "message": "添加成功"}


@router.post("/ips/batch")
async def batch_import(req: BatchImportRequest, request: Request):
    username = await require_auth(request)

    if not req.ips:
        return {"code": 400, "message": "没有要导入的数据"}

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    cursor = conn.cursor()
    
    added = 0
    skipped = 0
    errors = []
    
    try:
        for item in req.ips:
            ip = item.get("ip", "").strip()
            if not ip:
                skipped += 1
                continue
                
            if not is_valid_ip(ip):
                errors.append(f"无效IP格式: {ip}")
                skipped += 1
                continue
                
            port = int(item.get("port", 0))
            if port < 0 or port > 65535:
                errors.append(f"无效端口({ip}): {port}")
                skipped += 1
                continue
                
            cursor.execute("SELECT id FROM ips WHERE ip = ? AND port = ?", (ip, port))
            if cursor.fetchone():
                skipped += 1
                continue
                
            cursor.execute("""
                INSERT INTO ips (ip, port, threat_type, description, source, status, location, tags, related_virus, create_time, update_time)
                VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
            """, (
                ip, port,
                item.get("threat_type", ""),
                item.get("description", ""),
                req.source,
                item.get("location", ""),
                item.get("tags", ""),
                item.get("related_virus", ""),
                now, now
            ))
            added += 1
            
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        return {"code": 500, "message": f"导入失败: {str(e)}"}
    
    conn.close()
    add_audit_log(username, "批量导入", f"导入 {added} 条IP记录", request.client.host)
    
    result = {"code": 0, "data": {"added": added, "skipped": skipped}, "message": f"成功导入 {added} 条记录"}
    if errors:
        result["errors"] = errors
    return result


@router.put("/ips/{ip_id}")
async def update_ip(ip_id: int, req: UpdateIPRequest, request: Request):
    username = await require_auth(request)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM ips WHERE id = ?", (ip_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        return {"code": 404, "message": "记录不存在"}

    updates = []
    values = []
    for field in ("ip", "port", "threat_type", "description", "source", "status", "location", "tags", "related_virus"):
        val = getattr(req, field, None)
        if val is not None:
            updates.append(f"{field} = ?")
            values.append(val)

    if not updates:
        conn.close()
        return {"code": 400, "message": "没有要更新的字段"}

    updates.append("update_time = ?")
    values.append(now)
    values.append(ip_id)

    cursor.execute(f"UPDATE ips SET {', '.join(updates)} WHERE id = ?", values)
    conn.commit()
    conn.close()

    action = "过期IP" if req.status == "expired" else ("恢复IP" if req.status == "active" else "编辑IP")
    add_audit_log(username, action, f"ID: {ip_id}", request.client.host)
    return {"code": 0, "message": "更新成功"}


@router.delete("/ips/{ip_id}")
async def delete_ip(ip_id: int, request: Request):
    username = await require_auth(request)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM ips WHERE id = ?", (ip_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return {"code": 404, "message": "记录不存在"}

    ip_addr = row[0]
    cursor.execute("DELETE FROM ips WHERE id = ?", (ip_id,))
    conn.commit()
    conn.close()

    add_audit_log(username, "删除IP", f"IP: {ip_addr}", request.client.host)
    return {"code": 0, "message": "删除成功"}
