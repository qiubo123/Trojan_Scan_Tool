from datetime import datetime
from fastapi import APIRouter, Request, Query

from server.core.database import get_conn, dict_fetch_all, add_audit_log
from server.core.auth import require_auth

router = APIRouter(prefix="/api/v1/pending", tags=["审核管理"])


@router.get("/batches")
async def list_batches(request: Request, status: str = Query("pending", description="筛选状态: pending/rejected/all")):
    await require_auth(request)
    conn = get_conn()
    cursor = conn.cursor()

    where = ""
    if status == "pending":
        where = "WHERE p.review_status = 'pending'"
    elif status == "rejected":
        where = "WHERE p.review_status = 'rejected'"

    cursor.execute(f"""
        SELECT p.batch_id,
               p.client_id,
               c.hostname,
               c.os,
               c.ip_address as client_ip,
               COUNT(*) as ip_count,
               MAX(p.create_time) as push_time,
               MIN(p.review_status) as batch_status
        FROM pending_ips p
        LEFT JOIN clients c ON c.client_id = p.client_id
        {where}
        GROUP BY p.batch_id
        ORDER BY push_time DESC
    """)
    rows = dict_fetch_all(cursor)
    conn.close()
    return {"code": 0, "data": {"items": rows, "total": len(rows)}}


@router.get("/batch/{batch_id}")
async def get_batch_detail(batch_id: str, request: Request):
    await require_auth(request)

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM pending_ips WHERE batch_id = ? ORDER BY id ASC", (batch_id,))
    items = dict_fetch_all(cursor)

    client_info = None
    if items and items[0].get("client_id"):
        cursor.execute("SELECT * FROM clients WHERE client_id = ?", (items[0]["client_id"],))
        cli_row = cursor.fetchone()
        if cli_row:
            cli_columns = [d[0] for d in cursor.description]
            client_info = dict(zip(cli_columns, cli_row))

    conn.close()
    return {"code": 0, "data": {"items": items, "total": len(items), "client": client_info}}


@router.post("/batch/{batch_id}/approve")
async def approve_batch(batch_id: str, request: Request):
    username = await require_auth(request)

    conn = get_conn()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("SELECT * FROM pending_ips WHERE batch_id = ? AND review_status = 'pending'", (batch_id,))
    rows = dict_fetch_all(cursor)
    if not rows:
        conn.close()
        return {"code": 400, "message": "该批次没有待审核的记录"}

    approved_count = 0
    for item in rows:
        cursor.execute("SELECT id FROM ips WHERE ip = ? AND port = ?", (item["ip"], item["port"]))
        existing = cursor.fetchone()
        if existing:
            cursor.execute("""
                UPDATE ips SET threat_type=?, description=?, source=?, status='active', location=?, tags=?, related_virus=?, update_time=?
                WHERE id=?
            """, (
                item["threat_type"], item["description"], item["source"],
                item["location"], item["tags"], item["related_virus"],
                now, existing[0]
            ))
        else:
            cursor.execute("""
                INSERT INTO ips (ip, port, threat_type, description, source, status, location, tags, related_virus, create_time, update_time)
                VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
            """, (
                item["ip"], item["port"], item["threat_type"], item["description"],
                item["source"], item["location"], item["tags"],
                item["related_virus"], now, now
            ))

        cursor.execute("UPDATE pending_ips SET review_status = 'approved', update_time = ? WHERE id = ?", (now, item["id"]))
        approved_count += 1

    conn.commit()
    conn.close()

    add_audit_log(username, "批量审批",
                  f"批次: {batch_id}, 批准 {approved_count} 条IP",
                  request.client.host)
    return {"code": 0, "message": f"已批准 {approved_count} 条IP"}


@router.post("/batch/{batch_id}/reject")
async def reject_batch(batch_id: str, request: Request):
    username = await require_auth(request)

    conn = get_conn()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("UPDATE pending_ips SET review_status = 'rejected', update_time = ? WHERE batch_id = ? AND review_status = 'pending'", (now, batch_id))
    rejected_count = cursor.rowcount
    conn.commit()
    conn.close()

    if rejected_count == 0:
        return {"code": 400, "message": "该批次没有待审核的记录"}

    add_audit_log(username, "批量拒绝",
                  f"批次: {batch_id}, 拒绝 {rejected_count} 条IP",
                  request.client.host)
    return {"code": 0, "message": f"已拒绝 {rejected_count} 条IP"}


@router.post("/ips/{item_id}/approve")
async def approve_item(item_id: int, request: Request):
    username = await require_auth(request)

    conn = get_conn()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("SELECT * FROM pending_ips WHERE id = ? AND review_status = 'pending'", (item_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return {"code": 400, "message": "该记录不存在或已被审核"}

    columns = [d[0] for d in cursor.description]
    item = dict(zip(columns, row))

    cursor.execute("SELECT id FROM ips WHERE ip = ? AND port = ?", (item["ip"], item["port"]))
    existing = cursor.fetchone()
    if existing:
        cursor.execute("""
            UPDATE ips SET threat_type=?, description=?, source=?, status='active', location=?, tags=?, related_virus=?, update_time=?
            WHERE id=?
        """, (
            item["threat_type"], item["description"], item["source"],
            item["location"], item["tags"], item["related_virus"],
            now, existing[0]
        ))
    else:
        cursor.execute("""
            INSERT INTO ips (ip, port, threat_type, description, source, status, location, tags, related_virus, create_time, update_time)
            VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
        """, (
            item["ip"], item["port"], item["threat_type"], item["description"],
            item["source"], item["location"], item["tags"],
            item["related_virus"], now, now
        ))

    cursor.execute("UPDATE pending_ips SET review_status = 'approved', update_time = ? WHERE id = ?", (now, item_id))
    conn.commit()
    conn.close()

    add_audit_log(username, "单个审批",
                  f"IP: {item['ip']}:{item['port']}, 已批准",
                  request.client.host)
    return {"code": 0, "message": "已批准"}


@router.post("/ips/{item_id}/reject")
async def reject_item(item_id: int, request: Request):
    username = await require_auth(request)

    conn = get_conn()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("UPDATE pending_ips SET review_status = 'rejected', update_time = ? WHERE id = ? AND review_status = 'pending'", (now, item_id))
    affected = cursor.rowcount
    conn.commit()
    conn.close()

    if affected == 0:
        return {"code": 400, "message": "该记录不存在或已被审核"}

    add_audit_log(username, "单个拒绝",
                  f"ID: {item_id}, 已拒绝",
                  request.client.host)
    return {"code": 0, "message": "已拒绝"}
