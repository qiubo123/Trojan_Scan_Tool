from fastapi import APIRouter, Request, Query

from server.core.database import get_conn, dict_fetch_all
from server.core.auth import require_auth

router = APIRouter(prefix="/api/v1", tags=["审计日志"])


@router.get("/audit_log")
async def get_audit_log(
    request: Request,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200)
):
    await require_auth(request)
    offset = (page - 1) * size

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM audit_log")
    total = cursor.fetchone()[0]
    cursor.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?",
        (size, offset)
    )
    logs = dict_fetch_all(cursor)
    conn.close()

    return {"code": 0, "data": {"logs": logs, "total": total, "page": page, "size": size}}
