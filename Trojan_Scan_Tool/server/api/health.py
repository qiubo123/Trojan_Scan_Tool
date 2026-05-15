from fastapi import APIRouter, Query

from server.core.database import get_conn, verify_api_key

router = APIRouter(prefix="/api/v1", tags=["健康检查"])


@router.get("/health")
async def health(key: str = Query("")):
    if key:
        if not verify_api_key(key):
            return {"code": 401, "message": "API密钥错误"}

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM ips")
    ip_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM clients")
    client_count = cursor.fetchone()[0]
    conn.close()

    return {
        "code": 0,
        "data": {
            "status": "running",
            "version": "2.0.0",
            "ip_count": ip_count,
            "client_count": client_count
        }
    }
