import os
import ipaddress
import hashlib
import hmac
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse

from server.core.database import verify_session, add_audit_log, verify_api_key
from server.core.config import load_config, save_config, CONFIG_FILE

RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 60
_rate_records = {}
_allowed_networks_cache = None
_config_mtime = 0


def get_allowed_networks():
    global _allowed_networks_cache, _config_mtime
    try:
        current_mtime = os.path.getmtime(CONFIG_FILE)
        if current_mtime != _config_mtime:
            _allowed_networks_cache = None
            _config_mtime = current_mtime
    except OSError:
        pass
    if _allowed_networks_cache is None:
        cfg = load_config()
        _allowed_networks_cache = cfg.get("allowed_networks", [
            "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
        ])
    if not _allowed_networks_cache:
        _allowed_networks_cache = ["127.0.0.1"]
    return _allowed_networks_cache


def reload_allowed_networks():
    global _allowed_networks_cache
    _allowed_networks_cache = None
    return get_allowed_networks()


def update_allowed_networks(networks):
    global _allowed_networks_cache, _config_mtime
    cfg = load_config()
    cfg["allowed_networks"] = networks
    save_config(cfg)
    _allowed_networks_cache = list(networks)
    import time
    _config_mtime = time.time()


def check_network_access(client_ip):
    allowed = get_allowed_networks()
    if not allowed:
        return True
    ip = ipaddress.ip_address(client_ip)
    for net in allowed:
        try:
            if ip in ipaddress.ip_network(net.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def check_rate_limit(client_ip):
    import time
    now = time.time()
    if client_ip not in _rate_records:
        _rate_records[client_ip] = []
    _rate_records[client_ip] = [
        t for t in _rate_records[client_ip]
        if now - t < RATE_LIMIT_WINDOW
    ]
    if len(_rate_records[client_ip]) >= RATE_LIMIT_MAX:
        return False
    _rate_records[client_ip].append(now)
    return True


async def require_auth(request):
    token = request.headers.get("X-Auth-Token", "")
    if not token:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
    username = verify_session(token)
    if not username:
        raise HTTPException(status_code=401, detail="未登录或会话已过期")
    return username


def verify_sign(request: Request):
    query = dict(request.query_params)
    sign = query.pop("sign", "")
    if not sign:
        return False
    sorted_keys = sorted(query.keys())
    raw = "&".join(f"{k}={query[k]}" for k in sorted_keys)
    for row in _iter_db_keys():
        expected = hmac.new(
            row["api_key"].encode("utf-8"),
            raw.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        if sign == expected:
            return True
    return False


def _iter_db_keys():
    try:
        from server.core.database import get_conn, dict_fetch_all
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT api_key FROM api_keys")
        rows = dict_fetch_all(cursor)
        conn.close()
        return rows
    except Exception:
        return []


async def require_client_auth(request: Request):
    raw_sign = request.query_params.get("sign", "")
    if raw_sign:
        if verify_sign(request):
            return True
    token = request.headers.get("X-Auth-Token", "")
    if token:
        username = verify_session(token)
        if username:
            return True
    return False


async def network_middleware(request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"

    if not check_network_access(client_ip):
        return JSONResponse(
            status_code=403,
            content={"code": 403, "message": "禁止访问：不在允许的网段范围内"}
        )

    if not check_rate_limit(client_ip):
        return JSONResponse(
            status_code=429,
            content={"code": 429, "message": "请求过于频繁，请稍后再试"}
        )

    response = await call_next(request)
    return response
