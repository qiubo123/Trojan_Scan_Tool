from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

from server.core.auth import require_auth, get_allowed_networks, update_allowed_networks, reload_allowed_networks
from server.core.database import add_audit_log
from server.core.config import load_config, save_config
import secrets
import string

router = APIRouter(prefix="/api/v1/settings", tags=["设置管理"])


class UpdateNetworksRequest(BaseModel):
    allowed_networks: list


class UpdateSecretKeyRequest(BaseModel):
    secret_key: str


@router.get("/networks")
async def get_networks(request: Request):
    await require_auth(request)
    allowed = get_allowed_networks()
    return {"code": 0, "data": {"allowed_networks": allowed}}


@router.post("/networks")
async def set_networks(request: Request, body: UpdateNetworksRequest):
    username = await require_auth(request)
    networks = body.allowed_networks

    client_ip = request.client.host if request.client else "127.0.0.1"

    if not isinstance(networks, list):
        raise HTTPException(status_code=400, detail="参数格式错误")

    update_allowed_networks(networks)
    add_audit_log(username, "修改网段配置", f"更新允许访问网段: {', '.join(networks)}", client_ip)

    return {"code": 0, "message": "网段配置已更新"}


@router.get("/secret_key")
async def get_secret_key(request: Request):
    await require_auth(request)
    cfg = load_config()
    sk = cfg.get("secret_key", "")
    masked = sk[:6] + "..." + sk[-4:] if len(sk) > 10 else "未设置"
    return {"code": 0, "data": {"masked": masked}}


@router.post("/secret_key")
async def set_secret_key(request: Request, body: UpdateSecretKeyRequest):
    username = await require_auth(request)
    new_key = body.secret_key.strip()

    if not new_key:
        return {"code": 400, "message": "API密钥不能为空"}
    if len(new_key) < 6 and new_key != "":
        return {"code": 400, "message": "API密钥长度不能少于6位"}

    cfg = load_config()
    old_key = cfg.get("secret_key", "")
    cfg["secret_key"] = new_key
    save_config(cfg)

    client_ip = request.client.host if request.client else "127.0.0.1"
    add_audit_log(username, "修改API密钥",
                  f"密钥已更新 ({'old: ' + old_key[:6] + '...' if len(old_key) > 6 else '未设置'} -> {new_key[:6]}...)",
                  client_ip)

    return {"code": 0, "message": "API密钥已更新，正在使用新密钥的连接不受影响，下次连接时生效"}


@router.post("/secret_key/generate")
async def generate_secret_key(request: Request):
    username = await require_auth(request)
    alphabet = string.ascii_lowercase + string.digits
    new_key = "".join(secrets.choice(alphabet) for _ in range(10))

    cfg = load_config()
    cfg["secret_key"] = new_key
    save_config(cfg)

    client_ip = request.client.host if request.client else "127.0.0.1"
    add_audit_log(username, "自动生成API密钥", "已自动生成并更新API密钥", client_ip)

    masked = new_key[:6] + "..." + new_key[-4:]
    return {"code": 0, "data": {"secret_key": new_key, "masked": masked}, "message": "API密钥已自动生成并更新"}
