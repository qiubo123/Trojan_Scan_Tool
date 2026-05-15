import os
import json
import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

from server.core.database import init_db
from server.core.auth import network_middleware
from server.api import auth, ips, clients, audit, health, settings, keys, pending

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SERVER_DIR = Path(__file__).parent
DATABASE_DIR = SERVER_DIR / "database"
WEB_DIR = SERVER_DIR / "web"
DOWNLOAD_DIR = SERVER_DIR / "download"
DB_PATH = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    db_path = DB_PATH or str(DATABASE_DIR / "malicious_ips_server.db")
    if not DATABASE_DIR.exists():
        DATABASE_DIR.mkdir(parents=True, exist_ok=True)

    old_db = SERVER_DIR / "malicious_ips_server.db"
    if old_db.exists() and old_db.stat().st_size > 4096:
        logger.info(f"发现旧数据库文件，正在迁移数据...")
        try:
            from server.migrate_db import migrate
            migrate()
            logger.info(f"旧数据库数据迁移完成")
        except Exception as e:
            logger.error(f"数据迁移失败: {e}")

    init_db(db_path)
    logger.info(f"数据库初始化完成: {db_path}")

    try:
        from server.core.config import CONFIG_FILE
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            init_pw = cfg.pop("initial_admin_password", None)
            if init_pw:
                import hashlib
                pw_hash = hashlib.sha256(init_pw.encode()).hexdigest()
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                pw_hash = hashlib.sha256(init_pw.encode()).hexdigest()
                cursor.execute(
                    "UPDATE users SET password_hash = ? WHERE username = ?",
                    (pw_hash, "admin")
                )
                conn.commit()
                conn.close()
                with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, ensure_ascii=False, indent=2)
                logger.info("已应用初始管理员密码")
    except Exception:
        pass

    logger.info(f"管理界面: http://localhost:18080/web/login.html")
    yield


app = FastAPI(
    title="恶意IP管理服务端",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.middleware("http")(network_middleware)


@app.middleware("http")
async def path_security_middleware(request: Request, call_next):
    path = request.url.path

    allowed_prefixes = ["/api/", "/web/", "/download"]
    is_allowed = any(path.startswith(prefix) for prefix in allowed_prefixes)

    if not is_allowed:
        return HTMLResponse(
            status_code=404,
            content=open(WEB_DIR / "404.html", encoding="utf-8").read()
        )

    response = await call_next(request)
    return response


app.include_router(auth.router)
app.include_router(ips.router)
app.include_router(clients.router)
app.include_router(audit.router)
app.include_router(health.router)
app.include_router(settings.router)
app.include_router(keys.router)
app.include_router(pending.router)


@app.get("/web/{file_path:path}")
async def serve_web(file_path: str):
    if not file_path:
        file_path = "login.html"

    full_path = (WEB_DIR / file_path).resolve()
    web_dir_resolved = WEB_DIR.resolve()

    if not str(full_path).startswith(str(web_dir_resolved)):
        return HTMLResponse(
            status_code=404,
            content=open(WEB_DIR / "404.html", encoding="utf-8").read()
        )

    if not full_path.exists() or not full_path.is_file():
        return HTMLResponse(
            status_code=404,
            content=open(WEB_DIR / "404.html", encoding="utf-8").read()
        )

    return FileResponse(str(full_path))


@app.get("/download")
async def download_page():
    return RedirectResponse(url="/web/download.html")


@app.get("/download/{file_path:path}")
async def serve_download(file_path: str):
    if not file_path:
        return RedirectResponse(url="/web/download.html")

    if file_path == "index.json":
        files = []
        if DOWNLOAD_DIR.exists():
            for f in sorted(DOWNLOAD_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
                if f.is_file() and f.suffix.lower() in (".exe", ".msi", ".zip", ".7z", ".rar"):
                    stat = f.stat()
                    files.append({
                        "name": f.name,
                        "size": stat.st_size,
                        "date": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                    })
        return files

    full_path = (DOWNLOAD_DIR / file_path).resolve()
    download_dir_resolved = DOWNLOAD_DIR.resolve()

    if not str(full_path).startswith(str(download_dir_resolved)):
        return HTMLResponse(
            status_code=404,
            content=open(WEB_DIR / "404.html", encoding="utf-8").read()
        )

    if not full_path.exists() or not full_path.is_file():
        return HTMLResponse(
            status_code=404,
            content=open(WEB_DIR / "404.html", encoding="utf-8").read()
        )

    return FileResponse(str(full_path))


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return HTMLResponse(
        status_code=404,
        content=open(WEB_DIR / "404.html", encoding="utf-8").read()
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    return JSONResponse(
        status_code=500,
        content={"code": 500, "message": "服务器内部错误"}
    )
