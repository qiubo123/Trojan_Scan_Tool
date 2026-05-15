import sys
import os
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uvicorn
from server.core.config import load_config, save_config, CONFIG_FILE, DATABASE_DIR, DEFAULT_CONFIG
from server.app import app


def first_run_setup():
    print("")
    print("=" * 60)
    print("  检测到首次运行，请完成初始配置")
    print("=" * 60)
    print("")

    config = dict(DEFAULT_CONFIG)

    print("【1/2】管理员密码")
    print("  (默认用户名: admin)")
    while True:
        pw = input("  请输入管理员登录密码 (至少6位): ").strip()
        if len(pw) >= 6:
            break
        print("  !! 密码长度不能少于6位，请重新输入")
    config["initial_admin_password"] = pw

    print("")
    print("【2/2】监听端口")
    port_str = input(f"  请输入管理端口 (默认 {config['port']}): ").strip()
    if port_str:
        try:
            config["port"] = int(port_str)
        except ValueError:
            print(f"  输入无效，使用默认端口 {config['port']}")

    print("")
    print("=" * 60)
    print("  配置确认")
    print("=" * 60)
    print(f"  管理员: admin")
    print(f"  密  码: {'*' * len(config['initial_admin_password'])}")
    print(f"  端  口: {config['port']}")
    print("")

    confirm = input("  保存配置并启动? (Y/n): ").strip().lower()
    if confirm not in ("", "y", "yes"):
        print("")
        print("  已取消启动")
        sys.exit(0)

    os.makedirs(DATABASE_DIR, exist_ok=True)
    save_config(config)
    print("  配置已保存到:", CONFIG_FILE)
    print("")


def main():
    is_first_run = not os.path.exists(CONFIG_FILE)

    if is_first_run:
        first_run_setup()

    config = load_config()
    host = config.get("host", "0.0.0.0")
    port = int(config.get("port", 18080))
    db_path = config.get("data_file", "")

    from server.app import DB_PATH
    import server.app as app_module
    app_module.DB_PATH = db_path

    print(f"正在启动管理端服务 (FastAPI)...")
    print(f"监听地址: {host}:{port}")
    print(f"数据库: {db_path}")
    print(f"管理界面: http://localhost:{port}/web/login.html")
    print(f"API接口: http://localhost:{port}/api/v1/health")
    print("按 Ctrl+C 停止服务")

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        access_log=True
    )


if __name__ == "__main__":
    main()
