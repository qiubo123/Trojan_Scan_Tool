import os
import json

SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_DIR = os.path.join(SERVER_DIR, "database")
CONFIG_FILE = os.path.join(DATABASE_DIR, "server_config.json")

DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 18080,
    "secret_key": "change_this_to_a_random_secret_key",
    "data_file": os.path.join(DATABASE_DIR, "malicious_ips_server.db"),
    "max_sync_records": 5000,
    "log_file": os.path.join(SERVER_DIR, "server.log"),
    "allow_auto_register": True,
    "allowed_networks": [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ],
}


def load_config():
    if not os.path.exists(DATABASE_DIR):
        os.makedirs(DATABASE_DIR, exist_ok=True)
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            merged = dict(DEFAULT_CONFIG)
            merged.update(cfg)
            return merged
        except (json.JSONDecodeError, IOError):
            pass
    save_config(DEFAULT_CONFIG)
    return dict(DEFAULT_CONFIG)


def save_config(config):
    try:
        if not os.path.exists(DATABASE_DIR):
            os.makedirs(DATABASE_DIR, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
    except IOError:
        pass
