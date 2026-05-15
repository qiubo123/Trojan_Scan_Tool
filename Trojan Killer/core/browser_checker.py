import os
import json
import platform

VPN_EXTENSIONS = {
    "clash": ["Clash", "Clash for Chrome", "Clash Proxy", "Proxy SwitchyOmega"],
    "v2ray": ["V2Ray", "V2Ray Helper", "V2Ray Plugin"],
    "shadowsocks": ["Shadowsocks", "SS Helper", "ShadowVPN"],
    "trojan": ["Trojan", "Trojan Plugin"],
    "bypass": ["Bypass", "GoAgent", "GoProxy"],
    "freegate": ["Freegate", "Ultrasurf", "Hotspot Shield"],
    "lantern": ["Lantern", "Blue Lantern"],
    "psiphon": ["Psiphon", "Psiphon Browser"],
}

SUSPICIOUS_EXTENSION_KEYWORDS = [
    "proxy", "vpn", "unblock", "bypass", "free", "anonymous",
    "tor", "onion", "darknet", "privacy", "encrypt",
    "cipher", "secure", "stealth", "hidden", "mask",
    "cloak", "tunnel", "bridge", "gateway", "relay"
]

def get_chrome_extensions():
    extensions = []
    try:
        if platform.system() == "Windows":
            app_data = os.environ.get("LOCALAPPDATA", "")
            paths = [
                os.path.join(app_data, "Google", "Chrome", "User Data", "Default", "Extensions"),
                os.path.join(app_data, "Microsoft", "Edge", "User Data", "Default", "Extensions"),
            ]
        elif platform.system() == "Linux":
            home = os.environ.get("HOME", "")
            paths = [
                os.path.join(home, ".config", "google-chrome", "Default", "Extensions"),
                os.path.join(home, ".config", "chromium", "Default", "Extensions"),
            ]
        else:
            return extensions

        for base_path in paths:
            if not os.path.exists(base_path):
                continue
            for ext_id in os.listdir(base_path):
                ext_path = os.path.join(base_path, ext_id)
                if not os.path.isdir(ext_path):
                    continue
                for version in os.listdir(ext_path):
                    manifest_path = os.path.join(ext_path, version, "manifest.json")
                    if os.path.exists(manifest_path):
                        try:
                            with open(manifest_path, "r", encoding="utf-8") as f:
                                manifest = json.load(f)
                            name = manifest.get("name", "")
                            if isinstance(name, dict):
                                name = name.get("en", "") or list(name.values())[0] if name else ""
                            version = manifest.get("version", "")
                            extensions.append({
                                "id": ext_id,
                                "name": name,
                                "version": version,
                                "browser": "Chrome" if "Google" in base_path else "Edge",
                                "path": ext_path
                            })
                        except Exception:
                            continue
    except Exception:
        pass
    return extensions

def get_firefox_extensions():
    extensions = []
    try:
        if platform.system() == "Windows":
            app_data = os.environ.get("APPDATA", "")
            profiles_path = os.path.join(app_data, "Mozilla", "Firefox", "Profiles")
        elif platform.system() == "Linux":
            home = os.environ.get("HOME", "")
            profiles_path = os.path.join(home, ".mozilla", "firefox")
        else:
            return extensions

        if not os.path.exists(profiles_path):
            return extensions

        for profile in os.listdir(profiles_path):
            extensions_path = os.path.join(profiles_path, profile, "extensions")
            if not os.path.exists(extensions_path):
                continue
            for item in os.listdir(extensions_path):
                item_path = os.path.join(extensions_path, item)
                if item.endswith(".xpi"):
                    try:
                        import zipfile
                        with zipfile.ZipFile(item_path, 'r') as z:
                            if "manifest.json" in z.namelist():
                                with z.open("manifest.json") as f:
                                    manifest = json.load(f)
                                    name = manifest.get("name", "")
                                    if isinstance(name, dict):
                                        name = name.get("en", "") or list(name.values())[0] if name else ""
                                    version = manifest.get("version", "")
                                    extensions.append({
                                        "id": item.replace(".xpi", ""),
                                        "name": name,
                                        "version": version,
                                        "browser": "Firefox",
                                        "path": item_path
                                    })
                    except Exception:
                        continue
                elif os.path.isdir(item_path):
                    manifest_path = os.path.join(item_path, "manifest.json")
                    if os.path.exists(manifest_path):
                        try:
                            with open(manifest_path, "r", encoding="utf-8") as f:
                                manifest = json.load(f)
                            name = manifest.get("name", "")
                            if isinstance(name, dict):
                                name = name.get("en", "") or list(name.values())[0] if name else ""
                            version = manifest.get("version", "")
                            extensions.append({
                                "id": item,
                                "name": name,
                                "version": version,
                                "browser": "Firefox",
                                "path": item_path
                            })
                        except Exception:
                            continue
    except Exception:
        pass
    return extensions

def detect_vpn_extensions():
    results = []
    all_extensions = get_chrome_extensions() + get_firefox_extensions()
    
    for ext in all_extensions:
        name_lower = ext["name"].lower() if ext["name"] else ""
        is_suspicious = False
        reason = ""
        
        for category, names in VPN_EXTENSIONS.items():
            for vpn_name in names:
                if vpn_name.lower() in name_lower:
                    is_suspicious = True
                    reason = f"已知VPN扩展: {vpn_name}"
                    break
            if is_suspicious:
                break
        
        if not is_suspicious:
            for keyword in SUSPICIOUS_EXTENSION_KEYWORDS:
                if keyword in name_lower:
                    is_suspicious = True
                    reason = f"名称含可疑关键词: {keyword}"
                    break
        
        if is_suspicious:
            results.append({
                **ext,
                "is_suspicious": True,
                "reason": reason
            })
    
    return results

def check_proxy_settings():
    suspicious_settings = []
    
    try:
        if platform.system() == "Windows":
            import winreg
            try:
                reg_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
                    proxy_enabled = winreg.QueryValueEx(key, "ProxyEnable")[0]
                    if proxy_enabled == 1:
                        proxy_server = winreg.QueryValueEx(key, "ProxyServer")[0]
                        suspicious_settings.append({
                            "type": "系统代理",
                            "status": "已启用",
                            "details": f"代理服务器: {proxy_server}"
                        })
            except Exception as e:
                pass
    except Exception:
        pass
    
    return suspicious_settings