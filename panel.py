#!/usr/bin/env python3
"""Chernox — локальная веб-панель для управления sing-box на OpenWrt.

Хранит ключи/конфиги в SQLite, умеет применять их к /etc/sing-box/config.json,
запускать и останавливать sing-box вместе с tproxy.
"""

import argparse
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

VERSION = "1.1"
DEFAULT_CONFIG_PATH = "/etc/singbox-panel/config.json"
PBKDF2_ITERATIONS = 200000
MAX_BODY = 2 * 1024 * 1024
COOKIE_NAME = "chernox_session"
SUPPORTED_PROXY_TYPES = {"vless", "hysteria2", "ssh"}
ROUTING_OUTBOUND_TYPES = {"direct", "block", "dns", "selector", "urltest"}
SUPPORTED_URI_SCHEMES = {
    "vless": "vless",
    "hysteria2": "hysteria2",
    "hy2": "hysteria2",
    "ssh": "ssh",
}
ROUTE_MODES = {
    "all": {
        "title": "Весь трафик через VPN",
        "short": "весь трафик через VPN",
        "hint": "Без разделения: все сайты идут через активный ключ.",
    },
    "ru_direct": {
        "title": "RU-сайты напрямую",
        "short": "RU напрямую",
        "hint": "Российские домены и IP идут напрямую, остальное через VPN.",
    },
    "ru_vpn": {
        "title": "Только RU через VPN",
        "short": "только RU через VPN",
        "hint": "Российские сайты идут через VPN, остальное напрямую.",
    },
}
RU_GEOSITE_URL = (
    "https://raw.githubusercontent.com/SagerNet/sing-geosite/"
    "rule-set/geosite-category-ru.srs"
)
RU_GEOIP_URL = (
    "https://raw.githubusercontent.com/SagerNet/sing-geoip/"
    "rule-set/geoip-ru.srs"
)
DEFAULT_AUTHOR = {
    "name": "Автор Chernox",
    "tagline": "Разработка и поддержка панели",
    "about": (
        "Chernox — локальная панель для управления sing-box на OpenWrt. "
        "Спасибо, что пользуетесь проектом."
    ),
    "donations": [],
    "links": [],
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS panel_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

SETTINGS = {}
SESSION_TTL = 12 * 60 * 60
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()
LOGIN_ATTEMPTS = {}
LOGIN_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Настройки
# ---------------------------------------------------------------------------


def default_settings():
    return {
        "host": "0.0.0.0",
        "port": 8080,
        "password_hash": "",
        "db_path": "/etc/singbox-panel/panel.db",
        "singbox_config": "/etc/sing-box/config.json",
        "singbox_service": "/etc/init.d/sing-box",
        "singbox_binary": "",
        "singbox_workdir": "/usr/share/sing-box",
        "tproxy_helper": "/usr/bin/singbox-tproxy.sh",
        "manual_stop_file": "/tmp/singbox-manual-stop",
        "author_file": "/etc/singbox-panel/author.json",
        "session_ttl": 12 * 60 * 60,
    }


def load_settings(path):
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Файл настроек должен содержать JSON-объект.")
    settings = default_settings()
    settings.update(data)
    return settings


def save_settings(path, settings):
    ensure_parent(path, 0o700)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(settings, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)


def ensure_parent(path, mode=0o700):
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, mode=mode, exist_ok=True)


def hash_password(password, salt=None, iterations=PBKDF2_ITERATIONS):
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        iterations,
    )
    return "pbkdf2_sha256${}${}${}".format(iterations, salt, digest.hex())


def verify_password(password, stored):
    try:
        algorithm, iterations, salt, expected = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt),
            int(iterations),
        )
        return hmac.compare_digest(digest.hex(), expected)
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# База данных
# ---------------------------------------------------------------------------


def db_connect(path):
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


def init_db(path):
    ensure_parent(path, 0o700)
    with db_connect(path) as connection:
        connection.executescript(SCHEMA)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def init_storage(settings):
    init_db(settings["db_path"])


def fetch_configs(settings):
    with db_connect(settings["db_path"]) as connection:
        rows = connection.execute(
            "SELECT id, name, kind, content, created_at, active "
            "FROM configs ORDER BY id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def fetch_config(settings, config_id):
    with db_connect(settings["db_path"]) as connection:
        row = connection.execute(
            "SELECT id, name, kind, content, created_at, active "
            "FROM configs WHERE id = ?",
            (config_id,),
        ).fetchone()
    return dict(row) if row else None


def fetch_active_config(settings):
    with db_connect(settings["db_path"]) as connection:
        row = connection.execute(
            "SELECT id, name, kind, content, created_at, active "
            "FROM configs WHERE active = 1 LIMIT 1"
        ).fetchone()
    return dict(row) if row else None


def get_setting(settings, key, default=None):
    with db_connect(settings["db_path"]) as connection:
        row = connection.execute(
            "SELECT value FROM panel_settings WHERE key = ?", (key,)
        ).fetchone()
    return row["value"] if row else default


def set_setting(settings, key, value):
    with db_connect(settings["db_path"]) as connection:
        connection.execute(
            "INSERT OR REPLACE INTO panel_settings (key, value) VALUES (?, ?)",
            (key, str(value)),
        )


def get_route_mode(settings):
    mode = get_setting(settings, "route_mode", "all")
    return mode if mode in ROUTE_MODES else "all"


def clean_text(value, limit):
    return str(value or "").strip()[:limit]


def normalize_author(data):
    result = {
        "name": clean_text(data.get("name"), 64) or DEFAULT_AUTHOR["name"],
        "tagline": clean_text(data.get("tagline"), 140),
        "about": clean_text(data.get("about"), 2000),
        "donations": [],
        "links": [],
    }

    donations = data.get("donations")
    if isinstance(donations, list):
        for item in donations[:20]:
            if not isinstance(item, dict):
                continue
            label = clean_text(item.get("label"), 60)
            value = clean_text(item.get("value"), 300)
            note = clean_text(item.get("note"), 160)
            if label and value:
                result["donations"].append(
                    {"label": label, "value": value, "note": note}
                )

    links = data.get("links")
    if isinstance(links, list):
        for item in links[:10]:
            if not isinstance(item, dict):
                continue
            label = clean_text(item.get("label"), 60)
            url = clean_text(item.get("url"), 500)
            if label and (url.lower().startswith("http://") or url.lower().startswith("https://")):
                result["links"].append({"label": label, "url": url})

    return result


def load_author(settings):
    data = json.loads(json.dumps(DEFAULT_AUTHOR))
    author_file = settings.get("author_file")
    if author_file:
        try:
            with open(author_file, "r", encoding="utf-8") as handle:
                stored = json.load(handle)
            if isinstance(stored, dict):
                data.update(stored)
        except (OSError, TypeError, json.JSONDecodeError):
            pass
    return normalize_author(data)


def insert_config(settings, name, kind, content):
    with db_connect(settings["db_path"]) as connection:
        cursor = connection.execute(
            "INSERT INTO configs (name, kind, content, created_at) VALUES (?, ?, ?, ?)",
            (name, kind, content, int(time.time())),
        )
        return cursor.lastrowid


def mark_active(settings, config_id):
    with db_connect(settings["db_path"]) as connection:
        connection.execute("UPDATE configs SET active = 0")
        cursor = connection.execute(
            "UPDATE configs SET active = 1 WHERE id = ?", (config_id,)
        )
        if cursor.rowcount != 1:
            raise ValueError("Конфиг не найден.")


def delete_config(settings, config_id):
    record = fetch_config(settings, config_id)
    if record is None:
        raise ValueError("Конфиг не найден.")
    if record["active"]:
        raise ValueError("Нельзя удалить активный конфиг. Сначала активируйте другой.")
    with db_connect(settings["db_path"]) as connection:
        connection.execute("DELETE FROM configs WHERE id = ?", (config_id,))
    return record["name"]


# ---------------------------------------------------------------------------
# Конфиги sing-box
# ---------------------------------------------------------------------------


def first_value(fields, key, default=""):
    values = fields.get(key)
    if not values:
        return default
    return values[0]


def parse_vless_uri(uri):
    parsed = urlparse(uri.strip())
    if parsed.scheme.lower() != "vless":
        raise ValueError("Ожидается ссылка вида vless://...")

    uuid = unquote(parsed.username or "")
    if not uuid:
        raise ValueError("В ссылке нет UUID.")

    host = parsed.hostname
    if not host:
        raise ValueError("В ссылке нет адреса сервера.")

    try:
        port = parsed.port or 443
    except ValueError:
        raise ValueError("В ссылке некорректный порт.")

    query = {
        key: values[-1]
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items()
    }

    security = (query.get("security") or "none").lower()
    transport = (query.get("type") or "tcp").lower()
    flow = query.get("flow") or ""

    outbound = {
        "type": "vless",
        "tag": "ssh-out",
        "server": host,
        "server_port": int(port),
        "uuid": uuid,
    }
    if flow:
        outbound["flow"] = flow

    if transport == "ws":
        ws = {"type": "ws", "path": query.get("path") or "/"}
        ws_host = query.get("host")
        if ws_host:
            ws["headers"] = {"Host": ws_host}
        outbound["transport"] = ws
    elif transport == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": query.get("serviceName") or "",
        }
    elif transport in ("http", "h2"):
        http_transport = {"type": "http", "path": query.get("path") or "/"}
        http_hosts = query.get("host")
        if http_hosts:
            http_transport["host"] = [
                item.strip() for item in http_hosts.split(",") if item.strip()
            ]
        outbound["transport"] = http_transport
    elif transport not in ("tcp", ""):
        raise ValueError("Транспорт {} не поддерживается панелью.".format(transport))

    if security in ("tls", "reality"):
        tls = {
            "enabled": True,
            "server_name": query.get("sni") or query.get("host") or host,
        }
        if query.get("allowInsecure") in ("1", "true", "True"):
            tls["insecure"] = True
        if query.get("alpn"):
            tls["alpn"] = [item for item in query["alpn"].split(",") if item]
        if query.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": query["fp"]}
        if security == "reality":
            public_key = query.get("pbk") or ""
            if not public_key:
                raise ValueError("Для reality в ссылке нужен параметр pbk.")
            tls["reality"] = {
                "enabled": True,
                "public_key": public_key,
                "short_id": query.get("sid") or "",
            }
        outbound["tls"] = tls
    elif security not in ("none", ""):
        raise ValueError("Тип безопасности {} не поддерживается панелью.".format(security))

    label = unquote(parsed.fragment).strip() or "{}:{}".format(host, port)
    return outbound, label


def parse_hysteria2_uri(uri):
    parsed = urlparse(uri.strip())
    if parsed.scheme.lower() not in ("hysteria2", "hy2"):
        raise ValueError("Ожидается ссылка вида hysteria2://... или hy2://...")

    host = parsed.hostname
    if not host:
        raise ValueError("В ссылке нет адреса сервера.")

    try:
        port = parsed.port or 443
    except ValueError:
        raise ValueError("В ссылке некорректный порт.")

    query = {
        key: values[-1]
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items()
    }

    username = unquote(parsed.username or "")
    user_password = unquote(parsed.password or "")
    if user_password:
        password = "{}:{}".format(username, user_password)
    else:
        password = username or query.get("auth") or query.get("password") or ""
    if not password:
        raise ValueError("В ссылке hysteria2 нет пароля.")

    outbound = {
        "type": "hysteria2",
        "tag": "ssh-out",
        "server": host,
        "server_port": int(port),
        "password": password,
    }

    tls = {
        "enabled": True,
        "server_name": query.get("sni") or query.get("peer") or host,
    }
    if query.get("insecure") in ("1", "true", "True") or query.get(
        "allowInsecure"
    ) in ("1", "true", "True"):
        tls["insecure"] = True
    if query.get("alpn"):
        tls["alpn"] = [item for item in query["alpn"].split(",") if item]
    outbound["tls"] = tls

    obfs_type = (query.get("obfs") or "").lower()
    if obfs_type and obfs_type != "none":
        if obfs_type not in ("salamander", "gecko"):
            raise ValueError("Obfs {} не поддерживается.".format(obfs_type))
        obfs_password = query.get("obfs-password") or query.get("obfs_password") or ""
        if not obfs_password:
            raise ValueError("Для obfs нужен параметр obfs-password.")
        outbound["obfs"] = {"type": obfs_type, "password": obfs_password}

    for field, keys in (
        ("up_mbps", ("upmbps", "up_mbps", "up")),
        ("down_mbps", ("downmbps", "down_mbps", "down")),
    ):
        for key in keys:
            value = query.get(key)
            if not value:
                continue
            try:
                number = int(value)
            except ValueError:
                raise ValueError("Параметр {} должен быть числом.".format(key))
            if number > 0:
                outbound[field] = number
            break

    ports = query.get("mport") or query.get("ports")
    if ports:
        server_ports = []
        for chunk in ports.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                start, end = chunk.split("-", 1)
                server_ports.append("{}:{}".format(start, end))
            elif ":" in chunk:
                server_ports.append(chunk)
            else:
                server_ports.append("{}:{}".format(chunk, chunk))
        if server_ports:
            outbound["server_ports"] = server_ports

    label = unquote(parsed.fragment).strip() or "{}:{}".format(host, port)
    return outbound, label


def parse_ssh_uri(uri):
    parsed = urlparse(uri.strip())
    if parsed.scheme.lower() != "ssh":
        raise ValueError("Ожидается ссылка вида ssh://...")

    host = parsed.hostname
    if not host:
        raise ValueError("В ссылке нет адреса сервера.")

    try:
        port = parsed.port or 22
    except ValueError:
        raise ValueError("В ссылке некорректный порт.")

    query = {
        key: values[-1]
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items()
    }

    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    if not password:
        password = query.get("password") or query.get("pass") or ""

    private_key = query.get("private_key") or query.get("privateKey") or ""
    private_key_path = (
        query.get("private_key_path")
        or query.get("privateKeyPath")
        or query.get("key_path")
        or ""
    )
    passphrase = (
        query.get("private_key_passphrase")
        or query.get("privateKeyPassphrase")
        or query.get("passphrase")
        or ""
    )

    if not (password or private_key or private_key_path):
        raise ValueError(
            "Для SSH нужен пароль или ключ "
            "(password, private_key или private_key_path)."
        )

    outbound = {
        "type": "ssh",
        "tag": "ssh-out",
        "server": host,
        "server_port": int(port),
    }
    if user:
        outbound["user"] = user
    if password:
        outbound["password"] = password
    if private_key:
        outbound["private_key"] = private_key
    if private_key_path:
        outbound["private_key_path"] = private_key_path
    if passphrase:
        outbound["private_key_passphrase"] = passphrase

    host_keys = query.get("host_key") or query.get("hostkey") or ""
    if host_keys:
        outbound["host_key"] = [
            item.strip() for item in host_keys.split(",") if item.strip()
        ]

    host_key_algorithms = (
        query.get("host_key_algorithms")
        or query.get("hostKeyAlgorithms")
        or ""
    )
    if host_key_algorithms:
        outbound["host_key_algorithms"] = [
            item.strip() for item in host_key_algorithms.split(",") if item.strip()
        ]

    client_version = query.get("client_version") or query.get("clientVersion") or ""
    if client_version:
        outbound["client_version"] = client_version

    label = unquote(parsed.fragment).strip() or "{}:{}".format(host, port)
    return outbound, label


def parse_uri(uri):
    scheme = urlparse(uri.strip()).scheme.lower()
    if scheme == "vless":
        return parse_vless_uri(uri)
    if scheme in ("hysteria2", "hy2"):
        return parse_hysteria2_uri(uri)
    if scheme == "ssh":
        return parse_ssh_uri(uri)
    raise ValueError(
        "Протокол {} не поддерживается. Разрешены только vless, hysteria2 и ssh.".format(
            scheme or "без схемы"
        )
    )


def build_config_from_uri(uri):
    outbound, label = parse_uri(uri)
    config = {
        "log": {"level": "error"},
        "inbounds": [
            {
                "type": "tproxy",
                "listen": "0.0.0.0",
                "listen_port": 12345,
            }
        ],
        "outbounds": [outbound],
        "route": {"auto_detect_interface": True},
    }
    return config, label


def normalize_json_config(text):
    try:
        config = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "Некорректный JSON: {} (строка {}, колонка {}).".format(
                exc.msg, exc.lineno, exc.colno
            )
        )

    if not isinstance(config, dict):
        raise ValueError("Конфиг должен быть JSON-объектом.")

    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds:
        raise ValueError("В конфиге нет непустого списка outbounds.")

    valid_outbounds = [item for item in outbounds if isinstance(item, dict)]
    if not valid_outbounds:
        raise ValueError("Список outbounds заполнен неверно.")

    if "type" not in valid_outbounds[0] and "protocol" in valid_outbounds[0]:
        raise ValueError(
            "Похоже, это конфиг Xray. Панель принимает JSON-конфиг sing-box."
        )

    outbound_types = set()
    for outbound in valid_outbounds:
        outbound_type = outbound.get("type")
        if not isinstance(outbound_type, str) or not outbound_type:
            raise ValueError("У одного из outbounds не указан type.")
        outbound_types.add(outbound_type)

    unsupported = sorted(
        outbound_types - SUPPORTED_PROXY_TYPES - ROUTING_OUTBOUND_TYPES
    )
    if unsupported:
        raise ValueError(
            "Протокол(ы) {} не поддерживаются. Разрешены только vless, "
            "hysteria2 и ssh.".format(", ".join(unsupported))
        )

    if not outbound_types & SUPPORTED_PROXY_TYPES:
        raise ValueError("В конфиге нет outbound vless, hysteria2 или ssh.")

    if not any(item.get("tag") == "ssh-out" for item in valid_outbounds):
        for outbound in valid_outbounds:
            if (
                outbound.get("type") in SUPPORTED_PROXY_TYPES
                and "tag" not in outbound
            ):
                outbound["tag"] = "ssh-out"
                break

    label = outbound_summary(config)
    return config, label


def outbound_summary(config):
    outbounds = [item for item in config.get("outbounds", []) if isinstance(item, dict)]
    if not outbounds:
        return "конфиг sing-box"
    outbound = next(
        (item for item in outbounds if item.get("tag") == "ssh-out"), None
    )
    if outbound is None:
        outbound = next(
            (item for item in outbounds if item.get("type") in SUPPORTED_PROXY_TYPES),
            outbounds[0],
        )
    kind = outbound.get("type") or "?"
    server = outbound.get("server") or outbound.get("address")
    port = outbound.get("server_port") or outbound.get("port")
    if server and port:
        return "{} · {}:{}".format(kind, server, port)
    return str(kind)


def config_has_check_tag(config):
    return any(
        isinstance(item, dict) and item.get("tag") == "ssh-out"
        for item in config.get("outbounds", [])
    )


def render_record(record):
    content = record["content"]
    if record["kind"] == "uri":
        config, label = build_config_from_uri(content)
    elif record["kind"] == "json":
        config, label = normalize_json_config(content)
    else:
        raise ValueError("Неизвестный тип конфига.")
    text = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    return text, config, label


def detect_kind(content):
    stripped = content.lstrip("\ufeff \t\r\n")
    if stripped.startswith("{"):
        return "json"
    scheme = urlparse(stripped).scheme.lower()
    if scheme in SUPPORTED_URI_SCHEMES:
        return "uri"
    if scheme:
        raise ValueError(
            "Протокол {} не поддерживается. Разрешены только vless, "
            "hysteria2 и ssh.".format(scheme)
        )
    raise ValueError(
        "Вставьте ключ vless://, hysteria2:// (hy2://), ssh:// "
        "или JSON-конфиг sing-box."
    )


def record_protocol(record):
    if record.get("kind") == "uri":
        scheme = urlparse(record.get("content", "").strip()).scheme.lower()
        return SUPPORTED_URI_SCHEMES.get(scheme, scheme)
    if record.get("kind") == "json":
        try:
            config = json.loads(record.get("content", ""))
        except (TypeError, json.JSONDecodeError):
            return ""
        for outbound in config.get("outbounds", []):
            if isinstance(outbound, dict) and outbound.get("type") in SUPPORTED_PROXY_TYPES:
                return outbound["type"]
    return ""


def record_type_label(record):
    protocol = record_protocol(record)
    if record.get("kind") == "uri":
        return {
            "vless": "VLESS-ссылка",
            "hysteria2": "Hysteria2-ссылка",
            "ssh": "SSH-ссылка",
        }.get(protocol, "Ссылка")
    if record.get("kind") == "json":
        return "JSON · {}".format(protocol) if protocol else "JSON sing-box"
    return "Конфиг"


# ---------------------------------------------------------------------------
# Команды OpenWrt
# ---------------------------------------------------------------------------


def run_command(args, timeout=30, cwd=None):
    # Вывод пишем в файл, а не в pipe: фоновый процесс, унаследовавший
    # stdout/stderr, иначе может держать pipe открытым и подвесить вызов.
    output = tempfile.TemporaryFile(mode="w+b")
    try:
        process = subprocess.run(
            args,
            stdout=output,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            cwd=cwd,
        )
        output.seek(0)
        text = output.read().decode("utf-8", "replace")
        return process.returncode, text
    except FileNotFoundError:
        return 127, "Команда не найдена: {}".format(args[0])
    except subprocess.TimeoutExpired:
        return 124, "Превышено время выполнения команды."
    except OSError as exc:
        return 1, str(exc)
    finally:
        output.close()


def find_singbox():
    configured = SETTINGS.get("singbox_binary")
    if configured:
        return configured
    for path in ("/usr/bin/sing-box", "/usr/sbin/sing-box", "/usr/local/bin/sing-box"):
        if os.path.isfile(path):
            return path
    return shutil.which("sing-box")


def singbox_check_error(config_text):
    binary = find_singbox()
    if not binary:
        return None

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", prefix="singbox-panel-", delete=False, encoding="utf-8"
        ) as handle:
            handle.write(config_text)
            tmp_path = handle.name
        workdir = SETTINGS.get("singbox_workdir") or None
        if workdir and not os.path.isdir(workdir):
            workdir = None
        code, output = run_command(
            [binary, "check", "-c", tmp_path], timeout=45, cwd=workdir
        )
        if code == 0:
            return None
        return output.strip() or "sing-box check завершился с ошибкой."
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def singbox_version():
    binary = find_singbox()
    if not binary:
        return None
    code, output = run_command([binary, "version"], timeout=5)
    if code != 0:
        return None
    match = re.search(
        r"sing-box\s+version\s+v?(\d+)\.(\d+)(?:\.(\d+))?", output, re.IGNORECASE
    )
    if not match:
        return None
    return tuple(int(part) if part else 0 for part in match.groups())


def validate_route_mode(mode):
    if mode not in ROUTE_MODES:
        raise ValueError("Неизвестный режим маршрутизации.")
    if mode == "all":
        return None
    version = singbox_version()
    if version is None:
        raise ValueError(
            "Не удалось определить версию sing-box для раздельной маршрутизации."
        )
    if version < (1, 8):
        raise ValueError(
            "Для маршрутизации RU-сайтов нужен sing-box 1.8 или новее."
        )
    return version


def find_proxy_tag(config):
    outbounds = config.get("outbounds", [])
    route = config.get("route")
    if isinstance(route, dict) and route.get("final"):
        final_tag = route["final"]
        final_outbound = next(
            (
                item
                for item in outbounds
                if isinstance(item, dict) and item.get("tag") == final_tag
            ),
            None,
        )
        if final_outbound and final_outbound.get("type") in (
            SUPPORTED_PROXY_TYPES | {"selector", "urltest"}
        ):
            return final_tag

    for outbound in outbounds:
        if (
            isinstance(outbound, dict)
            and outbound.get("tag") == "ssh-out"
            and outbound.get("type") in SUPPORTED_PROXY_TYPES
        ):
            return "ssh-out"
    for outbound in outbounds:
        if (
            isinstance(outbound, dict)
            and outbound.get("type") in SUPPORTED_PROXY_TYPES
            and outbound.get("tag")
        ):
            return outbound["tag"]
    return None


def apply_route_mode(config, mode):
    if mode == "all":
        return config

    version = validate_route_mode(mode)

    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds:
        raise ValueError("В конфиге нет outbounds.")

    proxy_tag = find_proxy_tag(config)
    if not proxy_tag:
        raise ValueError("Не удалось найти proxy-outbound для VPN.")

    outbound_tags = {
        item.get("tag"): item
        for item in outbounds
        if isinstance(item, dict) and item.get("tag")
    }

    direct_tag = "direct"
    if direct_tag in outbound_tags and outbound_tags[direct_tag].get("type") != "direct":
        direct_tag = "chernox-direct"
    if direct_tag in outbound_tags and outbound_tags[direct_tag].get("type") != "direct":
        direct_tag = "chernox-direct-out"

    if direct_tag not in outbound_tags:
        outbounds.append({"type": "direct", "tag": direct_tag})
        outbound_tags[direct_tag] = outbounds[-1]

    route = config.get("route")
    if route is None:
        route = {}
        config["route"] = route
    if not isinstance(route, dict):
        raise ValueError("Поле route в конфиге должно быть объектом.")

    rule_sets = route.get("rule_set")
    if rule_sets is None:
        rule_sets = []
        route["rule_set"] = rule_sets
    if not isinstance(rule_sets, list):
        raise ValueError("Поле route.rule_set должно быть списком.")

    existing_rule_sets = {
        item.get("tag")
        for item in rule_sets
        if isinstance(item, dict) and item.get("tag")
    }
    for tag, url in (
        ("geosite-ru", RU_GEOSITE_URL),
        ("geoip-ru", RU_GEOIP_URL),
    ):
        if tag in existing_rule_sets:
            continue
        rule_sets.append(
            {
                "tag": tag,
                "type": "remote",
                "format": "binary",
                "url": url,
                "download_detour": proxy_tag,
            }
        )

    rules = route.get("rules")
    if rules is None:
        rules = []
        route["rules"] = rules
    if not isinstance(rules, list):
        raise ValueError("Поле route.rules должно быть списком.")

    if version >= (1, 11):
        has_sniff = any(
            isinstance(item, dict) and item.get("action") == "sniff"
            for item in rules
        )
        if not has_sniff:
            rules.insert(0, {"action": "sniff"})
    else:
        for inbound in config.get("inbounds", []):
            if isinstance(inbound, dict) and inbound.get("type") in ("tproxy", "tun"):
                inbound["sniff"] = True

    target = direct_tag if mode == "ru_direct" else proxy_tag
    route_rule = {"rule_set": ["geosite-ru", "geoip-ru"], "outbound": target}
    same_rule = any(
        isinstance(item, dict)
        and item.get("rule_set") == route_rule["rule_set"]
        and item.get("outbound") == target
        for item in rules
    )
    if not same_rule:
        insert_at = (
            1
            if rules
            and isinstance(rules[0], dict)
            and rules[0].get("action") == "sniff"
            else 0
        )
        rules.insert(insert_at, route_rule)

    route["final"] = proxy_tag if mode == "ru_direct" else direct_tag
    return config


def render_applied_config(record, route_mode):
    _, config, label = render_record(record)
    config = apply_route_mode(config, route_mode)
    config_text = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    return config_text, config, label


def service_running():
    code, _ = run_command(["pidof", "sing-box"], timeout=5)
    return code == 0


def wait_service_running(timeout=5):
    deadline = time.time() + timeout
    while True:
        if service_running():
            return True
        if time.time() >= deadline:
            return False
        time.sleep(0.5)


def tproxy_active():
    code, output = run_command(
        ["nft", "list", "chain", "inet", "fw4", "mangle_prerouting"], timeout=5
    )
    return code == 0 and "tproxy ip to :" in output


def manual_stop_requested(settings):
    return os.path.exists(settings["manual_stop_file"])


def set_manual_stop(settings, enabled):
    path = settings["manual_stop_file"]
    if enabled:
        ensure_parent(path, 0o700)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("1\n")
        os.chmod(path, 0o600)
    else:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


def apply_config(settings, record, route_mode=None):
    if route_mode is None:
        route_mode = get_route_mode(settings)
    config_text, config, label = render_applied_config(record, route_mode)

    check_error = singbox_check_error(config_text)
    if check_error:
        raise ValueError("sing-box отклонил конфиг:\n{}".format(check_error))

    target = settings["singbox_config"]
    ensure_parent(target, 0o700)

    if os.path.isfile(target) and os.path.getsize(target) > 0:
        try:
            shutil.copy2(target, target + ".bak")
        except OSError:
            pass

    tmp_path = target + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.write(config_text)
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, target)

    set_manual_stop(settings, False)

    code, output = run_command([settings["singbox_service"], "restart"], timeout=40)
    if code != 0:
        raise RuntimeError(
            "Не удалось перезапустить sing-box:\n{}".format(
                output.strip() or "код {}".format(code)
            )
        )

    if not wait_service_running(5):
        raise RuntimeError("sing-box не запустился после применения конфига.")

    code, output = run_command([settings["tproxy_helper"], "enable"], timeout=15)
    warning = ""
    if code != 0:
        warning = "tproxy не включён: {}".format(output.strip() or code)

    return label, config, warning


def start_vpn(settings):
    if fetch_active_config(settings) is None:
        raise ValueError("Сначала активируйте один из сохранённых конфигов.")

    set_manual_stop(settings, False)

    if not service_running():
        code, output = run_command([settings["singbox_service"], "start"], timeout=40)
        if code != 0:
            raise RuntimeError(
                "Не удалось запустить sing-box:\n{}".format(
                    output.strip() or "код {}".format(code)
                )
            )
    if not wait_service_running(5):
        raise RuntimeError("sing-box не запустился.")

    code, output = run_command([settings["tproxy_helper"], "enable"], timeout=15)
    if code != 0:
        return "VPN запущен, но tproxy не включён: {}".format(
            output.strip() or "код {}".format(code)
        )
    return "VPN включён."


def stop_vpn(settings):
    set_manual_stop(settings, True)
    run_command([settings["tproxy_helper"], "disable"], timeout=15)
    code, output = run_command([settings["singbox_service"], "stop"], timeout=30)
    if code != 0:
        return "VPN выключен, но sing-box остановить не удалось: {}".format(
            output.strip() or "код {}".format(code)
        )
    return "VPN выключен."


# ---------------------------------------------------------------------------
# Сессии
# ---------------------------------------------------------------------------


def create_session():
    token = secrets.token_urlsafe(32)
    session = {
        "token": token,
        "csrf": secrets.token_urlsafe(32),
        "expires": time.time() + SESSION_TTL,
        "flash": None,
    }
    with SESSIONS_LOCK:
        SESSIONS[token] = session
    return session


def get_session(token):
    if not token:
        return None
    now = time.time()
    with SESSIONS_LOCK:
        session = SESSIONS.get(token)
        if session is None:
            return None
        if session["expires"] < now:
            SESSIONS.pop(token, None)
            return None
        session["expires"] = now + SESSION_TTL
        return session


def drop_session(token):
    with SESSIONS_LOCK:
        SESSIONS.pop(token, None)


def set_flash(session, message, kind="ok"):
    if session is None:
        return
    with SESSIONS_LOCK:
        session["flash"] = {"message": message, "kind": kind}


def pop_flash(session):
    if session is None:
        return None
    with SESSIONS_LOCK:
        flash = session.get("flash")
        session["flash"] = None
    return flash


def login_blocked(ip):
    now = time.time()
    with LOGIN_LOCK:
        attempts = [item for item in LOGIN_ATTEMPTS.get(ip, []) if now - item < 300]
        LOGIN_ATTEMPTS[ip] = attempts
        return len(attempts) >= 5


def register_failed_login(ip):
    with LOGIN_LOCK:
        LOGIN_ATTEMPTS.setdefault(ip, []).append(time.time())


def clear_login_attempts(ip):
    with LOGIN_LOCK:
        LOGIN_ATTEMPTS.pop(ip, None)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------


LOGO_MARK_SVG = """
<svg class="chernox-mark" viewBox="0 0 64 72" xmlns="http://www.w3.org/2000/svg"
     role="img" aria-label="Chernox" focusable="false">
  <defs>
    <linearGradient id="cx-mini" x1="8" y1="4" x2="56" y2="68"
                    gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#5bffd0"/>
      <stop offset=".5" stop-color="#18c8a2"/>
      <stop offset="1" stop-color="#4f8dff"/>
    </linearGradient>
  </defs>
  <path d="M32 4 L58 14 V34 C58 51 47 62 32 68
           C17 62 6 51 6 34 V14 Z"
        fill="#0a1f1d" fill-opacity=".92"
        stroke="url(#cx-mini)" stroke-width="3.4" stroke-linejoin="round"/>
  <path d="M32 10 L52 18 V34 C52 47 44 56 32 61
           C20 56 12 47 12 34 V18 Z"
        fill="none" stroke="#5bffd0" stroke-opacity=".18" stroke-width="1.2"/>
  <g fill="none" stroke="url(#cx-mini)" stroke-width="3.8"
     stroke-linecap="round">
    <path d="M20 34 C24 27 40 27 44 34"/>
    <path d="M24 41 C27 36 37 36 40 41"/>
    <path d="M28 48 C30 46 34 46 36 48"/>
  </g>
  <circle cx="32" cy="54" r="2.8" fill="#63ffd7"/>
</svg>
"""

LOGO_SVG = """
<svg class="chernox-mark" viewBox="0 0 120 120" xmlns="http://www.w3.org/2000/svg"
     role="img" aria-label="Chernox" focusable="false">
  <defs>
    <linearGradient id="cx-stroke" x1="14" y1="10" x2="108" y2="112"
                    gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#5bffd0"/>
      <stop offset=".48" stop-color="#18c8a2"/>
      <stop offset="1" stop-color="#4f8dff"/>
    </linearGradient>
    <radialGradient id="cx-bg" cx="50%" cy="32%" r="78%">
      <stop offset="0" stop-color="#102b29"/>
      <stop offset=".68" stop-color="#071518"/>
      <stop offset="1" stop-color="#030a0d"/>
    </radialGradient>
    <filter id="cx-glow" x="-60%" y="-60%" width="220%" height="220%">
      <feGaussianBlur stdDeviation="2.1" result="blur"/>
      <feMerge>
        <feMergeNode in="blur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
  </defs>
  <circle cx="60" cy="60" r="56" fill="url(#cx-bg)"
          stroke="url(#cx-stroke)" stroke-width="2.4"/>
  <circle cx="60" cy="60" r="49.5" fill="none"
          stroke="#5bffd0" stroke-opacity=".14" stroke-width="1"/>
  <g stroke="#2ee5ae" stroke-opacity=".18" stroke-width="1" fill="none">
    <path d="M17 37h8l6 6h6"/>
    <path d="M103 37h-8l-6 6h-6"/>
    <path d="M17 87h8l6-6h6"/>
    <path d="M103 87h-8l-6-6h-6"/>
    <path d="M60 13v5"/>
  </g>
  <g fill="#2ee5ae" fill-opacity=".38">
    <circle cx="17" cy="37" r="1.4"/>
    <circle cx="103" cy="37" r="1.4"/>
    <circle cx="17" cy="87" r="1.4"/>
    <circle cx="103" cy="87" r="1.4"/>
  </g>
  <g stroke="url(#cx-stroke)" stroke-width="2.4" fill="none"
     stroke-linecap="round" opacity=".82">
    <rect x="9" y="53" width="14" height="9" rx="4.5"
          transform="rotate(-32 16 57.5)"/>
    <rect x="19" y="62" width="14" height="9" rx="4.5"
          transform="rotate(-32 26 66.5)"/>
    <rect x="97" y="53" width="14" height="9" rx="4.5"
          transform="rotate(32 104 57.5)"/>
    <rect x="87" y="62" width="14" height="9" rx="4.5"
          transform="rotate(32 94 66.5)"/>
  </g>
  <path d="M60 21 L88 32.5 V56 C88 75 76 87.5 60 96
           C44 87.5 32 75 32 56 V32.5 Z"
        fill="#071716" fill-opacity=".82"
        stroke="url(#cx-stroke)" stroke-width="3.4"
        stroke-linejoin="round" filter="url(#cx-glow)"/>
  <path d="M60 27 L82 36 V56 C82 71 72 82 60 89
           C48 82 38 71 38 56 V36 Z"
        fill="none" stroke="#5bffd0" stroke-opacity=".16" stroke-width="1.2"/>
  <g fill="none" stroke="url(#cx-stroke)" stroke-width="5.2"
     stroke-linecap="round" filter="url(#cx-glow)">
    <path d="M44 61 C50 51 70 51 76 61"/>
    <path d="M49 69 C53 63 67 63 71 69"/>
    <path d="M54 77 C56 74 64 74 66 77"/>
  </g>
  <circle cx="60" cy="83.5" r="3.8" fill="#63ffd7" filter="url(#cx-glow)"/>
</svg>
"""

CSS = """
:root {
  --bg: #071010;
  --card: #0c1919;
  --card-2: #0a1515;
  --field: #081414;
  --text: #e9f7f2;
  --muted: #8ca39f;
  --line: #1d3230;
  --accent: #2ee5ae;
  --accent-dark: #17c79a;
  --danger: #ff9b93;
  --danger-bg: #2a1517;
  --warn-bg: #2a210f;
  --warn-text: #ffd28f;
  --err-bg: #2a1214;
  --ok-bg: #0d2a23;
  --ok-text: #6df0c8;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background:
    radial-gradient(ellipse at 12% 0%, rgba(20, 190, 145, .10), transparent 42%),
    radial-gradient(ellipse at 92% 100%, rgba(50, 105, 255, .08), transparent 45%),
    var(--bg);
  color: var(--text);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
  min-height: 100vh;
}
.wrap { max-width: 1000px; margin: 0 auto; padding: 24px 16px 48px; }
header {
  display: flex; align-items: center; justify-content: space-between;
  gap: 16px; margin-bottom: 22px;
}
.header-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.brand { display: flex; align-items: center; gap: 12px; }
.brand-logo {
  width: 38px; height: 44px; flex: 0 0 38px;
  filter: drop-shadow(0 4px 10px rgba(15, 123, 95, .18));
}
.brand-logo svg, .login-logo svg {
  display: block; width: 100%; height: 100%;
}
.brand-name { font-size: 19px; font-weight: 700; line-height: 1.2; }
.brand-sub { color: var(--muted); font-size: 13px; }
h1 { font-size: 24px; margin: 0 0 16px; }
h2 { font-size: 17px; margin: 0 0 14px; }
.muted { color: var(--muted); }
.small { font-size: 13px; }
.form-hint { margin: -4px 0 14px; }
.form-hint code { color: var(--ok-text); }
.route-options { display: grid; gap: 8px; margin-bottom: 14px; }
.route-option {
  display: flex; align-items: flex-start; gap: 10px;
  padding: 11px 12px; border: 1px solid var(--line); border-radius: 10px;
  cursor: pointer; font-weight: 400; transition: border-color .2s, background .2s, box-shadow .2s;
}
.route-option:hover { border-color: #2e4b47; background: #0e1d1c; }
.route-option input { margin: 3px 0 0; accent-color: var(--accent); }
.route-option-body b { display: block; font-size: 14px; }
.route-option-body small { display: block; color: var(--muted); font-size: 12px; margin-top: 2px; }
.route-option:has(input:checked) {
  border-color: var(--accent);
  background: #0d2420;
  box-shadow: inset 0 0 0 1px rgba(46, 229, 174, .16);
}
.route-note { margin: 12px 0 0; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
.card {
  background: var(--card); border: 1px solid var(--line); border-radius: 14px;
  padding: 18px; margin-bottom: 16px;
}
.stats { margin: 0; }
.stats > div {
  display: flex; align-items: center; justify-content: space-between;
  gap: 12px; padding: 7px 0; border-bottom: 1px dashed var(--line);
}
.stats > div:last-child { border-bottom: 0; }
.stats dt { color: var(--muted); }
.stats dd { margin: 0; text-align: right; font-weight: 600; overflow-wrap: anywhere; }
.pill {
  display: inline-block; padding: 3px 10px; border-radius: 999px;
  font-size: 12px; font-weight: 700; white-space: nowrap;
}
.pill.ok { background: var(--ok-bg); color: var(--ok-text); }
.pill.off { background: #152424; color: #9ab0ac; }
.pill.bad { background: var(--err-bg); color: var(--danger); }
.pill.warn { background: var(--warn-bg); color: var(--warn-text); }
.alert {
  border-radius: 12px; padding: 12px 14px; margin-bottom: 16px;
  white-space: pre-wrap; overflow-wrap: anywhere;
}
.alert.ok { background: var(--ok-bg); color: var(--ok-text); }
.alert.error { background: var(--err-bg); color: var(--danger); }
.alert.warn { background: var(--warn-bg); color: var(--warn-text); }
form { margin: 0; }
label { display: block; margin-bottom: 12px; font-weight: 600; }
input[type="text"], input[type="password"], textarea {
  width: 100%; margin-top: 6px; padding: 10px 12px;
  border: 1px solid var(--line); border-radius: 10px; background: var(--field);
  color: var(--text); font: 14px/1.45 ui-monospace, SFMono-Regular, Consolas, monospace;
}
input[type="text"], input[type="password"] {
  font-family: inherit;
}
textarea { min-height: 150px; resize: vertical; }
input:focus, textarea:focus {
  outline: 2px solid rgba(46, 229, 174, .18); border-color: var(--accent);
  background: #0d1f1e;
}
input::placeholder, textarea::placeholder { color: #5f7773; }
.file-row {
  display: flex; align-items: center; gap: 10px; margin: -4px 0 14px;
  color: var(--muted); font-size: 13px;
}
.file-row input { font-size: 13px; }
.btn {
  display: inline-block; border: 0; border-radius: 10px; padding: 9px 16px;
  font: 600 14px/1.2 inherit; cursor: pointer; text-decoration: none;
  background: #142323; color: var(--text); white-space: nowrap;
}
.btn:hover { background: #1a2d2c; }
.btn.primary { background: var(--accent); color: #04130f; }
.btn.primary:hover { background: var(--accent-dark); }
.btn.danger { background: var(--danger-bg); color: var(--danger); }
.btn.danger:hover { background: #381b1d; }
.btn.ghost { background: transparent; border: 1px solid var(--line); }
.btn.ghost:hover { background: #111f1e; }
.btn.small { padding: 6px 11px; font-size: 13px; }
.btn:disabled { opacity: .45; cursor: not-allowed; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.actions form { display: inline-block; }
.table-wrap { overflow-x: auto; max-width: 100%; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 11px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: middle; }
th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
tr:last-child td { border-bottom: 0; }
.type { color: var(--muted); font-size: 12px; margin-top: 2px; }
details { margin-top: 10px; max-width: 100%; }
summary { cursor: pointer; color: var(--accent); font-weight: 600; }
pre {
  margin: 10px 0 0; padding: 12px; background: #071313; border: 1px solid var(--line);
  border-radius: 10px; overflow: auto; width: 100%; max-width: 100%; max-height: 360px;
  white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word;
  font: 12px/1.5 ui-monospace, SFMono-Regular, Consolas, monospace;
}
.empty { color: var(--muted); text-align: center; padding: 22px 8px; }
.author-hero { display: flex; align-items: center; gap: 22px; }
.author-avatar {
  width: 112px; height: 112px; flex: 0 0 112px;
  filter: drop-shadow(0 12px 30px rgba(15, 123, 95, .22));
}
.author-avatar svg { display: block; width: 100%; height: 100%; }
.author-info h1 { margin: 0 0 4px; font-size: 30px; letter-spacing: -.03em; }
.author-tagline { color: var(--accent); font-weight: 600; margin-bottom: 10px; }
.author-about { color: var(--muted); margin: 0; white-space: pre-line; }
.author-section-head {
  display: flex; align-items: center; justify-content: space-between;
  gap: 12px; flex-wrap: wrap; margin-bottom: 14px;
}
.author-section-head h2 { margin: 0; }
.donate-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
  gap: 12px;
}
.donate-card {
  border: 1px solid var(--line); border-radius: 12px;
  padding: 14px; background: var(--card-2);
}
.donate-label {
  color: var(--muted); font-size: 11px; font-weight: 700;
  letter-spacing: .08em; text-transform: uppercase;
}
.donate-value {
  margin: 7px 0; font: 600 13px/1.5 ui-monospace, SFMono-Regular, Consolas, monospace;
  overflow-wrap: anywhere; word-break: break-word;
}
.donate-note { color: var(--muted); font-size: 12px; margin-bottom: 10px; }
.author-links { display: flex; flex-wrap: wrap; gap: 8px; }
.footer { color: var(--muted); font-size: 12px; text-align: center; margin-top: 24px; }
@media (max-width: 760px) {
  .grid { grid-template-columns: 1fr; }
  .wrap { padding-top: 16px; }
  th:nth-child(2), td:nth-child(2) { display: none; }
  .author-hero { flex-direction: column; align-items: flex-start; }
  .author-avatar { width: 92px; height: 92px; flex-basis: 92px; }
}
"""

JS = """
document.addEventListener('change', function (event) {
  if (event.target && event.target.id === 'keyfile') {
    var file = event.target.files && event.target.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () {
      var area = document.getElementById('content');
      if (area) area.value = reader.result;
    };
    reader.readAsText(file);
  }
});
document.addEventListener('submit', function (event) {
  var form = event.target;
  if (form && form.dataset && form.dataset.confirm) {
    if (!window.confirm(form.dataset.confirm)) event.preventDefault();
  }
});
document.addEventListener('click', function (event) {
  var button = event.target.closest('[data-copy]');
  if (!button) return;
  var text = button.getAttribute('data-copy');
  var original = button.textContent;

  function done() {
    button.textContent = 'Скопировано';
    window.setTimeout(function () { button.textContent = original; }, 1600);
  }

  function fallback() {
    var area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', 'readonly');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    try { document.execCommand('copy'); done(); } catch (err) {}
    document.body.removeChild(area);
  }

  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done).catch(fallback);
  } else {
    fallback();
  }
});
"""


def escape(value):
    return html.escape(str(value), quote=True)


def badge(text, kind):
    return '<span class="pill {}">{}</span>'.format(kind, escape(text))


def format_time(timestamp):
    try:
        return time.strftime("%d.%m.%Y %H:%M", time.localtime(int(timestamp)))
    except (ValueError, TypeError, OSError):
        return "—"


LOGIN_CSS = """
.login-body {
  margin: 0;
  min-height: 100vh;
  background: #050b0e;
  color: #eaf6f3;
  overflow-x: hidden;
  position: relative;
}
.login-body::before {
  content: "";
  position: fixed;
  inset: -25%;
  z-index: 0;
  pointer-events: none;
  background:
    radial-gradient(ellipse at 22% 18%, rgba(20, 220, 160, .20), transparent 44%),
    radial-gradient(ellipse at 82% 76%, rgba(42, 110, 255, .18), transparent 45%),
    radial-gradient(ellipse at 55% 42%, rgba(12, 110, 92, .14), transparent 42%);
  animation: chernox-bg 16s ease-in-out infinite alternate;
}
.login-body::after {
  content: "";
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  background-image:
    linear-gradient(rgba(130, 255, 220, .035) 1px, transparent 1px),
    linear-gradient(90deg, rgba(130, 255, 220, .035) 1px, transparent 1px);
  background-size: 54px 54px;
  -webkit-mask-image: radial-gradient(circle at 50% 45%, #000 0%, transparent 72%);
  mask-image: radial-gradient(circle at 50% 45%, #000 0%, transparent 72%);
}
.login-orb {
  position: fixed;
  z-index: 0;
  border-radius: 50%;
  filter: blur(72px);
  opacity: .36;
  pointer-events: none;
}
.login-orb.orb-1 {
  width: 440px; height: 440px; left: -160px; top: -150px;
  background: #0bd8a4;
  animation: chernox-drift-1 16s ease-in-out infinite;
}
.login-orb.orb-2 {
  width: 380px; height: 380px; right: -130px; bottom: -150px;
  background: #2563eb;
  animation: chernox-drift-2 20s ease-in-out infinite;
}
.login-orb.orb-3 {
  width: 260px; height: 260px; left: 66%; top: 10%;
  background: #7c3aed;
  opacity: .20;
  animation: chernox-drift-1 22s ease-in-out infinite reverse;
}
.login-shell {
  position: relative;
  z-index: 2;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 28px 18px;
}
.login-card {
  position: relative;
  width: min(400px, 100%);
  padding: 36px 32px 26px;
  overflow: hidden;
  border: 1px solid rgba(160, 255, 225, .14);
  border-radius: 24px;
  background: linear-gradient(165deg, rgba(18, 32, 34, .94), rgba(7, 15, 18, .97));
  box-shadow:
    0 40px 90px rgba(0, 0, 0, .58),
    0 0 0 1px rgba(0, 0, 0, .35) inset;
  -webkit-backdrop-filter: blur(18px);
  backdrop-filter: blur(18px);
  animation: chernox-card-in .8s cubic-bezier(.16, 1, .3, 1) both;
}
.login-card::before {
  content: "";
  position: absolute;
  inset: -1px;
  padding: 1px;
  border-radius: inherit;
  pointer-events: none;
  background: linear-gradient(140deg, rgba(71, 255, 205, .45), rgba(255, 255, 255, 0) 36%, rgba(72, 132, 255, .38));
  -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
  -webkit-mask-composite: xor;
  mask-composite: exclude;
}
.login-card::after {
  content: "";
  position: absolute;
  width: 260px; height: 260px; right: -120px; top: -130px;
  pointer-events: none;
  background: radial-gradient(circle, rgba(30, 220, 170, .22), transparent 66%);
}
.login-logo {
  position: relative;
  z-index: 1;
  width: 96px; height: 96px;
  margin-bottom: 16px;
  filter: drop-shadow(0 14px 34px rgba(24, 210, 160, .26));
  animation: chernox-logo-float 6s ease-in-out infinite;
}
.login-head { position: relative; z-index: 1; }
.login-head h1 {
  margin: 0 0 6px;
  font-size: 36px;
  line-height: 1.1;
  letter-spacing: -.04em;
  color: #effffb;
  background: linear-gradient(95deg, #ffffff 8%, #a7ffe7 56%, #8db7ff 100%);
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
}
.login-head p {
  margin: 0 0 26px;
  color: #8fa6a3;
  font-size: 14px;
}
.login-form { position: relative; z-index: 1; }
.login-field {
  display: block;
  margin: 0 0 8px;
  color: #a9c3be;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .10em;
  text-transform: uppercase;
}
.password-wrap { position: relative; }
.password-wrap input {
  width: 100%;
  margin: 0;
  padding: 15px 82px 15px 15px;
  border: 1px solid rgba(180, 255, 235, .14);
  border-radius: 13px;
  background: rgba(255, 255, 255, .045);
  color: #f4fffc;
  font-size: 15px;
  line-height: 1.3;
  transition: border-color .2s, box-shadow .2s, background .2s;
}
.password-wrap input::placeholder { color: #5e7470; }
.password-wrap input:focus {
  outline: none;
  border-color: rgba(77, 235, 190, .7);
  background: rgba(255, 255, 255, .07);
  box-shadow: 0 0 0 4px rgba(45, 220, 170, .10), 0 0 34px rgba(45, 220, 170, .10);
}
.password-toggle {
  position: absolute;
  right: 9px;
  top: 50%;
  padding: 8px;
  border: 0;
  border-radius: 8px;
  background: transparent;
  color: #79e6c6;
  font: 700 11px/1 inherit;
  letter-spacing: .04em;
  text-transform: uppercase;
  cursor: pointer;
  transform: translateY(-50%);
}
.password-toggle:hover { background: rgba(121, 230, 198, .08); }
.login-submit {
  width: 100%;
  margin-top: 18px;
  padding: 15px 18px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  border: 0;
  border-radius: 13px;
  background: linear-gradient(100deg, #4ff0c2, #12c9a2 48%, #4f8dff);
  background-size: 170% 100%;
  color: #04130f;
  font: 800 15px/1 inherit;
  cursor: pointer;
  box-shadow: 0 16px 40px rgba(27, 205, 160, .24);
  transition: transform .2s, box-shadow .2s, background-position .35s;
}
.login-submit:hover {
  transform: translateY(-1px);
  background-position: 100% 0;
  box-shadow: 0 20px 50px rgba(27, 205, 160, .34);
}
.login-submit:active { transform: translateY(0) scale(.995); }
.login-submit .arrow { font-size: 18px; line-height: 1; transition: transform .2s; }
.login-submit:hover .arrow { transform: translateX(3px); }
.login-alert {
  position: relative;
  z-index: 1;
  margin: 0 0 16px;
  padding: 11px 13px;
  border: 1px solid rgba(255, 105, 85, .30);
  border-radius: 12px;
  background: rgba(180, 35, 24, .16);
  color: #ffb4aa;
  font-size: 13px;
  animation: chernox-alert-in .3s ease both;
}
.login-alert.warn {
  border-color: rgba(255, 190, 90, .28);
  background: rgba(161, 92, 0, .18);
  color: #ffd28f;
}
.login-meta {
  position: relative;
  z-index: 1;
  display: flex;
  justify-content: space-between;
  gap: 12px;
  margin-top: 22px;
  padding-top: 16px;
  border-top: 1px solid rgba(160, 255, 225, .08);
  color: #58706c;
  font-size: 10px;
  letter-spacing: .16em;
  text-transform: uppercase;
}
.login-foot {
  margin-top: 22px;
  color: #526864;
  font-size: 11px;
  letter-spacing: .08em;
  text-transform: uppercase;
  text-align: center;
}
.login-foot a { color: #79e6c6; text-decoration: none; }
.login-foot a:hover { text-decoration: underline; }
@keyframes chernox-card-in {
  from { opacity: 0; transform: translateY(24px) scale(.97); }
  to { opacity: 1; transform: none; }
}
@keyframes chernox-logo-float {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-5px); }
}
@keyframes chernox-bg {
  0% { transform: translate3d(-2%, -1%, 0) scale(1.04); }
  100% { transform: translate3d(2%, 2%, 0) scale(1.10); }
}
@keyframes chernox-drift-1 {
  0%, 100% { transform: translate3d(0, 0, 0) scale(1); }
  50% { transform: translate3d(46px, -34px, 0) scale(1.08); }
}
@keyframes chernox-drift-2 {
  0%, 100% { transform: translate3d(0, 0, 0) scale(1.05); }
  50% { transform: translate3d(-40px, 28px, 0) scale(.95); }
}
@keyframes chernox-alert-in {
  from { opacity: 0; transform: translateY(-6px); }
  to { opacity: 1; transform: none; }
}
@media (max-width: 600px) {
  .login-orb { animation: none; filter: blur(48px); opacity: .22; }
  .login-body::before { animation: none; }
  .login-card {
    -webkit-backdrop-filter: blur(10px);
    backdrop-filter: blur(10px);
  }
}
@media (max-width: 480px) {
  .login-card { padding: 30px 22px 22px; border-radius: 20px; }
  .login-logo { width: 82px; height: 82px; }
  .login-head h1 { font-size: 31px; }
  .login-body::after { background-size: 40px 40px; }
}
@media (prefers-reduced-motion: reduce) {
  .login-card, .login-logo, .login-orb, .login-body::before, .login-alert {
    animation: none !important;
  }
}
"""

LOGIN_JS = """
(function () {
  var input = document.getElementById('password');
  var toggle = document.getElementById('toggle-password');
  if (!input || !toggle) return;
  toggle.addEventListener('click', function () {
    var visible = input.type === 'text';
    input.type = visible ? 'password' : 'text';
    toggle.textContent = visible ? 'Показать' : 'Скрыть';
    toggle.setAttribute('aria-label', visible ? 'Показать пароль' : 'Скрыть пароль');
    input.focus();
  });
})();
"""


def render_page(body, session, title="Chernox", current="dashboard"):
    flash = pop_flash(session)
    flash_html = ""
    if flash:
        kind = flash.get("kind", "ok")
        if kind not in ("ok", "error", "warn"):
            kind = "ok"
        flash_html = '<div class="alert {}">{}</div>'.format(
            kind, escape(flash.get("message", ""))
        )

    csrf = escape(session["csrf"]) if session else ""
    if current == "author":
        nav_html = '<a class="btn ghost small" href="/">Панель</a>'
    else:
        nav_html = '<a class="btn ghost small" href="/author">Автор</a>'

    if session:
        nav_html += """
        <form method="post" action="/logout">
          <input type="hidden" name="csrf" value="{csrf}">
          <button class="btn ghost small" type="submit">Выйти</button>
        </form>
        """.format(csrf=csrf)
    elif current != "author":
        nav_html += '<a class="btn ghost small" href="/login">Войти</a>'
    else:
        nav_html = '<a class="btn ghost small" href="/login">Войти</a>'

    return """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>{title}</title>
<style>{css}</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <div class="brand-logo">{logo}</div>
      <div>
        <div class="brand-name">Chernox</div>
        <div class="brand-sub">локальная панель</div>
      </div>
    </div>
    <div class="header-actions">{nav}</div>
  </header>
  {flash}
  {body}
  <div class="footer">Chernox {version} · панель работает только в локальной сети. Не открывайте её порт в интернет.</div>
</div>
<script>{js}</script>
</body>
</html>
""".format(
        title=escape(title),
        css=CSS,
        js=JS,
        nav=nav_html,
        flash=flash_html,
        body=body,
        logo=LOGO_MARK_SVG,
        version=escape(VERSION),
    )


def render_login(error="", status_hint=""):
    alert_html = ""
    if error:
        alert_html = '<div class="login-alert">{}</div>'.format(escape(error))
    elif status_hint:
        alert_html = '<div class="login-alert warn">{}</div>'.format(
            escape(status_hint)
        )

    return """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Вход · Chernox</title>
<style>{css}{login_css}</style>
</head>
<body class="login-body">
<div class="login-orb orb-1"></div>
<div class="login-orb orb-2"></div>
<div class="login-orb orb-3"></div>
<main class="login-shell">
  <section class="login-card">
    <div class="login-logo">{logo}</div>
    <div class="login-head">
      <h1>Chernox</h1>
      <p>Локальная панель управления</p>
    </div>
    {alert}
    <form method="post" action="/login" class="login-form">
      <label class="login-field" for="password">Пароль</label>
      <div class="password-wrap">
        <input id="password" type="password" name="password"
          autocomplete="current-password" autofocus required placeholder="Введите пароль">
        <button class="password-toggle" type="button" id="toggle-password"
          aria-label="Показать пароль">Показать</button>
      </div>
      <button class="login-submit" type="submit">
        <span>Войти</span><span class="arrow">→</span>
      </button>
    </form>
    <div class="login-meta"><span>Local access</span><span>Chernox</span></div>
  </section>
  <div class="login-foot">Chernox {version} · только локальная сеть · <a href="/author">Автор</a></div>
</main>
<script>{login_js}</script>
</body>
</html>
""".format(
        css=CSS,
        login_css=LOGIN_CSS,
        login_js=LOGIN_JS,
        alert=alert_html,
        logo=LOGO_SVG,
        version=escape(VERSION),
    )


def render_author_page(settings):
    author = load_author(settings)

    about_html = ""
    if author["about"]:
        about_html = '<p class="author-about">{}</p>'.format(
            escape(author["about"])
        )

    hero = """
    <section class="card author-hero">
      <div class="author-avatar">{logo}</div>
      <div class="author-info">
        <h1>{name}</h1>
        <div class="author-tagline">{tagline}</div>
        {about}
      </div>
    </section>
    """.format(
        logo=LOGO_SVG,
        name=escape(author["name"]),
        tagline=escape(author["tagline"]) or "&nbsp;",
        about=about_html,
    )

    donation_cards = []
    for item in author["donations"]:
        note_html = ""
        if item["note"]:
            note_html = '<div class="donate-note">{}</div>'.format(
                escape(item["note"])
            )
        donation_cards.append(
            """
            <article class="donate-card">
              <div class="donate-label">{label}</div>
              <div class="donate-value">{value}</div>
              {note}
              <button class="btn small" type="button" data-copy="{value_attr}">Скопировать</button>
            </article>
            """.format(
                label=escape(item["label"]),
                value=escape(item["value"]),
                value_attr=escape(item["value"]),
                note=note_html,
            )
        )

    if donation_cards:
        donations_html = '<div class="donate-grid">{}</div>'.format(
            "".join(donation_cards)
        )
    else:
        donations_html = (
            '<div class="empty">Реквизиты для донатов пока не добавлены.</div>'
        )

    links_html = ""
    if author["links"]:
        links = []
        for item in author["links"]:
            links.append(
                '<a class="btn ghost" href="{url}" target="_blank" '
                'rel="noopener noreferrer">{label}</a>'.format(
                    url=escape(item["url"]), label=escape(item["label"])
                )
            )
        links_html = """
        <section class="card">
          <h2>Ссылки</h2>
          <div class="author-links">{links}</div>
        </section>
        """.format(links="".join(links))

    body = """
    {hero}
    <section class="card">
      <div class="author-section-head">
        <h2>Помогите проекту в развитии</h2>
      </div>
      {donations}
    </section>
    {links}
    """.format(
        hero=hero,
        donations=donations_html,
        links=links_html,
    )
    return body


def render_dashboard(settings, session, configs):
    running = service_running()
    tproxy = tproxy_active()
    manual = manual_stop_requested(settings)
    active = next((item for item in configs if item["active"]), None)
    route_mode = get_route_mode(settings)
    route_info = ROUTE_MODES[route_mode]

    if running:
        singbox_badge = badge("Работает", "ok")
    else:
        singbox_badge = badge("Остановлен", "off")

    if tproxy:
        tproxy_badge = badge("Включён", "ok")
    elif manual:
        tproxy_badge = badge("Выключен вручную", "warn")
    else:
        tproxy_badge = badge("Выключен", "off")

    active_name = active["name"] if active else "не выбран"
    active_summary = ""
    tag_warning = ""
    if active:
        try:
            _, active_config, _ = render_record(active)
            active_summary = outbound_summary(active_config)
            if not config_has_check_tag(active_config):
                tag_warning = (
                    "В активном конфиге нет outbound с tag ssh-out. "
                    "Скрипт check-internet может отключать tproxy."
                )
        except Exception as exc:
            active_summary = "ошибка: {}".format(exc)

    warning_html = ""
    if tag_warning:
        warning_html = '<div class="alert warn">{}</div>'.format(escape(tag_warning))

    status_body = """
    <div class="grid">
      <section class="card">
        <h2>Состояние</h2>
        <dl class="stats">
          <div><dt>sing-box</dt><dd>{singbox_badge}</dd></div>
          <div><dt>VPN (tproxy)</dt><dd>{tproxy_badge}</dd></div>
          <div><dt>Маршрутизация</dt><dd>{route_short}</dd></div>
          <div><dt>Активный конфиг</dt><dd>{active_name}</dd></div>
          <div><dt>Сервер</dt><dd>{active_summary}</dd></div>
        </dl>
      </section>
      <section class="card">
        <h2>Управление</h2>
        <p class="muted small">Включение запускает sing-box и tproxy. Выключение останавливает sing-box и снимает tproxy.</p>
        <div class="actions">
          <form method="post" action="/vpn/start">
            <input type="hidden" name="csrf" value="{csrf}">
            <button class="btn primary" type="submit">Включить VPN</button>
          </form>
          <form method="post" action="/vpn/stop" data-confirm="Выключить VPN?">
            <input type="hidden" name="csrf" value="{csrf}">
            <button class="btn danger" type="submit">Выключить VPN</button>
          </form>
        </div>
      </section>
    </div>
    """.format(
        singbox_badge=singbox_badge,
        tproxy_badge=tproxy_badge,
        active_name=escape(active_name),
        active_summary=escape(active_summary or "—"),
        route_short=escape(route_info["short"]),
        csrf=escape(session["csrf"]),
    )

    route_options = []
    for mode_key, mode_info in ROUTE_MODES.items():
        checked = " checked" if mode_key == route_mode else ""
        route_options.append(
            """
            <label class="route-option">
              <input type="radio" name="mode" value="{value}"{checked}>
              <span class="route-option-body">
                <b>{title}</b>
                <small>{hint}</small>
              </span>
            </label>
            """.format(
                value=escape(mode_key),
                checked=checked,
                title=escape(mode_info["title"]),
                hint=escape(mode_info["hint"]),
            )
        )

    routing_body = """
    <section class="card">
      <h2>Маршрутизация</h2>
      <form method="post" action="/routing/mode">
        <input type="hidden" name="csrf" value="{csrf}">
        <div class="route-options">{options}</div>
        <button class="btn primary" type="submit">Применить режим</button>
      </form>
      <p class="muted small route-note">Списки RU-сайтов берутся из SagerNet geosite-category-ru и geoip-ru и скачиваются через активный ключ.</p>
    </section>
    """.format(
        csrf=escape(session["csrf"]),
        options="".join(route_options),
    )

    add_form = """
    <section class="card">
      <h2>Добавить ключ</h2>
      <form method="post" action="/configs/add">
        <input type="hidden" name="csrf" value="{csrf}">
        <label>Название <span class="muted small">(необязательно)</span>
          <input type="text" name="name" maxlength="100" placeholder="Например, основной сервер">
        </label>
        <label>Ключ или конфиг
          <textarea id="content" name="content" required
            placeholder="vless://...&#10;hysteria2://... или hy2://...&#10;ssh://...&#10;&#10;JSON sing-box (только vless / hysteria2 / ssh)"></textarea>
        </label>
        <p class="muted small form-hint">Поддерживаются <code>vless://</code>, <code>hysteria2://</code> / <code>hy2://</code> и <code>ssh://</code>.</p>
        <div class="file-row">
          <span>Загрузить из файла:</span>
          <input type="file" id="keyfile" accept=".json,.txt,.conf,application/json,text/plain">
        </div>
        <button class="btn primary" type="submit">Сохранить</button>
      </form>
    </section>
    """.format(csrf=escape(session["csrf"]))

    rows = []
    for item in configs:
        activate_button = ""
        if not item["active"]:
            activate_button = """
            <form method="post" action="/configs/activate">
              <input type="hidden" name="csrf" value="{csrf}">
              <input type="hidden" name="id" value="{id}">
              <button class="btn small primary" type="submit">Включить</button>
            </form>
            """.format(csrf=escape(session["csrf"]), id=int(item["id"]))

        delete_button = """
        <form method="post" action="/configs/delete" data-confirm="Удалить конфиг «{name}»?">
          <input type="hidden" name="csrf" value="{csrf}">
          <input type="hidden" name="id" value="{id}">
          <button class="btn small danger" type="submit"{disabled}>Удалить</button>
        </form>
        """.format(
            name=escape(item["name"]),
            csrf=escape(session["csrf"]),
            id=int(item["id"]),
            disabled=" disabled" if item["active"] else "",
        )

        if item["active"]:
            state = badge("Активен", "ok")
        else:
            state = badge("Не активен", "off")

        rows.append(
            """
            <tr>
              <td>
                <strong>{name}</strong>
                <div class="type">{kind}</div>
                <details>
                  <summary>Показать конфиг</summary>
                  <pre>{preview}</pre>
                </details>
              </td>
              <td>{created}</td>
              <td>{state}</td>
              <td><div class="actions">{activate}{delete}</div></td>
            </tr>
            """.format(
                name=escape(item["name"]),
                kind=escape(record_type_label(item)),
                preview=escape(item["content"]),
                created=escape(format_time(item["created_at"])),
                state=state,
                activate=activate_button,
                delete=delete_button,
            )
        )

    if rows:
        table_html = """
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Конфиг</th><th>Добавлен</th><th>Статус</th><th>Действия</th></tr>
            </thead>
            <tbody>{rows}</tbody>
          </table>
        </div>
        """.format(rows="".join(rows))
    else:
        table_html = '<div class="empty">Пока нет сохранённых конфигов. Добавьте первый ключ выше.</div>'

    configs_body = """
    <section class="card">
      <h2>Сохранённые конфиги</h2>
      {table}
    </section>
    """.format(table=table_html)

    return (
        warning_html
        + status_body
        + routing_body
        + add_form
        + configs_body
    )


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class PanelHandler(BaseHTTPRequestHandler):
    server_version = "Chernox/" + VERSION
    protocol_version = "HTTP/1.1"

    # ----- низкоуровневые ответы -----

    def log_message(self, fmt, *args):
        sys.stdout.write(
            "{} - - [{}] {}\n".format(
                self.client_address[0], self.log_date_time_string(), fmt % args
            )
        )
        sys.stdout.flush()

    def send_body(self, status, body, content_type="text/html; charset=utf-8", extra=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; form-action 'self'; "
            "frame-ancestors 'none'; base-uri 'none'",
        )
        if extra:
            for key, value in extra:
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def send_redirect(self, location, extra=None):
        body = '<!doctype html><meta charset="utf-8"><a href="{}">Перейти</a>'.format(
            escape(location)
        )
        self.send_body(303, body, extra=[("Location", location)] + (extra or []))

    def send_error_page(self, status, message):
        body = """
        <div class="login-wrap">
          <div class="card">
            <h1>Ошибка {status}</h1>
            <p>{message}</p>
            <p><a class="btn ghost" href="/">На главную</a></p>
          </div>
        </div>
        """.format(status=int(status), message=escape(message))
        page = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ошибка</title><style>{css}</style></head>
<body><div class="wrap">{body}</div></body></html>
""".format(css=CSS, body=body)
        self.send_body(status, page)

    # ----- cookies / сессии -----

    def get_cookie(self, name):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = cookies.SimpleCookie()
        try:
            jar.load(raw)
        except cookies.CookieError:
            return None
        item = jar.get(name)
        return item.value if item else None

    def session_cookie(self, token, max_age):
        return (
            "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}".format(
                COOKIE_NAME, token, int(max_age)
            )
        )

    def current_session(self):
        return get_session(self.get_cookie(COOKIE_NAME))

    # ----- маршрутизация -----

    def do_GET(self):
        try:
            self.handle_get()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            traceback.print_exc()
            try:
                self.send_error_page(500, "Внутренняя ошибка панели. Подробности в logread.")
            except Exception:
                pass

    def do_POST(self):
        try:
            self.handle_post()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            traceback.print_exc()
            try:
                self.send_error_page(500, "Внутренняя ошибка панели. Подробности в logread.")
            except Exception:
                pass

    def handle_get(self):
        path = urlparse(self.path).path
        if path == "/favicon.ico":
            self.send_body(204, "", content_type="text/plain; charset=utf-8")
            return

        session = self.current_session()

        if path == "/login":
            if session:
                self.send_redirect("/")
            else:
                self.send_body(200, render_login())
            return

        if path == "/author":
            body = render_author_page(SETTINGS)
            self.send_body(
                200,
                render_page(body, session, "Автор · Chernox", current="author"),
            )
            return

        if session is None:
            self.send_redirect("/login")
            return

        if path in ("/", "/index.html"):
            configs = fetch_configs(SETTINGS)
            body = render_dashboard(SETTINGS, session, configs)
            self.send_body(200, render_page(body, session))
        else:
            self.send_error_page(404, "Страница не найдена.")

    def read_fields(self):
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        if length < 0 or length > MAX_BODY:
            raise ValueError("Слишком большой запрос.")
        body = self.rfile.read(length).decode("utf-8", "replace")
        return parse_qs(body, keep_blank_values=True)

    def handle_post(self):
        path = urlparse(self.path).path

        try:
            fields = self.read_fields()
        except ValueError as exc:
            self.send_error_page(413, str(exc))
            return

        if path == "/login":
            self.handle_login(fields)
            return

        session = self.current_session()
        if session is None:
            self.send_redirect("/login")
            return

        csrf = first_value(fields, "csrf")
        if not csrf or not hmac.compare_digest(csrf, session["csrf"]):
            self.send_error_page(403, "Проверка безопасности не пройдена. Обновите страницу.")
            return

        if path == "/logout":
            drop_session(session["token"])
            self.send_redirect(
                "/login",
                extra=[("Set-Cookie", self.session_cookie("", 0))],
            )
            return

        try:
            if path == "/configs/add":
                self.action_add(fields)
            elif path == "/configs/activate":
                self.action_activate(fields)
            elif path == "/configs/delete":
                self.action_delete(fields)
            elif path == "/routing/mode":
                self.action_set_mode(fields)
            elif path == "/vpn/start":
                message = start_vpn(SETTINGS)
                set_flash(session, message, "ok")
            elif path == "/vpn/stop":
                message = stop_vpn(SETTINGS)
                set_flash(session, message, "warn" if "не удалось" in message else "ok")
            else:
                self.send_error_page(404, "Действие не найдено.")
                return
        except (ValueError, RuntimeError, OSError) as exc:
            set_flash(session, str(exc), "error")
        except Exception as exc:
            traceback.print_exc()
            set_flash(session, "Неожиданная ошибка: {}".format(exc), "error")

        self.send_redirect("/")

    def handle_login(self, fields):
        ip = self.client_address[0]

        if login_blocked(ip):
            self.send_body(
                429,
                render_login(
                    "Слишком много неудачных попыток. Попробуйте через 5 минут."
                ),
            )
            return

        password = first_value(fields, "password")
        if not password:
            self.send_body(400, render_login("Введите пароль."))
            return

        if not verify_password(password, SETTINGS.get("password_hash", "")):
            register_failed_login(ip)
            self.send_body(401, render_login("Неверный пароль."))
            return

        clear_login_attempts(ip)
        session = create_session()
        self.send_redirect(
            "/",
            extra=[
                ("Set-Cookie", self.session_cookie(session["token"], SESSION_TTL))
            ],
        )

    # ----- действия -----

    def parse_id(self, fields):
        try:
            return int(first_value(fields, "id"))
        except (TypeError, ValueError):
            raise ValueError("Некорректный идентификатор конфига.")

    def action_add(self, fields):
        content = first_value(fields, "content").strip().lstrip("\ufeff")
        if not content:
            raise ValueError("Ключ или конфиг не может быть пустым.")

        kind = detect_kind(content)
        name = first_value(fields, "name").strip()[:100]

        record = {"kind": kind, "content": content}
        config_text, _, label = render_record(record)

        check_error = singbox_check_error(config_text)
        if check_error:
            raise ValueError("sing-box отклонил конфиг:\n{}".format(check_error))

        if not name:
            name = label[:100]

        insert_config(SETTINGS, name, kind, content)
        session = self.current_session()
        set_flash(session, "Конфиг «{}» сохранён.".format(name), "ok")

    def action_activate(self, fields):
        config_id = self.parse_id(fields)
        record = fetch_config(SETTINGS, config_id)
        if record is None:
            raise ValueError("Конфиг не найден.")

        route_mode = get_route_mode(SETTINGS)
        _, _, warning = apply_config(SETTINGS, record, route_mode)
        mark_active(SETTINGS, config_id)

        message = "Конфиг «{}» активирован, VPN включён. Маршрутизация: {}.".format(
            record["name"], ROUTE_MODES[route_mode]["short"]
        )
        if warning:
            message += "\n" + warning
        session = self.current_session()
        set_flash(session, message, "warn" if warning else "ok")

    def action_set_mode(self, fields):
        mode = first_value(fields, "mode")
        if mode not in ROUTE_MODES:
            raise ValueError("Неизвестный режим маршрутизации.")

        validate_route_mode(mode)

        active = fetch_active_config(SETTINGS)
        warning = ""
        if active is not None:
            _, _, warning = apply_config(SETTINGS, active, mode)

        set_setting(SETTINGS, "route_mode", mode)

        if active is not None:
            message = "Маршрутизация: {}. Конфиг применён.".format(
                ROUTE_MODES[mode]["short"]
            )
        else:
            message = (
                "Маршрутизация: {}. Применится при активации ключа.".format(
                    ROUTE_MODES[mode]["short"]
                )
            )
        if warning:
            message += "\n" + warning
        session = self.current_session()
        set_flash(session, message, "warn" if warning else "ok")

    def action_delete(self, fields):
        config_id = self.parse_id(fields)
        name = delete_config(SETTINGS, config_id)
        session = self.current_session()
        set_flash(session, "Конфиг «{}» удалён.".format(name), "ok")


# ---------------------------------------------------------------------------
# Запуск
# ---------------------------------------------------------------------------


def initialize_settings(path, password, host, port):
    if os.path.exists(path):
        settings = load_settings(path)
    else:
        settings = default_settings()

    if host:
        settings["host"] = host
    if port:
        settings["port"] = int(port)

    settings["password_hash"] = hash_password(password)
    save_settings(path, settings)
    init_storage(settings)
    return settings


def main():
    global SETTINGS, SESSION_TTL

    parser = argparse.ArgumentParser(description="Chernox — локальная веб-панель sing-box")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="путь к файлу настроек")
    parser.add_argument("--init", action="store_true", help="создать/обновить настройки и выйти")
    parser.add_argument("--host", default=None, help="адрес прослушивания")
    parser.add_argument("--port", type=int, default=None, help="порт панели")
    args = parser.parse_args()

    if args.init:
        password = sys.stdin.readline().rstrip("\r\n")
        if not password:
            sys.exit("Пустой пароль.")
        settings = initialize_settings(args.config, password, args.host, args.port)
        print("Настройки сохранены: {}".format(args.config))
        print("База данных: {}".format(settings["db_path"]))
        return

    try:
        settings = load_settings(args.config)
    except FileNotFoundError:
        sys.exit(
            "Файл настроек не найден: {}. Запустите install_panel.sh.".format(args.config)
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        sys.exit("Не удалось прочитать настройки: {}".format(exc))

    if not settings.get("password_hash"):
        sys.exit("В настройках не задан пароль. Запустите install_panel.sh.")

    try:
        init_storage(settings)
    except (OSError, sqlite3.Error) as exc:
        sys.exit("Не удалось открыть базу данных: {}".format(exc))

    SETTINGS = settings
    SESSION_TTL = int(settings.get("session_ttl", SESSION_TTL))

    host = str(settings.get("host", "0.0.0.0"))
    port = int(settings.get("port", 8080))

    try:
        server = ThreadingHTTPServer((host, port), PanelHandler)
    except OSError as exc:
        sys.exit("Не удалось запустить панель на {}:{} — {}".format(host, port, exc))

    server.daemon_threads = True
    print("Chernox {}: http://{}:{}".format(VERSION, host, port))
    sys.stdout.flush()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
