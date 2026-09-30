"""
Серверный обработчик для POZIStore.
Модерация + VirusTotal + баны с причиной.
"""
import os
import json
import bcrypt
import requests
import base64
from datetime import datetime


SERVER_TOKEN = os.environ.get("SERVER_TOKEN", "")
VT_API_KEY = os.environ.get("VT_API_KEY", "")
ACTION = os.environ.get("ACTION", "hello")
PAYLOAD = os.environ.get("PAYLOAD", "{}")
USERNAME = os.environ.get("USERNAME", "")
PASSWORD = os.environ.get("PASSWORD", "")

GITHUB_ORG = "POZIStore-Developers"
GITHUB_REPO = "pozi-store"

HEADERS = {
    "Authorization": f"token {SERVER_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

VT_HEADERS = {
    "x-apikey": VT_API_KEY,
    "Accept": "application/json"
}


# ============================================================
# ЧТЕНИЕ / ЗАПИСЬ JSON
# ============================================================

def read_json_file(path):
    url = f"https://api.github.com/repos/{GITHUB_ORG}/{GITHUB_REPO}/contents/{path}"
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        return None, None
    data = r.json()
    content = json.loads(base64.b64decode(data['content']).decode('utf-8'))
    return content, data['sha']


def write_json_file(path, content, sha, message):
    url = f"https://api.github.com/repos/{GITHUB_ORG}/{GITHUB_REPO}/contents/{path}"
    new_content = base64.b64encode(
        json.dumps(content, ensure_ascii=False, indent=2).encode('utf-8')
    ).decode('utf-8')
    payload = {
        "message": message,
        "content": new_content,
    }
    if sha:
        payload["sha"] = sha
    r = requests.put(url, headers=HEADERS, json=payload)
    return r.status_code in (200, 201)


# ============================================================
# АВТОРИЗАЦИЯ
# ============================================================

def check_auth():
    users, _ = read_json_file("users.json")
    if not users:
        return None
    for u in users.get("users", []):
        if u.get("username", "").lower() == USERNAME.lower():
            stored = u.get("password_hash", "")
            if stored and bcrypt.checkpw(PASSWORD.encode(), stored.encode()):
                return u
    return None


# ============================================================
# ПРОСТЫЕ ДЕЙСТВИЯ
# ============================================================

def handle_hello():
    return {
        "status": "ok",
        "message": "Hello from Actions!",
        "server_token_length": len(SERVER_TOKEN),
        "vt_configured": bool(VT_API_KEY)
    }


def handle_check_auth():
    user = check_auth()
    if not user:
        return {"status": "error", "message": "Неверный логин или пароль"}
    return {
        "status": "ok",
        "username": user.get("username"),
        "role": user.get("role", "user")
    }


# ============================================================
# РЕГИСТРАЦИЯ / ЛОГИН
# ============================================================

def handle_register():
    users, sha = read_json_file("users.json")
    if users is None:
        users = {"users": []}
        sha = None

    for u in users.get("users", []):
        if u.get("username", "").lower() == USERNAME.lower():
            return {"status": "error", "message": "Логин занят"}

    password_hash = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt()).decode()

    next_id = max([u.get("id", 0) for u in users.get("users", [])] + [0]) + 1
    new_user = {
        "id": next_id,
        "username": USERNAME,
        "password_hash": password_hash,
        "role": "user",
        "blocked": False,
        "ban_reason": "",
        "avatar": "",
        "banner": "",
        "description": "",
        "website": "",
        "created_at": datetime.now().isoformat()
    }
    users.setdefault("users", []).append(new_user)

    if not write_json_file("users.json", users, sha, f"Register {USERNAME}"):
        return {"status": "error", "message": "Ошибка записи users.json"}

    return {"status": "ok", "user_id": next_id, "username": USERNAME}


def handle_login():
    user = check_auth()
    if not user:
        return {"status": "error", "message": "Неверный логин или пароль"}

    if user.get("blocked"):
        reason = user.get("ban_reason", "")
        msg = "Аккаунт заблокирован"
        if reason:
            msg += f". Причина: {reason}"
        return {"status": "error", "message": msg}

    return {
        "status": "ok",
        "user_id": user.get("id"),
        "username": user.get("username"),
        "role": user.get("role", "user")
    }


# ============================================================
# МОДЕРАЦИЯ: ЗАЯВКИ НА ПУБЛИКАЦИЮ
# ============================================================

def handle_request_publish():
    """
    Разработчик отправляет приложение на модерацию.
    Приложение уходит в pending_apps.json.
    """
    user = check_auth()
    if not user:
        return {"status": "error", "message": "Неверный логин или пароль"}
    if user.get("role") not in ("developer", "admin"):
        return {"status": "error", "message": "Нет прав"}

    payload = json.loads(PAYLOAD)
    app_data = payload.get("app", {})
    edit_mode = payload.get("edit_mode", False)

    if not app_data.get("id"):
        return {"status": "error", "message": "Нет id приложения"}

    pending, sha = read_json_file("pending_apps.json")
    if pending is None:
        pending = {"pending_apps": []}
        sha = None

    # Удаляем старую заявку с таким же id (если повторная отправка)
    pending["pending_apps"] = [
        p for p in pending.get("pending_apps", [])
        if p.get("id") != app_data["id"]
    ]

    # Добавляем новую
    app_data["submitted_at"] = datetime.now().isoformat()
    app_data["submitted_by"] = user.get("username", "")
    app_data["edit_mode"] = edit_mode
    app_data["vt_status"] = app_data.get("vt_status", "pending")
    app_data["vt_link"] = app_data.get("vt_link", "")
    app_data["vt_analysis_id"] = app_data.get("vt_analysis_id", "")
    app_data["status"] = "pending"
    app_data["reject_reason"] = ""

    pending.setdefault("pending_apps", []).append(app_data)

    if not write_json_file(
        "pending_apps.json", pending, sha,
        f"Pending app: {app_data['id']}"
    ):
        return {"status": "error", "message": "Ошибка записи pending_apps.json"}

    return {
        "status": "ok",
        "message": "Заявка отправлена на модерацию",
        "app_id": app_data["id"]
    }


def handle_get_pending_apps():
    """Список всех заявок (только админ)."""
    user = check_auth()
    if not user or user.get("role") != "admin":
        return {"status": "error", "message": "Нет прав"}

    pending, _ = read_json_file("pending_apps.json")
    if pending is None:
        pending = {"pending_apps": []}

    return {"status": "ok", "pending_apps": pending.get("pending_apps", [])}


def handle_get_my_pending_apps():
    """Заявки текущего разработчика (для консоли)."""
    user = check_auth()
    if not user:
        return {"status": "error", "message": "Неверный логин или пароль"}

    pending, _ = read_json_file("pending_apps.json")
    if pending is None:
        return {"status": "ok", "pending_apps": []}

    my = [
        p for p in pending.get("pending_apps", [])
        if p.get("submitted_by", "").lower() == user.get("username", "").lower()
    ]

    return {"status": "ok", "pending_apps": my}


def handle_approve_app():
    """Админ одобряет заявку. Приложение уходит в apps.json."""
    user = check_auth()
    if not user or user.get("role") != "admin":
        return {"status": "error", "message": "Только админ"}

    payload = json.loads(PAYLOAD)
    app_id = payload.get("app_id", "")

    if not app_id:
        return {"status": "error", "message": "Нет app_id"}

    # 1. Читаем pending
    pending, p_sha = read_json_file("pending_apps.json")
    if pending is None:
        return {"status": "error", "message": "pending_apps.json не найден"}

    target = None
    for p in pending.get("pending_apps", []):
        if p.get("id") == app_id:
            target = p
            break

    if not target:
        return {"status": "error", "message": "Заявка не найдена"}

    edit_mode = target.get("edit_mode", False)

    # 2. Читаем apps.json
    apps, a_sha = read_json_file("apps.json")
    if apps is None:
        apps = {"apps": []}
        a_sha = None

    # 3. Готовим данные для apps.json
    app_for_catalog = {k: v for k, v in target.items()
                       if k not in ("submitted_at", "submitted_by",
                                    "edit_mode", "status", "reject_reason")}

    if edit_mode:
        # Обновляем существующее
        found = False
        for i, a in enumerate(apps.get("apps", [])):
            if a.get("id") == app_id:
                apps["apps"][i] = app_for_catalog
                found = True
                break
        if not found:
            apps.setdefault("apps", []).append(app_for_catalog)
    else:
        # Добавляем новое
        exists = any(a.get("id") == app_id for a in apps.get("apps", []))
        if not exists:
            apps.setdefault("apps", []).append(app_for_catalog)

    if not write_json_file("apps.json", apps, a_sha, f"Approve app {app_id}"):
        return {"status": "error", "message": "Ошибка записи apps.json"}

    # 4. Убираем из pending
    pending["pending_apps"] = [
        p for p in pending.get("pending_apps", [])
        if p.get("id") != app_id
    ]
    write_json_file("pending_apps.json", pending, p_sha, f"Approved {app_id}")

    return {"status": "ok", "message": f"Приложение {app_id} одобрено"}


def handle_reject_app():
    """Админ отклоняет заявку. Оставляем в pending со статусом rejected и причиной."""
    user = check_auth()
    if not user or user.get("role") != "admin":
        return {"status": "error", "message": "Только админ"}

    payload = json.loads(PAYLOAD)
    app_id = payload.get("app_id", "")
    reason = payload.get("reason", "")

    if not app_id:
        return {"status": "error", "message": "Нет app_id"}

    pending, sha = read_json_file("pending_apps.json")
    if pending is None:
        return {"status": "error", "message": "pending_apps.json не найден"}

    found = False
    for p in pending.get("pending_apps", []):
        if p.get("id") == app_id:
            p["status"] = "rejected"
            p["reject_reason"] = reason or "Без указания причины"
            p["rejected_at"] = datetime.now().isoformat()
            found = True
            break

    if not found:
        return {"status": "error", "message": "Заявка не найдена"}

    if not write_json_file(
        "pending_apps.json", pending, sha,
        f"Reject {app_id}: {reason}"
    ):
        return {"status": "error", "message": "Ошибка записи"}

    return {"status": "ok", "message": "Заявка отклонена"}


# ============================================================
# КАТАЛОГ
# ============================================================

def handle_update_apps():
    """Обновить apps.json напрямую (для админа)."""
    user = check_auth()
    if not user:
        return {"status": "error", "message": "Неверный логин или пароль"}
    if user.get("role") not in ("developer", "admin"):
        return {"status": "error", "message": "Нет прав"}

    payload = json.loads(PAYLOAD)
    new_apps = payload.get("apps", [])

    content, sha = read_json_file("apps.json")
    if content is None:
        return {"status": "error", "message": "apps.json не найден"}

    if write_json_file("apps.json", {"apps": new_apps}, sha, "Update apps"):
        return {"status": "ok", "message": "apps.json обновлён"}
    return {"status": "error", "message": "Ошибка записи"}


# ============================================================
# ЗАЯВКА НА РАЗРАБОТЧИКА
# ============================================================

def handle_request_developer():
    user = check_auth()
    if not user:
        return {"status": "error", "message": "Неверный логин или пароль"}

    if user.get("role") in ("developer", "admin"):
        return {"status": "error", "message": "Ты уже разработчик"}

    payload = json.loads(PAYLOAD)
    real_name = payload.get("real_name", "")
    contact = payload.get("contact", "")
    description = payload.get("description", "")

    if not real_name or not contact or not description:
        return {"status": "error", "message": "Заполни имя, контакт и описание"}

    reqs, sha = read_json_file("requests.json")
    if reqs is None:
        reqs = {"requests": []}
        sha = None

    for r in reqs.get("requests", []):
        if r.get("username") == USERNAME and r.get("status") == "pending":
            return {"status": "error", "message": "Заявка уже подана"}

    next_id = max([r.get("id", 0) for r in reqs.get("requests", [])] + [0]) + 1
    reqs.setdefault("requests", []).append({
        "id": next_id,
        "username": USERNAME,
        "user_id": user.get("id"),
        "real_name": real_name,
        "contact": contact,
        "description": description,
        "status": "pending",
        "created_at": datetime.now().isoformat()
    })

    if not write_json_file("requests.json", reqs, sha, f"Request from {USERNAME}"):
        return {"status": "error", "message": "Ошибка записи requests.json"}

    return {"status": "ok", "message": "Заявка отправлена"}


def handle_get_requests():
    user = check_auth()
    if not user or user.get("role") != "admin":
        return {"status": "error", "message": "Нет прав"}

    reqs, _ = read_json_file("requests.json")
    if reqs is None:
        reqs = {"requests": []}

    return {"status": "ok", "requests": reqs.get("requests", [])}


# ============================================================
# СОЗДАНИЕ / УДАЛЕНИЕ РЕПО
# ============================================================

def handle_create_repo():
    user = check_auth()
    if not user or user.get("role") != "admin":
        return {"status": "error", "message": "Только админ"}

    payload = json.loads(PAYLOAD)
    target_username = payload.get("target_username", "")

    if not target_username:
        return {"status": "error", "message": "Не указан target_username"}

    repo_name = f"pozi-store-server-{target_username.lower()}"

    r = requests.post(
        f"https://api.github.com/orgs/{GITHUB_ORG}/repos",
        headers=HEADERS,
        json={
            "name": repo_name,
            "description": f"POZIStore repo for {target_username}",
            "private": False,
            "auto_init": True
        }
    )

    if r.status_code not in (201, 422):
        return {"status": "error", "message": f"Ошибка создания: {r.status_code} {r.text[:200]}"}

    users, sha = read_json_file("users.json")
    for u in users.get("users", []):
        if u.get("username", "").lower() == target_username.lower():
            u["role"] = "developer"
            u["repo"] = repo_name
            break
    write_json_file("users.json", users, sha, f"Set developer {target_username}")

    reqs, req_sha = read_json_file("requests.json")
    if reqs:
        reqs["requests"] = [
            r for r in reqs.get("requests", [])
            if not (r.get("username", "").lower() == target_username.lower()
                    and r.get("status") == "pending")
        ]
        write_json_file("requests.json", reqs, req_sha, f"Clear requests {target_username}")

    return {"status": "ok", "message": f"Репозиторий {repo_name} создан, {target_username} — developer"}


def handle_delete_repo():
    user = check_auth()
    if not user or user.get("role") != "admin":
        return {"status": "error", "message": "Только админ"}

    payload = json.loads(PAYLOAD)
    repo_name = payload.get("repo_name", "")

    if not repo_name:
        return {"status": "error", "message": "Не указан repo_name"}

    r = requests.delete(
        f"https://api.github.com/repos/{GITHUB_ORG}/{repo_name}",
        headers=HEADERS
    )

    if r.status_code == 204:
        return {"status": "ok", "message": f"Репо {repo_name} удалён"}
    return {"status": "error", "message": f"Ошибка удаления: {r.status_code}"}


# ============================================================
# БАН / РАЗБАН / РОЛЬ
# ============================================================

def handle_ban_user():
    user = check_auth()
    if not user or user.get("role") != "admin":
        return {"status": "error", "message": "Только админ"}

    payload = json.loads(PAYLOAD)
    target = payload.get("target_username", "")
    blocked = payload.get("blocked", True)
    reason = payload.get("reason", "")

    if not target:
        return {"status": "error", "message": "Не указан target_username"}

    users, sha = read_json_file("users.json")
    found = False
    for u in users.get("users", []):
        if u.get("username", "").lower() == target.lower():
            u["blocked"] = blocked
            u["ban_reason"] = reason if blocked else ""
            found = True
            break

    if not found:
        return {"status": "error", "message": "Юзер не найден"}

    if write_json_file("users.json", users, sha,
                       f"{'Ban' if blocked else 'Unban'} {target}"):
        return {"status": "ok",
                "message": f"{'Забанен' if blocked else 'Разбанен'} {target}"}
    return {"status": "error", "message": "Ошибка записи"}


def handle_set_role():
    user = check_auth()
    if not user or user.get("role") != "admin":
        return {"status": "error", "message": "Только админ"}

    payload = json.loads(PAYLOAD)
    target = payload.get("target_username", "")
    role = payload.get("role", "user")

    if role not in ("user", "developer", "admin"):
        return {"status": "error", "message": "Неверная роль"}

    # Защита: нельзя снять админа с себя
    if (target.lower() == user.get("username", "").lower()
            and role != "admin"):
        return {"status": "error",
                "message": "Нельзя снять роль админа с себя"}

    users, sha = read_json_file("users.json")
    found = False
    for u in users.get("users", []):
        if u.get("username", "").lower() == target.lower():
            u["role"] = role
            found = True
            break

    if not found:
        return {"status": "error", "message": "Юзер не найден"}

    if write_json_file("users.json", users, sha, f"Set role {target}={role}"):
        return {"status": "ok", "message": f"Роль {role} для {target}"}
    return {"status": "error", "message": "Ошибка записи"}


# ============================================================
# VIRUSTOTAL
# ============================================================

def handle_scan_file():
    """Отправляет URL файла в VirusTotal. Не требует пароля."""
    payload = json.loads(PAYLOAD)
    file_url = payload.get("file_url", "")
    app_id = payload.get("app_id", "")

    if not file_url or not app_id:
        return {"status": "error", "message": "Нужны file_url и app_id"}

    if not VT_API_KEY:
        return {"status": "error", "message": "VT_API_KEY не настроен"}

    try:
        r = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=VT_HEADERS,
            data={"url": file_url},
            timeout=30
        )
    except Exception as e:
        return {"status": "error", "message": f"Ошибка VT: {e}"}

    if r.status_code not in (200, 201):
        return {
            "status": "error",
            "message": f"VT вернул {r.status_code}: {r.text[:200]}"
        }

    analysis_id = r.json().get("data", {}).get("id", "")
    if not analysis_id:
        return {"status": "error", "message": "Нет analysis_id"}

    vt_link = f"https://www.virustotal.com/gui/url/{analysis_id.split('-')[-1]}"

    # Обновляем pending_apps.json
    pending, p_sha = read_json_file("pending_apps.json")
    if pending is None:
        return {"status": "error", "message": "pending_apps.json не найден"}

    for p in pending.get("pending_apps", []):
        if p.get("id") == app_id:
            p["vt_status"] = "pending"
            p["vt_link"] = vt_link
            p["vt_analysis_id"] = analysis_id
            break

    write_json_file("pending_apps.json", pending, p_sha, f"VT pending {app_id}")

    return {
        "status": "ok",
        "message": "Файл отправлен в VirusTotal",
        "analysis_id": analysis_id,
        "vt_link": vt_link,
        "vt_status": "pending"
    }


def handle_check_scan():
    """Проверяет статус сканирования в VT. Обновляет pending_apps.json."""
    payload = json.loads(PAYLOAD)
    app_id = payload.get("app_id", "")

    if not app_id:
        return {"status": "error", "message": "Нужен app_id"}

    if not VT_API_KEY:
        return {"status": "error", "message": "VT_API_KEY не настроен"}

    pending, sha = read_json_file("pending_apps.json")
    if pending is None:
        return {"status": "error", "message": "pending_apps.json не найден"}

    target = None
    for p in pending.get("pending_apps", []):
        if p.get("id") == app_id:
            target = p
            break

    if not target:
        return {"status": "error", "message": "Заявка не найдена"}

    analysis_id = target.get("vt_analysis_id", "")
    if not analysis_id:
        return {"status": "error", "message": "Нет analysis_id"}

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=VT_HEADERS,
            timeout=30
        )
    except Exception as e:
        return {"status": "error", "message": f"Ошибка VT: {e}"}

    if r.status_code != 200:
        return {"status": "error", "message": f"VT вернул {r.status_code}"}

    data = r.json().get("data", {})
    attrs = data.get("attributes", {})
    status = attrs.get("status", "queued")

    if status == "completed":
        stats = attrs.get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious >= 5:
            vt_status = "dangerous"
        elif malicious >= 1 or suspicious >= 3:
            vt_status = "suspicious"
        elif malicious == 0 and suspicious == 0:
            vt_status = "safe"
        else:
            vt_status = "normal"

        target["vt_status"] = vt_status
        write_json_file("pending_apps.json", pending, sha, f"VT done {app_id}")

        return {"status": "ok", "vt_status": vt_status, "stats": stats}

    target["vt_status"] = "pending"
    write_json_file("pending_apps.json", pending, sha, f"VT pending {app_id}")

    return {"status": "ok", "vt_status": "pending", "vt_raw_status": status}


# ============================================================
# MAIN
# ============================================================

def main():
    actions = {
        "hello": handle_hello,
        "check_auth": handle_check_auth,
        "register": handle_register,
        "login": handle_login,
        "update_apps": handle_update_apps,
        "request_developer": handle_request_developer,
        "get_requests": handle_get_requests,
        "create_repo": handle_create_repo,
        "delete_repo": handle_delete_repo,
        "ban_user": handle_ban_user,
        "set_role": handle_set_role,
        "request_publish": handle_request_publish,
        "get_pending_apps": handle_get_pending_apps,
        "get_my_pending_apps": handle_get_my_pending_apps,
        "approve_app": handle_approve_app,
        "reject_app": handle_reject_app,
        "scan_file": handle_scan_file,
        "check_scan": handle_check_scan,
    }

    handler = actions.get(ACTION)
    if not handler:
        result = {"status": "error", "message": f"Неизвестное действие: {ACTION}"}
    else:
        try:
            result = handler()
        except Exception as e:
            import traceback
            result = {"status": "error", "message": str(e),
                      "trace": traceback.format_exc()}

    with open("result.json", "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
