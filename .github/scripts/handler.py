"""
Серверный обработчик для POZIStore.
Запускается в GitHub Actions. Имеет доступ к SERVER_TOKEN.
"""
import os
import json
import bcrypt
import requests
import base64
from datetime import datetime


SERVER_TOKEN = os.environ.get("SERVER_TOKEN", "")
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


# ============================================================
# ЧТЕНИЕ / ЗАПИСЬ JSON
# ============================================================

def read_json_file(path):
    """Читает JSON-файл из репо."""
    url = f"https://api.github.com/repos/{GITHUB_ORG}/{GITHUB_REPO}/contents/{path}"
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        return None, None
    data = r.json()
    content = json.loads(base64.b64decode(data['content']).decode('utf-8'))
    return content, data['sha']


def write_json_file(path, content, sha, message):
    """Записывает JSON-файл в репо."""
    url = f"https://api.github.com/repos/{GITHUB_ORG}/{GITHUB_REPO}/contents/{path}"
    new_content = base64.b64encode(
        json.dumps(content, ensure_ascii=False, indent=2).encode('utf-8')
    ).decode('utf-8')
    r = requests.put(url, headers=HEADERS, json={
        "message": message,
        "content": new_content,
        "sha": sha
    })
    return r.status_code == 200


# ============================================================
# АВТОРИЗАЦИЯ
# ============================================================

def check_auth():
    """Проверяет логин/пароль. Возвращает юзера или None."""
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
    """Тест."""
    return {
        "status": "ok",
        "message": "Hello from Actions!",
        "server_token_length": len(SERVER_TOKEN)
    }


def handle_check_auth():
    """Проверка логина/пароля."""
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
    """Регистрация нового пользователя."""
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
    """Логин."""
    user = check_auth()
    if not user:
        return {"status": "error", "message": "Неверный логин или пароль"}

    if user.get("blocked"):
        return {"status": "error", "message": "Аккаунт заблокирован"}

    return {
        "status": "ok",
        "user_id": user.get("id"),
        "username": user.get("username"),
        "role": user.get("role", "user")
    }


# ============================================================
# КАТАЛОГ
# ============================================================

def handle_update_apps():
    """Обновляет apps.json (только developer/admin)."""
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
    """Юзер подаёт заявку на разработчика."""
    user = check_auth()
    if not user:
        return {"status": "error", "message": "Неверный логин или пароль"}

    if user.get("role") in ("developer", "admin"):
        return {"status": "error", "message": "Ты уже разработчик"}

    reqs, sha = read_json_file("requests.json")
    if reqs is None:
        reqs = {"requests": []}
        sha = None

    # Проверка на дубликат
    for r in reqs.get("requests", []):
        if r.get("username") == USERNAME and r.get("status") == "pending":
            return {"status": "error", "message": "Заявка уже подана"}

    next_id = max([r.get("id", 0) for r in reqs.get("requests", [])] + [0]) + 1
    reqs.setdefault("requests", []).append({
        "id": next_id,
        "username": USERNAME,
        "user_id": user.get("id"),
        "status": "pending",
        "created_at": datetime.now().isoformat()
    })

    if not write_json_file("requests.json", reqs, sha, f"Request from {USERNAME}"):
        return {"status": "error", "message": "Ошибка записи requests.json"}

    return {"status": "ok", "message": "Заявка отправлена"}


def handle_get_requests():
    """Список заявок (только админ)."""
    user = check_auth()
    if not user or user.get("role") != "admin":
        return {"status": "error", "message": "Нет прав"}

    reqs, _ = read_json_file("requests.json")
    if reqs is None:
        reqs = {"requests": []}

    return {"status": "ok", "requests": reqs.get("requests", [])}


# ============================================================
# СОЗДАНИЕ РЕПО ДЛЯ РАЗРАБОТЧИКА
# ============================================================

def handle_create_repo():
    """Создаёт репо pozi-store-server-{username} и даёт права юзеру."""
    user = check_auth()
    if not user or user.get("role") != "admin":
        return {"status": "error", "message": "Только админ может создавать репо"}

    payload = json.loads(PAYLOAD)
    target_username = payload.get("target_username", "")

    if not target_username:
        return {"status": "error", "message": "Не указан target_username"}

    repo_name = f"pozi-store-server-{target_username.lower()}"

    # 1. Создаём репо
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

    if r.status_code not in (201, 422):  # 422 = уже существует
        return {"status": "error", "message": f"Ошибка создания: {r.status_code} {r.text[:200]}"}

    # 2. Обновляем users.json — роль developer
    users, sha = read_json_file("users.json")
    for u in users.get("users", []):
        if u.get("username", "").lower() == target_username.lower():
            u["role"] = "developer"
            u["repo"] = repo_name
            break
    write_json_file("users.json", users, sha, f"Set developer {target_username}")

    # 3. Убираем заявку
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
    """Удаляет репо разработчика (при бане/удалении)."""
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
    """Бан/разбан юзера (только админ)."""
    user = check_auth()
    if not user or user.get("role") != "admin":
        return {"status": "error", "message": "Только админ"}

    payload = json.loads(PAYLOAD)
    target = payload.get("target_username", "")
    blocked = payload.get("blocked", True)

    if not target:
        return {"status": "error", "message": "Не указан target_username"}

    users, sha = read_json_file("users.json")
    found = False
    for u in users.get("users", []):
        if u.get("username", "").lower() == target.lower():
            u["blocked"] = blocked
            found = True
            break

    if not found:
        return {"status": "error", "message": "Юзер не найден"}

    if write_json_file("users.json", users, sha, f"{'Ban' if blocked else 'Unban'} {target}"):
        return {"status": "ok", "message": f"{'Забанен' if blocked else 'Разбанен'} {target}"}
    return {"status": "error", "message": "Ошибка записи"}


def handle_set_role():
    """Смена роли юзера (только админ)."""
    user = check_auth()
    if not user or user.get("role") != "admin":
        return {"status": "error", "message": "Только админ"}

    payload = json.loads(PAYLOAD)
    target = payload.get("target_username", "")
    role = payload.get("role", "user")

    if role not in ("user", "developer", "admin"):
        return {"status": "error", "message": "Неверная роль"}

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
    }

    handler = actions.get(ACTION)
    if not handler:
        result = {"status": "error", "message": f"Неизвестное действие: {ACTION}"}
    else:
        try:
            result = handler()
        except Exception as e:
            import traceback
            result = {"status": "error", "message": str(e), "trace": traceback.format_exc()}

    with open("result.json", "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
