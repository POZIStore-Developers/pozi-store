"""
Серверный обработчик для POZIStore.
Запускается в GitHub Actions. Имеет доступ к SERVER_TOKEN.
"""
import os
import json
import bcrypt
import requests
import base64


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


def read_json_file(path):
    """Читает JSON-файл из репо."""
    url = f"https://api.github.com/repos/{GITHUB_ORG}/{GITHUB_REPO}/contents/{path}"
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        return None, None
    data = r.json()
    content = json.loads(
        base64.b64decode(data['content']).decode('utf-8')
    )
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


def handle_hello():
    """Простое действие для теста."""
    return {
        "status": "ok",
        "message": "Hello from Actions!",
        "server_token_length": len(SERVER_TOKEN)
    }


def handle_check_auth():
    """Проверяет, работает ли авторизация через Actions."""
    user = check_auth()
    if not user:
        return {"status": "error", "message": "Неверный логин или пароль"}
    return {
        "status": "ok",
        "username": user.get("username"),
        "role": user.get("role", "user")
    }


def handle_register():
    """Регистрация нового пользователя."""
    from datetime import datetime

    users, sha = read_json_file("users.json")
    if users is None:
        users = {"users": []}
        sha = None

    # Проверка: занят ли логин
    for u in users.get("users", []):
        if u.get("username", "").lower() == USERNAME.lower():
            return {"status": "error", "message": "Логин занят"}

    # Хешируем пароль
    password_hash = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt()).decode()

    # Новый юзер
    next_id = max([u.get("id", 0) for u in users.get("users", [])] + [0]) + 1
    new_user = {
        "id": next_id,
        "username": USERNAME,
        "password_hash": password_hash,
        "role": "user",
        "avatar": "",
        "banner": "",
        "description": "",
        "website": "",
        "created_at": datetime.now().isoformat()
    }
    users.setdefault("users", []).append(new_user)

    # Запись
    if not write_json_file("users.json", users, sha, f"Register {USERNAME}"):
        return {"status": "error", "message": "Ошибка записи users.json"}

    return {"status": "ok", "user_id": next_id, "username": USERNAME}


def handle_login():
    """Проверка логина/пароля."""
    user = check_auth()
    if not user:
        return {"status": "error", "message": "Неверный логин или пароль"}
    return {
        "status": "ok",
        "user_id": user.get("id"),
        "username": user.get("username"),
        "role": user.get("role", "user")
    }


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


def main():
    actions = {
        "hello": handle_hello,
        "check_auth": handle_check_auth,
        "register": handle_register,
        "login": handle_login,
        "update_apps": handle_update_apps,
    }

    handler = actions.get(ACTION)
    if not handler:
        result = {"status": "error", "message": f"Неизвестное действие: {ACTION}"}
    else:
        try:
            result = handler()
        except Exception as e:
            result = {"status": "error", "message": str(e)}

    with open("result.json", "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
