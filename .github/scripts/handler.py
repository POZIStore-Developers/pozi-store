"""
Серверный обработчик для POZIStore.
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

MAX_LOGS = 2000


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


def write_log(user, role, action, target="", details="", reason=""):
    try:
        logs, sha = read_json_file("logs.json")
        if logs is None:
            logs = {"logs": []}
            sha = None

        logs_list = logs.get("logs", [])
        next_id = max((l.get("id", 0) for l in logs_list), default=0) + 1

        logs_list.append({
            "id": next_id,
            "time": datetime.now().isoformat(),
            "user": user or "unknown",
            "role": role or "user",
            "action": action,
            "target": target,
            "details": details,
            "reason": reason,
        })

        if len(logs_list) > MAX_LOGS:
            logs_list = logs_list[-MAX_LOGS:]

        logs["logs"] = logs_list
        write_json_file("logs.json", logs, sha, f"Log: {action}")
    except Exception as e:
        print(f"[logs] Ошибка: {e}")


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


def get_user_by_username(username):
    users, _ = read_json_file("users.json")
    if not users:
        return None
    for u in users.get("users", []):
        if u.get("username", "").lower() == username.lower():
            return u
    return None


def is_moderator_or_admin(user):
    return user and user.get("role") in ("moderator", "admin")


def is_admin(user):
    return user and user.get("role") == "admin"


# ==================== ПРОСТЫЕ ====================

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


# ==================== РЕГИСТРАЦИЯ / ЛОГИН ====================

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
        "library": [],
        "created_at": datetime.now().isoformat()
    }
    users.setdefault("users", []).append(new_user)

    if not write_json_file("users.json", users, sha, f"Register {USERNAME}"):
        return {"status": "error", "message": "Ошибка записи users.json"}

    write_log(USERNAME, "user", "register", target=USERNAME)
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

    write_log(user.get("username"), user.get("role", "user"), "login",
              target=user.get("username"))

    return {
        "status": "ok",
        "user_id": user.get("id"),
        "username": user.get("username"),
        "role": user.get("role", "user")
    }


# ==================== МОДЕРАЦИЯ ====================

def handle_request_publish():
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

    pending["pending_apps"] = [
        p for p in pending.get("pending_apps", [])
        if p.get("id") != app_data["id"]
    ]

    app_data["submitted_at"] = datetime.now().isoformat()
    app_data["submitted_by"] = user.get("username", "")
    app_data["edit_mode"] = edit_mode
    app_data["vt_status"] = app_data.get("vt_status", "pending")
    app_data["vt_link"] = app_data.get("vt_link", "")
    app_data["vt_analysis_id"] = app_data.get("vt_analysis_id", "")
    app_data["vt_manual"] = False
    app_data["vt_manual_by"] = ""
    app_data["vt_manual_link"] = ""
    app_data["vt_manual_comment"] = ""
    app_data["status"] = "pending"
    app_data["reject_reason"] = ""

    pending.setdefault("pending_apps", []).append(app_data)

    if not write_json_file(
        "pending_apps.json", pending, sha,
        f"Pending app: {app_data['id']}"
    ):
        return {"status": "error", "message": "Ошибка записи pending_apps.json"}

    write_log(user.get("username"), user.get("role"),
              "publish_request", target=app_data["id"],
              details=f"Заявка: {app_data.get('name')}")

    return {"status": "ok", "message": "Заявка отправлена", "app_id": app_data["id"]}


def handle_get_pending_apps():
    user = check_auth()
    if not is_moderator_or_admin(user):
        return {"status": "error", "message": "Нет прав"}

    pending, _ = read_json_file("pending_apps.json")
    if pending is None:
        pending = {"pending_apps": []}

    return {"status": "ok", "pending_apps": pending.get("pending_apps", [])}


def handle_get_my_pending_apps():
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
    user = check_auth()
    if not is_moderator_or_admin(user):
        return {"status": "error", "message": "Только модератор/админ"}

    payload = json.loads(PAYLOAD)
    app_id = payload.get("app_id", "")

    if not app_id:
        return {"status": "error", "message": "Нет app_id"}

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

    apps, a_sha = read_json_file("apps.json")
    if apps is None:
        apps = {"apps": []}
        a_sha = None

    app_for_catalog = {k: v for k, v in target.items()
                       if k not in ("submitted_at", "submitted_by",
                                    "edit_mode", "status", "reject_reason")}

    app_for_catalog.setdefault("hidden", False)
    app_for_catalog.setdefault("hidden_by", "")
    app_for_catalog.setdefault("hidden_reason", "")
    app_for_catalog.setdefault("vt_manual", False)
    app_for_catalog.setdefault("vt_manual_by", "")
    app_for_catalog.setdefault("vt_manual_link", "")
    app_for_catalog.setdefault("vt_manual_comment", "")
    app_for_catalog.setdefault("downloads", 0)
    app_for_catalog.setdefault("category_id", "other")

    if edit_mode:
        found = False
        for i, a in enumerate(apps.get("apps", [])):
            if a.get("id") == app_id:
                for key in ("hidden", "hidden_by", "hidden_reason",
                            "vt_manual", "vt_manual_by",
                            "vt_manual_link", "vt_manual_comment",
                            "downloads"):
                    if key not in app_for_catalog and key in a:
                        app_for_catalog[key] = a[key]
                apps["apps"][i] = app_for_catalog
                found = True
                break
        if not found:
            apps.setdefault("apps", []).append(app_for_catalog)
    else:
        exists = any(a.get("id") == app_id for a in apps.get("apps", []))
        if not exists:
            apps.setdefault("apps", []).append(app_for_catalog)

    if not write_json_file("apps.json", apps, a_sha, f"Approve app {app_id}"):
        return {"status": "error", "message": "Ошибка записи apps.json"}

    pending["pending_apps"] = [
        p for p in pending.get("pending_apps", [])
        if p.get("id") != app_id
    ]
    write_json_file("pending_apps.json", pending, p_sha, f"Approved {app_id}")

    write_log(user.get("username"), user.get("role"),
              "approve_app", target=app_id,
              details=f"Одобрено: {target.get('name')}")

    return {"status": "ok", "message": f"Приложение {app_id} одобрено"}


def handle_reject_app():
    user = check_auth()
    if not is_moderator_or_admin(user):
        return {"status": "error", "message": "Только модератор/админ"}

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

    write_log(user.get("username"), user.get("role"),
              "reject_app", target=app_id,
              details=f"Отклонено: {reason}",
              reason=reason)

    return {"status": "ok", "message": "Заявка отклонена"}


# ==================== СКРЫТИЕ ====================

def handle_hide_app():
    user = check_auth()
    if not is_moderator_or_admin(user):
        return {"status": "error", "message": "Только модератор/админ"}

    payload = json.loads(PAYLOAD)
    app_id = payload.get("app_id", "")
    reason = payload.get("reason", "")

    if not app_id:
        return {"status": "error", "message": "Нет app_id"}

    apps, sha = read_json_file("apps.json")
    if apps is None:
        return {"status": "error", "message": "apps.json не найден"}

    found = False
    for a in apps.get("apps", []):
        if a.get("id") == app_id:
            a["hidden"] = True
            a["hidden_by"] = user.get("username", "")
            a["hidden_reason"] = reason or "Без причины"
            found = True
            break

    if not found:
        return {"status": "error", "message": "Приложение не найдено"}

    if not write_json_file("apps.json", apps, sha, f"Hide app {app_id}"):
        return {"status": "error", "message": "Ошибка записи"}

    write_log(user.get("username"), user.get("role"),
              "hide_app", target=app_id,
              details=f"Скрыто: {reason}",
              reason=reason)

    return {"status": "ok", "message": f"Приложение скрыто"}


def handle_unhide_app():
    user = check_auth()
    if not is_moderator_or_admin(user):
        return {"status": "error", "message": "Только модератор/админ"}

    payload = json.loads(PAYLOAD)
    app_id = payload.get("app_id", "")

    if not app_id:
        return {"status": "error", "message": "Нет app_id"}

    apps, sha = read_json_file("apps.json")
    if apps is None:
        return {"status": "error", "message": "apps.json не найден"}

    found = False
    for a in apps.get("apps", []):
        if a.get("id") == app_id:
            a["hidden"] = False
            a["hidden_by"] = ""
            a["hidden_reason"] = ""
            found = True
            break

    if not found:
        return {"status": "error", "message": "Приложение не найдено"}

    if not write_json_file("apps.json", apps, sha, f"Unhide app {app_id}"):
        return {"status": "error", "message": "Ошибка записи"}

    write_log(user.get("username"), user.get("role"),
              "unhide_app", target=app_id,
              details="Восстановлено")

    return {"status": "ok", "message": f"Приложение восстановлено"}


def handle_delete_app():
    user = check_auth()
    if not is_admin(user):
        return {"status": "error", "message": "Только админ"}

    payload = json.loads(PAYLOAD)
    app_id = payload.get("app_id", "")

    if not app_id:
        return {"status": "error", "message": "Нет app_id"}

    apps, sha = read_json_file("apps.json")
    if apps is None:
        return {"status": "error", "message": "apps.json не найден"}

    old_len = len(apps.get("apps", []))
    apps["apps"] = [a for a in apps.get("apps", []) if a.get("id") != app_id]

    if len(apps["apps"]) == old_len:
        return {"status": "error", "message": "Приложение не найдено"}

    if not write_json_file("apps.json", apps, sha, f"Delete app {app_id}"):
        return {"status": "error", "message": "Ошибка записи"}

    write_log(user.get("username"), user.get("role"),
              "delete_app", target=app_id, details="Удалено навсегда")

    return {"status": "ok", "message": f"Приложение удалено"}


# ==================== ОТЗЫВЫ ====================

def handle_hide_review():
    user = check_auth()
    if not is_moderator_or_admin(user):
        return {"status": "error", "message": "Только модератор/админ"}

    payload = json.loads(PAYLOAD)
    app_id = payload.get("app_id", "")
    author = payload.get("author", "")
    reason = payload.get("reason", "")

    if not app_id or not author:
        return {"status": "error", "message": "Нужны app_id и author"}

    reviews, sha = read_json_file("reviews.json")
    if reviews is None:
        return {"status": "error", "message": "reviews.json не найден"}

    found = False
    for r in reviews.get("reviews", {}).get(app_id, []):
        if r.get("author") == author:
            r["hidden"] = True
            r["hidden_by"] = user.get("username", "")
            r["hidden_reason"] = reason or "Без причины"
            found = True
            break

    if not found:
        return {"status": "error", "message": "Отзыв не найден"}

    if not write_json_file("reviews.json", reviews, sha,
                           f"Hide review {app_id}/{author}"):
        return {"status": "error", "message": "Ошибка записи"}

    write_log(user.get("username"), user.get("role"),
              "hide_review", target=f"{app_id}/{author}",
              details=f"Скрыт: {reason}", reason=reason)

    return {"status": "ok", "message": "Отзыв скрыт"}


def handle_unhide_review():
    user = check_auth()
    if not is_moderator_or_admin(user):
        return {"status": "error", "message": "Только модератор/админ"}

    payload = json.loads(PAYLOAD)
    app_id = payload.get("app_id", "")
    author = payload.get("author", "")

    if not app_id or not author:
        return {"status": "error", "message": "Нужны app_id и author"}

    reviews, sha = read_json_file("reviews.json")
    if reviews is None:
        return {"status": "error", "message": "reviews.json не найден"}

    found = False
    for r in reviews.get("reviews", {}).get(app_id, []):
        if r.get("author") == author:
            r["hidden"] = False
            r["hidden_by"] = ""
            r["hidden_reason"] = ""
            found = True
            break

    if not found:
        return {"status": "error", "message": "Отзыв не найден"}

    if not write_json_file("reviews.json", reviews, sha,
                           f"Unhide review {app_id}/{author}"):
        return {"status": "error", "message": "Ошибка записи"}

    write_log(user.get("username"), user.get("role"),
              "unhide_review", target=f"{app_id}/{author}",
              details="Отзыв восстановлен")

    return {"status": "ok", "message": "Отзыв восстановлен"}


def handle_delete_review():
    user = check_auth()
    if not is_admin(user):
        return {"status": "error", "message": "Только админ"}

    payload = json.loads(PAYLOAD)
    app_id = payload.get("app_id", "")
    author = payload.get("author", "")

    if not app_id or not author:
        return {"status": "error", "message": "Нужны app_id и author"}

    reviews, sha = read_json_file("reviews.json")
    if reviews is None:
        return {"status": "error", "message": "reviews.json не найден"}

    old = reviews.get("reviews", {}).get(app_id, [])
    new = [r for r in old if r.get("author") != author]

    if len(new) == len(old):
        return {"status": "error", "message": "Отзыв не найден"}

    reviews["reviews"][app_id] = new

    if not write_json_file("reviews.json", reviews, sha,
                           f"Delete review {app_id}/{author}"):
        return {"status": "error", "message": "Ошибка записи"}

    write_log(user.get("username"), user.get("role"),
              "delete_review", target=f"{app_id}/{author}",
              details="Удалён навсегда")

    return {"status": "ok", "message": "Отзыв удалён"}


# ==================== ЛАЙК / ДИЗЛАЙК ====================

def handle_vote_review():
    voter = USERNAME.strip()
    if not voter:
        return {"status": "error", "message": "Войди в аккаунт"}

    payload = json.loads(PAYLOAD)
    app_id = payload.get("app_id", "")
    author = payload.get("author", "")
    vote = payload.get("vote", "")

    if not app_id or not author or vote not in ("like", "dislike", "none"):
        return {"status": "error", "message": "Неверные параметры"}

    if voter.lower() == author.lower():
        return {"status": "error", "message": "Нельзя голосовать за свой отзыв"}

    reviews, sha = read_json_file("reviews.json")
    if reviews is None:
        return {"status": "error", "message": "reviews.json не найден"}

    found = False
    for r in reviews.get("reviews", {}).get(app_id, []):
        if r.get("author") == author:
            likes = r.setdefault("likes", [])
            dislikes = r.setdefault("dislikes", [])

            likes[:] = [l for l in likes if l.lower() != voter.lower()]
            dislikes[:] = [d for d in dislikes if d.lower() != voter.lower()]

            if vote == "like":
                likes.append(voter)
            elif vote == "dislike":
                dislikes.append(voter)

            found = True
            break

    if not found:
        return {"status": "error", "message": "Отзыв не найден"}

    if not write_json_file("reviews.json", reviews, sha,
                           f"Vote {vote} {app_id}/{author}"):
        return {"status": "error", "message": "Ошибка записи"}

    return {"status": "ok", "message": "Голос учтён"}


# ==================== БИБЛИОТЕКА ====================

def handle_add_to_library():
    username = USERNAME.strip()
    if not username:
        return {"status": "error", "message": "Войди в аккаунт"}

    payload = json.loads(PAYLOAD)
    app_id = payload.get("app_id", "")

    if not app_id:
        return {"status": "error", "message": "Нет app_id"}

    users, sha = read_json_file("users.json")
    if users is None:
        return {"status": "error", "message": "users.json не найден"}

    found = False
    for u in users.get("users", []):
        if u.get("username", "").lower() == username.lower():
            lib = u.setdefault("library", [])
            if app_id not in lib:
                lib.append(app_id)
            found = True
            break

    if not found:
        return {"status": "error", "message": "Юзер не найден"}

    if not write_json_file("users.json", users, sha, f"Add to library {app_id}"):
        return {"status": "error", "message": "Ошибка записи"}

    write_log(username, "user", "add_to_library", target=app_id)

    return {"status": "ok", "message": "Добавлено в библиотеку"}


def handle_remove_from_library():
    username = USERNAME.strip()
    if not username:
        return {"status": "error", "message": "Войди в аккаунт"}

    payload = json.loads(PAYLOAD)
    app_id = payload.get("app_id", "")

    if not app_id:
        return {"status": "error", "message": "Нет app_id"}

    users, sha = read_json_file("users.json")
    if users is None:
        return {"status": "error", "message": "users.json не найден"}

    for u in users.get("users", []):
        if u.get("username", "").lower() == username.lower():
            lib = u.get("library", [])
            if app_id in lib:
                lib.remove(app_id)
            break

    if not write_json_file("users.json", users, sha, f"Remove from library {app_id}"):
        return {"status": "error", "message": "Ошибка записи"}

    write_log(username, "user", "remove_from_library", target=app_id)

    return {"status": "ok", "message": "Убрано из библиотеки"}


def handle_increment_downloads():
    payload = json.loads(PAYLOAD)
    app_id = payload.get("app_id", "")

    if not app_id:
        return {"status": "error", "message": "Нет app_id"}

    apps, sha = read_json_file("apps.json")
    if apps is None:
        return {"status": "error", "message": "apps.json не найден"}

    for a in apps.get("apps", []):
        if a.get("id") == app_id:
            a["downloads"] = a.get("downloads", 0) + 1
            break

    if not write_json_file("apps.json", apps, sha, f"Download {app_id}"):
        return {"status": "error", "message": "Ошибка записи"}

    return {"status": "ok", "message": "Счётчик увеличен"}


def handle_report_app():
    username = USERNAME.strip()
    if not username:
        return {"status": "error", "message": "Войди в аккаунт"}

    payload = json.loads(PAYLOAD)
    app_id = payload.get("app_id", "")
    reason = payload.get("reason", "")
    reason_text = payload.get("reason_text", "")
    description = payload.get("description", "")

    if not app_id or not reason:
        return {"status": "error", "message": "Не хватает данных"}

    reports, sha = read_json_file("reports.json")
    if reports is None:
        reports = {"reports": []}
        sha = None

    next_id = max((r.get("id", 0) for r in reports.get("reports", [])), default=0) + 1

    reports.setdefault("reports", []).append({
        "id": next_id,
        "time": datetime.now().isoformat(),
        "app_id": app_id,
        "user": username,
        "reason": reason,
        "reason_text": reason_text,
        "description": description,
        "status": "pending",
    })

    if not write_json_file("reports.json", reports, sha, f"Report {app_id}"):
        return {"status": "error", "message": "Ошибка записи"}

    write_log(username, "user", "report_app", target=app_id,
              details=f"{reason_text}: {description[:100]}")

    return {"status": "ok", "message": "Жалоба отправлена"}


# ==================== КАТАЛОГ ====================

def handle_update_apps():
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


# ==================== ЗАЯВКА НА РАЗРАБОТЧИКА ====================

def handle_request_developer():
    user = check_auth()
    if not user:
        return {"status": "error", "message": "Неверный логин или пароль"}

    if user.get("role") in ("developer", "moderator", "admin"):
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

    write_log(user.get("username"), user.get("role"),
              "request_developer", target=USERNAME)

    return {"status": "ok", "message": "Заявка отправлена"}


def handle_get_requests():
    user = check_auth()
    if not is_moderator_or_admin(user):
        return {"status": "error", "message": "Нет прав"}

    reqs, _ = read_json_file("requests.json")
    if reqs is None:
        reqs = {"requests": []}

    return {"status": "ok", "requests": reqs.get("requests", [])}


# ==================== РЕПО ====================

def handle_create_repo():
    user = check_auth()
    if not is_admin(user):
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
        return {"status": "error", "message": f"Ошибка создания: {r.status_code}"}

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

    write_log(user.get("username"), user.get("role"),
              "create_repo", target=target_username,
              details=f"Создан {repo_name}")

    return {"status": "ok", "message": f"Репозиторий {repo_name} создан"}


def handle_delete_repo():
    user = check_auth()
    if not is_admin(user):
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
        write_log(user.get("username"), user.get("role"),
                  "delete_repo", target=repo_name)
        return {"status": "ok", "message": f"Репо {repo_name} удалён"}
    return {"status": "error", "message": f"Ошибка: {r.status_code}"}


# ==================== БАН / РОЛИ ====================

def handle_ban_user():
    user = check_auth()
    if not is_moderator_or_admin(user):
        return {"status": "error", "message": "Только модератор/админ"}

    payload = json.loads(PAYLOAD)
    target = payload.get("target_username", "")
    blocked = payload.get("blocked", True)
    reason = payload.get("reason", "")

    if not target:
        return {"status": "error", "message": "Не указан target_username"}

    if target.lower() == user.get("username", "").lower():
        return {"status": "error", "message": "Нельзя забанить себя"}

    users, sha = read_json_file("users.json")
    found = False
    for u in users.get("users", []):
        if u.get("username", "").lower() == target.lower():
            target_role = u.get("role", "user")

            if user.get("role") == "moderator" and target_role in ("admin", "moderator"):
                return {"status": "error", "message": "Нельзя банить админа/модератора"}

            if user.get("role") == "admin" and target_role == "admin" and blocked:
                return {"status": "error", "message": "Нельзя банить админа"}

            u["blocked"] = blocked
            u["ban_reason"] = reason if blocked else ""
            found = True
            break

    if not found:
        return {"status": "error", "message": "Юзер не найден"}

    if write_json_file("users.json", users, sha,
                       f"{'Ban' if blocked else 'Unban'} {target}"):
        write_log(user.get("username"), user.get("role"),
                  "ban_user" if blocked else "unban_user",
                  target=target, details=f"{'Бан' if blocked else 'Разбан'}: {reason}",
                  reason=reason)
        return {"status": "ok",
                "message": f"{'Забанен' if blocked else 'Разбанен'} {target}"}
    return {"status": "error", "message": "Ошибка записи"}


def handle_set_role():
    user = check_auth()
    if not is_admin(user):
        return {"status": "error", "message": "Только админ"}

    payload = json.loads(PAYLOAD)
    target = payload.get("target_username", "")
    role = payload.get("role", "user")

    if role not in ("user", "developer", "moderator", "admin"):
        return {"status": "error", "message": "Неверная роль"}

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
        write_log(user.get("username"), user.get("role"),
                  "set_role", target=target,
                  details=f"Новая роль: {role}")
        return {"status": "ok", "message": f"Роль {role} для {target}"}
    return {"status": "error", "message": "Ошибка записи"}


# ==================== VT ВРУЧНУЮ ====================

def handle_set_vt_status():
    username = USERNAME.strip()
    if not username:
        return {"status": "error", "message": "Войди в аккаунт"}

    user = get_user_by_username(username)
    if not user or user.get("role") not in ("moderator", "admin"):
        return {"status": "error", "message": "Только модератор/админ"}

    payload = json.loads(PAYLOAD)
    app_id = payload.get("app_id", "")
    vt_status = payload.get("vt_status", "")
    vt_link = payload.get("vt_link", "")
    comment = payload.get("comment", "")

    if not app_id:
        return {"status": "error", "message": "Нет app_id"}

    if vt_status not in ("pending", "safe", "normal", "suspicious", "dangerous"):
        return {"status": "error", "message": "Неверный статус"}

    apps, sha = read_json_file("apps.json")
    found = False

    if apps:
        for a in apps.get("apps", []):
            if a.get("id") == app_id:
                a["vt_status"] = vt_status
                a["vt_link"] = vt_link
                a["vt_manual"] = True
                a["vt_manual_by"] = username
                a["vt_manual_link"] = vt_link
                a["vt_manual_comment"] = comment
                found = True
                break

        if found:
            write_json_file("apps.json", apps, sha, f"VT manual {app_id}")

    if not found:
        pending, p_sha = read_json_file("pending_apps.json")
        if pending:
            for p in pending.get("pending_apps", []):
                if p.get("id") == app_id:
                    p["vt_status"] = vt_status
                    p["vt_link"] = vt_link
                    p["vt_manual"] = True
                    p["vt_manual_by"] = username
                    p["vt_manual_link"] = vt_link
                    p["vt_manual_comment"] = comment
                    found = True
                    break
            if found:
                write_json_file("pending_apps.json", pending, p_sha,
                                f"VT manual {app_id}")

    if not found:
        return {"status": "error", "message": "Приложение не найдено"}

    write_log(username, user.get("role", "user"),
              "set_vt_status", target=app_id,
              details=f"VT вручную: {vt_status}",
              reason=comment)

    return {"status": "ok", "message": "VT-статус установлен"}


# ==================== ЛОГИ ====================

def handle_get_logs():
    user = check_auth()
    if not is_moderator_or_admin(user):
        return {"status": "error", "message": "Нет прав"}

    payload = json.loads(PAYLOAD)
    limit = payload.get("limit", 200)

    logs, _ = read_json_file("logs.json")
    if logs is None:
        return {"status": "ok", "logs": []}

    logs_list = logs.get("logs", [])
    logs_list = sorted(logs_list, key=lambda l: l.get("id", 0), reverse=True)

    return {"status": "ok", "logs": logs_list[:limit]}


# ==================== VIRUSTOTAL (авто) ====================

def handle_scan_file():
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
        return {"status": "error", "message": f"VT {r.status_code}"}

    analysis_id = r.json().get("data", {}).get("id", "")
    if not analysis_id:
        return {"status": "error", "message": "Нет analysis_id"}

    vt_link = f"https://www.virustotal.com/gui/url/{analysis_id.split('-')[-1]}"

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
        "message": "Файл отправлен в VT",
        "analysis_id": analysis_id,
        "vt_link": vt_link,
        "vt_status": "pending"
    }


def handle_check_scan():
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
        return {"status": "error", "message": f"VT {r.status_code}"}

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

    return {"status": "ok", "vt_status": "pending"}


# ==================== MAIN ====================

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
        "hide_app": handle_hide_app,
        "unhide_app": handle_unhide_app,
        "delete_app": handle_delete_app,
        "hide_review": handle_hide_review,
        "unhide_review": handle_unhide_review,
        "delete_review": handle_delete_review,
        "vote_review": handle_vote_review,
        "set_vt_status": handle_set_vt_status,
        "get_logs": handle_get_logs,
        "scan_file": handle_scan_file,
        "check_scan": handle_check_scan,
        "add_to_library": handle_add_to_library,
        "remove_from_library": handle_remove_from_library,
        "increment_downloads": handle_increment_downloads,
        "report_app": handle_report_app,
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
