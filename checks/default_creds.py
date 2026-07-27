# checks/default_creds.py
"""
⚠️ ВНИМАНИЕ: Этот модуль выполняет активные действия — попытки входа
с дефолтными учётными данными. Используйте ТОЛЬКО на своих ресурсах
или при наличии явного письменного разрешения.

Модуль отключён по умолчанию. Для включения используйте флаг --brute.
"""
import requests
import urllib3
from urllib.parse import urljoin

urllib3.disable_warnings()

# Популярные пути для проверки
LOGIN_PATHS = [
    "/admin",
    "/administrator",
    "/login",
    "/wp-admin/",
    "/wp-login.php",
    "/cpanel",
    "/manager/html",           # Tomcat
    "/console",                # WebLogic
    "/jenkins/login",
    "/phpmyadmin",
    "/adminer",
    "/solr/admin",
    "/_utils/",                # CouchDB
    "/api/v1/login",
    "/api/auth/login",
    "/auth/login",
    "/user/login",
    "/portal/login",
    "/signin",
    "/controlpanel",
]

# Популярные пары логин/пароль (ТОЛЬКО для тестирования своих систем!)
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "12345678"),
    ("admin", "admin123"),
    ("admin", "qwerty"),
    ("admin", "letmein"),
    ("admin", "welcome"),
    ("admin", "monkey"),
    ("admin", "master"),
    ("admin", "dragon"),
    ("admin", "login"),
    ("admin", "princess"),
    ("admin", "football"),
    ("admin", "shadow"),
    ("admin", "sunshine"),
    ("admin", "trustno1"),
    ("admin", "iloveyou"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("tomcat", "tomcat"),
    ("admin", ""),
    ("", "admin"),
]

# Сигнатуры успешного входа
SUCCESS_INDICATORS = [
    "dashboard", "welcome", "logout", "log out", "sign out",
    "my account", "мой аккаунт", "выход", "панель управления",
    "admin panel", "админ", "профиль", "profile",
]

# Сигнатуры неудачного входа
FAILURE_INDICATORS = [
    "invalid", "incorrect", "неверн", "ошибк", "wrong",
    "failed", "denied", "запрещ", "неправил",
]


def _check_login(url: str, path: str, username: str, password: str) -> dict:
    """Пробует войти с указанными учётными данными."""
    login_url = urljoin(url, path)
    result = {
        "path": path,
        "username": username,
        "password": password,
        "success": False,
        "details": ""
    }

    # Пробуем разные форматы данных
    payloads = [
        # Форма
        {"data": {"username": username, "password": password, "login": "Login"}},
        {"data": {"user": username, "pass": password, "submit": "Войти"}},
        {"data": {"email": username, "password": password}},
        {"data": {"log": username, "pwd": password}},  # WordPress
        # JSON
        {"json": {"username": username, "password": password}},
        {"json": {"user": username, "password": password}},
    ]

    try:
        for payload in payloads:
            try:
                if "data" in payload:
                    response = requests.post(
                        login_url,
                        data=payload["data"],
                        timeout=5,
                        verify=False,
                        allow_redirects=True,
                        headers={
                            "User-Agent": "Mozilla/5.0 (compatible; AutoSecAudit/2.0)",
                            "Content-Type": "application/x-www-form-urlencoded"
                        }
                    )
                else:
                    response = requests.post(
                        login_url,
                        json=payload["json"],
                        timeout=5,
                        verify=False,
                        allow_redirects=True,
                        headers={
                            "User-Agent": "Mozilla/5.0 (compatible; AutoSecAudit/2.0)",
                            "Content-Type": "application/json"
                        }
                    )

                content = response.text.lower()

                # Проверяем признаки успеха
                has_success = any(ind in content for ind in SUCCESS_INDICATORS)
                has_failure = any(ind in content for ind in FAILURE_INDICATORS)

                # Успех = есть признаки успеха И нет признаков неудачи
                if has_success and not has_failure:
                    result["success"] = True
                    result["details"] = f"Обнаружены признаки успешного входа"
                    return result

                # Также проверяем по редиректу и cookie
                if (response.history and
                    any(r.status_code in [301, 302] for r in response.history) and
                    has_success):
                    result["success"] = True
                    result["details"] = "Успешный редирект после входа"
                    return result

            except requests.RequestException:
                continue

    except Exception as e:
        result["details"] = f"Ошибка: {e}"

    return result


def check_default_credentials(url: str) -> dict:
    """
    Проверяет дефолтные учётные данные на популярных путях.
    ⚠️ ИСПОЛЬЗОВАТЬ ТОЛЬКО НА СВОИХ РЕСУРСАХ!
    """
    results = {
        "status": "PASS",
        "findings": [],
        "warning": "⚠️ Активная проверка учётных данных — только для авторизованного тестирования"
    }

    attempts = 0
    max_attempts = 50  # Ограничение для безопасности
    found_credentials = []

    # Сначала проверяем, какие пути вообще существуют (быстрая проверка)
    existing_paths = []
    for path in LOGIN_PATHS:
        try:
            response = requests.get(
                urljoin(url, path),
                timeout=5,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; AutoSecAudit/2.0)"}
            )
            # Если страница не 404 — она существует
            if response.status_code != 404:
                existing_paths.append(path)
        except requests.RequestException:
            continue

    if not existing_paths:
        results["findings"].append({
            "info": "Страницы входа не найдены",
            "severity": "INFO"
        })
        return results

    results["findings"].append({
        "info": f"Найдено {len(existing_paths)} потенциальных страниц входа",
        "severity": "INFO"
    })

    # Теперь пробуем учётки только на существующих путях
    for path in existing_paths:
        for username, password in DEFAULT_CREDENTIALS:
            if attempts >= max_attempts:
                results["findings"].append({
                    "warning": f"Достигнут лимит попыток ({max_attempts})",
                    "severity": "INFO"
                })
                return results

            attempts += 1
            result = _check_login(url, path, username, password)

            if result["success"]:
                results["status"] = "FAIL"
                creds_str = f"{username or '(пусто)'}:{password or '(пусто)'}"
                results["findings"].append({
                    "path": path,
                    "credentials": creds_str,
                    "issue": f"🚨 ОБНАРУЖЕНЫ ДЕФОЛТНЫЕ УЧЁТНЫЕ ДАННЫЕ!",
                    "description": f"Путь: {path}, Учётка: {creds_str}",
                    "severity": "CRITICAL",
                    "solution": "Немедленно смените пароль и отключите дефолтные учётки"
                })
                found_credentials.append((path, creds_str))

    if not found_credentials:
        results["findings"].append({
            "info": f"Дефолтные учётные данные не подошли (проверено {attempts} попыток)",
            "severity": "INFO"
        })

    return results
