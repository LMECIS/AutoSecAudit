# checks/default_creds.py
"""
⚠️ ВНИМАНИЕ: Активный модуль — использовать ТОЛЬКО на своих ресурсах!
"""
import httpx
from urllib.parse import urljoin
from models import Finding, ModuleResult, Severity


LOGIN_PATHS = [
    "/admin", "/administrator", "/login", "/wp-admin/", "/wp-login.php",
    "/cpanel", "/manager/html", "/console", "/jenkins/login",
    "/phpmyadmin", "/adminer", "/api/v1/login", "/api/auth/login",
    "/auth/login", "/user/login", "/portal/login", "/signin"
]

DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "12345678"), ("admin", "admin123"), ("admin", "qwerty"),
    ("admin", "letmein"), ("admin", "welcome"), ("root", "root"),
    ("test", "test"), ("user", "user"), ("guest", "guest"),
    ("tomcat", "tomcat"), ("admin", ""), ("", "admin"),
]

SUCCESS_INDICATORS = [
    "dashboard", "welcome", "logout", "log out", "sign out",
    "my account", "мой аккаунт", "выход", "панель управления",
    "admin panel", "админ", "профиль", "profile"
]

FAILURE_INDICATORS = [
    "invalid", "incorrect", "неверн", "ошибк", "wrong",
    "failed", "denied", "запрещ", "неправил"
]


async def _check_login(client: httpx.AsyncClient, login_url: str,
                       username: str, password: str) -> bool:
    """Пробует войти с указанными учётными данными."""
    payloads = [
        {"data": {"username": username, "password": password, "login": "Login"}},
        {"data": {"user": username, "pass": password, "submit": "Войти"}},
        {"data": {"log": username, "pwd": password}},
        {"json": {"username": username, "password": password}},
    ]

    for payload in payloads:
        try:
            if "data" in payload:
                response = await client.post(login_url, data=payload["data"],
                                             follow_redirects=True)
            else:
                response = await client.post(login_url, json=payload["json"],
                                             follow_redirects=True)

            content = response.text.lower()
            has_success = any(ind in content for ind in SUCCESS_INDICATORS)
            has_failure = any(ind in content for ind in FAILURE_INDICATORS)

            if has_success and not has_failure:
                return True
        except Exception:
            continue

    return False


async def check_default_creds(client: httpx.AsyncClient, url: str) -> ModuleResult:
    """
    Проверяет дефолтные учётные данные.
    ⚠️ ИСПОЛЬЗОВАТЬ ТОЛЬКО НА СВОИХ РЕСУРСАХ!
    """
    findings = []
    findings.append(Finding(
        info="⚠️ Активная проверка учётных данных",
        issue="Модуль активной проверки",
        severity=Severity.INFO,
        module="Дефолтные учётки"
    ))

    try:
        # Сначала проверяем существующие пути
        existing_paths = []
        for path in LOGIN_PATHS:
            try:
                response = await client.get(urljoin(url, path), follow_redirects=True)
                if response.status_code != 404:
                    existing_paths.append(path)
            except Exception:
                continue

        if not existing_paths:
            findings.append(Finding(
                info="Страницы входа не найдены",
                issue="Страницы входа не обнаружены",
                severity=Severity.INFO,
                module="Дефолтные учётки"
            ))
            return ModuleResult(status="PASS", findings=findings)

        findings.append(Finding(
            info=f"Найдено {len(existing_paths)} страниц входа",
            issue=f"Обнаружено {len(existing_paths)} потенциальных форм входа",
            severity=Severity.INFO,
            module="Дефолтные учётки"
        ))

        # Пробуем учётки
        attempts = 0
        max_attempts = 50

        for path in existing_paths:
            for username, password in DEFAULT_CREDENTIALS:
                if attempts >= max_attempts:
                    findings.append(Finding(
                        warning=f"Достигнут лимит попыток ({max_attempts})",
                        issue=f"Лимит попыток исчерпан",
                        severity=Severity.INFO,
                        module="Дефолтные учётки"
                    ))
                    return ModuleResult(status="PASS", findings=findings)

                attempts += 1
                login_url = urljoin(url, path)

                if await _check_login(client, login_url, username, password):
                    creds_str = f"{username or '(пусто)'}:{password or '(пусто)'}"
                    findings.append(Finding(
                        issue="🚨 ОБНАРУЖЕНЫ ДЕФОЛТНЫЕ УЧЁТНЫЕ ДАННЫЕ!",
                        severity=Severity.CRITICAL,
                        module="Дефолтные учётки",
                        path=path,
                        credentials=creds_str,
                        description=f"Путь: {path}, Учётка: {creds_str}",
                        solution="Немедленно смените пароль"
                    ))

        if not any(f.severity == Severity.CRITICAL for f in findings):
            findings.append(Finding(
                info=f"Дефолтные учётки не подошли (проверено {attempts})",
                issue="Дефолтные учётки не обнаружены",
                severity=Severity.INFO,
                module="Дефолтные учётки"
            ))

    except Exception as e:
        findings.append(Finding(
            issue="Ошибка проверки учётных данных",
            severity=Severity.INFO,
            module="Дефолтные учётки",
            error=str(e)
        ))

    status = "FAIL" if any(f.severity == Severity.CRITICAL for f in findings) else "PASS"
    return ModuleResult(status=status, findings=findings)