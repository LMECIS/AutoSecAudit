# checks/exposed_files.py
import httpx
from urllib.parse import urljoin
from models import Finding, ModuleResult, Severity


SENSITIVE_FILES = [
    {"path": ".git/config", "description": "Конфигурация Git", "severity": Severity.CRITICAL, "marker": "[core]"},
    {"path": ".env", "description": "Переменные окружения", "severity": Severity.CRITICAL, "marker": "="},
    {"path": ".env.backup", "description": "Резервная копия .env", "severity": Severity.CRITICAL, "marker": "="},
    {"path": "wp-config.php", "description": "Конфигурация WordPress", "severity": Severity.CRITICAL, "marker": "<?php"},
    {"path": "config.php", "description": "Конфигурационный файл", "severity": Severity.HIGH, "marker": "<?php"},
    {"path": "phpinfo.php", "description": "Информация о PHP", "severity": Severity.HIGH, "marker": "phpinfo()"},
    {"path": ".htaccess", "description": "Конфигурация Apache", "severity": Severity.MEDIUM, "marker": "RewriteEngine"},
    {"path": "server-status", "description": "Статус Apache", "severity": Severity.MEDIUM, "marker": "Apache Server Status"},
    {"path": "sitemap.xml", "description": "Карта сайта", "severity": Severity.INFO, "marker": "<urlset"},
    {"path": "robots.txt", "description": "Правила для поисковиков", "severity": Severity.INFO, "marker": "User-agent"},
]


async def check_exposed_files(client: httpx.AsyncClient, url: str) -> ModuleResult:
    """Ищет публично доступные чувствительные файлы."""
    findings = []

    async def _check_one(file_info: dict):
        try:
            full_url = urljoin(url, file_info["path"])
            response = await client.get(full_url, follow_redirects=False)

            if response.status_code == 200:
                content = response.text[:1000]
                if file_info["marker"] in content:
                    return Finding(
                        issue=f"Доступен файл: {file_info['path']}",
                        severity=file_info["severity"],
                        module="Утечки файлов",
                        description=file_info["description"],
                        url=full_url,
                        file=file_info["path"]
                    )
        except Exception:
            pass
        return None

    # Параллельная проверка всех файлов
    tasks = [_check_one(f) for f in SENSITIVE_FILES]
    results = await asyncio.gather(*tasks)

    for r in results:
        if r is not None:
            findings.append(r)

    status = "FAIL" if findings else "PASS"
    return ModuleResult(status=status, findings=findings)


# Импортируем asyncio для gather
import asyncio