# checks/directory_listing.py
import httpx
from urllib.parse import urljoin
from models import Finding, ModuleResult, Severity


COMMON_DIRECTORIES = [
    {"path": "backup/", "description": "Резервные копии", "severity": Severity.HIGH},
    {"path": "backups/", "description": "Резервные копии", "severity": Severity.HIGH},
    {"path": "uploads/", "description": "Загруженные файлы", "severity": Severity.MEDIUM},
    {"path": "logs/", "description": "Логи", "severity": Severity.HIGH},
    {"path": "log/", "description": "Логи", "severity": Severity.HIGH},
    {"path": "temp/", "description": "Временные файлы", "severity": Severity.MEDIUM},
    {"path": "tmp/", "description": "Временные файлы", "severity": Severity.MEDIUM},
    {"path": "admin/", "description": "Админ-панель", "severity": Severity.HIGH},
    {"path": "administrator/", "description": "Админ-панель", "severity": Severity.HIGH},
    {"path": "wp-admin/", "description": "WordPress админка", "severity": Severity.MEDIUM},
    {"path": "api/", "description": "API endpoints", "severity": Severity.MEDIUM},
    {"path": "swagger/", "description": "Swagger UI", "severity": Severity.MEDIUM},
    {"path": ".aws/", "description": "AWS конфиги", "severity": Severity.CRITICAL},
    {"path": "config/", "description": "Конфигурации", "severity": Severity.HIGH},
    {"path": "db/", "description": "Базы данных", "severity": Severity.CRITICAL},
]

DIRECTORY_LISTING_SIGNATURES = [
    "index of /", "directory listing for", "<title>index of",
    "directory listing", "[to parent directory]", "parent directory</a>",
]


async def check_directory_listing(client: httpx.AsyncClient, url: str) -> ModuleResult:
    """Ищет открытые директории (Directory Listing)."""
    findings = []

    async def _check_one(dir_info: dict):
        try:
            full_url = urljoin(url, dir_info["path"])
            response = await client.get(full_url, follow_redirects=False)

            if response.status_code == 200:
                content_type = response.headers.get("content-type", "")
                if "text/html" in content_type:
                    content = response.text[:5000].lower()
                    for signature in DIRECTORY_LISTING_SIGNATURES:
                        if signature in content:
                            return Finding(
                                issue=f"Открытая директория: {dir_info['path']}",
                                severity=dir_info["severity"],
                                module="Открытые директории",
                                description=dir_info["description"],
                                url=full_url,
                                path=dir_info["path"]
                            )
        except Exception:
            pass
        return None

    tasks = [_check_one(d) for d in COMMON_DIRECTORIES]
    results = await asyncio.gather(*tasks)

    for r in results:
        if r is not None:
            findings.append(r)

    status = "FAIL" if findings else "PASS"
    return ModuleResult(status=status, findings=findings)


import asyncio