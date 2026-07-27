# checks/directory_listing.py
import requests
import urllib3
from urllib.parse import urljoin

urllib3.disable_warnings()

# Популярные пути, где часто встречаются открытые директории
COMMON_DIRECTORIES = [
    {"path": "backup/", "description": "Резервные копии", "severity": "HIGH"},
    {"path": "backups/", "description": "Резервные копии", "severity": "HIGH"},
    {"path": "uploads/", "description": "Загруженные файлы", "severity": "MEDIUM"},
    {"path": "images/", "description": "Изображения", "severity": "LOW"},
    {"path": "assets/", "description": "Статические ресурсы", "severity": "LOW"},
    {"path": "static/", "description": "Статические файлы", "severity": "LOW"},
    {"path": "media/", "description": "Медиа-файлы", "severity": "LOW"},
    {"path": "files/", "description": "Файлы", "severity": "MEDIUM"},
    {"path": "downloads/", "description": "Загрузки", "severity": "MEDIUM"},
    {"path": "logs/", "description": "Логи (утечка информации)", "severity": "HIGH"},
    {"path": "log/", "description": "Логи", "severity": "HIGH"},
    {"path": "temp/", "description": "Временные файлы", "severity": "MEDIUM"},
    {"path": "tmp/", "description": "Временные файлы", "severity": "MEDIUM"},
    {"path": "cache/", "description": "Кэш", "severity": "MEDIUM"},
    {"path": "admin/", "description": "Админ-панель", "severity": "HIGH"},
    {"path": "administrator/", "description": "Админ-панель", "severity": "HIGH"},
    {"path": "wp-admin/", "description": "WordPress админка", "severity": "MEDIUM"},
    {"path": "wp-content/uploads/", "description": "WordPress загрузки", "severity": "MEDIUM"},
    {"path": "api/", "description": "API endpoints", "severity": "MEDIUM"},
    {"path": "docs/", "description": "Документация", "severity": "LOW"},
    {"path": "swagger/", "description": "Swagger UI", "severity": "MEDIUM"},
    {"path": "api-docs/", "description": "API документация", "severity": "MEDIUM"},
    {"path": ".aws/", "description": "AWS конфиги", "severity": "CRITICAL"},
    {"path": "config/", "description": "Конфигурации", "severity": "HIGH"},
    {"path": "conf/", "description": "Конфигурации", "severity": "HIGH"},
    {"path": "db/", "description": "Базы данных", "severity": "CRITICAL"},
    {"path": "database/", "description": "Базы данных", "severity": "CRITICAL"},
]

# Сигнатуры, указывающие на открытый индекс директории
DIRECTORY_LISTING_SIGNATURES = [
    "Index of /",
    "Directory listing for",
    "<title>Index of",
    "Directory Listing",
    "[To Parent Directory]",
    "Parent Directory</a>",
    "<h1>Index of",
]

def check_directory_listing(url: str) -> dict:
    """Ищет открытые директории (Directory Listing)."""
    results = {"status": "PASS", "findings": []}

    for dir_info in COMMON_DIRECTORIES:
        try:
            full_url = urljoin(url, dir_info["path"])
            response = requests.get(
                full_url,
                timeout=5,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; AutoSecAudit/2.0)"}
            )

            # Проверяем, что это 200 OK и это HTML-страница с индексом
            if response.status_code == 200:
                content_type = response.headers.get("Content-Type", "")
                if "text/html" in content_type:
                    content = response.text[:5000]
                    for signature in DIRECTORY_LISTING_SIGNATURES:
                        if signature.lower() in content.lower():
                            results["status"] = "FAIL"
                            results["findings"].append({
                                "path": dir_info["path"],
                                "url": full_url,
                                "description": f"Открытая директория: {dir_info['description']}",
                                "severity": dir_info["severity"]
                            })
                            break
        except requests.RequestException:
            continue

    return results
