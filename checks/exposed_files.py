# checks/exposed_files.py
import requests
import urllib3
from urllib.parse import urljoin

urllib3.disable_warnings()

# Список критических файлов, которые не должны быть доступны публично
SENSITIVE_FILES = [
    {
        "path": ".git/config",
        "description": "Конфигурация Git (может содержать учетные данные)",
        "severity": "CRITICAL",
        "marker": "[core]"  # Признак валидного git config
    },
    {
        "path": ".env",
        "description": "Переменные окружения (пароли, API ключи)",
        "severity": "CRITICAL",
        "marker": "="
    },
    {
        "path": ".env.backup",
        "description": "Резервная копия .env",
        "severity": "CRITICAL",
        "marker": "="
    },
    {
        "path": "wp-config.php",
        "description": "Конфигурация WordPress",
        "severity": "CRITICAL",
        "marker": "<?php"
    },
    {
        "path": "config.php",
        "description": "Конфигурационный файл",
        "severity": "HIGH",
        "marker": "<?php"
    },
    {
        "path": "phpinfo.php",
        "description": "Информация о PHP конфигурации",
        "severity": "HIGH",
        "marker": "phpinfo()"
    },
    {
        "path": ".htaccess",
        "description": "Конфигурация Apache",
        "severity": "MEDIUM",
        "marker": "RewriteEngine"
    },
    {
        "path": "server-status",
        "description": "Статус Apache (утечка информации)",
        "severity": "MEDIUM",
        "marker": "Apache Server Status"
    },
    {
        "path": "sitemap.xml",
        "description": "Карта сайта (раскрытие структуры)",
        "severity": "INFO",
        "marker": "<urlset"
    },
    {
        "path": "robots.txt",
        "description": "Правила для поисковиков",
        "severity": "INFO",
        "marker": "User-agent"
    }
]

def check_exposed_files(url: str) -> dict:
    """Ищет публично доступные чувствительные файлы."""
    results = {"status": "PASS", "findings": []}
    
    for file_info in SENSITIVE_FILES:
        try:
            full_url = urljoin(url, file_info["path"])
            response = requests.get(
                full_url, 
                timeout=5, 
                verify=False, 
                allow_redirects=False  # Не следовать редиректам
            )
            
            # Проверяем, что файл реально существует (200 OK) и содержит маркер
            if response.status_code == 200:
                content = response.text[:1000]  # Читаем только начало
                if file_info["marker"] in content:
                    results["status"] = "FAIL"
                    results["findings"].append({
                        "file": file_info["path"],
                        "url": full_url,
                        "description": file_info["description"],
                        "severity": file_info["severity"],
                        "size": len(response.content)
                    })
                    
        except requests.RequestException:
            continue  # Игнорируем ошибки сети
            
    return results
