# checks/robots_sitemap.py
import requests
import urllib3
import re
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree as ET

urllib3.disable_warnings()

# Паттерны, указывающие на интересные/скрытые пути
INTERESTING_PATTERNS = [
    r"admin", r"administrator", r"login", r"wp-admin", r"cpanel",
    r"backup", r"backups", r"\.bak$", r"\.sql$", r"\.tar\.gz$",
    r"\.zip$", r"\.env", r"\.git", r"config", r"conf",
    r"private", r"internal", r"secret", r"api", r"debug",
    r"test", r"staging", r"dev", r"temp", r"tmp",
    r"phpinfo", r"server-status", r"phpmyadmin", r"adminer"
]


def _parse_robots(url: str) -> tuple:
    """Парсит robots.txt, возвращает (disallow_paths, sitemap_urls)."""
    disallow_paths = []
    sitemap_urls = []

    try:
        robots_url = urljoin(url, "/robots.txt")
        response = requests.get(
            robots_url, timeout=10, verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; AutoSecAudit/2.0)"}
        )

        if response.status_code != 200:
            return disallow_paths, sitemap_urls

        for line in response.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    disallow_paths.append(path)
            elif line.lower().startswith("sitemap:"):
                sitemap_url = line.split(":", 1)[1].strip()
                if sitemap_url:
                    sitemap_urls.append(sitemap_url)

    except requests.RequestException:
        pass

    return disallow_paths, sitemap_urls


def _parse_sitemap(sitemap_url: str) -> list:
    """Парсит sitemap.xml, возвращает список URL."""
    urls = []
    try:
        response = requests.get(
            sitemap_url, timeout=15, verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; AutoSecAudit/2.0)"}
        )
        if response.status_code != 200:
            return urls

        # Обрабатываем sitemap index (ссылки на другие sitemap)
        if "<sitemapindex" in response.text:
            try:
                root = ET.fromstring(response.content)
                ns = {"ns": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                for loc in root.findall(".//ns:sitemap/ns:loc", ns) or root.findall(".//loc"):
                    child_sitemap = loc.text.strip()
                    urls.extend(_parse_sitemap(child_sitemap))
            except ET.ParseError:
                pass
            return urls

        # Обычный sitemap
        try:
            root = ET.fromstring(response.content)
            for loc in root.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc"):
                if loc.text:
                    urls.append(loc.text.strip())
            # Если namespace не сработал — пробуем без него
            if not urls:
                for loc in root.findall(".//loc"):
                    if loc.text:
                        urls.append(loc.text.strip())
        except ET.ParseError:
            pass

    except requests.RequestException:
        pass

    return urls


def _is_interesting(path: str) -> bool:
    """Проверяет, содержит ли путь интересные паттерны."""
    path_lower = path.lower()
    return any(re.search(pattern, path_lower) for pattern in INTERESTING_PATTERNS)


def check_robots_sitemap(url: str) -> dict:
    """Анализирует robots.txt и sitemap.xml на наличие скрытых путей."""
    results = {"status": "PASS", "findings": []}

    # 1. Парсим robots.txt
    disallow_paths, sitemap_urls = _parse_robots(url)

    if disallow_paths:
        results["findings"].append({
            "info": f"Найдено {len(disallow_paths)} путей в Disallow (robots.txt)",
            "severity": "INFO"
        })

        # Ищем интересные пути среди Disallow
        interesting_disallow = [p for p in disallow_paths if _is_interesting(p)]
        for path in interesting_disallow[:20]:  # Ограничиваем вывод
            full_url = urljoin(url, path)
            results["status"] = "FAIL"
            results["findings"].append({
                "path": path,
                "url": full_url,
                "issue": f"Скрытый путь в robots.txt: {path}",
                "description": "Путь скрыт от поисковиков, но доступен публично",
                "severity": "MEDIUM",
                "source": "robots.txt"
            })

    # 2. Добавляем sitemap из robots.txt + стандартный /sitemap.xml
    sitemap_urls.append(urljoin(url, "/sitemap.xml"))
    sitemap_urls = list(set(sitemap_urls))  # Убираем дубли

    all_urls = []
    for sitemap_url in sitemap_urls:
        all_urls.extend(_parse_sitemap(sitemap_url))

    all_urls = list(set(all_urls))

    if all_urls:
        results["findings"].append({
            "info": f"Найдено {len(all_urls)} URL в sitemap",
            "severity": "INFO"
        })

        # Ищем интересные URL в sitemap
        interesting_urls = []
        for u in all_urls:
            parsed = urlparse(u)
            if _is_interesting(parsed.path):
                interesting_urls.append(u)

        for u in interesting_urls[:20]:
            results["status"] = "FAIL"
            results["findings"].append({
                "url": u,
                "issue": f"Интересный URL в sitemap: {u}",
                "description": "Путь может содержать чувствительную информацию",
                "severity": "LOW",
                "source": "sitemap.xml"
            })

    if not disallow_paths and not all_urls:
        results["findings"].append({
            "info": "robots.txt и sitemap.xml не найдены или пусты",
            "severity": "INFO"
        })
