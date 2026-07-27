# checks/robots_sitemap.py
import requests
import urllib3
import re
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree as ET

urllib3.disable_warnings()

# Лимиты для защиты от зависаний
MAX_SITEMAP_DEPTH = 3          # Максимальная глубина рекурсии
MAX_URLS_PER_SITEMAP = 500     # Максимум URL в одном sitemap
MAX_TOTAL_URLS = 1000          # Максимум URL всего
MAX_RESPONSE_SIZE = 1_000_000  # 1 MB
REQUEST_TIMEOUT = 5            # секунды

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
            robots_url,
            timeout=REQUEST_TIMEOUT,
            verify=False,
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


def _parse_sitemap(sitemap_url: str, visited: set = None, depth: int = 0,
                   total_counter: list = None) -> list:
    """
    Парсит sitemap.xml с защитой от рекурсии и циклов.
    
    Args:
        sitemap_url: URL sitemap
        visited: множество уже посещённых URL (защита от циклов)
        depth: текущая глубина рекурсии
        total_counter: счётчик общего количества URL (list для мутабельности)
    """
    # Инициализация при первом вызове
    if visited is None:
        visited = set()
    if total_counter is None:
        total_counter = [0]

    # Защита от рекурсии
    if depth > MAX_SITEMAP_DEPTH:
        return []

    # Защита от циклов
    if sitemap_url in visited:
        return []
    visited.add(sitemap_url)

    # Защита от превышения лимита
    if total_counter[0] >= MAX_TOTAL_URLS:
        return []

    urls = []

    try:
        response = requests.get(
            sitemap_url,
            timeout=REQUEST_TIMEOUT,
            verify=False,
            stream=True,  # Для контроля размера
            headers={"User-Agent": "Mozilla/5.0 (compatible; AutoSecAudit/2.0)"}
        )

        if response.status_code != 200:
            return urls

        # Читаем с ограничением размера
        content = b""
        for chunk in response.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > MAX_RESPONSE_SIZE:
                break
        else:
            # Если цикл завершился нормально (не было break)
            pass

        content_text = content.decode("utf-8", errors="ignore")

        # Обрабатываем sitemap index (ссылки на другие sitemap)
        if "<sitemapindex" in content_text:
            try:
                root = ET.fromstring(content)
                ns = {"ns": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                
                # Ищем ссылки на дочерние sitemap
                child_sitemaps = []
                for loc in root.findall(".//ns:sitemap/ns:loc", ns):
                    if loc.text:
                        child_sitemaps.append(loc.text.strip())
                
                # Если namespace не сработал
                if not child_sitemaps:
                    for loc in root.findall(".//loc"):
                        if loc.text:
                            child_sitemaps.append(loc.text.strip())

                # Рекурсивно парсим дочерние sitemap
                for child_url in child_sitemaps[:10]:  # Максимум 10 дочерних sitemap
                    if total_counter[0] >= MAX_TOTAL_URLS:
                        break
                    child_urls = _parse_sitemap(
                        child_url, visited, depth + 1, total_counter
                    )
                    urls.extend(child_urls)

            except ET.ParseError:
                pass
            return urls

        # Обычный sitemap с URL
        try:
            root = ET.fromstring(content)
            
            # Пробуем с namespace
            locs = root.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc")
            if not locs:
                locs = root.findall(".//loc")

            for loc in locs:
                if total_counter[0] >= MAX_TOTAL_URLS:
                    break
                if len(urls) >= MAX_URLS_PER_SITEMAP:
                    break
                if loc.text:
                    urls.append(loc.text.strip())
                    total_counter[0] += 1

        except ET.ParseError:
            pass

    except requests.RequestException:
        pass
    except Exception:
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

    # Парсим все sitemap с общей защитой от рекурсии
    visited = set()
    total_counter = [0]
    all_urls = []

    for sitemap_url in sitemap_urls:
        if total_counter[0] >= MAX_TOTAL_URLS:
            break
        urls = _parse_sitemap(sitemap_url, visited, depth=0, total_counter=total_counter)
        all_urls.extend(urls)

    all_urls = list(set(all_urls))  # Убираем дубли

    if all_urls:
        results["findings"].append({
            "info": f"Найдено {len(all_urls)} URL в sitemap (обработано sitemap: {len(visited)})",
            "severity": "INFO"
        })

        # Ищем интересные URL в sitemap
        interesting_urls = []
        for u in all_urls:
            try:
                parsed = urlparse(u)
                if _is_interesting(parsed.path):
                    interesting_urls.append(u)
            except Exception:
                continue

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

    return results