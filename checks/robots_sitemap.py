# checks/robots_sitemap.py
import re
import httpx
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree as ET
from models import Finding, ModuleResult, Severity


MAX_SITEMAP_DEPTH = 3
MAX_URLS_PER_SITEMAP = 500
MAX_TOTAL_URLS = 1000
MAX_RESPONSE_SIZE = 1_000_000

INTERESTING_PATTERNS = [
    r"admin", r"administrator", r"login", r"wp-admin", r"cpanel",
    r"backup", r"backups", r"\.bak$", r"\.sql$", r"\.tar\.gz$",
    r"\.zip$", r"\.env", r"\.git", r"config", r"conf",
    r"private", r"internal", r"secret", r"api", r"debug",
    r"test", r"staging", r"dev", r"temp", r"tmp",
    r"phpinfo", r"server-status", r"phpmyadmin", r"adminer"
]


def _parse_robots_text(text: str) -> tuple:
    """Парсит содержимое robots.txt."""
    disallow_paths = []
    sitemap_urls = []

    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                disallow_paths.append(path)
        elif line.lower().startswith("sitemap:"):
            sitemap_url = line.split(":", 1)[1].strip()
            if sitemap_url:
                sitemap_urls.append(sitemap_url)

    return disallow_paths, sitemap_urls


async def _parse_sitemap(client: httpx.AsyncClient, sitemap_url: str,
                         visited: set, depth: int, total_counter: list) -> list:
    """Парсит sitemap.xml с защитой от рекурсии."""
    if depth > MAX_SITEMAP_DEPTH or sitemap_url in visited:
        return []
    if total_counter[0] >= MAX_TOTAL_URLS:
        return []

    visited.add(sitemap_url)
    urls = []

    try:
        response = await client.get(sitemap_url)
        if response.status_code != 200:
            return urls

        content = response.content[:MAX_RESPONSE_SIZE]
        content_text = content.decode("utf-8", errors="ignore")

        if "<sitemapindex" in content_text:
            try:
                root = ET.fromstring(content)
                ns = {"ns": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                child_sitemaps = [
                    loc.text.strip()
                    for loc in (root.findall(".//ns:sitemap/ns:loc", ns) or root.findall(".//loc"))
                    if loc.text
                ]
                for child_url in child_sitemaps[:10]:
                    if total_counter[0] >= MAX_TOTAL_URLS:
                        break
                    child_urls = await _parse_sitemap(
                        client, child_url, visited, depth + 1, total_counter
                    )
                    urls.extend(child_urls)
            except ET.ParseError:
                pass
            return urls

        try:
            root = ET.fromstring(content)
            locs = root.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc")
            if not locs:
                locs = root.findall(".//loc")

            for loc in locs:
                if total_counter[0] >= MAX_TOTAL_URLS or len(urls) >= MAX_URLS_PER_SITEMAP:
                    break
                if loc.text:
                    urls.append(loc.text.strip())
                    total_counter[0] += 1
        except ET.ParseError:
            pass

    except Exception:
        pass

    return urls


def _is_interesting(path: str) -> bool:
    """Проверяет, содержит ли путь интересные паттерны."""
    path_lower = path.lower()
    return any(re.search(pattern, path_lower) for pattern in INTERESTING_PATTERNS)


async def check_robots_sitemap(client: httpx.AsyncClient, url: str) -> ModuleResult:
    """Анализирует robots.txt и sitemap.xml на наличие скрытых путей."""
    findings = []

    try:
        # 1. Парсим robots.txt
        robots_url = urljoin(url, "/robots.txt")
        robots_resp = await client.get(robots_url)
        disallow_paths = []
        sitemap_urls = []

        if robots_resp.status_code == 200:
            disallow_paths, sitemap_urls = _parse_robots_text(robots_resp.text)

        if disallow_paths:
            findings.append(Finding(
                info=f"Найдено {len(disallow_paths)} путей в Disallow",
                issue=f"Robots.txt содержит {len(disallow_paths)} скрытых путей",
                severity=Severity.INFO,
                module="Robots/Sitemap"
            ))

            for path in [p for p in disallow_paths if _is_interesting(p)][:20]:
                findings.append(Finding(
                    issue=f"Скрытый путь в robots.txt: {path}",
                    severity=Severity.MEDIUM,
                    module="Robots/Sitemap",
                    path=path,
                    url=urljoin(url, path),
                    description="Путь скрыт от поисковиков, но доступен публично"
                ))

        # 2. Парсим sitemap
        sitemap_urls.append(urljoin(url, "/sitemap.xml"))
        sitemap_urls = list(set(sitemap_urls))

        visited = set()
        total_counter = [0]
        all_urls = []

        for sitemap_url in sitemap_urls:
            if total_counter[0] >= MAX_TOTAL_URLS:
                break
            urls = await _parse_sitemap(client, sitemap_url, visited, 0, total_counter)
            all_urls.extend(urls)

        all_urls = list(set(all_urls))

        if all_urls:
            findings.append(Finding(
                info=f"Найдено {len(all_urls)} URL в sitemap",
                issue=f"Sitemap содержит {len(all_urls)} URL",
                severity=Severity.INFO,
                module="Robots/Sitemap"
            ))

            interesting = [u for u in all_urls if _is_interesting(urlparse(u).path)][:20]
            for u in interesting:
                findings.append(Finding(
                    issue=f"Интересный URL в sitemap: {u}",
                    severity=Severity.LOW,
                    module="Robots/Sitemap",
                    url=u
                ))

        if not disallow_paths and not all_urls:
            findings.append(Finding(
                info="robots.txt и sitemap.xml не найдены",
                issue="Файлы robots.txt/sitemap.xml отсутствуют",
                severity=Severity.INFO,
                module="Robots/Sitemap"
            ))

    except Exception as e:
        findings.append(Finding(
            issue="Ошибка анализа robots/sitemap",
            severity=Severity.INFO,
            module="Robots/Sitemap",
            error=str(e)
        ))

    status = "FAIL" if any(f.severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM)
                           for f in findings) else "PASS"
    return ModuleResult(status=status, findings=findings)