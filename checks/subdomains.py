# checks/subdomains.py
import asyncio
import random
import string
import socket
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import httpx
from urllib.parse import urlparse
from models import Finding, ModuleResult, Severity


SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "m", "shop", "blog", "portal", "vpn", "webmail", "cdn", "static",
    "support", "help", "docs", "status", "dashboard", "panel", "cloud",
    "app", "git", "jenkins", "ci", "monitor", "grafana", "kibana",
    "mysql", "postgres", "redis", "mongo", "elastic", "smtp", "pop",
    "imap", "mx", "ns1", "ns2", "backup", "db", "internal", "intranet",
    "proxy", "gateway", "auth", "sso", "login", "billing", "payment",
    "jira", "confluence", "gitlab", "github", "slack", "video", "stream",
    "archive", "old", "new", "beta", "alpha", "demo", "sandbox", "uat",
    "prod", "stage", "qa", "preprod", "edge", "origin", "assets", "files",
    "data", "analytics", "logs", "debug", "health", "info"
]

SENSITIVE_KEYWORDS = ["admin", "dev", "staging", "test", "internal",
                      "jenkins", "git", "dashboard", "panel", "db",
                      "mysql", "postgres", "redis", "mongo"]


# Настраиваем DNS-резолвер с нормальными таймаутами
def _get_resolver() -> dns.resolver.Resolver:
    """Создаёт настроенный DNS-резолвер."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0        # Таймаут одного запроса
    resolver.lifetime = 5.0       # Общее время жизни запроса
    # Используем публичные DNS, если системный не отвечает
    resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
    return resolver


def _detect_wildcard_sync(base_domain: str) -> bool:
    """Определяет wildcard DNS через случайный поддомен."""
    random_sub = ''.join(random.choices(string.ascii_lowercase, k=20))
    try:
        resolver = _get_resolver()
        resolver.resolve(f"{random_sub}.{base_domain}", "A")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except Exception:
        return False


def _check_subdomain_sync(subdomain: str, base_domain: str) -> dict:
    """
    Проверяет один поддомен.
    Использует dnspython с fallback на socket.gethostbyname().
    """
    full_domain = f"{subdomain}.{base_domain}"
    records = []

    # Метод 1: dnspython (поддерживает разные типы записей)
    try:
        resolver = _get_resolver()
        for record_type in ["A", "CNAME", "MX"]:
            try:
                answers = resolver.resolve(full_domain, record_type)
                for rdata in answers:
                    records.append({"type": record_type, "value": rdata.to_text()})
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
            except Exception:
                continue
    except Exception:
        pass

    # Метод 2: Fallback через socket (если dnspython не сработал)
    if not records:
        try:
            ip = socket.gethostbyname(full_domain)
            if ip:
                records.append({"type": "A", "value": ip})
        except socket.gaierror:
            pass
        except Exception:
            pass

    return {"subdomain": full_domain, "records": records} if records else None


async def check_subdomains(client: httpx.AsyncClient, url: str) -> ModuleResult:
    """Ищет поддомены через DNS-перебор по словарю."""
    findings = []

    parsed = urlparse(url)
    hostname = parsed.hostname or url.replace('https://', '').replace('http://', '')
    base_domain = hostname.replace("www.", "")

    print(f"        [i] Проверка поддоменов для: {base_domain}")

    try:
        # 1. Проверка wildcard DNS
        print(f"        [i] Проверка wildcard DNS...")
        has_wildcard = await asyncio.to_thread(_detect_wildcard_sync, base_domain)
        if has_wildcard:
            findings.append(Finding(
                issue="Wildcard DNS запись обнаружена",
                severity=Severity.INFO,
                module="Поддомены",
                info="Результаты могут содержать ложные срабатывания"
            ))
            print(f"        [!] Wildcard DNS обнаружен")
        else:
            print(f"        [✓] Wildcard DNS не обнаружен")

        # 2. Параллельная проверка поддоменов через ThreadPoolExecutor
        # Ограничиваем пул потоков, чтобы не перегружать DNS-резолвер
        print(f"        [i] Перебор {len(SUBDOMAIN_WORDLIST)} поддоменов...")
        found_subdomains = []
        errors_count = 0

        loop = asyncio.get_event_loop()
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            # Создаём futures для всех поддоменов
            futures = [
                loop.run_in_executor(
                    executor,
                    _check_subdomain_sync,
                    sub,
                    base_domain
                )
                for sub in SUBDOMAIN_WORDLIST
            ]
            
            # Ждём все результаты
            results = await asyncio.gather(*futures, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    errors_count += 1
                    continue
                if result is not None:
                    found_subdomains.append(result)

        print(f"        [✓] Найдено поддоменов: {len(found_subdomains)}, ошибок: {errors_count}")

        # 3. Формируем findings
        for sub in found_subdomains:
            records_str = ", ".join(f"{r['type']}:{r['value']}" for r in sub["records"])
            severity = Severity.MEDIUM if any(
                kw in sub["subdomain"].lower() for kw in SENSITIVE_KEYWORDS
            ) else Severity.INFO

            findings.append(Finding(
                issue=f"Найден поддомен: {sub['subdomain']}",
                severity=severity,
                module="Поддомены",
                subdomain=sub["subdomain"],
                description=records_str
            ))

        if found_subdomains:
            findings.insert(0, Finding(
                issue=f"Найдено {len(found_subdomains)} поддоменов",
                severity=Severity.INFO,
                module="Поддомены",
                info=f"Всего найдено поддоменов: {len(found_subdomains)}"
            ))
        else:
            findings.append(Finding(
                issue="Поддомены не обнаружены",
                severity=Severity.INFO,
                module="Поддомены",
                info="Ни один поддомен из словаря не резолвится"
            ))

    except Exception as e:
        print(f"        [✗] Критическая ошибка: {e}")
        findings.append(Finding(
            issue="Ошибка поиска поддоменов",
            severity=Severity.INFO,
            module="Поддомены",
            error=str(e)
        ))

    status = "FAIL" if any(f.severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM)
                           for f in findings) else "PASS"
    return ModuleResult(status=status, findings=findings)