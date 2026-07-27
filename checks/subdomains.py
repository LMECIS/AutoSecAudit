# checks/subdomains.py
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed

# Популярные поддомены (wordlist)
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "m", "mobile", "shop", "blog", "portal", "vpn", "webmail",
    "cdn", "static", "img", "media", "support", "help", "docs",
    "status", "dashboard", "panel", "cloud", "app", "git", "jenkins",
    "ci", "monitor", "grafana", "kibana", "prometheus", "mysql",
    "postgres", "redis", "mongo", "elastic", "rabbit", "smtp",
    "pop", "imap", "mx", "ns1", "ns2", "dns", "backup", "db",
    "internal", "intranet", "extranet", "proxy", "gateway", "auth",
    "sso", "oauth", "login", "register", "signup", "billing",
    "payment", "checkout", "cart", "orders", "users", "crm",
    "erp", "hr", "jira", "confluence", "gitlab", "bitbucket",
    "github", "slack", "teams", "zoom", "meet", "video", "stream",
    "radio", "tv", "news", "archive", "old", "new", "beta",
    "alpha", "demo", "sandbox", "uat", "prod", "production",
    "stage", "qa", "preprod", "edge", "origin", "assets", "files",
    "downloads", "uploads", "images", "videos", "audio", "data",
    "analytics", "stats", "metrics", "logs", "debug", "trace",
    "health", "ping", "ready", "live", "info", "about", "contact"
]

def _check_subdomain(subdomain: str, base_domain: str) -> dict:
    """Проверяет один поддомен."""
    full_domain = f"{subdomain}.{base_domain}"
    result = {"subdomain": full_domain, "records": []}

    for record_type in ["A", "AAAA", "CNAME", "MX"]:
        try:
            answers = dns.resolver.resolve(full_domain, record_type)
            for rdata in answers:
                result["records"].append({
                    "type": record_type,
                    "value": rdata.to_text()
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception:
            continue

    return result if result["records"] else None


def _detect_wildcard(base_domain: str) -> bool:
    """Определяет, есть ли wildcard DNS запись (чтобы избежать ложных срабатываний)."""
    import random
    import string
    # Генерируем случайный поддомен, которого точно не должно существовать
    random_sub = ''.join(random.choices(string.ascii_lowercase, k=20))
    try:
        dns.resolver.resolve(f"{random_sub}.{base_domain}", "A")
        return True  # Если резолвится — wildcard есть
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except Exception:
        return False


def check_subdomains(url: str) -> dict:
    """Ищет поддомены через DNS-перебор по словарю."""
    from urllib.parse import urlparse

    results = {"status": "PASS", "findings": []}
    hostname = urlparse(url).hostname or url.replace('https://', '').replace('http://', '')

    # Убираем www. если есть
    base_domain = hostname.replace("www.", "")

    # Проверка на wildcard DNS
    has_wildcard = _detect_wildcard(base_domain)
    if has_wildcard:
        results["findings"].append({
            "info": "Обнаружена wildcard DNS запись — результаты могут быть неточными",
            "severity": "INFO"
        })

    found_subdomains = []

    # Параллельная проверка поддоменов
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {
            executor.submit(_check_subdomain, sub, base_domain): sub
            for sub in SUBDOMAIN_WORDLIST
        }

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    # Если есть wildcard — фильтруем по уникальным IP
                    found_subdomains.append(result)
            except Exception:
                continue

    # Фильтрация wildcard-результатов (если есть wildcard, оставляем только с уникальными IP)
    if has_wildcard and found_subdomains:
        # Получаем IP wildcard-записи
        try:
            random_sub = "nonexistent12345xyz"
            wildcard_answers = dns.resolver.resolve(f"{random_sub}.{base_domain}", "A")
            wildcard_ips = {r.to_text() for r in wildcard_answers}

            filtered = []
            for sub in found_subdomains:
                ips = {r["value"] for r in sub["records"] if r["type"] == "A"}
                # Если IP поддомена отличается от wildcard — это реальный поддомен
                if not ips or not ips.issubset(wildcard_ips):
                    filtered.append(sub)
            found_subdomains = filtered
        except Exception:
            pass

    # Формируем findings
    for sub in found_subdomains:
        records_str = ", ".join(
            f"{r['type']}:{r['value']}" for r in sub["records"]
        )

        # Определяем severity по типу поддомена
        severity = "INFO"
        sensitive_keywords = ["admin", "dev", "staging", "test", "internal",
                              "jenkins", "git", "dashboard", "panel", "db",
                              "mysql", "postgres", "redis", "mongo"]
        if any(kw in sub["subdomain"].lower() for kw in sensitive_keywords):
            severity = "MEDIUM"

        results["findings"].append({
            "subdomain": sub["subdomain"],
            "issue": f"Найден поддомен: {sub['subdomain']}",
            "description": records_str,
            "severity": severity
        })

    if found_subdomains:
        results["status"] = "FAIL"
        results["findings"].insert(0, {
            "info": f"Всего найдено поддоменов: {len(found_subdomains)}",
            "severity": "INFO"
        })

    return results
