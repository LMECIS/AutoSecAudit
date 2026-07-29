# checks/dns_records.py
import asyncio
import dns.resolver
import httpx
from urllib.parse import urlparse
from models import Finding, ModuleResult, Severity


def _check_dns_sync(domain: str) -> dict:
    """Синхронная проверка DNS (запускается в thread)."""
    result = {"spf": False, "dmarc": False, "spf_error": None, "dmarc_error": None}

    # SPF
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if 'v=spf1' in rdata.to_text():
                result["spf"] = True
                break
    except dns.resolver.NoAnswer:
        result["spf_error"] = "NoAnswer"
    except dns.resolver.NXDOMAIN:
        result["spf_error"] = "NXDOMAIN"
    except Exception as e:
        result["spf_error"] = str(e)

    # DMARC
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for r in answers:
            if 'v=DMARC1' in r.to_text():
                result["dmarc"] = True
                break
    except dns.resolver.NXDOMAIN:
        result["dmarc_error"] = "NXDOMAIN"
    except dns.resolver.NoAnswer:
        result["dmarc_error"] = "NoAnswer"
    except Exception as e:
        result["dmarc_error"] = str(e)

    return result


async def check_dns(client: httpx.AsyncClient, url: str) -> ModuleResult:
    """Проверяет наличие SPF и DMARC записей."""
    findings = []

    parsed = urlparse(url)
    domain = parsed.hostname or url.replace('https://', '').replace('http://', '').split('/')[0]

    try:
        result = await asyncio.to_thread(_check_dns_sync, domain)

        if not result["spf"]:
            findings.append(Finding(
                issue="SPF запись отсутствует (риск Email Spoofing)",
                severity=Severity.HIGH,
                module="DNS (Email)",
                record="SPF"
            ))

        if not result["dmarc"]:
            findings.append(Finding(
                issue="DMARC запись отсутствует",
                severity=Severity.MEDIUM,
                module="DNS (Email)",
                record="DMARC"
            ))

        if result["spf"] and result["dmarc"]:
            findings.append(Finding(
                info="SPF и DMARC настроены корректно",
                issue="Email-безопасность настроена",
                severity=Severity.INFO,
                module="DNS (Email)"
            ))

    except Exception as e:
        findings.append(Finding(
            issue="Ошибка DNS проверки",
            severity=Severity.INFO,
            module="DNS (Email)",
            error=str(e)
        ))

    status = "FAIL" if any(f.severity in (Severity.HIGH, Severity.CRITICAL)
                           for f in findings) else "PASS"
    return ModuleResult(status=status, findings=findings)