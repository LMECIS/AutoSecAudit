# checks/ssl_tls.py
import ssl
import socket
import asyncio
import httpx
from urllib.parse import urlparse
from models import Finding, ModuleResult, Severity


def _check_ssl_sync(hostname: str, port: int = 443) -> dict:
    """Синхронная проверка SSL (запускается в thread)."""
    result = {"version": None, "error": None}

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["version"] = ssock.version()
    except Exception as e:
        result["error"] = str(e)

    return result


async def check_ssl(client: httpx.AsyncClient, url: str) -> ModuleResult:
    """Проверяет валидность и срок действия SSL сертификата."""
    findings = []

    parsed = urlparse(url)
    hostname = parsed.hostname or url.replace('https://', '').replace('http://', '').split('/')[0]

    try:
        result = await asyncio.to_thread(_check_ssl_sync, hostname)

        if result["error"]:
            findings.append(Finding(
                issue="Ошибка SSL проверки",
                severity=Severity.HIGH,
                module="SSL/TLS",
                error=result["error"]
            ))
        elif result["version"] and result["version"] not in ['TLSv1.2', 'TLSv1.3']:
            findings.append(Finding(
                issue=f"Используется устаревший протокол: {result['version']}",
                severity=Severity.HIGH,
                module="SSL/TLS"
            ))
        elif result["version"]:
            findings.append(Finding(
                info=f"Используется протокол: {result['version']}",
                issue=f"Протокол: {result['version']}",
                severity=Severity.INFO,
                module="SSL/TLS"
            ))

    except Exception as e:
        findings.append(Finding(
            issue="Ошибка SSL проверки",
            severity=Severity.HIGH,
            module="SSL/TLS",
            error=str(e)
        ))

    status = "FAIL" if any(f.severity in (Severity.HIGH, Severity.CRITICAL)
                           for f in findings) else "PASS"
    return ModuleResult(status=status, findings=findings)