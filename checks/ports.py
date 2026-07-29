# checks/ports.py
import asyncio
import socket
import httpx
from urllib.parse import urlparse
from models import Finding, ModuleResult, Severity


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP Proxy", 8443: "HTTPS Alt",
    9200: "Elasticsearch", 27017: "MongoDB"
}

DANGEROUS_PORTS = {23, 445, 6379, 27017, 9200}


async def _scan_port_async(hostname: str, port: int, timeout: float = 2.0) -> bool:
    """Асинхронная проверка одного порта."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def check_ports(client: httpx.AsyncClient, url: str) -> ModuleResult:
    """Сканирует топ портов на хосте."""
    findings = []

    parsed = urlparse(url)
    hostname = parsed.hostname or url.replace('https://', '').replace('http://', '').split('/')[0]

    try:
        # Параллельное сканирование всех портов
        tasks = [_scan_port_async(hostname, port) for port in COMMON_PORTS.keys()]
        results = await asyncio.gather(*tasks)

        for port, is_open in zip(COMMON_PORTS.keys(), results):
            if is_open:
                service = COMMON_PORTS[port]
                severity = Severity.HIGH if port in DANGEROUS_PORTS else Severity.INFO
                findings.append(Finding(
                    issue=f"Открыт порт {port} ({service})",
                    severity=severity,
                    module="Открытые порты",
                    port=port,
                    service=service
                ))

    except Exception as e:
        findings.append(Finding(
            issue="Ошибка сканирования портов",
            severity=Severity.INFO,
            module="Открытые порты",
            error=str(e)
        ))

    status = "FAIL" if any(f.severity == Severity.HIGH for f in findings) else "PASS"
    return ModuleResult(status=status, findings=findings)