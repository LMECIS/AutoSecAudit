# checks/headers.py
import httpx
from models import Finding, ModuleResult, Severity


REQUIRED_HEADERS = {
    'Strict-Transport-Security': {
        'description': 'HSTS (защита от SSL-stripping атак)',
        'severity': Severity.HIGH
    },
    'Content-Security-Policy': {
        'description': 'CSP (защита от XSS и инъекций)',
        'severity': Severity.HIGH
    },
    'X-Content-Type-Options': {
        'description': 'Запрет MIME-sniffing',
        'severity': Severity.MEDIUM
    },
    'X-Frame-Options': {
        'description': 'Защита от Clickjacking',
        'severity': Severity.MEDIUM
    },
    'Referrer-Policy': {
        'description': 'Контроль утечки Referer',
        'severity': Severity.LOW
    }
}


async def check_headers(client: httpx.AsyncClient, url: str) -> ModuleResult:
    """Проверяет наличие и качество HTTP заголовков безопасности."""
    findings = []

    try:
        response = await client.get(url, follow_redirects=True)

        for header, info in REQUIRED_HEADERS.items():
            if header not in response.headers:
                findings.append(Finding(
                    issue=f"Заголовок отсутствует: {header}",
                    severity=info['severity'],
                    module="HTTP Заголовки",
                    description=info['description'],
                    header=header
                ))
            else:
                if header == 'Strict-Transport-Security':
                    value = response.headers[header]
                    if 'includeSubDomains' not in value:
                        findings.append(Finding(
                            issue="HSTS: отсутствует директива includeSubDomains",
                            severity=Severity.LOW,
                            module="HTTP Заголовки",
                            header=header
                        ))

    except Exception as e:
        findings.append(Finding(
            issue="Ошибка проверки заголовков",
            severity=Severity.INFO,
            module="HTTP Заголовки",
            error=str(e)
        ))

    status = "FAIL" if findings else "PASS"
    return ModuleResult(status=status, findings=findings)