# checks/cors.py
import httpx
from models import Finding, ModuleResult, Severity


async def check_cors(client: httpx.AsyncClient, url: str) -> ModuleResult:
    """Проверяет конфигурацию CORS на уязвимости."""
    findings = []

    test_origins = [
        ("https://evil.com", "Произвольный домен"),
        ("https://example.evil.com", "Поддомен злоумышленника"),
        ("null", "Null origin"),
    ]

    try:
        for origin, description in test_origins:
            headers = {"Origin": origin}
            response = await client.get(url, follow_redirects=True, headers=headers)

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*" and acac.lower() == "true":
                findings.append(Finding(
                    issue="CORS: Wildcard (*) с credentials=true",
                    severity=Severity.HIGH,
                    module="CORS",
                    description="Сервер разрешает запросы с любого домена с cookies",
                    origin=origin,
                    solution="Убрать credentials или явно указать домены"
                ))

            if acao == origin and origin != "null":
                findings.append(Finding(
                    issue=f"CORS: Сервер отражает Origin ({description})",
                    severity=Severity.HIGH,
                    module="CORS",
                    origin=origin,
                    solution="Использовать whitelist разрешённых доменов"
                ))

            if acao == "null" and acac.lower() == "true":
                findings.append(Finding(
                    issue="CORS: Разрешён null origin с credentials",
                    severity=Severity.MEDIUM,
                    module="CORS",
                    origin=origin,
                    solution="Запретить null origin"
                ))

    except Exception as e:
        findings.append(Finding(
            issue="Ошибка проверки CORS",
            severity=Severity.INFO,
            module="CORS",
            error=str(e)
        ))

    status = "FAIL" if findings else "PASS"
    return ModuleResult(status=status, findings=findings)