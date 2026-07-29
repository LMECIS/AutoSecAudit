# checks/http_methods.py
import httpx
from models import Finding, ModuleResult, Severity


HTTP_METHODS = {
    "OPTIONS": {"risk": Severity.INFO, "description": "Информационный метод"},
    "GET": {"risk": Severity.INFO, "description": "Стандартный метод чтения"},
    "HEAD": {"risk": Severity.INFO, "description": "Получение заголовков"},
    "POST": {"risk": Severity.INFO, "description": "Стандартный метод отправки"},
    "PUT": {"risk": Severity.HIGH, "description": "Загрузка/замена файлов"},
    "DELETE": {"risk": Severity.HIGH, "description": "Удаление ресурсов"},
    "PATCH": {"risk": Severity.MEDIUM, "description": "Частичное изменение"},
    "TRACE": {"risk": Severity.HIGH, "description": "Уязвим к XST-атакам"},
    "CONNECT": {"risk": Severity.MEDIUM, "description": "Прокси-туннели"},
}


async def check_http_methods(client: httpx.AsyncClient, url: str) -> ModuleResult:
    """Проверяет доступные HTTP методы."""
    findings = []

    try:
        response = await client.request("OPTIONS", url, follow_redirects=True)
        allow_header = response.headers.get("Allow", "")

        if allow_header:
            methods = [m.strip().upper() for m in allow_header.split(",")]
        else:
            methods = []

        for method in methods:
            if method in HTTP_METHODS:
                info = HTTP_METHODS[method]
                if info["risk"] in [Severity.HIGH, Severity.MEDIUM]:
                    findings.append(Finding(
                        issue=f"Доступен опасный HTTP метод: {method}",
                        severity=info["risk"],
                        module="HTTP методы",
                        method=method,
                        description=info["description"],
                        solution=f"Отключить метод {method} в конфигурации сервера"
                    ))
                else:
                    findings.append(Finding(
                        issue=f"Доступен метод: {method}",
                        severity=Severity.INFO,
                        module="HTTP методы",
                        method=method
                    ))

        # Проверка TRACE
        try:
            trace_resp = await client.request(
                "TRACE", url,
                headers={"User-Agent": "AutoSecAudit-TRACE-TEST"}
            )
            if trace_resp.status_code == 200 and "AutoSecAudit-TRACE-TEST" in trace_resp.text:
                findings.append(Finding(
                    issue="TRACE метод активен и возвращает заголовки (XST)",
                    severity=Severity.HIGH,
                    module="HTTP методы",
                    method="TRACE",
                    solution="Отключить TRACE: TraceEnable Off (Apache)"
                ))
        except Exception:
            pass

        if not findings:
            findings.append(Finding(
                info="HTTP методы не определены",
                issue="Методы не раскрыты",
                severity=Severity.INFO,
                module="HTTP методы"
            ))

    except Exception as e:
        findings.append(Finding(
            issue="Ошибка проверки HTTP методов",
            severity=Severity.INFO,
            module="HTTP методы",
            error=str(e)
        ))

    status = "FAIL" if any(f.severity in (Severity.HIGH, Severity.CRITICAL)
                           for f in findings) else "PASS"
    return ModuleResult(status=status, findings=findings)