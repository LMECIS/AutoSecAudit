import requests
import urllib3

urllib3.disable_warnings()

def check_cors(url: str) -> dict:
    """Проверяет конфигурацию CORS на уязвимости."""
    results = {"status": "PASS", "findings": []}

    test_origins = [
        ("https://evil.com", "Произвольный домен"),
        ("https://example.evil.com", "Поддомен злоумышленника"),
        ("null", "Null origin (sandbox/iframes)"),
    ]

    try:
        for origin, description in test_origins:
            headers = {
                "Origin": origin,
                "User-Agent": "Mozilla/5.0 (compatible; AutoSecAudit/2.0)"
            }
            response = requests.get(
                url,
                timeout=10,
                verify=False,
                allow_redirects=True,
                headers=headers
            )

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*" and acac.lower() == "true":
                results["status"] = "FAIL"
                results["findings"].append({
                    "issue": "CORS: Wildcard (*) с credentials=true",
                    "description": "Сервер разрешает запросы с любого домена вместе с cookies",
                    "severity": "HIGH",
                    "origin": origin,
                    "solution": "Убрать credentials или явно указать разрешённые домены"
                })

            if acao == origin and origin != "null":
                results["status"] = "FAIL"
                results["findings"].append({
                    "issue": f"CORS: Сервер отражает Origin ({description})",
                    "description": f"Сервер разрешает запросы от {origin}",
                    "severity": "HIGH",
                    "origin": origin,
                    "solution": "Использовать whitelist разрешённых доменов"
                })

            if acao == "null" and acac.lower() == "true":
                results["status"] = "FAIL"
                results["findings"].append({
                    "issue": "CORS: Разрешён null origin с credentials",
                    "description": "Уязвимо к атакам через sandboxed iframes",
                    "severity": "MEDIUM",
                    "origin": origin,
                    "solution": "Запретить null origin или убрать credentials"
                })

        try:
            options_resp = requests.options(
                url,
                timeout=10,
                verify=False,
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Content-Type"
                }
            )
            methods = options_resp.headers.get("Access-Control-Allow-Methods", "")
            if "DELETE" in methods or "PUT" in methods or "PATCH" in methods:
                results["findings"].append({
                    "issue": f"CORS: Разрешены опасные методы ({methods})",
                    "description": "Атакующий может выполнять модифицирующие запросы",
                    "severity": "MEDIUM",
                    "solution": "Ограничить методы до необходимых (GET, POST)"
                })
        except requests.RequestException:
            pass

    except requests.RequestException as e:
        results["status"] = "ERROR"
        results["findings"].append({"error": str(e)})

    return results
