# checks/http_methods.py
import requests
import urllib3

urllib3.disable_warnings()

# HTTP методы и их оценка риска
HTTP_METHODS = {
    "OPTIONS": {"risk": "INFO", "description": "Информационный метод"},
    "GET": {"risk": "INFO", "description": "Стандартный метод чтения"},
    "HEAD": {"risk": "INFO", "description": "Получение только заголовков"},
    "POST": {"risk": "INFO", "description": "Стандартный метод отправки"},
    "PUT": {"risk": "HIGH", "description": "Загрузка/замена файлов — риск несанкционированной записи"},
    "DELETE": {"risk": "HIGH", "description": "Удаление ресурсов — риск потери данных"},
    "PATCH": {"risk": "MEDIUM", "description": "Частичное изменение ресурсов"},
    "TRACE": {"risk": "HIGH", "description": "Уязвим к XST-атакам (Cross-Site Tracing)"},
    "CONNECT": {"risk": "MEDIUM", "description": "Используется для прокси-туннелей"},
}

def check_http_methods(url: str) -> dict:
    """Проверяет доступные HTTP методы."""
    results = {"status": "PASS", "findings": []}

    try:
        # Сначала пробуем OPTIONS
        response = requests.options(
            url,
            timeout=10,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; AutoSecAudit/2.0)"}
        )

        # Парсим Allow заголовок
        allow_header = response.headers.get("Allow", "")
        if allow_header:
            methods = [m.strip().upper() for m in allow_header.split(",")]
        else:
            # Если Allow нет — пробуем каждый метод вручную
            methods = []
            for method in HTTP_METHODS.keys():
                try:
                    r = requests.request(
                        method, url,
                        timeout=5,
                        verify=False,
                        allow_redirects=False
                    )
                    # 405 = метод не разрешён, всё остальное — возможно разрешён
                    if r.status_code != 405:
                        methods.append(method)
                except requests.RequestException:
                    continue

        # Анализируем найденные методы
        for method in methods:
            if method in HTTP_METHODS:
                info = HTTP_METHODS[method]
                if info["risk"] in ["HIGH", "MEDIUM"]:
                    results["status"] = "FAIL"
                    results["findings"].append({
                        "method": method,
                        "issue": f"Доступен опасный HTTP метод: {method}",
                        "description": info["description"],
                        "severity": info["risk"],
                        "solution": f"Отключить метод {method} в конфигурации сервера"
                    })
                else:
                    results["findings"].append({
                        "method": method,
                        "issue": f"Доступен метод: {method}",
                        "description": info["description"],
                        "severity": "INFO"
                    })

        # Специальная проверка TRACE
        try:
            trace_resp = requests.request(
                "TRACE", url,
                timeout=5,
                verify=False,
                headers={"User-Agent": "AutoSecAudit-TRACE-TEST"}
            )
            if trace_resp.status_code == 200 and "AutoSecAudit-TRACE-TEST" in trace_resp.text:
                results["status"] = "FAIL"
                results["findings"].append({
                    "method": "TRACE",
                    "issue": "TRACE метод активен и возвращает заголовки",
                    "description": "Сервер уязвим к XST-атакам (кража cookie через XSS+TRACE)",
                    "severity": "HIGH",
                    "solution": "Отключить TRACE: TraceEnable Off (Apache)"
                })
        except requests.RequestException:
            pass

        if not results["findings"]:
            results["findings"].append({
                "info": "HTTP методы не определены",
                "severity": "INFO"
            })

    except requests.RequestException as e:
        results["status"] = "ERROR"
        results["findings"].append({"error": str(e)})

    return results
