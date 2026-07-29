# checks/tech_stack.py
import re
import httpx
from models import Finding, ModuleResult, Severity


TECH_SIGNATURES = {
    "headers": {
        "X-Powered-By": {
            "PHP": {"name": "PHP", "version_regex": r"PHP/([\d.]+)"},
            "ASP.NET": {"name": "ASP.NET", "version_regex": r"ASP\.NET(?:\s+([\d.]+))?"},
            "Express": {"name": "Express.js", "version_regex": None},
        },
        "Server": {
            "nginx": {"name": "Nginx", "version_regex": r"nginx/([\d.]+)"},
            "Apache": {"name": "Apache", "version_regex": r"Apache/([\d.]+)"},
            "Microsoft-IIS": {"name": "IIS", "version_regex": r"IIS/([\d.]+)"},
            "cloudflare": {"name": "Cloudflare", "version_regex": None},
            "LiteSpeed": {"name": "LiteSpeed", "version_regex": None},
        },
    },
    "cookies": {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java (Servlet/JSP)",
        "ASP.NET_SessionId": "ASP.NET",
        "csrftoken": "Django",
        "wp-settings": "WordPress",
        "laravel_session": "Laravel",
    }
}


async def check_tech_stack(client: httpx.AsyncClient, url: str) -> ModuleResult:
    """Определяет технологии, используемые сайтом, и флагует раскрытие версий."""
    findings = []
    detected = set()

    try:
        response = await client.get(url, follow_redirects=True)

        # 1. Анализ заголовков
        for header_name, signatures in TECH_SIGNATURES["headers"].items():
            header_value = response.headers.get(header_name, "")
            if header_value:
                for key, info in signatures.items():
                    if key.lower() in header_value.lower():
                        version = None
                        if info.get("version_regex"):
                            match = re.search(info["version_regex"], header_value, re.IGNORECASE)
                            if match:
                                version = match.group(1)

                        tech_id = f"{info['name']}_{version or 'any'}"
                        if tech_id not in detected:
                            detected.add(tech_id)
                            desc = info["name"] + (f" v{version}" if version else "")
                            
                            # 🔴 КЛЮЧЕВОЕ ИЗМЕНЕНИЕ: Если есть версия - это MEDIUM (FAIL)
                            if version:
                                findings.append(Finding(
                                    issue=f"Раскрытие версии ПО: {desc}",
                                    severity=Severity.MEDIUM,
                                    module="Технологии",
                                    technology=desc,
                                    description=f"Сервер раскрывает точную версию через заголовок {header_name}",
                                    solution="Скройте версию в конфигурации: server_tokens off; (Nginx) или expose_php = Off (PHP)"
                                ))
                            else:
                                findings.append(Finding(
                                    issue=f"Обнаружена технология: {desc}",
                                    severity=Severity.INFO,
                                    module="Технологии",
                                    technology=desc,
                                    description=f"Источник: заголовок {header_name}"
                                ))

        # 2. Анализ cookies
        for cookie in response.cookies:
            for pattern, tech_name in TECH_SIGNATURES["cookies"].items():
                if pattern.lower() in cookie.name.lower():
                    if tech_name not in detected:
                        detected.add(tech_name)
                        findings.append(Finding(
                            issue=f"Обнаружена технология: {tech_name}",
                            severity=Severity.INFO,
                            module="Технологии",
                            technology=tech_name,
                            description=f"Источник: cookie {cookie.name}"
                        ))

        # 3. Анализ HTML (meta generator)
        if "<meta" in response.text.lower():
            match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                              response.text, re.IGNORECASE)
            if match:
                generator = match.group(1)
                # Для CMS раскрытие названия обычно INFO, но если там есть версия - можно повысить
                findings.append(Finding(
                    issue=f"Обнаружена CMS: {generator}",
                    severity=Severity.INFO,
                    module="Технологии",
                    technology=generator,
                    description="Источник: meta generator"
                ))

        # Если вообще ничего не нашли - это хорошо (сервер скрытен)
        if not findings:
            findings.append(Finding(
                info="Технологии не определены",
                issue="Сервер не раскрывает информацию о стеке (хорошо)",
                severity=Severity.INFO,
                module="Технологии"
            ))

    except Exception as e:
        findings.append(Finding(
            issue="Ошибка определения технологий",
            severity=Severity.INFO,
            module="Технологии",
            error=str(e)
        ))

    # 🔴 ДИНАМИЧЕСКИЙ СТАТУС: Если есть хотя бы одна находка MEDIUM или выше → FAIL
    has_issues = any(f.severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM) for f in findings)
    status = "FAIL" if has_issues else "PASS"
    
    return ModuleResult(status=status, findings=findings)