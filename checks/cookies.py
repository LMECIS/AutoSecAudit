# checks/cookies.py
import httpx
from models import Finding, ModuleResult, Severity


async def check_cookies(client: httpx.AsyncClient, url: str) -> ModuleResult:
    """Проверяет атрибуты безопасности Cookie через заголовки Set-Cookie."""
    findings = []

    try:
        response = await client.get(url, follow_redirects=True)
        
        # httpx позволяет получить список всех заголовков Set-Cookie
        set_cookie_headers = response.headers.get_list("set-cookie")
        
        if not set_cookie_headers:
            findings.append(Finding(
                issue="Cookie не используются",
                severity=Severity.INFO,
                module="Cookie",
                info="Заголовки Set-Cookie отсутствуют"
            ))
            return ModuleResult(status="PASS", findings=findings)

        for header_value in set_cookie_headers:
            header_lower = header_value.lower()
            
            # Извлекаем имя cookie (всё до первого знака '=')
            cookie_name = header_value.split('=')[0].strip()
            
            issues = []
            
            # 1. Проверка флага Secure (обязателен для HTTPS)
            if url.startswith('https://') and 'secure' not in header_lower:
                issues.append("отсутствует флаг Secure")
                
            # 2. Проверка флага HttpOnly (защита от XSS-кражи cookie)
            if 'httponly' not in header_lower:
                issues.append("отсутствует флаг HttpOnly")
                
            # 3. Проверка флага SameSite (защита от CSRF)
            if 'samesite' not in header_lower:
                issues.append("отсутствует флаг SameSite")
                
            # Если найдены проблемы, добавляем их в отчёт
            if issues:
                findings.append(Finding(
                    issue=f"Небезопасная конфигурация Cookie: '{cookie_name}'",
                    severity=Severity.MEDIUM,
                    module="Cookie",
                    cookie=cookie_name,
                    description=f"Обнаруженные проблемы: {', '.join(issues)}",
                    solution="Настройте сервер на отправку cookie с флагами Secure, HttpOnly и SameSite=Strict (или Lax)."
                ))

    except Exception as e:
        findings.append(Finding(
            issue="Ошибка при проверке Cookie",
            severity=Severity.INFO,
            module="Cookie",
            error=str(e)
        ))

    # Если есть хотя бы одна MEDIUM находка, статус модуля = FAIL
    has_issues = any(f.severity == Severity.MEDIUM for f in findings)
    status = "FAIL" if has_issues else "PASS"
    
    return ModuleResult(status=status, findings=findings)