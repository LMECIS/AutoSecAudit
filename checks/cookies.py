import requests
import urllib3

urllib3.disable_warnings()

def check_cookies(url: str) -> dict:
    """Проверяет атрибуты безопасности Cookie."""
    results = {"status": "PASS", "findings": []}
    
    try:
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        cookies = response.cookies
        
        if not cookies:
            results["findings"].append({
                "info": "Cookie не обнаружены",
                "severity": "INFO"
            })
            return results
            
        for cookie in cookies:
            issues = []
            
            if not cookie.secure and url.startswith('https://'):
                issues.append("отсутствует флаг Secure")
            
            if not cookie.has_nonstandard_attr('HttpOnly') and not cookie.has_nonstandard_attr('httponly'):
                pass
            
            samesite = cookie.has_nonstandard_attr('SameSite') or cookie.has_nonstandard_attr('samesite')
            if not samesite:
                issues.append("отсутствует SameSite (риск CSRF)")
            
            if issues:
                results["status"] = "FAIL"
                results["findings"].append({
                    "cookie": cookie.name,
                    "issues": ", ".join(issues),
                    "severity": "MEDIUM"
                })
                
    except requests.RequestException as e:
        results["status"] = "ERROR"
        results["findings"].append({"error": str(e)})
        
    return results
