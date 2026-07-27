# checks/headers.py
import requests
import urllib3

# Отключаем предупреждения о небезопасных соединениях для целей аудита
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUIRED_HEADERS = {
    'Strict-Transport-Security': {
        'description': 'HSTS (защита от SSL-stripping атак)',
        'severity': 'HIGH'
    },
    'Content-Security-Policy': {
        'description': 'CSP (защита от XSS и инъекций)',
        'severity': 'HIGH'
    },
    'X-Content-Type-Options': {
        'description': 'Запрет MIME-sniffing',
        'severity': 'MEDIUM'
    },
    'X-Frame-Options': {
        'description': 'Защита от Clickjacking',
        'severity': 'MEDIUM'
    },
    'Referrer-Policy': {
        'description': 'Контроль утечки Referer',
        'severity': 'LOW'
    }
}

def check_headers(url: str) -> dict:
    """Проверяет наличие и качество HTTP заголовков безопасности."""
    results = {"status": "PASS", "findings": []}
    
    try:
        # allow_redirects=True важен, чтобы проверить заголовки после редиректа на HTTPS
        response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        
        for header, info in REQUIRED_HEADERS.items():
            if header not in response.headers:
                results["status"] = "FAIL"
                results["findings"].append({
                    "header": header,
                    "issue": f"Заголовок отсутствует",
                    "description": info['description'],
                    "severity": info['severity']
                })
            else:
                # Дополнительная логика для проверки качества заголовка (опционально)
                if header == 'Strict-Transport-Security' and 'includeSubDomains' not in response.headers[header]:
                    results["findings"].append({
                        "header": header,
                        "issue": "Отсутствует директива includeSubDomains",
                        "severity": "LOW"
                    })
                    
    except requests.RequestException as e:
        results["status"] = "ERROR"
        results["findings"].append({"error": str(e)})
        
    return results
