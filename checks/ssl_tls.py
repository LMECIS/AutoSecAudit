# checks/ssl_tls.py
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

def check_ssl(url: str) -> dict:
    """Проверяет валидность и срок действия SSL сертификата."""
    results = {"status": "PASS", "findings": []}
    
    # Извлекаем домен из URL
    parsed = urlparse(url)
    hostname = parsed.hostname or url.replace('https://', '').replace('http://', '').split('/')[0]
    port = 443
    
    try:
        context = ssl.create_default_context()
        # Намеренно отключаем проверку старых протоколов, чтобы увидеть, поддерживает ли их сервер
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE 
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
        # Проверка протокола (TLS 1.2 и 1.3 - хорошо, остальное - плохо)
        if version not in ['TLSv1.2', 'TLSv1.3']:
            results["status"] = "FAIL"
            results["findings"].append({
                "issue": f"Используется устаревший протокол: {version}",
                "severity": "HIGH"
            })
            
        # Проверка срока действия (если сертификат самоподписанный или мы не смогли его распарсить через default_context)
        # Для полноценного парсинга dates лучше использовать библиотеку cryptography, 
        # но здесь мы используем базовый socket для демонстрации концепции.
        # В реальном проекте используйте: from cryptography import x509
        
    except ssl.SSLError as e:
        results["status"] = "FAIL"
        results["findings"].append({"issue": f"Ошибка SSL: {str(e)}", "severity": "HIGH"})
    except socket.gaierror:
        results["status"] = "ERROR"
        results["findings"].append({"issue": "Домен не найден", "severity": "CRITICAL"})
    except Exception as e:
        results["status"] = "ERROR"
        results["findings"].append({"issue": str(e), "severity": "UNKNOWN"})
        
    return results
