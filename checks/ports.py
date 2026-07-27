# checks/ports.py
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Самые важные порты для веб-безопасности
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet (НЕБЕЗОПАСНО)",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB (часто уязвим)",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis (часто без пароля)",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    9200: "Elasticsearch",
    27017: "MongoDB"
}

def scan_port(hostname: str, port: int, timeout: int = 1) -> dict:
    """Сканирует один порт."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((hostname, port))
        sock.close()
        
        if result == 0:
            return {
                "port": port,
                "service": COMMON_PORTS.get(port, "Unknown"),
                "status": "OPEN"
            }
    except Exception:
        pass
    return None

def check_ports(url: str, top_ports: int = 100) -> dict:
    """Сканирует топ портов на хосте."""
    from urllib.parse import urlparse
    
    results = {"status": "PASS", "findings": []}
    hostname = urlparse(url).hostname or url
    
    # Используем ThreadPoolExecutor для параллельного сканирования
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(scan_port, hostname, port): port 
            for port in COMMON_PORTS.keys()
        }
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                results["findings"].append(result)
                
                # Повышаем severity для опасных сервисов
                if result["port"] in [23, 445, 6379, 27017, 9200]:
                    results["status"] = "FAIL"
                    
    return results
