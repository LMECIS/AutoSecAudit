# checks/tech_stack.py
import requests
import urllib3
import re
from bs4 import BeautifulSoup

urllib3.disable_warnings()

# Сигнатуры технологий
TECH_SIGNATURES = {
    "headers": {
        "X-Powered-By": {
            "PHP": {"name": "PHP", "version_regex": r"PHP/([\d.]+)", "severity": "INFO"},
            "ASP.NET": {"name": "ASP.NET", "version_regex": r"ASP\.NET", "severity": "INFO"},
            "Express": {"name": "Express.js", "version_regex": None, "severity": "INFO"},
        },
        "Server": {
            "nginx": {"name": "Nginx", "version_regex": r"nginx/([\d.]+)", "severity": "INFO"},
            "Apache": {"name": "Apache", "version_regex": r"Apache/([\d.]+)", "severity": "INFO"},
            "Microsoft-IIS": {"name": "IIS", "version_regex": r"IIS/([\d.]+)", "severity": "INFO"},
            "cloudflare": {"name": "Cloudflare", "version_regex": None, "severity": "INFO"},
            "LiteSpeed": {"name": "LiteSpeed", "version_regex": None, "severity": "INFO"},
        },
    },
    "cookies": {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java (Servlet/JSP)",
        "ASP.NET_SessionId": "ASP.NET",
        "csrftoken": "Django",
        "wp-settings": "WordPress",
        "laravel_session": "Laravel",
        "sessionid": "Python (Django/Flask)",
    },
    "meta_generators": {
        "WordPress": "WordPress",
        "Joomla": "Joomla",
        "Drupal": "Drupal",
        "Magento": "Magento",
        "Shopify": "Shopify",
        "Wix": "Wix",
        "MODX": "MODX",
        "Bitrix": "1С-Битрикс",
    }
}

def check_tech_stack(url: str) -> dict:
    """Определяет технологии, используемые сайтом."""
    results = {"status": "PASS", "findings": []}
    detected = set()

    try:
        response = requests.get(
            url,
            timeout=10,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; AutoSecAudit/2.0)"}
        )

        # 1. Анализ заголовков
        for header_name, signatures in TECH_SIGNATURES["headers"].items():
            header_value = response.headers.get(header_name, "")
            if header_value:
                for key, info in signatures.items():
                    if key.lower() in header_value.lower():
                        version = None
                        if info.get("version_regex"):
                            match = re.search(info["version_regex"], header_value)
                            if match:
                                version = match.group(1)

                        tech_id = f"{info['name']}_{version or 'any'}"
                        if tech_id not in detected:
                            detected.add(tech_id)
                            desc = info["name"]
                            if version:
                                desc += f" v{version}"
                            results["findings"].append({
                                "technology": desc,
                                "source": f"Заголовок {header_name}",
                                "issue": f"Обнаружена технология: {desc}",
                                "severity": info["severity"],
                                "info": f"Раскрытие версии может помочь атакующему"
                            })

        # 2. Анализ cookies
        for cookie in response.cookies:
            for pattern, tech_name in TECH_SIGNATURES["cookies"].items():
                if pattern.lower() in cookie.name.lower():
                    if tech_name not in detected:
                        detected.add(tech_name)
                        results["findings"].append({
                            "technology": tech_name,
                            "source": f"Cookie: {cookie.name}",
                            "issue": f"Обнаружена технология: {tech_name}",
                            "severity": "INFO"
                        })

        # 3. Анализ HTML (meta generator)
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            generator = soup.find("meta", attrs={"name": "generator"})
            if generator and generator.get("content"):
                content = generator["content"]
                for pattern, tech_name in TECH_SIGNATURES["meta_generators"].items():
                    if pattern.lower() in content.lower():
                        if tech_name not in detected:
                            detected.add(tech_name)
                            results["findings"].append({
                                "technology": tech_name,
                                "source": f"Meta generator: {content}",
                                "issue": f"Обнаружена CMS: {tech_name}",
                                "severity": "INFO"
                            })

            # Поиск по ссылкам и скриптам
            for link in soup.find_all("link", href=True):
                if "wp-content" in link["href"]:
                    if "WordPress" not in detected:
                        detected.add("WordPress")
                        results["findings"].append({
                            "technology": "WordPress",
                            "source": "Путь wp-content",
                            "issue": "Обнаружена CMS: WordPress",
                            "severity": "INFO"
                        })
        except Exception:
            pass

        # Если ничего не нашли — это тоже информация
        if not results["findings"]:
            results["findings"].append({
                "info": "Технологии не определены (хорошо — сервер не раскрывает информацию)",
                "severity": "INFO"
            })

    except requests.RequestException as e:
        results["status"] = "ERROR"
        results["findings"].append({"error": str(e)})

    return results
