# main.py
import argparse
import json
import webbrowser
import os
from datetime import datetime
from urllib.parse import urlparse

from checks.headers import check_headers
from checks.ssl_tls import check_ssl
from checks.dns_records import check_email_security
from checks.cookies import check_cookies
from checks.exposed_files import check_exposed_files
from checks.ports import check_ports
from checks.directory_listing import check_directory_listing
from checks.tech_stack import check_tech_stack
from checks.cors import check_cors
from checks.http_methods import check_http_methods
from checks.subdomains import check_subdomains
from checks.robots_sitemap import check_robots_sitemap
from checks.default_creds import check_default_credentials
from reports.html_report import generate_html_report


def run_audit(target_url: str, enable_subdomains: bool = False, 
              enable_brute: bool = False, auto_open: bool = True):
    print(f"\n{'='*60}")
    print(f"[*] AutoSecAudit v3.0")
    print(f"[*] Цель: {target_url}")
    print(f"[*] Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if enable_brute:
        print(f"[!] ⚠️  ВКЛЮЧЕНА ПРОВЕРКА ДЕФОЛТНЫХ УЧЁТОК (--brute)")
    print(f"{'='*60}\n")

    report = {
        "target": target_url,
        "scan_date": datetime.now().isoformat(),
        "options": {
            "subdomains": enable_subdomains,
            "brute_force": enable_brute
        },
        "modules": {}
    }

    domain = (
        urlparse(target_url).hostname
        or target_url.replace('https://', '').replace('http://', '').split('/')[0]
    )

    # Базовые модули (всегда включены)
    modules = [
        ("🔒 HTTP Заголовки", check_headers, target_url),
        ("🔐 SSL/TLS", check_ssl, target_url),
        ("📧 DNS (Email)", check_email_security, domain),
        ("🍪 Cookie", check_cookies, target_url),
        ("📂 Утечки файлов", check_exposed_files, target_url),
        ("🚪 Открытые порты", check_ports, target_url),
        ("📁 Открытые директории", check_directory_listing, target_url),
        ("🛠️ Технологии", check_tech_stack, target_url),
        ("🌐 CORS", check_cors, target_url),
        ("⚙️ HTTP методы", check_http_methods, target_url),
        ("📜 Robots/Sitemap", check_robots_sitemap, target_url),
    ]

    # Опциональные модули
    if enable_subdomains:
        modules.append(("🌍 Поддомены", check_subdomains, target_url))

    if enable_brute:
        modules.append(("🔑 Дефолтные учётки ⚠️", check_default_credentials, target_url))

    for i, (name, func, arg) in enumerate(modules, 1):
        print(f"[{i:2d}/{len(modules)}] {name}...")
        try:
            result = func(arg)
            # Защита от None
            if result is None:
                result = {
                    "status": "ERROR",
                    "findings": [{"error": "Модуль вернул None"}]
                }
            report["modules"][name] = result
        except Exception as e:
            print(f"        [!] Ошибка: {e}")
            report["modules"][name] = {
                "status": "ERROR",
                "findings": [{"error": str(e)}]
            }

    # --- Консольный вывод ---
    print(f"\n{'='*60}")
    print("[*] РЕЗУЛЬТАТЫ АУДИТА")
    print(f"{'='*60}")

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for module_name, module_result in report["modules"].items():
        # Дополнительная защита
        if module_result is None:
            print(f"\n[!] {module_name}:")
            print(f"    [ERROR] Модуль вернул None")
            continue
        
        findings = module_result.get("findings", [])
        if findings:
            print(f"\n[!] {module_name}:")
            for finding in findings:
                severity = finding.get("severity", finding.get("risk", "INFO")).upper()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                issue = (
                    finding.get("issue") or
                    finding.get("description") or
                    finding.get("name") or
                    finding.get("file") or
                    finding.get("cookie") or
                    finding.get("technology") or
                    finding.get("subdomain") or
                    finding.get("info") or
                    str(finding)
                )
                print(f"    [{severity}] {issue}")

    print(f"\n{'='*60}")
    print("[*] СВОДКА:")
    total = sum(severity_counts.values())
    if total == 0:
        print("    ✅ Проблем не обнаружено")
    else:
        for sev, count in severity_counts.items():
            if count > 0:
                print(f"    {sev}: {count}")
    print(f"{'='*60}\n")

    # --- Сохранение отчётов ---
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_filename = f"audit_report_{domain}_{timestamp}.json"
    with open(json_filename, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    print(f"[+] JSON отчёт: {json_filename}")

    html_filename = f"audit_report_{domain}_{timestamp}.html"
    generate_html_report(report, html_filename)
    print(f"[+] HTML отчёт: {html_filename}")
    
    # --- Автооткрытие HTML в браузере ---
    if auto_open:
        try:
            # Получаем абсолютный путь (webbrowser требует полный путь)
            html_path = os.path.abspath(html_filename)
            print(f"[🌐] Открываю отчёт в браузере...")
            webbrowser.open(f"file://{html_path}")
        except Exception as e:
            print(f"[!] Не удалось открыть браузер: {e}")
            print(f"[!] Откройте файл вручную: {html_filename}")
    
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AutoSecAudit v3.0 — Комплексный аудит безопасности",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ПРИМЕРЫ:
  python main.py https://example.com
      Базовый пассивный аудит (~1 минута)
      HTML отчёт откроется автоматически в браузере

  python main.py https://example.com --no-open
      Аудит без автооткрытия браузера

  python main.py https://example.com --subdomains
      + поиск поддоменов через DNS (~2-3 минуты)

  python main.py https://example.com --brute
      + проверка дефолтных учёток (~5-10 минут)
      ⚠️  ТОЛЬКО для своих ресурсов!

  python main.py https://example.com --subdomains --brute
      Полный аудит со всеми модулями
        """
    )
    parser.add_argument("url", help="URL целевого сайта")
    parser.add_argument(
        "--subdomains",
        action="store_true",
        help="Включить поиск поддоменов через DNS-словарь"
    )
    parser.add_argument(
        "--brute",
        action="store_true",
        help="⚠️  Включить проверку дефолтных учёток (ТОЛЬКО для своих ресурсов!)"
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Не открывать HTML отчёт в браузере автоматически"
    )
    args = parser.parse_args()

    if not args.url.startswith('http'):
        args.url = 'https://' + args.url

    # Предупреждение для --brute
    if args.brute:
        print("\n" + "="*60)
        print("⚠️  ВНИМАНИЕ!")
        print("="*60)
        print("Вы включили проверку дефолтных учётных данных.")
        print("Этот модуль выполняет активные действия и может")
        print("расцениваться как несанкционированный доступ.")
        print()
        print("Используйте ТОЛЬКО на своих ресурсах или при наличии")
        print("явного письменного разрешения владельца.")
        print("="*60 + "\n")

    # Автооткрытие включено по умолчанию, отключается через --no-open
    auto_open = not args.no_open

    run_audit(
        args.url, 
        enable_subdomains=args.subdomains, 
        enable_brute=args.brute,
        auto_open=auto_open
    )