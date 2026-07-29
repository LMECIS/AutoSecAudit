# main.py
import argparse
import asyncio
import json
import webbrowser
import os
import sys
from datetime import datetime
from urllib.parse import urlparse
import httpx

from models import AuditReport, Finding, Severity, ModuleResult
from plugin_loader import discover_plugins
from diff_engine import load_baseline, compare_reports, print_diff, should_fail_ci
from reports.html_report import generate_html_report


async def run_single_module(client: httpx.AsyncClient, name: str, func, url: str):
    """Запускает один модуль с обработкой ошибок."""
    try:
        result = await func(client, url)
        # Обновляем имя модуля во всех findings
        for f in result.findings:
            if hasattr(f, "module") and not f.module:
                f.module = name
        return name, result
    except Exception as e:
        error_finding = Finding(
            issue=f"Ошибка выполнения модуля",
            severity=Severity.INFO,
            module=name,
            error=str(e)
        )
        return name, ModuleResult(status="ERROR", findings=[error_finding])


async def run_audit(target_url: str, enable_subdomains: bool = False,
                    enable_brute: bool = False) -> AuditReport:
    """Запускает все модули параллельно."""
    print(f"\n{'='*60}")
    print(f"[*] AutoSecAudit v4.0 (async)")
    print(f"[*] Цель: {target_url}")
    print(f"[*] Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if enable_brute:
        print(f"[!] ⚠️  ВКЛЮЧЕНА ПРОВЕРКА ДЕФОЛТНЫХ УЧЁТОК (--brute)")
    print(f"{'='*60}\n")

    # Загружаем плагины
    all_plugins = discover_plugins()

    # Фильтруем опциональные модули
    plugins_to_run = {}
    for name, func in all_plugins.items():
        if "Subdomain" in name and not enable_subdomains:
            continue
        if "Default" in name and "Cred" in name and not enable_brute:
            continue
        plugins_to_run[name] = func

    print(f"[*] Загружено плагинов: {len(plugins_to_run)}")
    print(f"[*] Запуск параллельного сканирования...\n")

    async with httpx.AsyncClient(
        verify=False,
        timeout=15.0,
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        headers={"User-Agent": "Mozilla/5.0 (compatible; AutoSecAudit/4.0)"}
    ) as client:
        tasks = [
            run_single_module(client, name, func, target_url)
            for name, func in plugins_to_run.items()
        ]
        results = await asyncio.gather(*tasks)

    report = AuditReport(
        target=target_url,
        scan_date=datetime.now().isoformat(),
        options={
            "subdomains": enable_subdomains,
            "brute_force": enable_brute
        }
    )

    for name, result in results:
        report.modules[name] = result
        status_icon = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️"}.get(result.status, "❓")
        print(f"    {status_icon} {name}: {len(result.findings)} находок")

    return report


def print_summary(report: AuditReport):
    """Выводит сводку в консоль."""
    print(f"\n{'='*60}")
    print("[*] РЕЗУЛЬТАТЫ АУДИТА")
    print(f"{'='*60}")

    severity_counts = {s: 0 for s in Severity}

    for module_name, module_result in report.modules.items():
        if module_result.findings:
            print(f"\n[!] {module_name}:")
            for finding in module_result.findings:
                severity_counts[finding.severity] += 1
                print(f"    [{finding.severity.value}] {finding.issue}")

    print(f"\n{'='*60}")
    print("[*] СВОДКА:")
    total = sum(severity_counts.values())
    if total == 0:
        print("    ✅ Проблем не обнаружено")
    else:
        for sev, count in severity_counts.items():
            if count > 0:
                print(f"    {sev.value}: {count}")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="AutoSecAudit v4.0 — Async аудит безопасности с плагинами",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ПРИМЕРЫ:
  python main.py https://example.com
      Базовый async аудит (~40 секунд)

  python main.py https://example.com --baseline prev.json
      Сравнение с предыдущим сканом (CI режим)

  python main.py https://example.com --subdomains --brute
      Полный аудит со всеми модулями
        """
    )
    parser.add_argument("url", help="URL целевого сайта")
    parser.add_argument("--subdomains", action="store_true",
                        help="Включить поиск поддоменов")
    parser.add_argument("--brute", action="store_true",
                        help="⚠️  Проверка дефолтных учёток (ТОЛЬКО для своих!)")
    parser.add_argument("--baseline",
                        help="Путь к предыдущему отчёту для сравнения (CI)")
    parser.add_argument("--no-open", action="store_true",
                        help="Не открывать HTML отчёт")
    args = parser.parse_args()

    if not args.url.startswith('http'):
        args.url = 'https://' + args.url

    if args.brute:
        print("\n" + "="*60)
        print("⚠️  ВНИМАНИЕ: Активная проверка учётных данных!")
        print("Используйте ТОЛЬКО на своих ресурсах.")
        print("="*60 + "\n")

    # Запускаем async аудит
    report = asyncio.run(run_audit(
        args.url,
        enable_subdomains=args.subdomains,
        enable_brute=args.brute
    ))

    # Выводим результаты
    print_summary(report)

    # Diff-режим
    if args.baseline:
        try:
            baseline = load_baseline(args.baseline)
            diff = compare_reports(baseline, report)
            print_diff(diff)

            domain = urlparse(args.url).hostname
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            diff_filename = f"diff_report_{domain}_{timestamp}.json"
            with open(diff_filename, 'w', encoding='utf-8') as f:
                json.dump({
                    "new": [f.to_dict() for f in diff["new"]],
                    "fixed": [f.to_dict() for f in diff["fixed"]],
                    "unchanged_count": len(diff["unchanged"])
                }, f, indent=4, ensure_ascii=False)
            print(f"[+] Diff отчёт: {diff_filename}")

            if should_fail_ci(diff, fail_on_new=True):
                print(f"\n[!] CI FAIL: Обнаружены новые уязвимости")
                # Сохраняем отчёты перед выходом
                _save_reports(report, args.url, args.no_open)
                sys.exit(1)
            else:
                print(f"\n[✅] CI PASS: Новых уязвимостей не обнаружено")
        except Exception as e:
            print(f"[!] Ошибка загрузки baseline: {e}")
            sys.exit(1)

    # Сохраняем отчёты
    _save_reports(report, args.url, args.no_open)


def _save_reports(report: AuditReport, url: str, no_open: bool):
    """Сохраняет JSON и HTML отчёты."""
    domain = urlparse(url).hostname
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    json_filename = f"audit_report_{domain}_{timestamp}.json"
    with open(json_filename, 'w', encoding='utf-8') as f:
        json.dump(report.to_dict(), f, indent=4, ensure_ascii=False)
    print(f"[+] JSON отчёт: {json_filename}")

    html_filename = f"audit_report_{domain}_{timestamp}.html"
    generate_html_report(report.to_dict(), html_filename)
    print(f"[+] HTML отчёт: {html_filename}")

    if not no_open:
        try:
            html_path = os.path.abspath(html_filename)
            print(f"[🌐] Открываю отчёт в браузере...")
            webbrowser.open(f"file://{html_path}")
        except Exception as e:
            print(f"[!] Не удалось открыть браузер: {e}")

    print()


if __name__ == "__main__":
    main()