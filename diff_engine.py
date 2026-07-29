# diff_engine.py
import json
from models import AuditReport


def load_baseline(filepath: str) -> AuditReport:
    """Загружает предыдущий отчёт из JSON."""
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return AuditReport.from_dict(data)


def compare_reports(baseline: AuditReport, current: AuditReport) -> dict:
    """
    Сравнивает два отчёта и возвращает diff.
    """
    baseline_keys = {f.unique_key(): f for f in baseline.all_findings()}
    current_keys = {f.unique_key(): f for f in current.all_findings()}

    new_findings = []
    fixed_findings = []
    unchanged_findings = []

    for key, finding in current_keys.items():
        if key not in baseline_keys:
            new_findings.append(finding)
        else:
            unchanged_findings.append(finding)

    for key, finding in baseline_keys.items():
        if key not in current_keys:
            fixed_findings.append(finding)

    return {
        "new": new_findings,
        "fixed": fixed_findings,
        "unchanged": unchanged_findings
    }


def print_diff(diff: dict):
    """Красиво выводит diff в консоль."""
    new = diff["new"]
    fixed = diff["fixed"]
    unchanged = diff["unchanged"]

    print(f"\n{'='*60}")
    print("[*] СРАВНЕНИЕ С BASELINE")
    print(f"{'='*60}")

    if new:
        print(f"\n[+] НОВЫЕ НАХОДКИ ({len(new)}):")
        for f in new:
            print(f"    [{f.severity.value}] {f.issue}")

    if fixed:
        print(f"\n[-] ИСПРАВЛЕННЫЕ ({len(fixed)}):")
        for f in fixed:
            print(f"    [{f.severity.value}] {f.issue}")

    if unchanged:
        print(f"\n[=] БЕЗ ИЗМЕНЕНИЙ ({len(unchanged)})")

    print(f"\n{'='*60}")
    print(f"Итого: +{len(new)} новых, -{len(fixed)} исправлено, "
          f"={len(unchanged)} без изменений")
    print(f"{'='*60}\n")


def should_fail_ci(diff: dict, fail_on_new: bool = True) -> bool:
    """
    Определяет, должен ли CI упасть.
    """
    if fail_on_new:
        return len(diff["new"]) > 0
    else:
        return len(diff["new"]) + len(diff["unchanged"]) > 0