# reports/html_report.py
from datetime import datetime


def generate_html_report(report: dict, output_path: str) -> str:
    """Генерирует HTML-отчёт из данных аудита."""

    target = report.get("target", "Unknown")
    scan_date = report.get("scan_date", datetime.now().isoformat())
    modules = report.get("modules", {})

    # Подсчёт статистики
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    total_findings = 0

    for module_result in modules.values():
        for finding in module_result.get("findings", []):
            sev = finding.get("severity", "INFO").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            total_findings += 1

    # Оценка общего статуса
    if severity_counts["CRITICAL"] > 0:
        overall_status, overall_label, overall_color = "CRITICAL", "Критическое состояние", "#ff4757"
    elif severity_counts["HIGH"] > 0:
        overall_status, overall_label, overall_color = "HIGH", "Требует внимания", "#ff6348"
    elif severity_counts["MEDIUM"] > 0:
        overall_status, overall_label, overall_color = "MEDIUM", "Есть замечания", "#ffa502"
    elif total_findings > 0:
        overall_status, overall_label, overall_color = "LOW", "Незначительные замечания", "#3742fa"
    else:
        overall_status, overall_label, overall_color = "PASS", "Всё в порядке", "#2ed573"

    # Генерация карточек модулей
    modules_html = ""
    for module_name, module_result in modules.items():
        status = module_result.get("status", "UNKNOWN")
        findings = module_result.get("findings", [])

        status_colors = {"PASS": "#2ed573", "FAIL": "#ff4757", "ERROR": "#ffa502", "UNKNOWN": "#747d8c"}
        status_color = status_colors.get(status, "#747d8c")
        status_icon = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️"}.get(status, "❓")

        findings_rows = ""
        if findings:
            for f in findings:
                sev = f.get("severity", "INFO").upper()
                sev_colors = {
                    "CRITICAL": "#ff4757", "HIGH": "#ff6348",
                    "MEDIUM": "#ffa502", "LOW": "#3742fa", "INFO": "#747d8c"
                }
                sev_color = sev_colors.get(sev, "#747d8c")

                issue = (f.get("issue") or f.get("description") or f.get("info")
                         or f.get("error") or str(f))
                detail = ""
                for key in ["url", "path", "header", "port", "subdomain", "technology", "cookie"]:
                    if f.get(key):
                        detail += f'<br><span class="detail">{key}: {f[key]}</span>'
                if f.get("solution"):
                    detail += f'<br><span class="detail solution">Решение: {f["solution"]}</span>'

                findings_rows += f"""
                <tr>
                    <td><span class="badge" style="background:{sev_color}">{sev}</span></td>
                    <td>{issue}{detail}</td>
                </tr>"""
        else:
            findings_rows = """
                <tr>
                    <td colspan="2" style="text-align:center; color:#2ed573;">
                        Проблем не обнаружено ✅
                    </td>
                </tr>"""

        modules_html += f"""
        <div class="card">
            <div class="card-header">
                <h3>{status_icon} {module_name}</h3>
                <span class="status-badge" style="background:{status_color}">{status}</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width:120px">Уровень</th>
                        <th>Описание</th>
                    </tr>
                </thead>
                <tbody>{findings_rows}</tbody>
            </table>
        </div>"""

    # Сводка
    max_count = max(severity_counts.values()) if max(severity_counts.values()) > 0 else 1
    summary_bars = ""
    bar_colors = {
        "CRITICAL": "#ff4757", "HIGH": "#ff6348",
        "MEDIUM": "#ffa502", "LOW": "#3742fa", "INFO": "#747d8c"
    }
    for sev, count in severity_counts.items():
        width = int((count / max_count) * 100) if count > 0 else 0
        summary_bars += f"""
            <div class="bar-row">
                <span class="bar-label">{sev}</span>
                <div class="bar-track">
                    <div class="bar-fill" style="width:{width}%; background:{bar_colors[sev]}">
                        {count if count > 0 else ''}
                    </div>
                </div>
                <span class="bar-count">{count}</span>
            </div>"""

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoSecAudit — {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0f0f1a; color: #e1e1e6; line-height: 1.6; padding: 20px;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border: 1px solid #2a2a4a; border-radius: 16px;
            padding: 40px; margin-bottom: 30px; text-align: center;
        }}
        .header h1 {{ font-size: 2.2em; color: #fff; margin-bottom: 8px; }}
        .header h1 span {{ color: #2ed573; }}
        .header .meta {{ color: #747d8c; font-size: 0.95em; }}
        .header .meta strong {{ color: #a4b0be; }}
        .overall {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border: 1px solid #2a2a4a; border-radius: 16px;
            padding: 30px 40px; margin-bottom: 30px;
            display: flex; align-items: center; justify-content: space-between;
            flex-wrap: wrap; gap: 20px;
        }}
        .overall-left h2 {{ font-size: 1.4em; color: #fff; margin-bottom: 4px; }}
        .overall-left p {{ color: #747d8c; }}
        .overall-score {{
            font-size: 3em; font-weight: 800; color: {overall_color};
            text-shadow: 0 0 30px {overall_color}44;
        }}
        .summary {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border: 1px solid #2a2a4a; border-radius: 16px;
            padding: 30px 40px; margin-bottom: 30px;
        }}
        .summary h2 {{ color: #fff; margin-bottom: 20px; font-size: 1.3em; }}
        .bar-row {{ display: flex; align-items: center; margin-bottom: 12px; gap: 12px; }}
        .bar-label {{
            width: 80px; font-weight: 600; font-size: 0.85em;
            text-align: right; color: #a4b0be;
        }}
        .bar-track {{
            flex: 1; height: 28px; background: #1e1e36;
            border-radius: 14px; overflow: hidden;
        }}
        .bar-fill {{
            height: 100%; border-radius: 14px;
            display: flex; align-items: center; justify-content: flex-end;
            padding-right: 10px; font-size: 0.8em; font-weight: 700; color: #fff;
            min-width: 30px; transition: width 0.6s ease;
        }}
        .bar-count {{ width: 30px; text-align: left; font-weight: 700; color: #a4b0be; }}
        .card {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border: 1px solid #2a2a4a; border-radius: 16px;
            margin-bottom: 20px; overflow: hidden;
        }}
        .card-header {{
            display: flex; justify-content: space-between; align-items: center;
            padding: 20px 30px; border-bottom: 1px solid #2a2a4a;
        }}
        .card-header h3 {{ color: #fff; font-size: 1.15em; }}
        .status-badge {{
            padding: 4px 14px; border-radius: 20px;
            font-size: 0.8em; font-weight: 700; color: #fff;
            text-transform: uppercase;
        }}
        table {{ width: 100%; border-collapse: collapse; }}
        thead th {{
            background: #12121f; padding: 12px 20px; text-align: left;
            font-size: 0.85em; color: #747d8c; text-transform: uppercase;
        }}
        tbody td {{ padding: 14px 20px; border-top: 1px solid #1e1e36; font-size: 0.95em; }}
        tbody tr:hover {{ background: #1a1a30; }}
        .badge {{
            display: inline-block; padding: 3px 10px; border-radius: 12px;
            font-size: 0.75em; font-weight: 700; color: #fff;
        }}
        .detail {{ color: #747d8c; font-size: 0.85em; }}
        .detail.solution {{ color: #2ed573; }}
        .footer {{
            text-align: center; padding: 30px;
            color: #4a4a6a; font-size: 0.85em;
        }}
        @media (max-width: 700px) {{
            .overall {{ flex-direction: column; text-align: center; }}
            .card-header {{ flex-direction: column; gap: 10px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Auto<span>Sec</span>Audit</h1>
            <p class="meta">
                Цель: <strong>{target}</strong><br>
                Дата сканирования: <strong>{scan_date}</strong>
            </p>
        </div>
        <div class="overall">
            <div class="overall-left">
                <h2>Общая оценка безопасности</h2>
                <p>{overall_label} • Найдено проблем: {total_findings}</p>
            </div>
            <div class="overall-score">{overall_status}</div>
        </div>
        <div class="summary">
            <h2>📊 Сводка по уровням критичности</h2>
            {summary_bars}
        </div>
        <h2 style="color:#fff; margin-bottom:16px; font-size:1.3em;">🔍 Детальные результаты</h2>
        {modules_html}
        <div class="footer">
            Сгенерировано AutoSecAudit v4.0 • {datetime.now().strftime('%d.%m.%Y %H:%M')}
            <br>⚠️ Данный отчёт предназначен только для авторизованного использования.
        </div>
    </div>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    return output_path