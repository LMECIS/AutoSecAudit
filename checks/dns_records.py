# checks/dns_records.py
import dns.resolver

def check_email_security(domain: str) -> dict:
    """Проверяет наличие SPF и DMARC записей."""
    results = {"status": "PASS", "findings": []}
    
    # Проверка SPF
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_found = False
        for rdata in answers:
            if 'v=spf1' in rdata.to_text():
                spf_found = True
                break
        if not spf_found:
            results["status"] = "FAIL"
            results["findings"].append({
                "record": "SPF",
                "issue": "SPF запись отсутствует (риск Email Spoofing)",
                "severity": "HIGH"
            })
    except dns.resolver.NoAnswer:
        results["status"] = "FAIL"
        results["findings"].append({"record": "SPF", "issue": "SPF отсутствует", "severity": "HIGH"})
    except Exception as e:
        results["findings"].append({"record": "SPF", "issue": f"Ошибка DNS: {e}"})

    # Проверка DMARC
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_found = any('v=DMARC1' in r.to_text() for r in answers)
        if not dmarc_found:
            results["status"] = "FAIL"
            results["findings"].append({
                "record": "DMARC",
                "issue": "DMARC запись отсутствует",
                "severity": "MEDIUM"
            })
    except dns.resolver.NXDOMAIN:
        results["status"] = "FAIL"
        results["findings"].append({"record": "DMARC", "issue": "DMARC отсутствует", "severity": "MEDIUM"})
    except Exception as e:
        pass # NXDOMAIN или NoAnswer обрабатываются выше
        
    return results
