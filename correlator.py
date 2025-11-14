import re
def normalize(raw):
    sev = "low"
    mitre = []

    if "failed password" in raw.lower():
        sev = "medium"
        mitre.append("T1110 Brute Force")

    if "deny" in raw.lower() or "blocked" in raw.lower():
        sev = "medium"
        mitre.append("T1046 Network Scan")

    if "unauthorized" in raw.lower() or "403" in raw:
        sev = "high"
        mitre.append("T1190 Exploit Public-Facing App")

    if "exploit" in raw.lower() or "cve" in raw.lower():
        sev = "critical"
        mitre.append("TA0001 Initial Access")

    ip = re.findall(r"\d+\.\d+\.\d+\.\d+", raw)
    src_ip = ip[0] if ip else None

    return {
        "raw": raw,
        "severity": sev,
        "mitre": mitre,
        "src_ip": src_ip
    }
