import re
import json
import pandas as pd

def detect_log_type(log):
    if "DROP" in log or "ACCEPT" in log:
        return "firewall"
    if "Failed password" in log:
        return "auth"
    if "DNS" in log:
        return "dns"
    if "GET" in log or "POST" in log:
        return "proxy"
    return "unknown"

def normalize(log):
    log_type = detect_log_type(log)
    data = {"raw": log, "type": log_type}

    if log_type == "firewall":
        m = re.findall(r"SRC=([\d\.]+)|DST=([\d\.]+)|PROTO=(\w+)", log)
        data.update({
            "src_ip": m[0][0] if m else None,
            "dst_ip": m[1][1] if len(m) > 1 else None,
            "protocol": m[2][2] if len(m) > 2 else None
        })

    elif log_type == "auth":
        m = re.search(r"from ([\d\.]+)", log)
        data["src_ip"] = m.group(1) if m else None
        data["action"] = "failed-login"

    elif log_type == "dns":
        m = re.search(r"query: (\S+)", log)
        data["domain"] = m.group(1) if m else None

    elif log_type == "proxy":
        m = re.search(r"(GET|POST) (\S+)", log)
        data["method"] = m.group(1) if m else None
        data["url"] = m.group(2) if m else None

    return data

def mitre_tag(normalized):
    if normalized["type"] == "auth" and "failed-login" in normalized.get("action",""):
        return ["T1110 Brute Force"]

    if normalized["type"] == "dns":
        return ["T1568 DNS Tunneling"]

    if normalized["type"] == "proxy" and "login" in normalized.get("url",""):
        return ["T1056 Credential Phishing"]

    if normalized["type"] == "firewall" and normalized.get("protocol") == "TCP":
        return ["T1046 Port Scanning"]

    return ["T0000 Unknown"]

def process(log):
    n = normalize(log)
    n["mitre"] = mitre_tag(n)
    return n

if __name__ == "__main__":
    test = "Failed password for root from 192.168.1.10 port 22"
    print(json.dumps(process(test), indent=2))
