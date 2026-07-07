import json
import re

requests = {}


with open("./requests/final_dataset.json") as f:
    original = json.load(f)

labels = {
    r["req_number"]: r["label"]
    for r in original
}


# ---------------------------------------------------
# Load feature extraction output
# ---------------------------------------------------

with open("../logs/transactions.jsonl") as f:
    counter = 0
    for line in f:
        
        tx = json.loads(line)
        if(counter == 0):
            print(line)
            print(tx["raw_request"]["headers"]["x-request-number"])
            counter +=1
        # print(counter)    
        req_number = int(tx["raw_request"]["headers"]["x-request-number"])
        requests[tx["request_id"]] = {
            "features": tx["features"],
            "label": labels[req_number],
            "req_number": req_number,
            "modsec": {},
            "waf": {}
        }

# ---------------------------------------------------
# Load ModSecurity
# ---------------------------------------------------

with open("../logs/modsec_audit.log") as f:
    for line in f:
        if not line.strip():
            continue

        audit = json.loads(line)

        transaction = audit["transaction"]

        headers = transaction["request"]["headers"]

        request_id = headers.get("X-WAF-Request-ID")

        if request_id not in requests:
            continue

        messages = transaction.get("messages", [])

        anomaly_score = 0

        for m in messages:
             if "Inbound Anomaly Score" in m["message"]:
                anomaly_score = int(
                    m["message"].split("Total Score: ")[1].rstrip(")")
                )
                break
        tags = [
            tag
            for m in messages
            for tag in m["details"].get("tags", [])
        ]

        rule_ids = [
            m["details"]["ruleId"]
            for m in messages
        ]

        requests[request_id]["modsec"] = {
            "http_code": transaction["response"]["http_code"],

            "rule_count": len(messages),
            "unique_rule_count": len(set(rule_ids)),
            "anomaly_score": anomaly_score,
            
            "scanner_rule_count": sum("attack-reputation-scanner" in t for t in tags),

            "xss_rule_count": sum("attack-xss" in t for t in tags),
            "sqli_rule_count": sum("attack-sqli" in t for t in tags),
            "lfi_rule_count": sum("attack-lfi" in t for t in tags),
            "rce_rule_count": sum("attack-rce" in t for t in tags),
            "php_rule_count": sum("attack-injection-php" in t for t in tags),

            "severity_0": sum(m["details"].get("severity") == "0" for m in messages),
            "severity_1": sum(m["details"].get("severity") == "1" for m in messages),
            "severity_2": sum(m["details"].get("severity") == "2" for m in messages),
            "severity_3": sum(m["details"].get("severity") == "3" for m in messages),
            "severity_4": sum(m["details"].get("severity") == "4" for m in messages),
        }

# ---------------------------------------------------
# Load WAF log
# ---------------------------------------------------

with open("../logs/waf.jsonl") as f:
    for line in f:
        if not line.strip():
            continue

        event = json.loads(line)

        request_id = event["data"]["request_id"]

        if request_id not in requests:
            continue

        reasons = event["data"].get("reasons", [])

        requests[request_id]["waf"] = {
            "decision": 1 if event["message"] == "Request blocked" else 0,

            "score": event["data"]["score"],

            "reason_count": len(reasons),

            "xss_count": sum(r.startswith("xss:") for r in reasons),
            "sqli_count": sum(r.startswith("sqli:") for r in reasons),
            "lfi_count": sum(r.startswith("lfi:") for r in reasons),
            "rce_count": sum(r.startswith("rce:") for r in reasons),
            "cmd_count": sum(r.startswith("cmd:") for r in reasons),
            "upload_count": sum(r.startswith("upload:") for r in reasons),
        }
# print(requests)




# ---------------------------------------------------
# Flatten everything into one ML feature vector
# ---------------------------------------------------
dataset = []

for request_id, req in requests.items():

    row = {
        "request_id": request_id,
        "req_number": req["req_number"]
    }

    # Original extracted features
    row.update(req["features"])

    # ModSecurity features
    for key, value in req["modsec"].items():
        row[f"mod_security_{key}"] = value

    # Lua WAF features
    for key, value in req["waf"].items():
        row[f"lua_detection_{key}"] = value

    # Label (ground truth)
    row["label"] = req["label"]

    dataset.append(row)


print(len(dataset[0]))


import csv

with open("./final_dataset/dataset.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=dataset[0].keys())
    writer.writeheader()
    writer.writerows(dataset)

print(f"Saved {len(dataset)} samples to dataset.csv")