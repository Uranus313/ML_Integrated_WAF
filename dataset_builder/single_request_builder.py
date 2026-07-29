import csv
import json

REQUEST_ID = "2cbd1589929fe8617b45a44d64aba202"

# ---------------------------------------------------
# Find transaction
# ---------------------------------------------------

def find_transaction(request_id):
    with open("../logs/transactions.jsonl") as f:
        for line in f:
            tx = json.loads(line)
            if tx["request_id"] == request_id:
                return tx
    return None


# ---------------------------------------------------
# Find ModSecurity
# ---------------------------------------------------

def find_modsec(request_id):
    with open("../logs/modsec_audit.log") as f:
        for line in f:
            if not line.strip():
                continue

            audit = json.loads(line)

            headers = audit["transaction"]["request"]["headers"]

            if headers.get("X-WAF-Request-ID") != request_id:
                continue

            transaction = audit["transaction"]
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

            return {
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

    return {}


# ---------------------------------------------------
# Find Lua WAF
# ---------------------------------------------------

def find_waf(request_id):
    with open("../logs/waf.jsonl") as f:
        for line in f:
            if not line.strip():
                continue

            event = json.loads(line)

            if event["data"]["request_id"] != request_id:
                continue

            reasons = event["data"].get("reasons", [])

            return {
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

    return {}


# ---------------------------------------------------
# Build feature row
# ---------------------------------------------------

tx = find_transaction(REQUEST_ID)

if tx is None:
    raise Exception(f"Request '{REQUEST_ID}' not found.")

row = {}

# Original extracted features
row.update(tx["features"])

# ModSecurity
for k, v in find_modsec(REQUEST_ID).items():
    row[f"mod_security_{k}"] = v

# Lua WAF
for k, v in find_waf(REQUEST_ID).items():
    row[f"lua_detection_{k}"] = v


# ---------------------------------------------------
# Load training dataset header
# ---------------------------------------------------

with open("./final_dataset/dataset.csv", newline="", encoding="utf-8") as f:
    reader = csv.reader(f)
    dataset_columns = next(reader)


# ---------------------------------------------------
# One-hot encode categorical features
# ---------------------------------------------------

CATEGORICAL_COLUMNS = [
    "request_method",
    "extension",
]

for column in CATEGORICAL_COLUMNS:
    value = row.pop(column, "")

    prefix = column + "_"

    for csv_column in dataset_columns:
        if csv_column.startswith(prefix):
            category = csv_column[len(prefix):]
            row[csv_column] = int(value == category)


# ---------------------------------------------------
# Fill missing features
# ---------------------------------------------------

IGNORE = {
    "request_id",
    "req_number",
    "label",
}

feature_row = {}

for column in dataset_columns:
    if column in IGNORE:
        continue

    feature_row[column] = row.get(column, 0)


print(json.dumps(feature_row, indent=2))
