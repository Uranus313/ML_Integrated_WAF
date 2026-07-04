import json

requests = {}

# ---------------------------------------------------
# Load feature extraction output
# ---------------------------------------------------

with open("../logs/transactions.jsonl") as f:
    for line in f:
        tx = json.loads(line)

        requests[tx["request_id"]] = {
            "features": tx["features"],
            "label": None,
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

        requests[request_id]["modsec"] = {
            "http_code": transaction["response"]["http_code"],
            "rule_ids": [
                m["details"]["ruleId"]
                for m in messages
            ],
            "messages": [
                m["message"]
                for m in messages
            ],
            "tags": sorted({
                tag
                for m in messages
                for tag in m["details"].get("tags", [])
            })
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

        requests[request_id]["waf"] = {
            "decision": event["message"],
            "score": event["data"]["score"],
            "reasons": event["data"].get("reasons", [])
        }
print(requests)
