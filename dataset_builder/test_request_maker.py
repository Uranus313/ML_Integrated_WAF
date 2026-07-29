import json
import random
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
BASE_URL = "http://localhost:8080"

with open("./requests/final_dataset.json", encoding="utf-8") as f:
    dataset = json.load(f)


# Keep only 80% for training
split = int(len(dataset) * 0.8)
dataset = dataset[split:]      # last 20%, same as X_test
# dataset = dataset[:1000]
print(f"Sending {len(dataset)} training requests.")

MAX_WORKERS = 200

session = requests.Session()

def send_request(req):
    method = req["method"].upper()

    path = req["path"]
    if " HTTP/" in path:
        path = path.split(" HTTP/")[0]

    url = BASE_URL + path

    query = req.get("query", {})
    body = req.get("body", "")

    headers = req.get("headers", {}).copy()

    headers.pop("Host", None)
    headers.pop("Content-Length", None)

    if headers.get("Transfer-Encoding", "").lower() != "chunked":
        headers.pop("Transfer-Encoding", None)

    headers["X-Request-Number"] = str(req["req_number"])

    try:
        response = session.request(
            method=method,
            url=url,
            params=query,
            headers=headers,
            data=body,
            timeout=10,
            allow_redirects=False,
        )

        label = req["label"]

        expected = 403 if label == 1 else 502
        correct = response.status_code == expected

        return {
            "req": req["req_number"],
            "label": label,
            "expected": expected,
            "actual": response.status_code,
            "correct": correct,
        }

    except Exception as e:
        return {
            "req": req["req_number"],
            "error": str(e),
            "correct": False,
        }


results = []
correct = 0
total = 0
with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
    futures = [pool.submit(send_request, r) for r in dataset]

    for f in as_completed(futures):
        result = f.result()
        results.append(result)
        if "error" in result:
            print(f'#{result["req"]} ERROR {result["error"]}')
            continue

        total += 1
        if result["correct"]:
            correct += 1

        mark = "✓" if result["correct"] else "✗"

        print(
            f'{mark} #{result["req"]:6d} '
            f'label={result["label"]} '
            f'expected={result["expected"]} '
            f'got={result["actual"]}'
        )

print(f"\nAccuracy: {correct}/{total} = {correct/total:.2%}")


tp = tn = fp = fn = 0

for result in results:
    try:
        label = result["label"]
        attack = result["actual"] == 403

        if label == 1 and attack:
            tp += 1
        elif label == 0 and not attack:
            tn += 1
        elif label == 0 and attack:
            fp += 1
        else:
            fn += 1
    except:
        pass 

print(f"TP={tp}")
print(f"TN={tn}")
print(f"FP={fp}")
print(f"FN={fn}")