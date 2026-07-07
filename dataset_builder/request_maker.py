import json
import random
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
BASE_URL = "http://localhost:8080"

with open("./requests/final_dataset.json", encoding="utf-8") as f:
    dataset = json.load(f)


# Keep only 80% for training
dataset = dataset[: int(len(dataset) * 0.8)]

print(f"Sending {len(dataset)} training requests.")

MAX_WORKERS = 50

session = requests.Session()

def send_request(req):

    method = req["method"].upper()

    path = req["path"]

    # Remove accidental HTTP version if present
    if " HTTP/" in path:
        path = path.split(" HTTP/")[0]

    url = BASE_URL + path

    query = req.get("query", {})
    body = req.get("body", "")

    headers = req.get("headers", {}).copy()

    # Let requests generate these correctly
    headers.pop("Host", None)
    headers.pop("Content-Length", None)

    # Remove invalid Transfer-Encoding values
    if headers.get("Transfer-Encoding", "").lower() != "chunked":
        headers.pop("Transfer-Encoding", None)

    # Add request number header
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

        print(
            f'#{req["req_number"]:6d} '
            f'{method:6} '
            f'{response.status_code} '
            f'{url}'
        )

    except Exception as e:
        print(f'#{req["req_number"]} ERROR: {e}')

with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
    futures = [pool.submit(send_request, r) for r in dataset]

    for f in as_completed(futures):
        num, status = f.result()
        print(num, status)        