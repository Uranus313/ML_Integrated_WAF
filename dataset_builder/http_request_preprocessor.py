import csv
import json
from urllib.parse import urlparse, parse_qs
import random



counter = 0

all_requests = []

requests = []

with open("../datasets/csic2010/csic_database.csv",
          newline="",
          encoding="utf-8") as f:

    reader = csv.DictReader(f)

    for row in reader:

        url = urlparse(row["URL"])

        request = {
            "method": row["Method"],

            "path": url.path,

            "query": {
                k: v[0] if len(v) == 1 else v
                for k, v in parse_qs(url.query).items()
            },

            "headers": {},

            "body": row["content"],

            "label": row["classification"].strip().lower(),

            "req_number": counter
        }

        # Add every non-empty header
        header_map = {
            "User-Agent": "User-Agent",
            "Pragma": "Pragma",
            "Cache-Control": "Cache-Control",
            "Accept": "Accept",
            "Accept-encoding": "Accept-Encoding",
            "Accept-charset": "Accept-Charset",
            "language": "Accept-Language",
            "host": "Host",
            "cookie": "Cookie",
            "content-type": "Content-Type",
            "connection": "Connection",
            "lenght": "Content-Length"
        }

        for csv_name, header_name in header_map.items():
            value = row.get(csv_name, "").strip()

            if value != "":
                request["headers"][header_name] = value

        requests.append(request)
        counter += 1


all_requests.extend(requests)

with open("./requests/csic2010_requests.json", "w") as f:
    json.dump(requests, f, indent=4)

print(f"Converted {len(requests)} requests.")




def convert_esml(input_file, output_file):
    global counter
    requests = []

    with open(input_file, encoding="utf-8") as f:
        text = f.read()

    blocks = text.split("Start - Id:")

    for block in blocks:
        block = block.strip()

        if not block:
            continue

        lines = [l.rstrip() for l in block.splitlines()]

        request_id = None
        label = 0
        request_line = None
        headers = {}
        body = []

        reading_headers = False
        reading_body = False

        for line in lines:

            line = line.strip()

            if not line:
                continue

            if line.startswith("End - Id"):
                break

            if request_id is None:
                request_id = line
                continue

            if line.startswith("class:"):
                cls = line.split(":", 1)[1].strip().lower()
                label = 0 if cls == "valid" else 1
                continue

            if (
                request_line is None
                and line.startswith(
                    ("GET ", "POST ", "PUT ", "DELETE ",
                     "PATCH ", "HEAD ", "OPTIONS ")
                )
            ):
                request_line = line
                reading_headers = True
                continue

            if reading_headers:

                if line.startswith(("----", "~~~~")):
                    reading_headers = False
                    reading_body = True
                    continue

                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()

            elif reading_body:

                if (
                    line == "null"
                    or line.startswith(("----", "~~~~"))
                ):
                    continue

                body.append(line)

        if request_line is None:
            continue

        parts = request_line.split()

        method = parts[0]
        version = parts[-1]  # Parsed but unused
        url = " ".join(parts[1:-1])

        parsed = urlparse(url)

        requests.append({
            "method": method,
            "path": parsed.path,
            "query": {
                k: v[0] if len(v) == 1 else v
                for k, v in parse_qs(parsed.query).items()
            },
            "headers": headers,
            "body": "\n".join(body),
            "label": label,
            "req_number": counter
        })
        counter += 1

    all_requests.extend(requests)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(requests, f, indent=4)

    print(f"{input_file}: Converted {len(requests)} requests.")


# ----------------------------
# Convert both datasets
# ----------------------------

convert_esml(
    "../datasets/esml_pkdd/xml_train.txt",
    "./requests/esml_train_requests.json"
)

convert_esml(
    "../datasets/esml_pkdd/xml_test.txt",
    "./requests/esml_test_requests.json"
)






requests = []


query_names = [
    "q", "search", "id", "page", "file",
    "cmd", "input", "name", "value"
]

header_names = [
    "X-Test", "X-Forwarded-For", "X-Api-Key",
    "Referer", "Origin", "X-Custom"
]

cookie_names = [
    "session", "token", "id",
    "prefs", "user", "data"
]

with open("../datasets/HttpParamsDataset/payload_full.csv", newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)

    for i, row in enumerate(reader):

        label = (
            "normal"
            if row["label"].strip().lower() in ("norm", "normal", "benign")
            else "attack"
        )

        payload = row["payload"]

        request = {
            "method": "GET",
            "path": "/",
            "query": {},
            "headers": {
                "Host": "localhost",
                "User-Agent": "Dataset"
            },
            "body": "",
            "metadata": {
                "length": int(row["length"]),
                "attack_type": row["attack_type"],
                "label": label
            },
            "req_number": counter
        }

        # Rotate payload location
        location = i % 4

        # 25% Query parameter
        if location == 0:
            request["query"][random.choice(query_names)] = payload

        # 25% POST body
        elif location == 1:
            request["method"] = "POST"
            request["headers"]["Content-Type"] = "text/plain"
            request["body"] = payload

        # 25% Header
        elif location == 2:
            request["headers"][random.choice(header_names)] = payload

        # 25% Cookie
        else:
            request["headers"][random.choice(cookie_names)] = f"session=12345; payload={payload}"

        requests.append(request)
        counter += 1

all_requests.extend(requests)

with open("./requests/HttpParamsDataset_requests.json", "w", encoding="utf-8") as f:
    json.dump(requests, f, indent=4)

print(f"Converted {len(requests)} requests.")



# -----------------------------------
# Build one final randomized dataset
# -----------------------------------

random.shuffle(all_requests)

# Give new sequential request numbers
for i, request in enumerate(all_requests):
    request["req_number"] = i

with open("./requests/final_dataset.json", "w", encoding="utf-8") as f:
    json.dump(all_requests, f, indent=4)

print(f"Final dataset contains {len(all_requests)} requests.")