import csv
import json

from collections import Counter

codes = Counter()

with open("dataset.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        codes[row["mod_security_http_code"]] += 1

print(codes)



# ----------------------------
# Ground truth labels
# ----------------------------



with open("./requests/final_dataset.json", encoding="utf-8") as f:
    requests = json.load(f)

ground_truth = {
    int(r["req_number"]): int(r["label"])
    for r in requests
}

# ----------------------------
# Benchmark
# ----------------------------

TP = FP = TN = FN = 0

with open("./dataset.csv", encoding="utf-8") as f:
    reader = csv.DictReader(f)

    for row in reader:

        req_number = int(row["req_number"])

        if req_number not in ground_truth:
            continue

        actual = ground_truth[req_number]

        status = int(row["mod_security_http_code"])

        # ModSecurity prediction
        predicted = 1 if status == 403 else 0

        if predicted == 1 and actual == 1:
            TP += 1
        elif predicted == 1 and actual == 0:
            FP += 1
        elif predicted == 0 and actual == 0:
            TN += 1
        else:
            FN += 1

# ----------------------------
# Metrics
# ----------------------------

total = TP + TN + FP + FN

accuracy = (TP + TN) / total if total else 0
precision = TP / (TP + FP) if TP + FP else 0
recall = TP / (TP + FN) if TP + FN else 0
f1 = (
    2 * precision * recall / (precision + recall)
    if precision + recall
    else 0
)

print("Confusion Matrix")
print("----------------")
print(f"TP: {TP}")
print(f"FP: {FP}")
print(f"TN: {TN}")
print(f"FN: {FN}")

print("\nMetrics")
print("-------")
print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")