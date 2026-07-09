import pandas as pd

from lightgbm import LGBMClassifier
from sklearn.metrics import classification_report, confusion_matrix

from sklearn.metrics import roc_auc_score
from sklearn.metrics import average_precision_score


from skl2onnx import to_onnx
from skl2onnx.common.data_types import FloatTensorType
import onnx
import json

import treelite

import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType



df = pd.read_csv("../../dataset_builder/final_dataset/dataset.csv")

df = df.fillna(0)

X = df.drop(columns=[
    "label",
    "request_id",
    "req_number",
    "header_fingerprint"
])

# X = pd.get_dummies(
#     X,
#     columns=["request_method", "extension"],
#     dtype=int
# )

y = df["label"]

# Same split as Random Forest
split = int(len(df) * 0.8)

X_train = X.iloc[:split]
X_test  = X.iloc[split:]

y_train = y.iloc[:split]
y_test  = y.iloc[split:]

print(df["label"].value_counts())
print("Train:")
print(y_train.value_counts())

print("\nTest:")
print(y_test.value_counts())

model = LGBMClassifier(
    objective="binary",
    boosting_type="gbdt",

    n_estimators=500,
    learning_rate=0.05,

    num_leaves=63,
    max_depth=-1,

    class_weight="balanced",

    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

pred = model.predict(X_test)


probs = model.predict_proba(X_test)[:,1]

print("ROC-AUC:", roc_auc_score(y_test, probs))
print("PR-AUC :", average_precision_score(y_test, probs))

print(classification_report(y_test, pred))
print(confusion_matrix(y_test, pred))



tl_model = treelite.frontend.from_lightgbm(model.booster_)

tl_model.serialize("../treelite/lightgbm_model.tl")

print("Saved Treelite model")


with open("../treelite/feature_columns.json", "w") as f:
    json.dump(list(X.columns), f, indent=2)

print("Saved feature_columns.json")



# Export LightGBM -> ONNX
initial_type = [
    ("input", FloatTensorType([None, X_train.shape[1]]))
]

onnx_model = onnxmltools.convert_lightgbm(
    model,
    initial_types=initial_type,
    zipmap=False
)

with open("../onnx/lightgbm.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

print("Saved ONNX model")


feature_schema = []

for column in X.columns:

    if column.startswith("request_method_"):
        feature_schema.append({
            "name": column,
            "type": "onehot",
            "source": "request_method",
            "value": column[len("request_method_"):]
        })

    elif column.startswith("extension_"):
        feature_schema.append({
            "name": column,
            "type": "onehot",
            "source": "extension",
            "value": column[len("extension_"):]
        })

    else:
        feature_schema.append({
            "name": column,
            "type": "numeric"
        })

with open("../onnx/feature_schema.json", "w") as f:
    json.dump(feature_schema, f, indent=2)

with open("../treelite/feature_schema.json", "w") as f:
    json.dump(feature_schema, f, indent=2)

print("Saved feature_schema.json")


metadata = {
    "algorithm": "LightGBM",
    "feature_count": len(X.columns),
    "positive_class": 1,
    "negative_class": 0,
    "threshold": 0.5
}

with open("../onnx/model_metadata.json", "w") as f:
    json.dump(metadata, f, indent=2)

with open("../treelite/model_metadata.json", "w") as f:
    json.dump(metadata, f, indent=2)