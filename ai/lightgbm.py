import pandas as pd

from lightgbm import LGBMClassifier
from sklearn.metrics import classification_report, confusion_matrix

from sklearn.metrics import roc_auc_score
from sklearn.metrics import average_precision_score


df = pd.read_csv("../dataset_builder/final_dataset/dataset.csv")

df = df.fillna(0)

X = df.drop(columns=[
    "label",
    "request_id",
    "req_number",
    "header_fingerprint"
])

X = pd.get_dummies(
    X,
    columns=["request_method", "extension"],
    dtype=int
)

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