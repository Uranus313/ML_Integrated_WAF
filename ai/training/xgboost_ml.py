import pandas as pd

from xgboost import XGBClassifier

from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix


from sklearn.metrics import roc_auc_score
from sklearn.metrics import average_precision_score



# -------------------------
# Load dataset
# -------------------------

df = pd.read_csv("../../dataset_builder/final_dataset/dataset.csv")
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

# -------------------------
# Same split as RF/LightGBM
# -------------------------

split = int(len(df) * 0.8)

X_train = X.iloc[:split]
X_test = X.iloc[split:]

y_train = y.iloc[:split]
y_test = y.iloc[split:]

print(df["label"].value_counts())

print("Train:")
print(y_train.value_counts())

print("\nTest:")
print(y_test.value_counts())

# -------------------------
# XGBoost
# -------------------------

model = XGBClassifier(
    objective="binary:logistic",
    eval_metric="logloss",

    n_estimators=500,
    learning_rate=0.05,

    max_depth=8,
    min_child_weight=2,

    subsample=0.8,
    colsample_bytree=0.8,

    tree_method="hist",      # fastest on CPU
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# -------------------------
# Evaluation
# -------------------------

pred = model.predict(X_test)

probs = model.predict_proba(X_test)[:,1]

print("ROC-AUC:", roc_auc_score(y_test, probs))
print("PR-AUC :", average_precision_score(y_test, probs))

print(classification_report(y_test, pred))
print(confusion_matrix(y_test, pred))