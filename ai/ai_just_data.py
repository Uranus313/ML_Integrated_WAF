import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix

df = pd.read_csv("../dataset_builder/final_dataset_ml.csv")

df = df.fillna(0)

X = df.drop(columns=[
    "label",
])

X = pd.get_dummies(
    X,
    columns=["request_method", "extension"],
    dtype=int
)

y = df["label"]

split = int(len(df) * 0.8)
print(X.dtypes[X.dtypes == "object"])
X_train = X.iloc[:split]
X_test  = X.iloc[split:]

y_train = y.iloc[:split]
y_test  = y.iloc[split:]
print(df["label"].value_counts())
print("Train:")
print(y_train.value_counts())

print("\nTest:")
print(y_test.value_counts())
model = RandomForestClassifier(
    n_estimators=300,
    class_weight="balanced",
    n_jobs=-1,
    random_state=42
)
print(X_train.select_dtypes(include="object").columns)
model.fit(X_train, y_train)

pred = model.predict(X_test)

print(classification_report(y_test, pred))
print(confusion_matrix(y_test, pred))