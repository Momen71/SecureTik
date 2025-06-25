import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from joblib import dump

df = pd.read_csv("labeled_alerts.csv")
X = df.drop("label", axis=1)
y = df["label"]

model = RandomForestClassifier()
model.fit(X, y)

dump(model, "ai_ids_model.joblib")
print("[+] Model trained and saved as ai_ids_model.joblib")
