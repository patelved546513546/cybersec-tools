# insane_detector.py

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# 1️⃣ DOWNLOAD OR USE LOCAL CSV
# Download manually from Kaggle or CIC:
# https://www.unb.ca/cic/datasets/ids-2017.html
# Save as 'CICIDS2017.csv' in this folder.

# 2️⃣ LOAD DATA

df = pd.read_csv('CICIDS2017.csv')
df.columns = df.columns.str.strip()
print(f"✅ Loaded {len(df):,} rows with {df.shape[1]} features.")

# 3️⃣ PREPROCESS
# Drop non-numeric and ID columns
if 'Label' not in df.columns:
    raise SystemExit("❌ 'Label' column not found!")
df['LabelBin'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
X = df.select_dtypes(include=[np.number]).drop(['LabelBin'], axis=1)
y = df['LabelBin']

# Handle NaN/inf
X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

# 4️⃣ SPLIT
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

print(f"🧪 Training on {len(X_train):,} samples, testing on {len(X_test):,} samples.")

# 5️⃣ ISOLATION FOREST
iso = IsolationForest(contamination=0.1, random_state=42)
iso.fit(X_train)
pred_if = iso.predict(X_test)
y_if = np.where(pred_if == 1, 0, 1)

acc_if = accuracy_score(y_test, y_if)
print(f"\n🎯 IsolationForest Accuracy: {acc_if:.4f}")

# 6️⃣ RANDOM FOREST
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)
y_rf = rf.predict(X_test)

acc_rf = accuracy_score(y_test, y_rf)
print(f"🎯 RandomForest Accuracy: {acc_rf:.4f}")

print("\n📋 RandomForest Classification Report:")
print(classification_report(y_test, y_rf, target_names=["BENIGN", "ATTACK"]))

# 7️⃣ SAVE RESULTS
pd.DataFrame({
    'Actual': y_test,
    'IF_Pred': y_if,
    'RF_Pred': y_rf
}).to_csv("insane_detector_output.csv", index=False)

print("💾 Results saved to insane_detector_output.csv")
