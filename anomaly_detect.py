import pandas as pd
from sklearn.ensemble import IsolationForest

filename = input("Enter CSV file name: ")
data = pd.read_csv(filename)

print("CSV columns found:", data.columns.tolist())   # 👈 This will print your actual columns

X = data[['attempts']]  # Check if 'attempts' really exists

model = IsolationForest(contamination=0.2)
model.fit(X)

data['anomaly'] = model.predict(X)

for index, row in data.iterrows():
    status = "Anomaly" if row['anomaly'] == -1 else "Normal"
    print(f"{row['username']} ({row['ip']}) - Attempts: {row['attempts']} → {status}")

