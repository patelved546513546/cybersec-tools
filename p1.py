import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

# Load data
df = pd.read_csv("CICIDS2017.csv")
df.columns = df.columns.str.strip()  # Fix column names

print(f"✅ Loaded {df.shape[0]:,} rows with {df.shape[1]} features.")

if 'Label' not in df.columns:
    print("❌ 'Label' column not found!")
    exit()

# Now you can continue your analysis
