import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
 
data={
	"packet_size":[60,52,1800,324,542,456,6322],
	"time_delta":[0.01,0.02,0.04,0.03,0.07,0.83,0.02],}
df=pd.DataFrame(data)
model=IsolationForest(contamination=0.1,random_state=42)
df["anomaly"]=model.fit_predict(df)

anomalies=df[df["anomaly"]==-1]
print("[+] Detected Anomalies:")
print(anomalies)

anomalies.to_csv("anomalous_packets.csv",index=False)
print("[+] Results saved to anomalous_packets.csv")

