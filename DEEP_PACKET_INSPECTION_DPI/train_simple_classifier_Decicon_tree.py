from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import numpy as np
import pandas as pd
df=pd.read_csv("packet_features.csv")
df["label"]=np.random.randint(0,2,size=len(df))
x=df[["protocol","length"]]
y=df["label"]
x_train,x_test,y_train,y_test=train_test_split(x,y,test_size=0.2)
model=DecisionTreeClassifier()
model.fit(x_train,y_train)
preds=model.predict(x_test)
print(classification_report(y_test,preds))
