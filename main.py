import pandas as pd
from detection.hybrid_model import hybrid_predict

X = pd.read_csv("XGboost/X_test_scaled.csv")
y = pd.read_csv("XGboost/y_test.csv")

for i in range(10):
    sample = X.iloc[[i]]

    prediction = hybrid_predict(sample)
    actual = y.iloc[i]   # ✅ FIX (no .values[0])

    print(f"Row {i}")
    print("Prediction:", prediction)
    print("Actual:", actual)
    print("----------------------")