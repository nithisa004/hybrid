import pandas as pd
import numpy as np
import joblib

from tensorflow.keras.models import load_model
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# ======================================
# 1. Load Model
# ======================================

print("Loading Autoencoder Model...")
model = load_model("autoencoder_model.h5")

print("Loading threshold...")
threshold = joblib.load("threshold.pkl")

print("Loaded Threshold:", threshold)

# ======================================
# 2. Load Test Dataset
# ======================================

print("Loading Test Dataset...")

X_test = pd.read_csv("X_test_scaled.csv")
y_test = pd.read_csv("y_test.csv").values.ravel()

print("Test shape:", X_test.shape)

# Convert labels to binary
y_test_binary = (y_test != 0).astype(int)

print("Benign samples :", (y_test_binary == 0).sum())
print("Attack samples :", (y_test_binary == 1).sum())

# ======================================
# 3. Reconstruction
# ======================================

print("Reconstructing Test Data...")

reconstruction = model.predict(X_test)

# ======================================
# 4. Calculate Reconstruction Error
# ======================================

mse = np.mean((X_test.values - reconstruction) ** 2, axis=1)

# ======================================
# 5. Predict Attacks
# ======================================

y_pred = (mse > threshold).astype(int)

# ======================================
# 6. Evaluation
# ======================================

accuracy = accuracy_score(y_test_binary, y_pred)

print("\n========================================")
print("Autoencoder Detection Results")
print("========================================")

print("Accuracy :", accuracy)

print("\nClassification Report\n")
print(classification_report(y_test_binary, y_pred))

print("\nConfusion Matrix\n")
print(confusion_matrix(y_test_binary, y_pred))