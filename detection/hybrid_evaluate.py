# ==========================================
# HYBRID SIEM EVALUATION (FINAL - FIXED)
# ==========================================

import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    roc_curve,
    auc
)

from tensorflow.keras.models import load_model

# -----------------------------
# 1. Load Models
# -----------------------------
autoencoder = load_model("../autoencoder/autoencoder_model.h5")
xgb_model = joblib.load("../XGboost/xgboost_model.pkl")

# -----------------------------
# 2. Load TEST DATA (IMPORTANT)
# -----------------------------
X = pd.read_csv("../autoencoder/X_test_scaled.csv").values
y_true = pd.read_csv("../autoencoder/y_test.csv").values.ravel()

print("Data Loaded Successfully ✅")
print("Shape:", X.shape)

# -----------------------------
# 3. Autoencoder Prediction
# -----------------------------
reconstructed = autoencoder.predict(X)

# Reconstruction error
recon_error = np.mean(np.square(X - reconstructed), axis=1)

# 🔥 Better Threshold (tune here)
threshold = np.percentile(recon_error, 97)
print("\nThreshold:", threshold)

ae_pred = (recon_error > threshold).astype(int)

# -----------------------------
# 4. XGBoost Prediction
# -----------------------------
xgb_pred = xgb_model.predict(X)

# -----------------------------
# 5. Hybrid Logic
# -----------------------------
final_pred = []

for i in range(len(X)):
    if ae_pred[i] == 1:
        final_pred.append(1)  # anomaly
    else:
        final_pred.append(xgb_pred[i])

final_pred = np.array(final_pred)

# -----------------------------
# 6. Evaluation Metrics
# -----------------------------
print("\n✅ Accuracy:")
print(accuracy_score(y_true, final_pred))

print("\n📊 Classification Report:\n")
print(classification_report(y_true, final_pred))

# -----------------------------
# 7. Confusion Matrix
# -----------------------------
cm = confusion_matrix(y_true, final_pred)

print("\n📌 Confusion Matrix:\n", cm)

plt.figure()
plt.imshow(cm)
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.colorbar()
plt.show()

# -----------------------------
# 8. ROC Curve + AUC
# -----------------------------
# -----------------------------
# FIX LABELS (IMPORTANT)
# -----------------------------
y_true = (y_true > 0).astype(int)

# -----------------------------
# ROC Curve + AUC
# -----------------------------
fpr, tpr, _ = roc_curve(y_true, recon_error)
roc_auc = auc(fpr, tpr)

print("\n🎯 AUC Score:", roc_auc)

plt.figure()
plt.plot(fpr, tpr, label="AUC = %0.2f" % roc_auc)
plt.plot([0, 1], [0, 1])
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curve")
plt.legend()
plt.show()

# -----------------------------
# 9. Reconstruction Error Graph
# -----------------------------
plt.figure()
plt.hist(recon_error, bins=50)
plt.axvline(threshold, linestyle='--')
plt.title("Reconstruction Error Distribution")
plt.xlabel("Error")
plt.ylabel("Frequency")
plt.show()