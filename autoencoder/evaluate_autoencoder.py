import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

from tensorflow.keras.models import load_model
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_curve,
    auc,
    precision_score,
    recall_score,
    f1_score
)

# =====================================
# 1. Load Model & Threshold
# =====================================

print("Loading Autoencoder Model...")
model = load_model("autoencoder_model.h5")

print("Loading threshold...")
threshold = joblib.load("threshold.pkl")

print(f"Loaded Threshold: {threshold:.6f}")

# =====================================
# 2. Load Test Dataset
# =====================================

print("Loading Test Dataset...")

X_test = pd.read_csv("X_test_scaled.csv")
y_test = pd.read_csv("y_test.csv").values.ravel()

print("Test shape:", X_test.shape)

# =====================================
# 3. Convert Labels to Binary
# =====================================

y_test_binary = (y_test != 0).astype(int)

print(f"Benign samples : {(y_test_binary == 0).sum()}")
print(f"Attack samples : {(y_test_binary == 1).sum()}")

# =====================================
# 4. Reconstruct Test Data
# =====================================

print("Reconstructing Test Data...")

reconstructions = model.predict(X_test)

mse = np.mean(np.power(X_test.values - reconstructions, 2), axis=1)

# =====================================
# 5. Predict Attacks
# =====================================

y_pred = (mse > threshold).astype(int)

# =====================================
# 6. Evaluation Metrics
# =====================================

accuracy  = accuracy_score(y_test_binary, y_pred)
precision = precision_score(y_test_binary, y_pred, zero_division=0)
recall    = recall_score(y_test_binary, y_pred, zero_division=0)
f1        = f1_score(y_test_binary, y_pred, zero_division=0)

print("\n" + "="*40)
print("Autoencoder Detection Results")
print("="*40)

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")

print("\nClassification Report\n")
print(classification_report(y_test_binary, y_pred, target_names=["BENIGN","ATTACK"]))

# =====================================
# 7. Confusion Matrix
# =====================================

cm = confusion_matrix(y_test_binary, y_pred)

plt.figure(figsize=(6,5))

sns.heatmap(
    cm,
    annot=True,
    fmt='d',
    cmap='Blues',
    xticklabels=["BENIGN","ATTACK"],
    yticklabels=["BENIGN","ATTACK"]
)

plt.title("Confusion Matrix - Autoencoder")
plt.xlabel("Predicted")
plt.ylabel("Actual")

plt.tight_layout()
plt.savefig("confusion_matrix.png", dpi=150)

plt.show()

# =====================================
# 8. ROC Curve
# =====================================

fpr, tpr, thresholds = roc_curve(y_test_binary, mse)

roc_auc = auc(fpr, tpr)

plt.figure(figsize=(7,5))

plt.plot(fpr, tpr, lw=2, label=f"AUC = {roc_auc:.4f}")
plt.plot([0,1], [0,1], 'k--')

plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")

plt.title("ROC Curve - Autoencoder")
plt.legend(loc="lower right")

plt.tight_layout()
plt.savefig("roc_curve.png", dpi=150)

plt.show()

print(f"\nROC AUC Score: {roc_auc:.4f}")

# =====================================
# 9. Reconstruction Error Distribution
# =====================================

plt.figure(figsize=(10,5))

plt.hist(mse[y_test_binary == 0], bins=100, alpha=0.6, label="BENIGN")
plt.hist(mse[y_test_binary == 1], bins=100, alpha=0.6, label="ATTACK")

plt.axvline(threshold, linestyle="--", linewidth=2, label="Threshold")

plt.title("Reconstruction Error Distribution")
plt.xlabel("Reconstruction Error (MSE)")
plt.ylabel("Frequency")

plt.legend()

plt.tight_layout()
plt.savefig("reconstruction_error_dist.png", dpi=150)

plt.show()

print("\nPlots saved:")
print("confusion_matrix.png")
print("roc_curve.png")
print("reconstruction_error_dist.png")