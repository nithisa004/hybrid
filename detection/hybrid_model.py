import joblib
import numpy as np
import os
from tensorflow.keras.models import load_model

# Base path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load models
xgb_model = joblib.load(os.path.join(BASE_DIR, "XGboost", "xgboost_model.pkl"))
autoencoder = load_model(os.path.join(BASE_DIR, "autoencoder", "autoencoder_model.h5"))

# ⚠️ DO NOT USE SCALER (already scaled data)

# Fix threshold (manual for now)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

threshold = joblib.load(os.path.join(BASE_DIR, "autoencoder", "threshold.pkl"))   # ✅ MUCH BETTER VALUE


# =========================
# Reconstruction Error
# =========================
def get_reconstruction_error(x):
    recon = autoencoder.predict(x)
    error = np.mean((x - recon) ** 2, axis=1)
    return error


# =========================
# Hybrid Prediction
# =========================
def hybrid_predict(x):
    x_scaled = x

    xgb_pred = xgb_model.predict(x_scaled)
    recon_error = get_reconstruction_error(x_scaled)

    # ✅ FIX HERE
    error_value = float(recon_error.iloc[0])

    print("XGB:", xgb_pred[0],
          "Error:", error_value,
          "Threshold:", threshold)

    if xgb_pred[0] != 0:
        return "Attack (Known)"
    elif error_value > threshold:
        return "Anomaly (Unknown Attack)"
    else:
        return "Normal"