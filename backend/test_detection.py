import os
import sys
import django
import numpy as np
import joblib
from tensorflow.keras.models import load_model

# Setup Django environment to access settings
sys.path.append(r'd:\hybrid\backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
django.setup()

from django.conf import settings
from detection.services import detect_anomaly

def test_fallback():
    features = [-0.35] * 77
    result, xgb_pred, recon_error = detect_anomaly(features)
    print(f"Features: {features[:5]}... (length {len(features)})")
    print(f"Result: {result}")
    print(f"XGB Prediction: {xgb_pred}")
    print(f"Reconstruction Error: {recon_error}")

if __name__ == "__main__":
    test_fallback()
