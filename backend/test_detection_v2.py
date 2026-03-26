import os
import sys
import numpy as np
import joblib
from tensorflow.keras.models import load_model

# Mock django settings
class MockSettings:
    BASE_DIR = r'd:\hybrid\backend'

sys.modules['django.conf'] = type('Module', (), {'settings': MockSettings})

# Add detection module to path
sys.path.append(r'd:\hybrid\backend')

try:
    from detection.services import detect_anomaly, load_models
    import detection.services as services

    # Manually load models to check for issues
    print("Loading models...")
    services.load_models()
    print(f"Threshold: {services.threshold}")

    features = [-0.35] * 77
    print(f"Testing features: {features[:5]}... (length {len(features)})")
    
    result, xgb_pred, recon_error = detect_anomaly(features)
    
    print("\n--- RESULTS ---")
    print(f"Result: {result}")
    print(f"XGB Prediction: {xgb_pred}")
    print(f"Reconstruction Error: {recon_error}")
    print(f"Threshold: {services.threshold}")
    
except Exception as e:
    import traceback
    print(f"Error occurred: {e}")
    traceback.print_exc()
