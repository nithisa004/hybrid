import os
import joblib
import numpy as np
from django.conf import settings
from tensorflow.keras.models import load_model

xgb_model = None
autoencoder_model = None
threshold = None

def load_models():
    global xgb_model, autoencoder_model, threshold
    if xgb_model is None:
        xgb_path = os.path.join(settings.BASE_DIR, '..', 'XGboost', 'xgboost_model.pkl')
        xgb_model = joblib.load(xgb_path)
    
    if autoencoder_model is None:
        ae_path = os.path.join(settings.BASE_DIR, '..', 'autoencoder', 'autoencoder_model.h5')
        autoencoder_model = load_model(ae_path)
        
    if threshold is None:
        threshold_path = os.path.join(settings.BASE_DIR, '..', 'autoencoder', 'threshold.pkl')
        threshold = joblib.load(threshold_path)

def detect_anomaly(data):
    """
    data: list or array-like (1D) containing the features
    Returns: (final_result, xgb_pred, recon_error)
    """
    load_models()
    
    # Preprocess data if needed (assuming it matches training features)
    x = np.array(data).reshape(1, -1)
    
    # XGBoost Prediction
    xgb_pred = int(xgb_model.predict(x)[0])
    
    # Autoencoder Reconstruction Error
    recon = autoencoder_model.predict(x)
    recon_error = float(np.mean((x - recon) ** 2, axis=1)[0])
    
    # Hybrid Logic
    if xgb_pred != 0:
        result = "Attack (Known)"
    elif recon_error > threshold:
        result = "Anomaly (Unknown Attack)"
    else:
        result = "Normal"
        
    return result, xgb_pred, recon_error