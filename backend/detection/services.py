import os
import joblib
from django.conf import settings

model = None

def get_model():
    global model
    if model is None:
        model_path = os.path.join(settings.BASE_DIR, 'models', 'xgboost_model.pkl')
        model = joblib.load(model_path)
    return model


def detect_anomaly(data):
    model = get_model()
    return model.predict([data])