# ============================================
# Hybrid SIEM - Real-Time Detection
# Windows Logs + NIC Traffic (FINAL VERSION)
# ============================================

import win32evtlog
import numpy as np
import pandas as pd
import joblib
import threading
import time
from tensorflow.keras.models import load_model

from nic_capture import start_sniffing
from feature_mapper import map_to_ml_features

# =========================
# LOAD MODELS
# =========================
print("🔄 Loading models...")

try:
    xgb_model = joblib.load("../XGboost/xgboost_model.pkl")
    autoencoder = load_model("../autoencoder/autoencoder_model.h5")
    scaler = joblib.load("../autoencoder/scaler.pkl")

    feature_names = scaler.feature_names_in_

    print("✅ Models loaded successfully\n")

except Exception as e:
    print("❌ Error loading models:", e)
    exit()

# =========================
# FEATURE EXTRACTION (WINDOWS)
# =========================
def extract_features(event):
    features = np.zeros(len(feature_names))

    try:
        features[0] = event.EventID
        features[1] = len(str(event.SourceName))
        features[2] = int(event.TimeGenerated.hour)
        features[3] = int(event.TimeGenerated.day)
    except:
        pass

    return features

# =========================
# DETECTION FUNCTION
# =========================
THRESHOLD = 0.01   # Autoencoder threshold (tune later)

def detect(features, event_id=None):

    df = pd.DataFrame([features], columns=feature_names)

    # Scale
    scaled = scaler.transform(df)

    # Autoencoder reconstruction
    recon = autoencoder.predict(scaled, verbose=0)

    # Reconstruction error (CORRECT)
    error = np.mean((scaled - recon) ** 2)

    # XGBoost prediction
    pred = xgb_model.predict(df)[0]

    # =========================
    # FINAL DECISION LOGIC
    # =========================

    if event_id == 4672:
        if error > THRESHOLD:
            result = "⚠️ Suspicious Admin Activity"
        else:
            result = "✅ Normal Admin Activity"

    elif error > THRESHOLD and pred == 1:
        result = "🔥 CONFIRMED ATTACK"

    elif error > THRESHOLD:
        result = "⚠️ Suspicious Activity"

    else:
        result = "✅ Normal"

    return error, pred, result

# =========================
# NETWORK PACKET PROCESSING
# =========================
def process_packet(packet_features):

    data = map_to_ml_features(packet_features, feature_names)

    error, pred, result = detect(data)

    print("\n📡 NETWORK EVENT")
    print("Data:", packet_features)
    print("Anomaly Score:", round(error, 5))
    print("Prediction:", pred)
    print("Result:", result)
    print("-" * 50)

# =========================
# START NIC CAPTURE THREAD
# =========================
threading.Thread(
    target=start_sniffing,
    args=(process_packet,),
    daemon=True
).start()

# =========================
# WINDOWS LOG SETUP
# =========================
server = "localhost"
log_type = "Security"

try:
    handle = win32evtlog.OpenEventLog(server, log_type)
except:
    print("❌ Run as Administrator!")
    exit()

flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

print("🚀 Real-Time SIEM Detection Started...\n")

# Important events
important_events = {
    4625: "Failed Login 🚨",
    4688: "Process Created ⚠️",
    4672: "Admin Privileges ⚠️",
    4720: "User Created 🚨"
}

# =========================
# MAIN LOOP
# =========================
while True:

    events = win32evtlog.ReadEventLog(handle, flags, 0)

    if events:
        for event in events:

            event_id = event.EventID & 0xFFFF

            if event_id in important_events:

                try:
                    features = extract_features(event)

                    error, pred, result = detect(features, event_id)

                    print("\n🚨 WINDOWS EVENT")
                    print("Event ID:", event_id)
                    print("Type:", important_events[event_id])
                    print("Time:", event.TimeGenerated)
                    print("Anomaly Score:", round(error, 5))
                    print("XGBoost Prediction:", pred)
                    print("👉 FINAL RESULT:", result)
                    print("-" * 60)

                except Exception as e:
                    print("⚠️ Error:", e)

    time.sleep(2)