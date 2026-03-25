import pandas as pd
import numpy as np
import joblib

from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping

# ======================================
# 1. Load Training Data
# ======================================

print("Loading datasets...")

X_train = pd.read_csv("ae_train.csv")
X_val = pd.read_csv("ae_val.csv")

print("Train shape:", X_train.shape)
print("Validation shape:", X_val.shape)

# Remove label if present
if "Label" in X_train.columns:
    X_train = X_train.drop("Label", axis=1)

if "Label" in X_val.columns:
    X_val = X_val.drop("Label", axis=1)

input_dim = X_train.shape[1]

# ======================================
# 2. Build Autoencoder
# ======================================

input_layer = Input(shape=(input_dim,))

# Encoder
x = Dense(128, activation="relu")(input_layer)
x = Dropout(0.2)(x)

x = Dense(64, activation="relu")(x)
x = Dropout(0.2)(x)

encoded = Dense(32, activation="relu")(x)

# Decoder
x = Dense(64, activation="relu")(encoded)
x = Dense(128, activation="relu")(x)

decoded = Dense(input_dim, activation="sigmoid")(x)

autoencoder = Model(inputs=input_layer, outputs=decoded)

autoencoder.compile(
    optimizer="adam",
    loss="mse"
)

autoencoder.summary()

# ======================================
# 3. Train Model
# ======================================

early_stop = EarlyStopping(
    monitor="val_loss",
    patience=5,
    restore_best_weights=True
)

print("Training Autoencoder...")

history = autoencoder.fit(
    X_train,
    X_train,
    epochs=50,
    batch_size=256,
    shuffle=True,
    validation_data=(X_val, X_val),
    callbacks=[early_stop]
)

# ======================================
# 4. Save Model
# ======================================

autoencoder.save("autoencoder_model.h5")

print("Model saved.")

# ======================================
# 5. Calculate Threshold
# ======================================

print("Calculating anomaly threshold...")

reconstructions = autoencoder.predict(X_train)

mse_train = np.mean(np.power(X_train.values - reconstructions, 2), axis=1)

# Better threshold for anomaly detection
threshold = np.percentile(mse_train, 99)

print("Threshold:", threshold)

joblib.dump(threshold, "threshold.pkl")

print("Threshold saved.")