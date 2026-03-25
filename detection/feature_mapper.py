import numpy as np

def map_to_ml_features(packet_features, feature_names):
    data = np.zeros(len(feature_names))

    # Simple mapping (you can improve later)
    if 'packet_size' in packet_features:
        data[0] = packet_features['packet_size']

    if 'protocol' in packet_features:
        data[1] = packet_features['protocol']

    return data