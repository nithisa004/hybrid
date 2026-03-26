import numpy as np

def map_to_ml_features(packet_features, num_features=77):
    """
    Map raw packet features to a 77-feature vector expected by the ML model.
    This is a simplified mapping for demonstration.
    """
    data = np.zeros(num_features)
    
    # Map basic features to specific indices (representative of NSL-KDD/CICIDS formats)
    if 'packet_size' in packet_features:
        data[0] = packet_features['packet_size'] / 1500.0 # Normalized size
    
    if 'protocol' in packet_features:
        data[1] = packet_features['protocol']
        
    if 'src_port' in packet_features:
        data[2] = packet_features['src_port'] / 65535.0
        
    if 'dst_port' in packet_features:
        data[3] = packet_features['dst_port'] / 65535.0
        
    # Fill remaining with small random noise or defaults to keep it "live"
    return data.tolist()