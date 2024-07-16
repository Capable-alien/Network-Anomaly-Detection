#train_model.py
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import joblib

# Load dataset
dataset_file = 'dataset/network_traffic.csv'
data = pd.read_csv(dataset_file, header=None, names=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'])

# Label encode IP addresses
label_encoder = LabelEncoder()
data['src_ip'] = label_encoder.fit_transform(data['src_ip'])
data['dst_ip'] = label_encoder.fit_transform(data['dst_ip'])

# Example of adding more features
data['timestamp'] = pd.to_datetime('now').timestamp()  # Placeholder for timestamp
data['flags'] = 0  # Placeholder for flags, adjust as necessary

# Drop protocol as it's not needed for unsupervised anomaly detection
X = data.drop('protocol', axis=1)

# Define feature names
feature_names = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'timestamp', 'flags']
X.columns = feature_names

# Train Isolation Forest
clf = IsolationForest(contamination=0.01, random_state=42)
clf.fit(X)

# Save the trained model to disk
model_file = 'saved_models/iso_forest_model.joblib'
joblib.dump(clf, model_file)

# Save the LabelEncoder to disk
encoder_file = 'saved_models/label_encoder.joblib'
joblib.dump(label_encoder, encoder_file)

print("Model and LabelEncoder saved.")
