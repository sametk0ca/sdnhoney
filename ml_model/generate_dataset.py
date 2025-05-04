#!/usr/bin/env python3
import numpy as np
import pandas as pd
import os
import random
import pickle
from sklearn.model_selection import train_test_split

# Ensure directories exist
os.makedirs('models', exist_ok=True)
os.makedirs('../logs', exist_ok=True)

def generate_synthetic_dataset(num_samples=10000):
    """Generate a synthetic dataset for training the ML model"""
    print("Generating synthetic dataset...")
    
    # Common ports
    common_ports = {
        'web': [80, 443, 8080, 8443],
        'ssh': [22],
        'smb': [445],
        'rdp': [3389],
        'db': [1433, 3306, 5432],
        'telnet': [23],
        'ftp': [20, 21],
        'dns': [53],
        'ntp': [123],
        'smtp': [25, 587],
        'imap': [143, 993],
        'pop3': [110, 995]
    }
    
    # IP ranges
    internal_ip_prefix = '10.0.0.'
    external_ip_prefix = ['172.16.', '192.168.', '91.', '104.', '209.']
    malicious_ip_prefix = ['45.', '185.', '77.', '95.', '23.']
    
    data = []
    
    # Generate benign internal traffic (80% accuracy, 20% will be incorrectly labeled)
    for _ in range(int(num_samples * 0.4)):
        src_ip = internal_ip_prefix + str(random.randint(1, 20))
        dst_ip = internal_ip_prefix + str(random.randint(1, 20))
        
        # Randomly select service category
        service_type = random.choice(list(common_ports.keys()))
        dst_port = random.choice(common_ports[service_type])
        src_port = random.randint(49152, 65535)  # Ephemeral ports
        
        protocol = 'tcp' if dst_port not in [53, 123] else 'udp'
        payload_length = random.randint(64, 1500)
        duration = round(random.uniform(0.001, 1.0), 3)
        
        # 80% accuracy
        is_malicious = 0 if random.random() < 0.8 else 1
        
        data.append({
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'service': service_type,
            'payload_length': payload_length,
            'duration': duration,
            'is_malicious': is_malicious
        })
    
    # Generate benign external to internal traffic (70% accuracy)
    for _ in range(int(num_samples * 0.2)):
        src_ip = random.choice(external_ip_prefix) + str(random.randint(1, 255))
        dst_ip = internal_ip_prefix + str(random.randint(1, 20))
        
        # Mostly web traffic
        service_type = random.choice(['web'] * 7 + list(common_ports.keys()))
        dst_port = random.choice(common_ports[service_type])
        src_port = random.randint(49152, 65535)
        
        protocol = 'tcp' if dst_port not in [53, 123] else 'udp'
        payload_length = random.randint(64, 1500)
        duration = round(random.uniform(0.001, 2.0), 3)
        
        # 70% accuracy
        is_malicious = 0 if random.random() < 0.7 else 1
        
        data.append({
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'service': service_type,
            'payload_length': payload_length,
            'duration': duration,
            'is_malicious': is_malicious
        })
    
    # Generate malicious traffic (90% accuracy)
    for _ in range(int(num_samples * 0.4)):
        src_ip = random.choice(malicious_ip_prefix) + str(random.randint(1, 255))
        dst_ip = internal_ip_prefix + str(random.randint(1, 20))
        
        # Specific patterns for attacks
        attack_type = random.choice([
            'scan', 'ssh_bruteforce', 'smb_exploit', 'rdp_bruteforce', 
            'web_exploit', 'sql_injection'
        ])
        
        if attack_type == 'scan':
            dst_port = random.choice([22, 23, 80, 443, 445, 3389, 8080])
            payload_length = random.randint(40, 100)
            duration = round(random.uniform(0.001, 0.05), 3)
            service_type = next((k for k, v in common_ports.items() if dst_port in v), 'scan')
        
        elif attack_type == 'ssh_bruteforce':
            dst_port = 22
            payload_length = random.randint(100, 300)
            duration = round(random.uniform(0.1, 0.5), 3)
            service_type = 'ssh'
        
        elif attack_type == 'smb_exploit':
            dst_port = 445
            payload_length = random.randint(500, 1500)
            duration = round(random.uniform(0.1, 0.3), 3)
            service_type = 'smb'
        
        elif attack_type == 'rdp_bruteforce':
            dst_port = 3389
            payload_length = random.randint(200, 600)
            duration = round(random.uniform(0.2, 0.7), 3)
            service_type = 'rdp'
        
        elif attack_type == 'web_exploit':
            dst_port = random.choice([80, 443, 8080, 8443])
            payload_length = random.randint(800, 2000)
            duration = round(random.uniform(0.05, 0.2), 3)
            service_type = 'web'
        
        elif attack_type == 'sql_injection':
            dst_port = random.choice([80, 443, 8080, 3306, 1433, 5432])
            payload_length = random.randint(500, 1000)
            duration = round(random.uniform(0.05, 0.3), 3)
            service_type = 'web' if dst_port in [80, 443, 8080] else 'db'
        
        src_port = random.randint(49152, 65535)
        protocol = 'tcp'
        
        # 90% accuracy
        is_malicious = 1 if random.random() < 0.9 else 0
        
        data.append({
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'service': service_type,
            'payload_length': payload_length,
            'duration': duration,
            'is_malicious': is_malicious,
            'attack_type': attack_type
        })
    
    # Convert to DataFrame
    df = pd.DataFrame(data)
    
    # Add timestamp
    current_time = pd.Timestamp.now()
    timestamps = [(current_time - pd.Timedelta(seconds=random.uniform(0, 3600))).isoformat() 
                  for _ in range(len(df))]
    df['timestamp'] = timestamps
    
    return df

def preprocess_dataset(df):
    """Preprocess the dataset for ML model training"""
    print("Preprocessing dataset...")
    
    # Create feature vectors
    X = pd.DataFrame({
        'src_ip_hash': df['src_ip'].apply(lambda x: hash(x) % 1000),
        'dst_ip_hash': df['dst_ip'].apply(lambda x: hash(x) % 1000),
        'src_port': df['src_port'],
        'dst_port': df['dst_port'],
        'protocol_tcp': df['protocol'].apply(lambda x: 1 if x == 'tcp' else 0),
        'protocol_udp': df['protocol'].apply(lambda x: 1 if x == 'udp' else 0),
        'is_ssh': df['service'].apply(lambda x: 1 if x == 'ssh' else 0),
        'is_web': df['service'].apply(lambda x: 1 if x == 'web' else 0),
        'is_smb': df['service'].apply(lambda x: 1 if x == 'smb' else 0),
        'is_rdp': df['service'].apply(lambda x: 1 if x == 'rdp' else 0),
        'is_db': df['service'].apply(lambda x: 1 if x == 'db' else 0),
        'payload_length': df['payload_length'],
        'duration': df['duration']
    })
    
    y = df['is_malicious']
    
    # Split into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    return X_train, X_test, y_train, y_test

def save_dataset(df, X_train, X_test, y_train, y_test):
    """Save the dataset and split data"""
    print("Saving dataset...")
    
    # Save the full dataset as CSV
    df.to_csv('models/network_traffic_dataset.csv', index=False)
    
    # Save the training data as pickle files
    with open('models/X_train.pkl', 'wb') as f:
        pickle.dump(X_train, f)
    
    with open('models/X_test.pkl', 'wb') as f:
        pickle.dump(X_test, f)
    
    with open('models/y_train.pkl', 'wb') as f:
        pickle.dump(y_train, f)
    
    with open('models/y_test.pkl', 'wb') as f:
        pickle.dump(y_test, f)
    
    print(f"Dataset saved to models/network_traffic_dataset.csv")
    print(f"Training data saved to models/ directory")

def generate_feature_columns():
    """Generate feature column names for the dataset"""
    return [
        'src_ip_hash', 'dst_ip_hash', 'src_port', 'dst_port',
        'protocol_tcp', 'protocol_udp', 'is_ssh', 'is_web', 'is_smb', 'is_rdp', 'is_db',
        'payload_length', 'duration',
        # New features for better detection
        'is_unusual_port_combo', 'is_non_standard_combo', 'suspicious_count', 'benign_count'
    ]

if __name__ == '__main__':
    # Generate dataset
    df = generate_synthetic_dataset()
    
    # Preprocess dataset
    X_train, X_test, y_train, y_test = preprocess_dataset(df)
    
    # Save dataset
    save_dataset(df, X_train, X_test, y_train, y_test)
    
    print("Dataset generation complete!") 