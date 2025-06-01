#!/usr/bin/env python3

import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import os
from collections import defaultdict

class HoneypotMLSimulator:
    """Simulated ML model for traffic classification"""
    
    def __init__(self):
        self.log_dir = '/home/samet/Desktop/sdnhoney/logs'
        self.model_features = [
            'request_frequency',
            'failed_attempts',
            'time_pattern_score',
            'user_agent_score',
            'username_score',
            'ip_reputation_score'
        ]
    
    def extract_features(self, source_ip, time_window_hours=1):
        """Extract features from log data for a specific IP"""
        features = {
            'request_frequency': 0,
            'failed_attempts': 0,
            'time_pattern_score': 0,
            'user_agent_score': 0,
            'username_score': 0,
            'ip_reputation_score': 0
        }
        
        # Load logs from all honeypots and servers
        all_logs = []
        for log_file in ['triage_honeypot.log', 'deep_honeypot.log', 'normal_server_1.log', 
                        'normal_server_2.log', 'normal_server_3.log']:
            log_path = os.path.join(self.log_dir, log_file)
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    for line in f:
                        try:
                            log_entry = json.loads(line.strip())
                            if log_entry.get('source_ip') == source_ip:
                                all_logs.append(log_entry)
                        except json.JSONDecodeError:
                            continue
        
        if not all_logs:
            return features
        
        # Filter logs within time window
        current_time = datetime.now()
        time_threshold = current_time - timedelta(hours=time_window_hours)
        
        recent_logs = []
        for log in all_logs:
            try:
                log_time = datetime.fromisoformat(log['timestamp'])
                if log_time >= time_threshold:
                    recent_logs.append(log)
            except:
                continue
        
        # Calculate features
        features['request_frequency'] = len(recent_logs)
        
        # Failed attempts
        failed_count = sum(1 for log in recent_logs 
                          if log.get('request_type') == 'login_attempt' and not log.get('success', False))
        features['failed_attempts'] = failed_count
        
        # Time pattern analysis (rapid succession requests are suspicious)
        if len(recent_logs) > 1:
            time_diffs = []
            for i in range(1, len(recent_logs)):
                try:
                    t1 = datetime.fromisoformat(recent_logs[i-1]['timestamp'])
                    t2 = datetime.fromisoformat(recent_logs[i]['timestamp'])
                    diff = (t2 - t1).total_seconds()
                    time_diffs.append(diff)
                except:
                    continue
            
            if time_diffs:
                avg_time_diff = np.mean(time_diffs)
                if avg_time_diff < 5:  # Less than 5 seconds between requests
                    features['time_pattern_score'] = 50
                elif avg_time_diff < 30:
                    features['time_pattern_score'] = 25
        
        # User agent analysis
        user_agents = [log.get('user_agent', '') for log in recent_logs]
        suspicious_agents = ['curl', 'wget', 'python', 'bot', 'scanner', 'exploit']
        for agent in user_agents:
            if any(suspicious in agent.lower() for suspicious in suspicious_agents):
                features['user_agent_score'] += 20
        
        # Username analysis
        usernames = [log.get('username', '') for log in recent_logs if log.get('username')]
        attack_usernames = ['admin', 'root', 'administrator', 'test', 'guest', 'user']
        for username in usernames:
            if username.lower() in attack_usernames:
                features['username_score'] += 15
        
        # IP reputation (simplified - could integrate with threat intelligence)
        # For now, just check for private/internal IPs
        if source_ip.startswith('10.') or source_ip.startswith('192.168.') or source_ip.startswith('172.'):
            features['ip_reputation_score'] = 0  # Internal IP
        else:
            features['ip_reputation_score'] = 10  # External IP gets some score
        
        return features
    
    def classify_traffic(self, source_ip):
        """Classify traffic as normal, suspicious, or malicious"""
        features = self.extract_features(source_ip)
        
        # Calculate risk score
        risk_score = (
            min(features['request_frequency'] * 2, 40) +  # Cap at 40
            min(features['failed_attempts'] * 10, 50) +    # Cap at 50
            features['time_pattern_score'] +
            min(features['user_agent_score'], 30) +        # Cap at 30
            min(features['username_score'], 30) +          # Cap at 30
            features['ip_reputation_score']
        )
        
        # Classification thresholds
        if risk_score >= 80:
            classification = 'malicious'
            confidence = min(0.9, 0.6 + (risk_score - 80) * 0.01)
        elif risk_score >= 40:
            classification = 'suspicious'
            confidence = min(0.8, 0.5 + (risk_score - 40) * 0.0075)
        else:
            classification = 'normal'
            confidence = min(0.9, 0.7 - risk_score * 0.01)
        
        return {
            'classification': classification,
            'confidence': confidence,
            'risk_score': risk_score,
            'features': features,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_training_data(self):
        """Extract training data from honeypot logs"""
        training_data = []
        
        # Load all honeypot logs (these are malicious by definition)
        for honeypot_log in ['triage_honeypot.log', 'deep_honeypot.log']:
            log_path = os.path.join(self.log_dir, honeypot_log)
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    for line in f:
                        try:
                            log_entry = json.loads(line.strip())
                            features = self.extract_features(log_entry['source_ip'])
                            features['label'] = 'malicious'  # Honeypot traffic is malicious
                            training_data.append(features)
                        except:
                            continue
        
        # Load normal server logs (legitimate traffic)
        for server_log in ['normal_server_1.log', 'normal_server_2.log', 'normal_server_3.log']:
            log_path = os.path.join(self.log_dir, server_log)
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    for line in f:
                        try:
                            log_entry = json.loads(line.strip())
                            if log_entry.get('success', False):  # Successful logins are likely legitimate
                                features = self.extract_features(log_entry['source_ip'])
                                features['label'] = 'normal'
                                training_data.append(features)
                        except:
                            continue
        
        return training_data
    
    def retrain_model(self):
        """Simulate model retraining with new data"""
        training_data = self.get_training_data()
        
        if len(training_data) < 10:
            print("Insufficient training data for retraining")
            return False
        
        # Convert to DataFrame
        df = pd.DataFrame(training_data)
        
        # Basic statistics
        malicious_count = len(df[df['label'] == 'malicious'])
        normal_count = len(df[df['label'] == 'normal'])
        
        print(f"Retraining model with {len(training_data)} samples:")
        print(f"  - Malicious: {malicious_count}")
        print(f"  - Normal: {normal_count}")
        
        # In a real implementation, this would train a scikit-learn model
        # For now, we'll just save the training data
        training_file = os.path.join(self.log_dir, 'training_data.json')
        with open(training_file, 'w') as f:
            json.dump(training_data, f, indent=2)
        
        print("Model retrained and saved")
        return True
    
    def generate_report(self):
        """Generate a summary report of recent activity"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_ips_analyzed': 0,
            'classifications': {'normal': 0, 'suspicious': 0, 'malicious': 0},
            'top_threats': [],
            'summary': ''
        }
        
        # Analyze recent unique IPs
        unique_ips = set()
        for log_file in os.listdir(self.log_dir):
            if log_file.endswith('.log'):
                log_path = os.path.join(self.log_dir, log_file)
                with open(log_path, 'r') as f:
                    for line in f:
                        try:
                            log_entry = json.loads(line.strip())
                            unique_ips.add(log_entry['source_ip'])
                        except:
                            continue
        
        # Classify each IP
        threat_details = []
        for ip in unique_ips:
            result = self.classify_traffic(ip)
            report['classifications'][result['classification']] += 1
            
            if result['classification'] != 'normal':
                threat_details.append({
                    'ip': ip,
                    'classification': result['classification'],
                    'risk_score': result['risk_score'],
                    'confidence': result['confidence']
                })
        
        report['total_ips_analyzed'] = len(unique_ips)
        report['top_threats'] = sorted(threat_details, key=lambda x: x['risk_score'], reverse=True)[:10]
        
        # Generate summary
        malicious_count = report['classifications']['malicious']
        suspicious_count = report['classifications']['suspicious']
        report['summary'] = f"Analyzed {len(unique_ips)} unique IPs. Found {malicious_count} malicious and {suspicious_count} suspicious sources."
        
        return report

if __name__ == '__main__':
    # Test the ML simulator
    ml_model = HoneypotMLSimulator()
    
    print("Honeypot ML Model Simulator")
    print("=" * 40)
    
    # Generate report
    report = ml_model.generate_report()
    print(f"Report: {report['summary']}")
    
    # Attempt retraining
    ml_model.retrain_model() 