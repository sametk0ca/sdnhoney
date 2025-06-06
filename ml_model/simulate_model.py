#!/usr/bin/env python3

import json
import time
import random
from datetime import datetime
from collections import defaultdict

class SimpleMLSimulator:
    """
    Simplified ML model simulator that returns binary classification (1 or 0)
    - 1: Malicious traffic (should be redirected to deep honeypot)
    - 0: Benign traffic (can stay or go to normal servers)
    """
    
    def __init__(self):
        # Track IP behavior for consistent classification
        self.ip_behavior = {}
        self.request_history = defaultdict(list)
        
        # Simple parameters for classification
        self.malicious_threshold = 0.6
        self.time_window = 300  # 5 minutes in seconds
        
    def analyze_features(self, source_ip, request_data=None):
        """Extract simple features for classification"""
        current_time = time.time()
        
        # Clean old requests
        self.request_history[source_ip] = [
            req_time for req_time in self.request_history[source_ip]
            if current_time - req_time < self.time_window
        ]
        
        # Add current request
        self.request_history[source_ip].append(current_time)
        
        # Calculate features
        features = {
            'request_frequency': len(self.request_history[source_ip]),
            'time_since_first': current_time - min(self.request_history[source_ip]) if self.request_history[source_ip] else 0,
            'is_rapid_fire': len(self.request_history[source_ip]) > 10,  # More than 10 requests in 5 minutes
            'username_suspicious': False,
            'user_agent_suspicious': False
        }
        
        # Analyze request data if provided
        if request_data:
            username = request_data.get('username', '').lower()
            user_agent = request_data.get('user_agent', '').lower()
            
            # Suspicious usernames
            attack_usernames = ['admin', 'root', 'administrator', 'test', 'guest', 'user', 'oracle', 'sa']
            features['username_suspicious'] = username in attack_usernames
            
            # Suspicious user agents
            bot_agents = ['curl', 'wget', 'python', 'bot', 'scanner', 'exploit', 'nikto']
            features['user_agent_suspicious'] = any(bot in user_agent for bot in bot_agents)
        
        return features
    
    def predict(self, source_ip, request_data=None):
        """
        Main prediction function that returns binary classification
        Returns: 1 for malicious, 0 for benign
        """
        features = self.analyze_features(source_ip, request_data)
        
        # Calculate risk score (0.0 to 1.0)
        risk_score = 0.0
        
        # Request frequency factor
        if features['request_frequency'] > 15:
            risk_score += 0.4
        elif features['request_frequency'] > 5:
            risk_score += 0.2
        
        # Rapid fire requests
        if features['is_rapid_fire']:
            risk_score += 0.3
        
        # Suspicious username
        if features['username_suspicious']:
            risk_score += 0.3
        
        # Suspicious user agent
        if features['user_agent_suspicious']:
            risk_score += 0.2
        
        # Add some randomness for simulation (to avoid perfect predictability)
        risk_score += random.uniform(-0.1, 0.1)
        risk_score = max(0.0, min(1.0, risk_score))  # Clamp to [0, 1]
        
        # Store behavior for consistency
        self.ip_behavior[source_ip] = {
            'risk_score': risk_score,
            'features': features,
            'last_update': time.time()
        }
        
        # Binary classification
        classification = 1 if risk_score >= self.malicious_threshold else 0
        
        return {
            'prediction': classification,
            'risk_score': risk_score,
            'confidence': abs(risk_score - 0.5) * 2,  # Distance from boundary
            'features': features,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_ip_status(self, source_ip):
        """Get current status of an IP"""
        if source_ip in self.ip_behavior:
            return self.ip_behavior[source_ip]
        return None
    
    def reset_ip(self, source_ip):
        """Reset tracking for an IP"""
        if source_ip in self.ip_behavior:
            del self.ip_behavior[source_ip]
        if source_ip in self.request_history:
            del self.request_history[source_ip]

# Global ML model instance
ml_model = SimpleMLSimulator()

def classify_traffic(source_ip, request_data=None):
    """
    Simple interface function for triage honeypot
    Returns: 1 for malicious, 0 for benign
    """
    result = ml_model.predict(source_ip, request_data)
    return result['prediction'], result['risk_score']

if __name__ == '__main__':
    # Test the ML simulator
    print("Simple ML Model Simulator Test")
    print("=" * 40)
    
    # Test cases
    test_cases = [
        ('10.0.0.6', {'username': 'admin', 'user_agent': 'curl/7.68.0'}),
        ('10.0.0.6', {'username': 'admin', 'user_agent': 'curl/7.68.0'}),
        ('10.0.0.6', {'username': 'admin', 'user_agent': 'curl/7.68.0'}),
        ('192.168.1.100', {'username': 'john', 'user_agent': 'Mozilla/5.0'}),
        ('192.168.1.100', {'username': 'mary', 'user_agent': 'Mozilla/5.0'}),
    ]
    
    for ip, data in test_cases:
        prediction, risk_score = classify_traffic(ip, data)
        print(f"IP: {ip}, Username: {data['username']}, Prediction: {prediction}, Risk: {risk_score:.3f}") 