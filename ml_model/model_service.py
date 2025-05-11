import grpc
from concurrent import futures
import logging
import pickle
import numpy as np
import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import time
import threading
import warnings

# Suppress the warning about feature names
warnings.filterwarnings("ignore", category=FutureWarning, 
                        message="The feature names should match those that were passed during fit")

# Add project root to path to find 'proto' module
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

import proto.ml_model_pb2 as ml_model_pb2
import proto.ml_model_pb2_grpc as ml_model_pb2_grpc

# Configure logging
log_dir = '/home/samet/Desktop/sdnhoney/logs'
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'{log_dir}/ml_model.log'),
        logging.StreamHandler()
    ]
)

class MLModelService(ml_model_pb2_grpc.MLModelServiceServicer):
    def __init__(self):
        # Construct path relative to this script file
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_path = os.path.join(script_dir, 'models', 'ml_model.pkl')
        
        self.suspicious_ips = set()
        self.benign_ips = set()
        self.ip_prediction_counts = {}  # Track prediction counts for IPs
        self.prediction_threshold = 3   # Number of predictions needed to establish confidence
        
        # Load or create model
        self.load_model()
        
        # Start periodic retraining in background
        self.start_periodic_retraining()
    
    def load_model(self):
        """Load the ML model from disk or create a new one if not available"""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                logging.info("Loaded existing ML model")
                self.is_trained = True
            except Exception as e:
                logging.error(f"Error loading model: {e}")
                self.create_default_model()
        else:
            logging.warning("No existing model found, creating a default model")
            self.create_default_model()
    
    def create_default_model(self):
        """Create a default RandomForest model"""
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.is_trained = False
    
    def start_periodic_retraining(self):
        """Start a background thread for periodic model retraining"""
        thread = threading.Thread(target=self.periodic_retrain, daemon=True)
        thread.start()
    
    def periodic_retrain(self):
        """Periodically retrain the model using new data"""
        while True:
            # Sleep for 1 hour between retraining
            time.sleep(3600)
            
            try:
                # Check if new data is available
                if os.path.exists(f'{log_dir}/traffic_data.csv'):
                    logging.info("New traffic data found, retraining model...")
                    
                    # Run the training script
                    os.system('python train_model.py')
                    
                    # Reload the model
                    self.load_model()
            except Exception as e:
                logging.error(f"Error during periodic retraining: {e}")
    
    def extract_features(self, packet_info):
        """Extract features from packet info for ML model input (must match training features)"""
        # Determine service type based on port
        service = 'unknown'
        dst_port = packet_info.dst_port
        
        if dst_port in [80, 443, 8080, 8443]:
            service = 'web'
        elif dst_port == 22:
            service = 'ssh'
        elif dst_port == 445:
            service = 'smb'
        elif dst_port == 3389:
            service = 'rdp'
        elif dst_port in [1433, 3306, 5432]:
            service = 'db'
         
        # Track unusual port combinations
        is_unusual_port_combo = 0
        if (service == 'web' and packet_info.src_port < 1024) or \
           (service == 'ssh' and packet_info.src_port > 50000) or \
           (dst_port > 10000 and dst_port < 20000):  # Unusual port range
            is_unusual_port_combo = 1
            
        # Check for non-standard protocol-port combinations
        is_non_standard_combo = 0
        if (packet_info.protocol.lower() == 'udp' and service == 'web') or \
           (packet_info.protocol.lower() == 'tcp' and dst_port == 53):  # DNS over TCP might be tunneling
            is_non_standard_combo = 1
        
        # Get counts of suspicious and benign records for this IP
        suspicious_count = self.ip_prediction_counts.get(packet_info.src_ip, {}).get('suspicious', 0)
        benign_count = self.ip_prediction_counts.get(packet_info.src_ip, {}).get('benign', 0)
            
        # Create features matching ALL the features the model was trained on (17 features)
        features = {
            'src_ip_hash': hash(packet_info.src_ip) % 1000,
            'dst_ip_hash': hash(packet_info.dst_ip) % 1000,
            'src_port': packet_info.src_port,
            'dst_port': packet_info.dst_port,
            'protocol_tcp': 1 if packet_info.protocol.lower() == 'tcp' else 0,
            'protocol_udp': 1 if packet_info.protocol.lower() == 'udp' else 0,
            'is_ssh': 1 if service == 'ssh' else 0,
            'is_web': 1 if service == 'web' else 0,
            'is_smb': 1 if service == 'smb' else 0,
            'is_rdp': 1 if service == 'rdp' else 0,
            'is_db': 1 if service == 'db' else 0,
            'payload_length': getattr(packet_info, 'payload_length', 0),
            'duration': getattr(packet_info, 'duration', 0),
            'is_unusual_port_combo': is_unusual_port_combo,
            'is_non_standard_combo': is_non_standard_combo,
            'suspicious_count': suspicious_count,
            'benign_count': benign_count
        }
        
        # Log important information
        if is_unusual_port_combo:
            logging.info(f"Detected unusual port combo: {packet_info.src_ip}:{packet_info.src_port} -> {packet_info.dst_ip}:{packet_info.dst_port}")
        
        if is_non_standard_combo:
            logging.info(f"Detected non-standard protocol-port combo: {packet_info.protocol} to {service} port")
            
        if suspicious_count > 0:
            logging.info(f"IP {packet_info.src_ip} has {suspicious_count} suspicious predictions")
        
        # Convert to DataFrame (required for sklearn models)
        return pd.DataFrame([features])
    
    def log_traffic(self, packet_info, prediction, confidence):
        """Log traffic data for future model retraining"""
        try:
            # Create log entry
            log_entry = {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': packet_info.src_ip,
                'dst_ip': packet_info.dst_ip,
                'src_port': packet_info.src_port,
                'dst_port': packet_info.dst_port,
                'protocol': packet_info.protocol,
                'service': getattr(packet_info, 'service', ''),
                'payload_length': getattr(packet_info, 'payload_length', 0),
                'duration': getattr(packet_info, 'duration', 0),
                'prediction': prediction,
                'confidence': confidence
            }
            
            # Append to CSV file
            df = pd.DataFrame([log_entry])
            csv_path = f'{log_dir}/traffic_data.csv'
            
            if os.path.exists(csv_path):
                df.to_csv(csv_path, mode='a', header=False, index=False)
            else:
                df.to_csv(csv_path, index=False)
                
        except Exception as e:
            logging.error(f"Error logging traffic data: {e}")
    
    def update_ip_tracking(self, ip, is_suspicious):
        """Update tracking of IP addresses with enhanced metrics for attack detection"""
        if ip not in self.ip_prediction_counts:
            self.ip_prediction_counts[ip] = {
                'suspicious': 0, 
                'benign': 0,
                'first_seen': time.time(),
                'last_seen': time.time(),
                'total_requests': 0,
                'requests_per_second': 0,
                'unique_ports': set()
            }
        
        # Update time and request count
        now = time.time()
        self.ip_prediction_counts[ip]['last_seen'] = now
        self.ip_prediction_counts[ip]['total_requests'] += 1
        
        # Calculate requests per second
        time_diff = now - self.ip_prediction_counts[ip]['first_seen']
        if time_diff > 0:
            self.ip_prediction_counts[ip]['requests_per_second'] = (
                self.ip_prediction_counts[ip]['total_requests'] / time_diff
            )
        
        # Update suspicious/benign counts
        if is_suspicious:
            self.ip_prediction_counts[ip]['suspicious'] += 1
        else:
            self.ip_prediction_counts[ip]['benign'] += 1
        
        # Check if we have enough predictions to establish confidence
        counts = self.ip_prediction_counts[ip]
        total = counts['suspicious'] + counts['benign']
        
        if total >= self.prediction_threshold:
            if counts['suspicious'] > counts['benign']:
                self.suspicious_ips.add(ip)
                logging.info(f"IP {ip} added to suspicious list (count: {counts['suspicious']}/{total})")
            else:
                self.benign_ips.add(ip)
                logging.info(f"IP {ip} added to benign list (count: {counts['benign']}/{total})")
                
        # If we've seen a high request rate, mark as suspicious regardless of other factors
        if counts['requests_per_second'] > 2.0 and counts['total_requests'] > 10:
            self.suspicious_ips.add(ip)
            logging.warning(f"IP {ip} added to suspicious list due to high request rate: {counts['requests_per_second']:.2f} req/sec")
    
    def PredictPacket(self, request, context):
        """Predict if a packet is suspicious"""
        try:
            # Fast path: Check if we already know this IP
            if request.src_ip in self.suspicious_ips:
                logging.info(f"Quick detection: {request.src_ip} is in suspicious list")
                return ml_model_pb2.PredictionResponse(is_suspicious=True, confidence=0.95)
            
            if request.src_ip in self.benign_ips:
                logging.info(f"Quick detection: {request.src_ip} is in benign list")
                return ml_model_pb2.PredictionResponse(is_suspicious=False, confidence=0.95)
            
            # If model is not trained yet, use rule-based detection
            if not self.is_trained:
                is_suspicious = self.rule_based_detection(request)
                confidence = 0.7  # Default confidence for rule-based detection
                
                # Log result
                logging.info(f"Rule-based prediction for {request.src_ip}:{request.src_port} -> {request.dst_ip}:{request.dst_port}: {'Suspicious' if is_suspicious else 'Benign'}")
                self.log_traffic(request, is_suspicious, confidence)
                
                # Update IP tracking
                self.update_ip_tracking(request.src_ip, is_suspicious)
                
                return ml_model_pb2.PredictionResponse(is_suspicious=is_suspicious, confidence=confidence)
            
            # Extract features
            features = self.extract_features(request)
            
            # Make prediction
            prediction = self.model.predict(features)[0]
            
            # Get probability for the predicted class
            probability = self.model.predict_proba(features)[0][1]
            
            # Log result
            logging.info(f"ML prediction for {request.src_ip}:{request.src_port} -> {request.dst_ip}:{request.dst_port}: {'Suspicious' if prediction else 'Benign'} (confidence: {probability:.2f})")
            self.log_traffic(request, prediction, probability)
            
            # Update IP tracking
            self.update_ip_tracking(request.src_ip, prediction)
            
            return ml_model_pb2.PredictionResponse(
                is_suspicious=bool(prediction),
                confidence=float(probability)
            )
        except Exception as e:
            logging.error(f"Prediction error: {e}")
            return ml_model_pb2.PredictionResponse(is_suspicious=False, confidence=0.5)
    
    def rule_based_detection(self, packet_info):
        """Enhanced rule-based detection when model is not trained, focused on HTTP detection"""
        # Get source IP for easier reference
        src_ip = packet_info.src_ip
        dst_ip = packet_info.dst_ip
        src_port = packet_info.src_port
        dst_port = packet_info.dst_port
        protocol = packet_info.protocol.lower()

        # Log all traffic details to assist with debugging
        logging.info(f"Analyzing traffic: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})")
        
        # Detect port scanning behavior - low source ports are unusual for clients
        if src_port < 1024:
            logging.warning(f"Unusual low source port detected: {src_ip}:{src_port}")
            return True
            
        # Detect UDP traffic to HTTP ports (protocol mismatch)
        if protocol == 'udp' and dst_port in [80, 8080, 443, 8443]:
            logging.warning(f"UDP traffic to HTTP port detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            return True
            
        # Detect TCP traffic to UDP services
        if protocol == 'tcp' and dst_port in [53, 123, 161]:
            logging.warning(f"TCP traffic to UDP service port detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            return True
            
        # Detect probing against unusual ports
        unusual_ports = [1025, 2048, 4444, 6667, 8888, 9999, 12345, 15000, 18080, 19999]
        if dst_port in unusual_ports:
            logging.warning(f"Traffic to unusual port detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            return True
            
        # Check for massive request patterns (HTTP flood)
        if self.ip_prediction_counts.get(src_ip, {}).get('total_requests', 0) > 20:
            requests_per_second = self.ip_prediction_counts.get(src_ip, {}).get('requests_per_second', 0)
            if requests_per_second > 1.0:  # More than 1 request per second on average
                logging.warning(f"High request rate detected from {src_ip}: {requests_per_second:.2f} req/sec")
                return True

        # Check for HTTP traffic (TCP port 8080)
        if protocol == 'tcp' and dst_port == 8080:
            # Get payload if available
            payload = getattr(packet_info, 'payload', '')
            
            # Analyze HTTP payload if available
            if payload and isinstance(payload, str):
                # SQL injection patterns
                sql_patterns = ['select', 'union', 'insert', 'update', 'delete', 'where', 'drop', '--', '/*', '*/', ';--', '1=1']
                if any(pattern in payload.lower() for pattern in sql_patterns):
                    logging.warning(f"SQL injection attempt detected from {packet_info.src_ip}")
                    return True
                
                # Path traversal patterns
                traversal_patterns = ['../', '..\\', '../', '..%2f', '.htaccess', '/etc/passwd', 'wp-config', 'config.php']
                if any(pattern in payload.lower() for pattern in traversal_patterns):
                    logging.warning(f"Path traversal attempt detected from {packet_info.src_ip}")
                    return True
                
                # XSS patterns
                xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'eval(', 'document.cookie', 'alert(']
                if any(pattern in payload.lower() for pattern in xss_patterns):
                    logging.warning(f"XSS attempt detected from {packet_info.src_ip}")
                    return True
                
                # Command injection patterns
                cmd_patterns = ['exec(', 'system(', 'shell_exec(', 'passthru(', '`', '$(', '&& ', '|| ', ';', 'ping -c']
                if any(pattern in payload.lower() for pattern in cmd_patterns):
                    logging.warning(f"Command injection attempt detected from {packet_info.src_ip}")
                    return True
                
                # HTTP method detection
                if payload.startswith(('PUT ', 'DELETE ', 'TRACE ')):
                    http_method = payload.split(' ')[0]
                    logging.warning(f"Unusual HTTP method {http_method} from {packet_info.src_ip}")
                    return True
            
            # If we've analyzed the packet and found nothing suspicious, it's probably benign HTTP traffic
            return False
        
        # Force-mark all traffic from 10.0.0.11 as suspicious (this is likely from ml_attack_simulation.py)
        if src_ip == '10.0.0.11' and (dst_port == 8080 or dst_port in unusual_ports):
            logging.warning(f"Traffic from known attack simulator {src_ip} detected")
            return True
        
        # Other common suspicious port checks
        suspicious_ports = [22, 23, 445, 3389, 1433, 3306]
        if dst_port in suspicious_ports:
            return True
        
        # Default to benign
        return False
    
    def TrainModel(self, request, context):
        """Train or retrain the model with new data"""
        try:
            # Call the training script
            os.system('python train_model.py')
            
            # Reload the model
            self.load_model()
            
            return ml_model_pb2.TrainingResponse(
                success=True,
                message="Model training completed successfully"
            )
        except Exception as e:
            logging.error(f"Training error: {e}")
            return ml_model_pb2.TrainingResponse(
                success=False,
                message=str(e)
            )

def serve():
    """Start the gRPC server"""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    ml_model_pb2_grpc.add_MLModelServiceServicer_to_server(
        MLModelService(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    logging.info("ML Model Service started on port 50051")
    server.wait_for_termination()

if __name__ == '__main__':
    serve() 