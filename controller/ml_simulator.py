import grpc
from concurrent import futures
import random
import ml_model_pb2
import ml_model_pb2_grpc
import logging

# Loglama ayarları
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/samet/capstone/logs/ml_service.log'),
        logging.StreamHandler()
    ]
)

class MLModelService(ml_model_pb2_grpc.MLModelServiceServicer):
    def PredictPacket(self, request, context):
        # Gelen paket bilgilerini logla
        logging.info(f"Paket alındı: {request.src_ip}:{request.src_port} -> {request.dst_ip}:{request.dst_port} (Proto: {request.protocol})")
        
        # Rastgele tahmin (0 = normal, 1 = şüpheli)
        # %20 olasılıkla şüpheli (1) döndür
        is_suspicious = 1 if random.random() < 0.2 else 0
        
        # Şüpheli trafik için belirli port/protokol kuralları da ekleyebiliriz
        if request.dst_port in [22, 23, 3389, 445, 135, 139]:  # SSH, Telnet, RDP, SMB vb.
            is_suspicious = 1
        
        # Sonucu logla
        logging.info(f"Tahmin: Şüpheli mi: {is_suspicious} (src_ip: {request.src_ip}, dst_ip: {request.dst_ip})")
        
        return ml_model_pb2.Prediction(is_suspicious=is_suspicious)

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    ml_model_pb2_grpc.add_MLModelServiceServicer_to_server(MLModelService(), server)
    server.add_insecure_port('[::]:50051')  # Port 50051'de çalışacak
    logging.info("gRPC sunucusu başlatıldı, port: 50051")
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    serve()
