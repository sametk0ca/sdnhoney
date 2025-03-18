import grpc
from concurrent import futures
import random
import ml_model_pb2
import ml_model_pb2_grpc

class MLModelService(ml_model_pb2_grpc.MLModelServiceServicer):
    def PredictPacket(self, request, context):
        # Simüle edilmiş model: Rastgele 0 veya 1 döndür
        is_suspicious = random.randint(0, 1)
        print(f"Paket alındı: {request.src_ip} -> {request.dst_ip}, Şüpheli mi: {is_suspicious}")
        return ml_model_pb2.Prediction(is_suspicious=is_suspicious)

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    ml_model_pb2_grpc.add_MLModelServiceServicer_to_server(MLModelService(), server)
    server.add_insecure_port('[::]:50051')  # Port 50051’de çalışacak
    print("gRPC sunucusu başlatıldı, port: 50051")
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    serve()
