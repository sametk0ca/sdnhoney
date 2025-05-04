# -*- coding: utf-8 -*-
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

from . import ml_model_pb2 as ml__model__pb2


class MLModelServiceStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.PredictPacket = channel.unary_unary(
                '/ml_model.MLModelService/PredictPacket',
                request_serializer=ml__model__pb2.PacketInfo.SerializeToString,
                response_deserializer=ml__model__pb2.PredictionResponse.FromString,
                )
        self.TrainModel = channel.unary_unary(
                '/ml_model.MLModelService/TrainModel',
                request_serializer=ml__model__pb2.TrainingRequest.SerializeToString,
                response_deserializer=ml__model__pb2.TrainingResponse.FromString,
                )


class MLModelServiceServicer(object):
    """Missing associated documentation comment in .proto file."""

    def PredictPacket(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def TrainModel(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_MLModelServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'PredictPacket': grpc.unary_unary_rpc_method_handler(
                    servicer.PredictPacket,
                    request_deserializer=ml__model__pb2.PacketInfo.FromString,
                    response_serializer=ml__model__pb2.PredictionResponse.SerializeToString,
            ),
            'TrainModel': grpc.unary_unary_rpc_method_handler(
                    servicer.TrainModel,
                    request_deserializer=ml__model__pb2.TrainingRequest.FromString,
                    response_serializer=ml__model__pb2.TrainingResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'ml_model.MLModelService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class MLModelService(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def PredictPacket(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/ml_model.MLModelService/PredictPacket',
            ml__model__pb2.PacketInfo.SerializeToString,
            ml__model__pb2.PredictionResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def TrainModel(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/ml_model.MLModelService/TrainModel',
            ml__model__pb2.TrainingRequest.SerializeToString,
            ml__model__pb2.TrainingResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
