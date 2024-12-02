from proto.tendermint.p2p.types_pb2 import NodeInfo


class Proto:

    def __init__(self, obj):
        self.obj = obj

    def __getattr__(self, name):
        return getattr(self.obj, name)

    def __setattr__(self, name, value):
        if name == 'obj':
            super().__setattr__(name, value)
        else:
            setattr(self.obj, name, value)

    def get(self):
        return self.obj

    def serialize(self) -> bytes:
        return self.obj.SerializeToString()

    def deserialize(self, data: bytes):
        return self.obj.ParseFromString(data)


class NodeInfoProto(Proto):

    def __init__(self):
        super().__init__(NodeInfo())

