from dataclasses import dataclass

@dataclass
class Buffer:
    data: bytearray
    in_use: bool

class SimplePool:
    def __init__(self, size: int, count: int):
        self.buffers: list = [
            Buffer(bytearray(size), False) for _ in range(count)
        ]

    def get(self, size: int) -> bytearray:
        for buffer in self.buffers:
            if not buffer.in_use:
                buffer.in_use = True
                return buffer.data
        # If no buffer available, create new one (shouldn't happen with proper pool size)
        return bytearray(size)

    def put(self, buffer: bytearray) -> None:
        for buf in self.buffers:
            if buf.data is buffer:
                buf.in_use = False
                break