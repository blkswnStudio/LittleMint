import socket
import struct
import threading
import time

import cryptography
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from hashlib import new as newhash
from dataclasses import dataclass
import binascii
import hmac
import hashlib
import math
from merlin_transcripts import MerlinTranscript

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


class SecretConnection:
    AEAD_SIZE_OVERHEAD = 16

    DATA_LEN_SIZE = 4
    DATA_MAX_SIZE = 1024
    TOTAL_FRAME_SIZE = 1028


    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.socket = None
        self.send_cipher = None
        self.recv_cipher = None
        self.send_nonce = bytearray(12)
        self.recv_nonce = bytearray(12)

        self.send_mtx = threading.Lock()
        self.recv_mtx = threading.Lock()

        # Create buffer pool (matching Go's sync.Pool behavior)
        self.pool = SimplePool(
            max(self.TOTAL_FRAME_SIZE, self.AEAD_SIZE_OVERHEAD + self.TOTAL_FRAME_SIZE),
            2  # Keep two buffers in pool for frame and sealedFrame
        )

    def connect(self, local_priv_key: bytes, local_pub_key: bytes) -> None:
        """Establish secure connection using STS protocol"""
        # Create socket connection
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

        print(local_pub_key.hex())
        print(local_priv_key.hex())

        # Generate ephemeral keypair
        local_eph_pub_key, local_eph_priv_key = self._generate_ephemeral_keypair()

        # Step 1: Send ephemeral public key
        self.socket.sendall(bytes.fromhex("220a20") + local_eph_pub_key)

        # Step 2: Receive peer's ephemeral public key
        remote_eph_pub_key = self.socket.recv(64)[3:]

        # Sort keys and determine if we're the "lower" party
        lo_eph_pub_key, hi_eph_pub_key = self._sort_keys(local_eph_pub_key, remote_eph_pub_key)
        local_is_lower = (lo_eph_pub_key == local_eph_pub_key)

        # Create transcript for key derivation
        transcript = MerlinTranscript(b'TENDERMINT_SECRET_CONNECTION_TRANSCRIPT_HASH')
        transcript.append_message(b"EPHEMERAL_LOWER_PUBLIC_KEY", lo_eph_pub_key)
        transcript.append_message(b"EPHEMERAL_UPPER_PUBLIC_KEY", hi_eph_pub_key)

        # Compute shared secret using X25519
        shared_secret = self._compute_shared_secret(remote_eph_pub_key, local_eph_priv_key)
        transcript.append_message(b"DH_SECRET", shared_secret)

        # Derive encryption keys
        recv_key, send_key = self._derive_secrets(shared_secret, local_is_lower)

        # Initialize ciphers
        self.send_cipher = ChaCha20Poly1305(send_key)
        self.recv_cipher = ChaCha20Poly1305(recv_key)

        # Generate challenge for authentication
        challenge = transcript.challenge_bytes(b"SECRET_CONNECTION_MAC", 32)

        # Sign challenge with long-term private key
        key = ed25519.Ed25519PrivateKey.from_private_bytes(local_priv_key)
        local_signature = key.sign(challenge)
        key.public_key().verify(local_signature, challenge)

        # Exchange signatures and public keys
        self._exchange_auth(local_pub_key, local_signature)

    def generate_keypair(self) -> tuple[bytes, bytes]:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        return public_key.public_bytes_raw(), private_key.private_bytes_raw()


    def _generate_ephemeral_keypair(self) -> tuple[bytes, bytes]:
        """Generate ephemeral X25519 keypair"""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()

        return public_key.public_bytes_raw(), private_key.private_bytes_raw()

    def _compute_shared_secret(self, remote_pub: bytes, local_priv: bytes) -> bytes:
        """Compute shared secret using X25519"""
        if len(remote_pub) != 32 or len(local_priv) != 32:
            raise ValueError("Invalid key length")

        private_key = x25519.X25519PrivateKey.from_private_bytes(local_priv)
        public_key = x25519.X25519PublicKey.from_public_bytes(remote_pub)
        return private_key.exchange(public_key)

    def _sort_keys(self, key1: bytes, key2: bytes) -> tuple[bytes, bytes]:
        """Sort two keys in ascending order"""
        if len(key1) != 32 or len(key2) != 32:
            raise ValueError("Invalid key length")
        return (key1, key2) if key1 < key2 else (key2, key1)

    def _derive_secrets(self, shared_secret: bytes, local_is_lower: bool) -> tuple[bytes, bytes]:
        """Derive encryption keys from shared secret"""

        def hkdf(secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
            if not salt:
                salt = bytes([0] * hashlib.sha256().digest_size)
            prk = hmac.new(salt, secret, hashlib.sha256).digest()

            n = math.ceil(length / hashlib.sha256().digest_size)
            t = b""
            output = b""
            for i in range(n):
                data = (t + info + bytes([i + 1])) if i > 0 else (info + bytes([1]))
                t = hmac.new(prk, data, hashlib.sha256).digest()
                output += t

            return output[:length]

        key_material = hkdf(
            secret=shared_secret,
            salt=b"",
            info=b"TENDERMINT_SECRET_CONNECTION_KEY_AND_CHALLENGE_GEN",
            length=96  # 32 bytes for each key + 32 bytes for challenge
        )

        if local_is_lower:
            recv_key = key_material[0:32]
            send_key = key_material[32:64]
        else:
            send_key = key_material[0:32]
            recv_key = key_material[32:64]

        return recv_key, send_key

    def _exchange_auth(self, local_pub_key: bytes, signature: bytes):
        """Exchange authentication materials with encryption"""
        # Prepare the auth message
        auth_msg = (
            bytes.fromhex("660a220a20") + local_pub_key + bytes.fromhex("1240") + signature
        )

        self.write(auth_msg)

        # Receive peer's encrypted auth message
        encrypted_auth = self.read()
        time.sleep(1)
        node_data = self.read()
        print(node_data[0])

    def _incr_nonce(self, nonce: bytearray) -> None:
        # Extract counter from bytes 4-12 (8 bytes) in little endian
        counter = int.from_bytes(nonce[4:12], byteorder='little', signed=False)

        # Check for overflow (MaxUint64 = 2^64 - 1)
        if counter == 0xFFFFFFFFFFFFFFFF:  # same as math.MaxUint64 in Go
            raise OverflowError("can't increase nonce without overflow")

        # Increment counter
        counter += 1

        # Write back to nonce array in little endian
        nonce[4:12] = counter.to_bytes(8, byteorder='little', signed=False)

    def write(self, data: bytes) -> int:
        """
        Write data to the secret connection.
        Returns (number of bytes written, error if any)
        """
        with self.send_mtx:
            print(f"WriteData: {binascii.hexlify(data).decode()}")

            n = 0
            remaining_data = data

            while remaining_data:
                try:
                    # Get buffers from pool
                    sealed_frame = self.pool.get(self.AEAD_SIZE_OVERHEAD + self.TOTAL_FRAME_SIZE)
                    frame = self.pool.get(self.TOTAL_FRAME_SIZE)

                    try:
                        # Prepare the chunk
                        if len(remaining_data) > self.DATA_MAX_SIZE:
                            chunk = remaining_data[:self.DATA_MAX_SIZE]
                            remaining_data = remaining_data[self.DATA_MAX_SIZE:]
                        else:
                            chunk = remaining_data
                            remaining_data = b''

                        # Clear the frame buffer - Initialize all bytes to 0
                        frame[:] = bytearray(self.TOTAL_FRAME_SIZE)

                        # Write chunk length in little endian
                        struct.pack_into('<I', frame, 0, len(chunk))

                        # Copy chunk data and fill the rest with zeros
                        frame[self.DATA_LEN_SIZE:self.DATA_LEN_SIZE + len(chunk)] = chunk
                        # The rest of the frame is already filled with zeros from the initialization

                        # Encrypt the entire frame
                        encrypted = self.send_cipher.encrypt(
                            bytes(self.send_nonce),
                            bytes(frame),  # Encrypt the entire frame
                            None  # No associated data
                        )
                        sealed_frame[:len(encrypted)] = encrypted

                        print(f"SignedWrite: {binascii.hexlify(sealed_frame[:len(encrypted)]).decode()}")

                        # Write to connection
                        bytes_written = self.socket.sendall(sealed_frame[:len(encrypted)])

                        # Increment nonce
                        self._incr_nonce(self.send_nonce)

                        n += len(chunk)

                    finally:
                        # Return buffers to pool
                        self.pool.put(sealed_frame)
                        self.pool.put(frame)

                except Exception as e:
                    return n

            return n

    def read(self) -> tuple[bytes, Exception]:
        """
        Read data from the secret connection.
        Returns (data read, error if any)
        """
        with self.recv_mtx:
            try:
                # Get buffers from pool
                sealed_frame = self.pool.get(self.AEAD_SIZE_OVERHEAD + self.TOTAL_FRAME_SIZE)
                frame = self.pool.get(self.TOTAL_FRAME_SIZE)

                try:
                    # Read encrypted frame
                    bytes_read = self.socket.recv_into(sealed_frame, self.AEAD_SIZE_OVERHEAD + self.TOTAL_FRAME_SIZE)
                    if bytes_read == 0:
                        return b'', ConnectionError("Connection closed")

                    print(f"SignedRead: {binascii.hexlify(sealed_frame[:bytes_read]).decode()}")

                    # Decrypt the frame
                    try:
                        decrypted = self.recv_cipher.decrypt(
                            bytes(self.recv_nonce),
                            sealed_frame[:bytes_read],
                            None  # No associated data
                        )
                    except Exception as e:
                        return b'', Exception(f"Failed to decrypt frame: {str(e)}")

                    # Increment nonce
                    self._incr_nonce(self.recv_nonce)

                    # Get data length from frame
                    data_len = struct.unpack_from('<I', decrypted, 0)[0]
                    if data_len > self.DATA_MAX_SIZE:
                        return b'', ValueError(f"Frame data length {data_len} exceeds maximum {self.DATA_MAX_SIZE}")

                    # Extract actual data
                    data = decrypted[self.DATA_LEN_SIZE:self.DATA_LEN_SIZE + data_len]
                    print(f"ReadData: {binascii.hexlify(data).decode()}")

                    return data, None

                finally:
                    # Return buffers to pool
                    self.pool.put(sealed_frame)
                    self.pool.put(frame)

            except Exception as e:
                return b'', e


if "__main__" == __name__:
    host = "162.19.234.220" # 213.136.69.68
    port = 26656

    sc = SecretConnection(host, port)
    local_pub_key, local_priv_key = sc.generate_keypair()
    sc.connect(local_priv_key, local_pub_key)