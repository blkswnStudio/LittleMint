import socket
import struct
import threading
import time
import hmac
import hashlib
import math

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import x25519
from merlin_transcripts import MerlinTranscript

from .simple_pool import SimplePool


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
        self.send_nonce = 0
        self.recv_nonce = 0

        self.send_mtx = threading.Lock()
        self.recv_mtx = threading.Lock()

        # Create buffer pool
        self.pool = SimplePool(max(self.TOTAL_FRAME_SIZE, self.AEAD_SIZE_OVERHEAD + self.TOTAL_FRAME_SIZE),2)

    def connect(self) -> None:
        """Establish secure connection using STS protocol"""

        # Generate main public and private key
        local_pub_key, local_priv_key = self.generate_keys()

        # Create socket connection
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

        # Generate ephemeral keypair
        local_eph_pub_key, local_eph_priv_key = self._generate_ephemeral_keypair()

        # Send ephemeral public key
        self.socket.sendall(bytes.fromhex("220a20") + local_eph_pub_key)

        # Receive peer's ephemeral public key
        # Remove proton stuff and length in the first three bytes
        remote_eph_pub_key = self.socket.recv(35)[3:]

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
        signature_key = ed25519.Ed25519PrivateKey.from_private_bytes(local_priv_key)
        local_signature = signature_key.sign(challenge)
        signature_key.public_key().verify(local_signature, challenge)

        # Exchange main public key and signature
        self._exchange_auth(local_pub_key, local_signature)

    @staticmethod
    def generate_keys() -> tuple[bytes, bytes]:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        return public_key.public_bytes_raw(), private_key.private_bytes_raw()

    def write(self, data: bytes) -> int:
        """
        Write data to the secret connection.
        """
        with self.send_mtx:
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
                            self.get_send_nonce(),
                            bytes(frame),  # Encrypt the entire frame
                            None  # No associated data
                        )
                        sealed_frame[:len(encrypted)] = encrypted

                        # Write to connection
                        self.socket.sendall(sealed_frame[:len(encrypted)])

                        # Increment nonce
                        self.send_nonce += 1
                        n += len(chunk)

                    finally:
                        # Return buffers to pool
                        self.pool.put(sealed_frame)
                        self.pool.put(frame)

                except Exception as e:
                    raise Exception(f"Failed to write data: {str(e)}")
            return n

    def read(self) -> bytes:
        """
        Read data from the secret connection.
        """
        with self.recv_mtx:
            # Get buffers from pool
            sealed_frame = self.pool.get(self.AEAD_SIZE_OVERHEAD + self.TOTAL_FRAME_SIZE)
            frame = self.pool.get(self.TOTAL_FRAME_SIZE)

            try:
                # Read encrypted frame
                bytes_read = self.socket.recv_into(sealed_frame, self.AEAD_SIZE_OVERHEAD + self.TOTAL_FRAME_SIZE)
                if bytes_read == 0:
                    raise ConnectionError("Connection closed")

                # Decrypt the frame
                try:
                    decrypted = self.recv_cipher.decrypt(
                        self.get_recv_nonce(),
                        sealed_frame[:bytes_read],
                        None  # No associated data
                    )
                except Exception as e:
                    raise Exception(f"Failed to decrypt frame: {str(e)}")

                # Increment nonce
                self.recv_nonce += 1

                # Get data length from frame
                data_len = struct.unpack_from('<I', decrypted, 0)[0]
                if data_len > self.DATA_MAX_SIZE:
                    raise ValueError(f"Frame data length {data_len} exceeds maximum {self.DATA_MAX_SIZE}")

                # Extract actual data
                data = decrypted[self.DATA_LEN_SIZE:self.DATA_LEN_SIZE + data_len]
                return data

            finally:
                # Return buffers to pool
                self.pool.put(sealed_frame)
                self.pool.put(frame)

    """ Helper methods for initiating secure connection """

    @staticmethod
    def _generate_ephemeral_keypair() -> tuple[bytes, bytes]:
        """Generate ephemeral X25519 keypair"""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()

        return public_key.public_bytes_raw(), private_key.private_bytes_raw()

    @staticmethod
    def _compute_shared_secret(remote_pub: bytes, local_priv: bytes) -> bytes:
        """Compute shared secret using X25519"""
        if len(remote_pub) != 32 or len(local_priv) != 32:
            raise ValueError("Invalid key length")

        private_key = x25519.X25519PrivateKey.from_private_bytes(local_priv)
        public_key = x25519.X25519PublicKey.from_public_bytes(remote_pub)
        return private_key.exchange(public_key)

    @staticmethod
    def _sort_keys(key1: bytes, key2: bytes) -> tuple[bytes, bytes]:
        """Sort two keys in ascending order"""
        if len(key1) != 32 or len(key2) != 32:
            raise ValueError("Invalid key length")
        return (key1, key2) if key1 < key2 else (key2, key1)

    @staticmethod
    def _derive_secrets(shared_secret: bytes, local_is_lower: bool) -> tuple[bytes, bytes]:
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

    def get_send_nonce(self) -> bytes:
        nonce: bytes = bytearray(12)
        nonce[4:12] = self.send_nonce.to_bytes(8, byteorder='little', signed=False)
        return nonce

    def get_recv_nonce(self) -> bytes:
        nonce: bytes = bytearray(12)
        nonce[4:12] = self.recv_nonce.to_bytes(8, byteorder='little', signed=False)
        return nonce

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
        print(node_data)