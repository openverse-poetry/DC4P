"""
NanoCell Core - Binary protocol for efficient communication
Message format: [magic][type][length][payload][mac]
"""

import struct
import msgpack
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import IntEnum


MAGIC_NUMBER = 0x4E43  # "NC" for NanoCell
HEADER_SIZE = 8  # magic(2) + type(1) + length(2) + flags(1) + seq(2)
MAC_SIZE = 16


class MessageType(IntEnum):
    """Protocol message types"""
    # Handshake
    HELLO = 1
    HELLO_ACK = 2
    KEY_EXCHANGE = 3
    KEY_EXCHANGE_ACK = 4
    
    # Messaging
    MESSAGE = 10
    MESSAGE_ACK = 11
    MESSAGE_DELIVERED = 12
    
    # Presence
    PING = 20
    PONG = 21
    STATUS_UPDATE = 22
    
    # Coordination (bootstrap server)
    REGISTER = 30
    REGISTER_ACK = 31
    LOOKUP = 32
    LOOKUP_RESPONSE = 33
    PEER_INFO = 34
    
    # Relay
    RELAY_REQUEST = 40
    RELAY_DATA = 41
    
    # Admin
    AUTH_REQUEST = 50
    AUTH_RESPONSE = 51
    ROLE_ASSIGN = 52
    ROLE_REVOKE = 53
    
    # Error
    ERROR = 255


class ErrorCode(IntEnum):
    """Error codes"""
    OK = 0
    INVALID_FORMAT = 1
    AUTH_FAILED = 2
    NOT_FOUND = 3
    PERMISSION_DENIED = 4
    INTERNAL_ERROR = 5
    UNAVAILABLE = 6


@dataclass
class Message:
    """Protocol message"""
    type: MessageType
    payload: Dict[str, Any]
    seq: int = 0
    flags: int = 0
    
    def to_bytes(self) -> bytes:
        """Serialize message to bytes"""
        # Pack payload with msgpack
        packed_payload = msgpack.packb(self.payload, use_bin_type=True)
        
        # Build header
        header = struct.pack(
            '>HBHBH',  # big-endian: magic, type, length, flags, seq
            MAGIC_NUMBER,
            self.type,
            len(packed_payload),
            self.flags,
            self.seq
        )
        
        return header + packed_payload
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'Message':
        """Deserialize message from bytes"""
        if len(data) < HEADER_SIZE:
            raise ValueError("Message too short")
        
        # Parse header
        magic, msg_type, length, flags, seq = struct.unpack('>HBHBH', data[:HEADER_SIZE])
        
        if magic != MAGIC_NUMBER:
            raise ValueError(f"Invalid magic number: {magic}")
        
        # Extract payload
        payload_data = data[HEADER_SIZE:HEADER_SIZE + length]
        payload = msgpack.unpackb(payload_data, raw=False)
        
        return cls(
            type=MessageType(msg_type),
            payload=payload,
            seq=seq,
            flags=flags
        )


@dataclass
class EncryptedMessage:
    """Encrypted message with MAC"""
    message: Message
    mac: bytes
    
    def to_bytes(self) -> bytes:
        """Serialize encrypted message"""
        msg_bytes = self.message.to_bytes()
        return msg_bytes + self.mac
    
    @classmethod
    def from_bytes(cls, data: bytes, mac_size: int = MAC_SIZE) -> 'EncryptedMessage':
        """Deserialize encrypted message"""
        if len(data) < HEADER_SIZE + mac_size:
            raise ValueError("Message too short")
        
        mac = data[-mac_size:]
        msg_data = data[:-mac_size]
        message = Message.from_bytes(msg_data)
        
        return cls(message=message, mac=mac)


class Protocol:
    """High-level protocol operations"""
    
    def __init__(self, node_id: str):
        self.node_id = node_id
        self._seq_counter = 0
    
    def _next_seq(self) -> int:
        """Get next sequence number"""
        seq = self._seq_counter
        self._seq_counter = (self._seq_counter + 1) & 0xFFFF
        return seq
    
    def create_hello(self, version: str = "1.0") -> Message:
        """Create HELLO message"""
        return Message(
            type=MessageType.HELLO,
            payload={
                'node_id': self.node_id,
                'version': version,
                'capabilities': ['p2p', 'relay', 'e2e']
            },
            seq=self._next_seq()
        )
    
    def create_message(self, recipient: str, content: bytes, 
                       encrypted: bool = True) -> Message:
        """Create chat message"""
        return Message(
            type=MessageType.MESSAGE,
            payload={
                'from': self.node_id,
                'to': recipient,
                'content': content.hex() if isinstance(content, bytes) else content,
                'encrypted': encrypted,
                'timestamp': self._timestamp()
            },
            seq=self._next_seq()
        )
    
    def create_register(self, public_ip: str, public_port: int) -> Message:
        """Create registration message for bootstrap server"""
        return Message(
            type=MessageType.REGISTER,
            payload={
                'node_id': self.node_id,
                'public_ip': public_ip,
                'public_port': public_port,
                'nat_type': self._detect_nat_type()
            },
            seq=self._next_seq()
        )
    
    def create_lookup(self, target_id: str) -> Message:
        """Create peer lookup request"""
        return Message(
            type=MessageType.LOOKUP,
            payload={
                'requester': self.node_id,
                'target': target_id
            },
            seq=self._next_seq()
        )
    
    def create_auth_request(self, role: str, signature: str) -> Message:
        """Create authentication request for admin"""
        return Message(
            type=MessageType.AUTH_REQUEST,
            payload={
                'node_id': self.node_id,
                'role': role,
                'signature': signature
            },
            seq=self._next_seq()
        )
    
    def create_error(self, code: ErrorCode, message: str) -> Message:
        """Create error message"""
        return Message(
            type=MessageType.ERROR,
            payload={
                'code': code,
                'message': message
            },
            seq=self._next_seq()
        )
    
    @staticmethod
    def _timestamp() -> int:
        """Get current timestamp in milliseconds"""
        import time
        return int(time.time() * 1000)
    
    @staticmethod
    def _detect_nat_type() -> str:
        """Detect NAT type (simplified)"""
        # In real implementation, this would use STUN
        return "unknown"
    
    @staticmethod
    def verify_mac(data: bytes, mac: bytes, key: bytes) -> bool:
        """Verify message authentication code"""
        import nacl.secret
        box = nacl.secret.SecretBox(key)
        try:
            box.decrypt(data + mac)
            return True
        except:
            return False
    
    @staticmethod
    def compute_mac(data: bytes, key: bytes) -> bytes:
        """Compute message authentication code"""
        import nacl.secret
        import nacl.utils
        box = nacl.secret.SecretBox(key)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = box.encrypt(data, nonce)
        return encrypted[-MAC_SIZE:]  # Last 16 bytes as MAC
