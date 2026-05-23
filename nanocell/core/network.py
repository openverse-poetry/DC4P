"""
NanoCell Network - UDP networking with NAT traversal
Supports hole punching for direct P2P and relay fallback
"""

import socket
import asyncio
import threading
import time
from typing import Dict, Tuple, Optional, Callable, Set
from dataclasses import dataclass
import struct


@dataclass
class PeerInfo:
    """Information about a peer"""
    node_id: str
    public_ip: str
    public_port: int
    nat_type: str = "unknown"
    last_seen: float = 0.0
    
    @property
    def address(self) -> Tuple[str, int]:
        return (self.public_ip, self.public_port)


class UDPSocket:
    """Non-blocking UDP socket wrapper"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 0):
        self.host = host
        self.port = port
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((host, port))
        self._socket.setblocking(False)
        
        # Get actual bound port (if port was 0)
        _, self.bound_port = self._socket.getsockname()
    
    def send(self, data: bytes, address: Tuple[str, int]) -> int:
        """Send data to address"""
        return self._socket.sendto(data, address)
    
    def recv(self, bufsize: int = 65535) -> Tuple[bytes, Tuple[str, int]]:
        """Receive data"""
        try:
            data, addr = self._socket.recvfrom(bufsize)
            return data, addr
        except BlockingIOError:
            return b'', ('', 0)
    
    def close(self) -> None:
        """Close socket"""
        self._socket.close()
    
    @property
    def fileno(self) -> int:
        return self._socket.fileno()


class HolePuncher:
    """UDP hole punching coordinator"""
    
    def __init__(self, bootstrap_server: Tuple[str, int]):
        self.bootstrap_server = bootstrap_server
        self._peers: Dict[str, PeerInfo] = {}
        self._pending_connections: Set[str] = set()
    
    def register_peer(self, peer: PeerInfo) -> None:
        """Register peer for hole punching"""
        self._peers[peer.node_id] = peer
    
    def get_peer(self, node_id: str) -> Optional[PeerInfo]:
        """Get peer info"""
        return self._peers.get(node_id)
    
    def initiate_hole_punch(self, target_id: str, local_socket: UDPSocket,
                           callback: Callable[[str], None]) -> bool:
        """Initiate hole punch to target peer"""
        peer = self.get_peer(target_id)
        if not peer:
            return False
        
        # Send packets to peer's public address to open NAT hole
        # Repeat to increase success rate
        magic = b'NCPUNCH'
        for _ in range(5):
            local_socket.send(magic, peer.address)
            time.sleep(0.1)
        
        self._pending_connections.add(target_id)
        return True
    
    def check_connection(self, target_id: str) -> bool:
        """Check if connection is established"""
        return target_id not in self._pending_connections


class NetworkEngine:
    """Main network engine with P2P and relay support"""
    
    def __init__(self, node_id: str, bootstrap_server: Tuple[str, int],
                 relay_server: Optional[Tuple[str, int]] = None):
        self.node_id = node_id
        self.bootstrap_server = bootstrap_server
        self.relay_server = relay_server
        
        self._socket: Optional[UDPSocket] = None
        self._hole_puncher = HolePuncher(bootstrap_server)
        self._peers: Dict[str, PeerInfo] = {}
        self._message_handlers: Dict[int, Callable] = {}
        self._running = False
        self._recv_thread: Optional[threading.Thread] = None
        
        # Connection state
        self._direct_peers: Set[str] = set()  # Peers with direct connection
        self._relay_peers: Set[str] = set()   # Peers via relay
    
    def start(self, port: int = 0) -> int:
        """Start network engine, returns bound port"""
        self._socket = UDPSocket('0.0.0.0', port)
        self._running = True
        
        # Register with bootstrap server
        self._register_with_bootstrap()
        
        # Start receive thread
        self._recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self._recv_thread.start()
        
        return self._socket.bound_port
    
    def stop(self) -> None:
        """Stop network engine"""
        self._running = False
        if self._socket:
            self._socket.close()
    
    def send_message(self, data: bytes, peer_id: str) -> bool:
        """Send message to peer (direct or relay)"""
        if peer_id in self._direct_peers:
            peer = self._hole_puncher.get_peer(peer_id)
            if peer:
                self._socket.send(data, peer.address)
                return True
        
        # Fallback to relay
        if self.relay_server and self._socket:
            # Prefix with relay header
            relay_header = struct.pack('>H', len(peer_id)) + peer_id.encode()
            self._socket.send(relay_header + data, self.relay_server)
            self._relay_peers.add(peer_id)
            return True
        
        return False
    
    def broadcast(self, data: bytes) -> int:
        """Broadcast to all connected peers"""
        count = 0
        for peer_id in list(self._direct_peers) + list(self._relay_peers):
            if self.send_message(data, peer_id):
                count += 1
        return count
    
    def register_handler(self, msg_type: int, handler: Callable) -> None:
        """Register message handler"""
        self._message_handlers[msg_type] = handler
    
    def add_peer(self, peer: PeerInfo) -> None:
        """Add known peer"""
        self._hole_puncher.register_peer(peer)
        self._peers[peer.node_id] = peer
    
    def connect_to_peer(self, peer_id: str, 
                       on_connect: Optional[Callable[[str], None]] = None) -> bool:
        """Attempt to connect to peer"""
        peer = self._hole_puncher.get_peer(peer_id)
        if not peer:
            # Request peer info from bootstrap
            self._request_peer_info(peer_id)
            return False
        
        # Try hole punching
        def on_punch_complete(target_id: str):
            if on_connect:
                on_connect(target_id)
        
        if self._hole_puncher.initiate_hole_punch(peer_id, self._socket, on_punch_complete):
            return True
        
        return False
    
    def _register_with_bootstrap(self) -> None:
        """Register with bootstrap server"""
        if not self._socket:
            return
        
        # Send registration message
        msg = struct.pack('>H', len(self.node_id)) + self.node_id.encode()
        msg += struct.pack('>H', self._socket.bound_port)
        self._socket.send(msg, self.bootstrap_server)
    
    def _request_peer_info(self, peer_id: str) -> None:
        """Request peer info from bootstrap"""
        if not self._socket:
            return
        
        msg = struct.pack('>H', len(peer_id)) + peer_id.encode()
        self._socket.send(msg, self.bootstrap_server)
    
    def _receive_loop(self) -> None:
        """Main receive loop"""
        while self._running:
            try:
                data, addr = self._socket.recv()
                if data and addr[0]:
                    self._process_message(data, addr)
            except Exception as e:
                if self._running:
                    time.sleep(0.01)
    
    def _process_message(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Process incoming message"""
        # Check if it's a hole punch response
        if data.startswith(b'NCPUNCH'):
            # Add sender as direct peer
            peer_id = f"{addr[0]}:{addr[1]}"
            self._direct_peers.add(peer_id)
            return
        
        # Parse message type (first byte after header)
        if len(data) < 7:
            return
        
        msg_type = data[2]  # Message type is at offset 2
        
        # Call handler if registered
        if msg_type in self._message_handlers:
            try:
                self._message_handlers[msg_type](data, addr)
            except Exception as e:
                print(f"Handler error: {e}")
    
    def is_direct_connected(self, peer_id: str) -> bool:
        """Check if peer has direct connection"""
        return peer_id in self._direct_peers
    
    def get_peer_count(self) -> int:
        """Get number of connected peers"""
        return len(self._direct_peers) + len(self._relay_peers)


class BootstrapClient:
    """Client for bootstrap server coordination"""
    
    def __init__(self, server: Tuple[str, int], node_id: str):
        self.server = server
        self.node_id = node_id
        self._socket = UDPSocket()
    
    def register(self, public_ip: str, public_port: int) -> bool:
        """Register with bootstrap server"""
        msg = struct.pack('>B', 1)  # REGISTER opcode
        msg += struct.pack('>H', len(self.node_id)) + self.node_id.encode()
        msg += struct.pack('>H', len(public_ip)) + public_ip.encode()
        msg += struct.pack('>H', public_port)
        
        self._socket.send(msg, self.server)
        
        # Wait for response
        self._socket._socket.settimeout(5.0)
        try:
            response, _ = self._socket.recv()
            return response[0] == 2  # REGISTER_ACK
        except socket.timeout:
            return False
        finally:
            self._socket._socket.settimeout(0)
    
    def lookup(self, target_id: str) -> Optional[PeerInfo]:
        """Lookup peer info"""
        msg = struct.pack('>B', 3)  # LOOKUP opcode
        msg += struct.pack('>H', len(target_id)) + target_id.encode()
        
        self._socket.send(msg, self.server)
        
        # Wait for response
        self._socket._socket.settimeout(5.0)
        try:
            response, _ = self._socket.recv()
            if response[0] != 4:  # LOOKUP_RESPONSE
                return None
            
            # Parse response
            offset = 1
            ip_len = struct.unpack('>H', response[offset:offset+2])[0]
            offset += 2
            ip = response[offset:offset+ip_len].decode()
            offset += ip_len
            port = struct.unpack('>H', response[offset:offset+2])[0]
            
            return PeerInfo(
                node_id=target_id,
                public_ip=ip,
                public_port=port
            )
        except socket.timeout:
            return None
        finally:
            self._socket._socket.settimeout(0)
    
    def close(self) -> None:
        """Close connection"""
        self._socket.close()
