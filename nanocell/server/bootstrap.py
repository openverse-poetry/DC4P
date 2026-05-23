"""
NanoCell Server - Bootstrap and Relay servers
Handles peer coordination and relay for NAT traversal
"""

import asyncio
import struct
import socket
from typing import Dict, Set, Tuple, Optional
from dataclasses import dataclass, field
import time


@dataclass
class Peer:
    """Registered peer information"""
    node_id: str
    address: Tuple[str, int]
    public_ip: str
    public_port: int
    last_seen: float = field(default_factory=time.time)
    
    def update_seen(self) -> None:
        self.last_seen = time.time()


class BootstrapServer:
    """
    Bootstrap server for peer discovery and coordination.
    Stateless design - only coordinates initial connections.
    """
    
    def __init__(self, host: str = '0.0.0.0', port: int = 9000):
        self.host = host
        self.port = port
        self._peers: Dict[str, Peer] = {}
        self._socket: Optional[socket.socket] = None
        self._running = False
    
    def start(self) -> None:
        """Start bootstrap server"""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.host, self.port))
        self._socket.setblocking(False)
        
        self._running = True
        print(f"Bootstrap server started on {self.host}:{self.port}")
        
        # Run event loop
        while self._running:
            try:
                data, addr = self._socket.recvfrom(65535)
                if data:
                    self._handle_message(data, addr)
            except BlockingIOError:
                pass
            except Exception as e:
                if self._running:
                    print(f"Error: {e}")
    
    def stop(self) -> None:
        """Stop bootstrap server"""
        self._running = False
        if self._socket:
            self._socket.close()
    
    def _handle_message(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle incoming message"""
        if len(data) < 1:
            return
        
        opcode = data[0]
        
        if opcode == 1:  # REGISTER
            self._handle_register(data, addr)
        elif opcode == 3:  # LOOKUP
            self._handle_lookup(data, addr)
        elif opcode == 5:  # PING (keepalive)
            self._handle_ping(addr)
    
    def _handle_register(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle peer registration"""
        # Parse registration data
        offset = 1
        node_id_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        node_id = data[offset:offset+node_id_len].decode()
        offset += node_id_len
        public_port = struct.unpack('>H', data[offset:offset+2])[0]
        
        # Extract public IP from address (NAT mapped)
        public_ip = addr[0]
        
        # Register peer
        peer = Peer(
            node_id=node_id,
            address=addr,
            public_ip=public_ip,
            public_port=public_port
        )
        self._peers[node_id] = peer
        
        # Send acknowledgment
        response = struct.pack('>B', 2)  # REGISTER_ACK
        response += struct.pack('>H', len(public_ip)) + public_ip.encode()
        response += struct.pack('>H', public_port)
        
        self._socket.sendto(response, addr)
        print(f"Registered peer: {node_id} @ {public_ip}:{public_port}")
    
    def _handle_lookup(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle peer lookup request"""
        # Parse target ID
        offset = 1
        target_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        target_id = data[offset:offset+target_len].decode()
        
        # Find peer
        peer = self._peers.get(target_id)
        
        if peer:
            # Send peer info
            response = struct.pack('>B', 4)  # LOOKUP_RESPONSE
            response += struct.pack('>H', len(peer.public_ip)) + peer.public_ip.encode()
            response += struct.pack('>H', peer.public_port)
            
            self._socket.sendto(response, addr)
            print(f"Lookup: {target_id} found at {peer.public_ip}:{peer.public_port}")
        else:
            # Peer not found
            response = struct.pack('>B', 5)  # NOT_FOUND
            self._socket.sendto(response, addr)
            print(f"Lookup: {target_id} not found")
    
    def _handle_ping(self, addr: Tuple[str, int]) -> None:
        """Handle keepalive ping"""
        # Find peer by address
        for peer in self._peers.values():
            if peer.address == addr:
                peer.update_seen()
                break
        
        # Send pong
        response = struct.pack('>B', 6)  # PONG
        self._socket.sendto(response, addr)
    
    def get_peer_count(self) -> int:
        """Get number of registered peers"""
        return len(self._peers)
    
    def cleanup_stale_peers(self, timeout: float = 300.0) -> None:
        """Remove peers that haven't sent keepalive"""
        now = time.time()
        stale = [
            node_id for node_id, peer in self._peers.items()
            if now - peer.last_seen > timeout
        ]
        
        for node_id in stale:
            del self._peers[node_id]
            print(f"Removed stale peer: {node_id}")


class RelayServer:
    """
    Relay server for NAT traversal fallback.
    Forwards messages between peers behind symmetric NATs.
    """
    
    def __init__(self, host: str = '0.0.0.0', port: int = 9001):
        self.host = host
        self.port = port
        self._clients: Dict[str, Tuple[str, int]] = {}  # node_id -> address
        self._reverse_map: Dict[Tuple[str, int], str] = {}  # address -> node_id
        self._socket: Optional[socket.socket] = None
        self._running = False
    
    def start(self) -> None:
        """Start relay server"""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.host, self.port))
        self._socket.setblocking(False)
        
        self._running = True
        print(f"Relay server started on {self.host}:{self.port}")
        
        # Run event loop
        while self._running:
            try:
                data, addr = self._socket.recvfrom(65535)
                if data:
                    self._handle_message(data, addr)
            except BlockingIOError:
                pass
            except Exception as e:
                if self._running:
                    print(f"Error: {e}")
    
    def stop(self) -> None:
        """Stop relay server"""
        self._running = False
        if self._socket:
            self._socket.close()
    
    def _handle_message(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle incoming message"""
        if len(data) < 1:
            return
        
        msg_type = data[0]
        
        if msg_type == 1:  # CONNECT
            self._handle_connect(data, addr)
        elif msg_type == 2:  # DISCONNECT
            self._handle_disconnect(addr)
        elif msg_type == 3:  # FORWARD
            self._handle_forward(data, addr)
        elif msg_type == 4:  # PING
            self._handle_ping(addr)
    
    def _handle_connect(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle client connection"""
        # Parse node ID
        offset = 1
        node_id_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        node_id = data[offset:offset+node_id_len].decode()
        
        # Register client
        self._clients[node_id] = addr
        self._reverse_map[addr] = node_id
        
        # Send acknowledgment
        response = struct.pack('>B', 10)  # CONNECT_ACK
        self._socket.sendto(response, addr)
        
        print(f"Relay client connected: {node_id}")
    
    def _handle_disconnect(self, addr: Tuple[str, int]) -> None:
        """Handle client disconnection"""
        node_id = self._reverse_map.pop(addr, None)
        if node_id:
            self._clients.pop(node_id, None)
            print(f"Relay client disconnected: {node_id}")
    
    def _handle_forward(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle message forwarding"""
        # Get sender
        sender_id = self._reverse_map.get(addr)
        if not sender_id:
            return
        
        # Parse recipient and message
        offset = 1
        recipient_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        recipient_id = data[offset:offset+recipient_len].decode()
        message = data[offset:]
        
        # Find recipient
        recipient_addr = self._clients.get(recipient_id)
        if recipient_addr:
            # Forward message with sender info
            forward_data = struct.pack('>H', len(sender_id)) + sender_id.encode() + message
            self._socket.sendto(forward_data, recipient_addr)
            print(f"Relayed: {sender_id} -> {recipient_id}")
        else:
            # Recipient not found
            error = struct.pack('>B', 20)  # ERROR
            error += struct.pack('>H', len(recipient_id)) + recipient_id.encode()
            self._socket.sendto(error, addr)
    
    def _handle_ping(self, addr: Tuple[str, int]) -> None:
        """Handle keepalive ping"""
        # Send pong
        response = struct.pack('>B', 11)  # PONG
        self._socket.sendto(response, addr)
    
    def get_client_count(self) -> int:
        """Get number of connected clients"""
        return len(self._clients)


async def run_bootstrap_server(host: str = '0.0.0.0', port: int = 9000) -> None:
    """Run bootstrap server asynchronously"""
    server = BootstrapServer(host, port)
    
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, server.start)


async def run_relay_server(host: str = '0.0.0.0', port: int = 9001) -> None:
    """Run relay server asynchronously"""
    server = RelayServer(host, port)
    
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, server.start)


def main():
    """Main entry point for running servers"""
    import argparse
    
    parser = argparse.ArgumentParser(description='NanoCell Server')
    parser.add_argument('--role', choices=['bootstrap', 'relay'], required=True)
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=None)
    
    args = parser.parse_args()
    
    if args.role == 'bootstrap':
        server = BootstrapServer(args.host, args.port or 9000)
    else:
        server = RelayServer(args.host, args.port or 9001)
    
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
        print("\nServer stopped")


if __name__ == '__main__':
    main()
