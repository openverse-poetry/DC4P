#!/usr/bin/env python3
"""
NanoCell Server Launcher
Run bootstrap and relay servers
"""

import sys
import argparse

# Add project root to path
sys.path.insert(0, '.')

from server.bootstrap import BootstrapServer, RelayServer


def main():
    parser = argparse.ArgumentParser(description='NanoCell Server')
    parser.add_argument('--role', choices=['bootstrap', 'relay'], required=True,
                       help='Server role: bootstrap or relay')
    parser.add_argument('--host', default='0.0.0.0',
                       help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=None,
                       help='Port to bind to (default: 9000 for bootstrap, 9001 for relay)')
    
    args = parser.parse_args()
    
    if args.role == 'bootstrap':
        port = args.port or 9000
        print(f"Starting Bootstrap Server on {args.host}:{port}")
        server = BootstrapServer(args.host, port)
    else:
        port = args.port or 9001
        print(f"Starting Relay Server on {args.host}:{port}")
        server = RelayServer(args.host, port)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()
        print("Server stopped")


if __name__ == '__main__':
    main()
