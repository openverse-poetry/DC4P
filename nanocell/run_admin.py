#!/usr/bin/env python3
"""
NanoCell Admin CLI Launcher
Manage network administrators and users
"""

import sys
import argparse

# Add project root to path
sys.path.insert(0, '.')

from admin.cli import AdminCLI


def main():
    parser = argparse.ArgumentParser(description='NanoCell Admin CLI')
    parser.add_argument('--owner-id', required=True,
                       help='Owner node ID (your identity)')
    
    args = parser.parse_args()
    
    print(f"Starting Admin CLI as owner: {args.owner_id}")
    cli = AdminCLI(args.owner_id)
    cli.run()


if __name__ == '__main__':
    main()
