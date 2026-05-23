"""
NanoCell Admin CLI - Command-line interface for network owner
Manage administrators, users, and server configuration
"""

import argparse
import json
import sys
from typing import Optional

# Add parent directory to path
sys.path.insert(0, '..')

from admin.roles import AccessControl, Permission, AuthManager


class AdminCLI:
    """Command-line interface for NanoCell administration"""
    
    def __init__(self, owner_id: str):
        self.ac = AccessControl()
        self.ac.set_owner(owner_id)
        self.auth = AuthManager(self.ac)
        self.owner_id = owner_id
    
    def run(self) -> None:
        """Run interactive CLI"""
        print(f"NanoCell Admin CLI - Owner: {self.owner_id}")
        print("Type 'help' for commands\n")
        
        while True:
            try:
                cmd = input("admin> ").strip()
                if not cmd:
                    continue
                
                if cmd == 'quit' or cmd == 'exit':
                    break
                
                parts = cmd.split()
                command = parts[0]
                args = parts[1:]
                
                self._execute_command(command, args)
            
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                print(f"Error: {e}")
    
    def _execute_command(self, command: str, args: list) -> None:
        """Execute CLI command"""
        commands = {
            'help': self.cmd_help,
            'appoint': self.cmd_appoint,
            'revoke': self.cmd_revoke,
            'ban': self.cmd_ban,
            'unban': self.cmd_unban,
            'kick': self.cmd_kick,
            'users': self.cmd_users,
            'admins': self.cmd_admins,
            'stats': self.cmd_stats,
            'role': self.cmd_role,
        }
        
        handler = commands.get(command)
        if handler:
            handler(args)
        else:
            print(f"Unknown command: {command}")
            print("Type 'help' for available commands")
    
    def cmd_help(self, args: list) -> None:
        """Show help"""
        help_text = """
Available commands:
  appoint <user> [role]  - Appoint user as admin (roles: user, moderator, admin, superadmin)
  revoke <user>          - Revoke admin privileges from user
  ban <user> [reason]    - Ban user from network
  unban <user>           - Unban user
  kick <user>            - Kick user (temporary disconnect)
  users                  - List all users
  admins                 - List all administrators
  stats                  - Show server statistics
  role create <name>     - Create custom role (advanced)
  
Examples:
  appoint alice admin
  revoke bob
  ban charlie spamming
  users
"""
        print(help_text)
    
    def cmd_appoint(self, args: list) -> None:
        """Appoint administrator"""
        if len(args) < 1:
            print("Usage: appoint <user> [role]")
            return
        
        user_id = args[0]
        role = args[1] if len(args) > 1 else 'admin'
        
        # Register user first (simulated)
        self.ac.register_user(user_id, b'')
        
        success = self.ac.appoint_admin(self.owner_id, user_id, role)
        if success:
            print(f"✓ Appointed {user_id} as {role}")
        else:
            print(f"✗ Failed to appoint {user_id}")
    
    def cmd_revoke(self, args: list) -> None:
        """Revoke admin"""
        if len(args) < 1:
            print("Usage: revoke <user>")
            return
        
        user_id = args[0]
        success = self.ac.revoke_admin(self.owner_id, user_id)
        
        if success:
            print(f"✓ Revoked admin from {user_id}")
        else:
            print(f"✗ Failed to revoke {user_id}")
    
    def cmd_ban(self, args: list) -> None:
        """Ban user"""
        if len(args) < 1:
            print("Usage: ban <user> [reason]")
            return
        
        user_id = args[0]
        reason = ' '.join(args[1:]) if len(args) > 1 else 'No reason given'
        
        success = self.ac.ban_user(self.owner_id, user_id, reason)
        if success:
            print(f"✓ Banned {user_id}: {reason}")
        else:
            print(f"✗ Failed to ban {user_id}")
    
    def cmd_unban(self, args: list) -> None:
        """Unban user"""
        if len(args) < 1:
            print("Usage: unban <user>")
            return
        
        user_id = args[0]
        success = self.ac.unban_user(self.owner_id, user_id)
        
        if success:
            print(f"✓ Unbanned {user_id}")
        else:
            print(f"✗ Failed to unban {user_id}")
    
    def cmd_kick(self, args: list) -> None:
        """Kick user"""
        if len(args) < 1:
            print("Usage: kick <user>")
            return
        
        user_id = args[0]
        success = self.ac.kick_user(self.owner_id, user_id)
        
        if success:
            print(f"✓ Kicked {user_id}")
        else:
            print(f"✗ Failed to kick {user_id}")
    
    def cmd_users(self, args: list) -> None:
        """List users"""
        users = self.ac.list_users(self.owner_id)
        
        if not users:
            print("No users registered")
            return
        
        print(f"\n{'ID':<40} {'ROLE':<15} {'BANNED':<8} {'LAST SEEN':<20}")
        print("-" * 83)
        
        for user in users:
            last_seen = user['last_seen']
            if last_seen == 0:
                last_seen_str = "Never"
            else:
                import time
                diff = time.time() - last_seen
                if diff < 60:
                    last_seen_str = f"{int(diff)}s ago"
                elif diff < 3600:
                    last_seen_str = f"{int(diff/60)}m ago"
                else:
                    last_seen_str = f"{int(diff/3600)}h ago"
            
            banned_str = "Yes" if user['banned'] else "No"
            print(f"{user['node_id']:<40} {user['role']:<15} {banned_str:<8} {last_seen_str:<20}")
        
        print(f"\nTotal: {len(users)} users")
    
    def cmd_admins(self, args: list) -> None:
        """List admins"""
        admins = self.ac.list_admins(self.owner_id)
        
        if not admins:
            print("No administrators")
            return
        
        print(f"\n{'ID':<40} {'ROLE':<15}")
        print("-" * 55)
        
        for admin in admins:
            print(f"{admin['node_id']:<40} {admin['role']:<15}")
        
        print(f"\nTotal: {len(admins)} administrators")
    
    def cmd_stats(self, args: list) -> None:
        """Show statistics"""
        stats = self.ac.get_server_stats(self.owner_id)
        
        if not stats:
            print("No statistics available")
            return
        
        print("\n=== Server Statistics ===")
        print(f"Total Users:     {stats['total_users']}")
        print(f"Active Users:    {stats['active_users']} (last 5 min)")
        print(f"Banned Users:    {stats['banned_users']}")
        print(f"Administrators:  {stats['admins']}")
        print(f"Owner:           {stats['owner']}")
        print(f"Available Roles: {', '.join(stats['roles'])}")
    
    def cmd_role(self, args: list) -> None:
        """Role management"""
        if len(args) < 1:
            print("Usage: role create <name>")
            return
        
        subcmd = args[0]
        if subcmd == 'create':
            if len(args) < 2:
                print("Usage: role create <name>")
                return
            
            name = args[1]
            # For simplicity, create with basic permissions
            perms = Permission.SEND_MESSAGE | Permission.RECEIVE_MESSAGE
            success = self.ac.create_custom_role(self.owner_id, name, perms)
            
            if success:
                print(f"✓ Created role: {name}")
            else:
                print(f"✗ Failed to create role: {name}")
        else:
            print(f"Unknown role command: {subcmd}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='NanoCell Admin CLI')
    parser.add_argument('--owner-id', required=True, help='Owner node ID')
    parser.add_argument('--config', help='Configuration file')
    
    args = parser.parse_args()
    
    cli = AdminCLI(args.owner_id)
    cli.run()


if __name__ == '__main__':
    main()
