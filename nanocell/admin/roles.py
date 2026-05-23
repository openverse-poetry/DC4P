"""
NanoCell Admin - Role-based access control and administration
Owner can appoint/revoke administrators with granular permissions
"""

from enum import IntFlag, auto
from typing import Dict, Set, Optional, List
from dataclasses import dataclass, field
import time
import hashlib


class Permission(IntFlag):
    """Granular permissions for roles"""
    # Messaging
    SEND_MESSAGE = auto()
    RECEIVE_MESSAGE = auto()
    
    # User management
    VIEW_USERS = auto()
    BAN_USER = auto()
    KICK_USER = auto()
    
    # Admin management
    VIEW_ADMINS = auto()
    APPOINT_ADMIN = auto()
    REVOKE_ADMIN = auto()
    
    # Server management
    VIEW_SERVER_STATS = auto()
    RESTART_SERVER = auto()
    CONFIGURE_SERVER = auto()
    
    # Network
    VIEW_PEERS = auto()
    MANAGE_RELAY = auto()
    
    # Full access (owner only)
    OWNER = auto()


# Predefined role permission sets
ROLE_PERMISSIONS = {
    'user': Permission.SEND_MESSAGE | Permission.RECEIVE_MESSAGE,
    
    'moderator': (
        Permission.SEND_MESSAGE | Permission.RECEIVE_MESSAGE |
        Permission.VIEW_USERS | Permission.KICK_USER
    ),
    
    'admin': (
        Permission.SEND_MESSAGE | Permission.RECEIVE_MESSAGE |
        Permission.VIEW_USERS | Permission.BAN_USER | Permission.KICK_USER |
        Permission.VIEW_ADMINS | Permission.VIEW_SERVER_STATS |
        Permission.VIEW_PEERS
    ),
    
    'superadmin': (
        Permission.SEND_MESSAGE | Permission.RECEIVE_MESSAGE |
        Permission.VIEW_USERS | Permission.BAN_USER | Permission.KICK_USER |
        Permission.VIEW_ADMINS | Permission.APPOINT_ADMIN | Permission.REVOKE_ADMIN |
        Permission.VIEW_SERVER_STATS | Permission.MANAGE_RELAY
    ),
    
    'owner': Permission(0xFFFF)  # All permissions
}


@dataclass
class Role:
    """Role definition"""
    name: str
    permissions: Permission
    description: str = ""
    created_at: float = field(default_factory=time.time)


@dataclass
class User:
    """User with role assignment"""
    node_id: str
    public_key: bytes
    role: str = "user"
    banned: bool = False
    created_at: float = field(default_factory=time.time)
    last_seen: float = 0.0
    
    def update_seen(self) -> None:
        self.last_seen = time.time()


class AccessControl:
    """Role-based access control system"""
    
    def __init__(self):
        self._roles: Dict[str, Role] = {}
        self._users: Dict[str, User] = {}
        self._owner_id: Optional[str] = None
        
        # Initialize default roles
        for name, perms in ROLE_PERMISSIONS.items():
            self._roles[name] = Role(name=name, permissions=perms)
    
    def set_owner(self, node_id: str) -> None:
        """Set owner of the network"""
        self._owner_id = node_id
        
        # Create user record if not exists
        if node_id not in self._users:
            self._users[node_id] = User(
                node_id=node_id,
                public_key=b'',
                role='owner'
            )
        else:
            self._users[node_id].role = 'owner'
        
        print(f"Owner set: {node_id}")
    
    def get_owner(self) -> Optional[str]:
        """Get owner ID"""
        return self._owner_id
    
    def register_user(self, node_id: str, public_key: bytes) -> User:
        """Register new user"""
        if node_id not in self._users:
            user = User(
                node_id=node_id,
                public_key=public_key,
                role='user'
            )
            self._users[node_id] = user
            print(f"User registered: {node_id}")
        
        return self._users[node_id]
    
    def get_user(self, node_id: str) -> Optional[User]:
        """Get user by ID"""
        return self._users.get(node_id)
    
    def has_permission(self, node_id: str, permission: Permission) -> bool:
        """Check if user has permission"""
        user = self._users.get(node_id)
        if not user or user.banned:
            return False
        
        role = self._roles.get(user.role)
        if not role:
            return False
        
        # Owner has all permissions
        if user.role == 'owner':
            return True
        
        return (role.permissions & permission) == permission
    
    def check_permissions(self, node_id: str, required: Permission) -> bool:
        """Check if user has all required permissions"""
        user = self._users.get(node_id)
        if not user or user.banned:
            return False
        
        if user.role == 'owner':
            return True
        
        role = self._roles.get(user.role)
        if not role:
            return False
        
        return (role.permissions & required) == required
    
    def appoint_admin(self, actor_id: str, target_id: str, 
                     role_name: str = 'admin') -> bool:
        """
        Appoint administrator.
        Only owner or superadmin can appoint admins.
        """
        # Check if actor has permission
        if not self.has_permission(actor_id, Permission.APPOINT_ADMIN):
            print(f"Permission denied: {actor_id} cannot appoint admin")
            return False
        
        # Check if target exists
        target = self._users.get(target_id)
        if not target:
            print(f"User not found: {target_id}")
            return False
        
        # Check if role exists
        if role_name not in self._roles:
            print(f"Role not found: {role_name}")
            return False
        
        # Cannot appoint higher role than yourself
        actor_role = self._roles.get(self._users[actor_id].role)
        target_role = self._roles.get(role_name)
        
        if actor_role and target_role:
            if target_role.permissions > actor_role.permissions:
                print(f"Cannot appoint higher role: {role_name}")
                return False
        
        # Assign role
        target.role = role_name
        target.update_seen()
        
        print(f"Appointed {target_id} as {role_name} by {actor_id}")
        return True
    
    def revoke_admin(self, actor_id: str, target_id: str) -> bool:
        """
        Revoke administrator privileges.
        Only owner can revoke admins.
        """
        # Only owner can revoke
        if actor_id != self._owner_id:
            print(f"Permission denied: only owner can revoke admins")
            return False
        
        # Check if target exists
        target = self._users.get(target_id)
        if not target:
            print(f"User not found: {target_id}")
            return False
        
        # Cannot revoke owner
        if target.role == 'owner':
            print("Cannot revoke owner role")
            return False
        
        # Revoke to user role
        target.role = 'user'
        
        print(f"Revoked admin from {target_id} by {actor_id}")
        return True
    
    def ban_user(self, actor_id: str, target_id: str, 
                reason: str = "") -> bool:
        """Ban user"""
        if not self.has_permission(actor_id, Permission.BAN_USER):
            print(f"Permission denied: {actor_id} cannot ban users")
            return False
        
        target = self._users.get(target_id)
        if not target:
            return False
        
        # Cannot ban owner
        if target.role == 'owner':
            return False
        
        target.banned = True
        print(f"Banned {target_id}: {reason}")
        return True
    
    def unban_user(self, actor_id: str, target_id: str) -> bool:
        """Unban user"""
        if not self.has_permission(actor_id, Permission.BAN_USER):
            return False
        
        target = self._users.get(target_id)
        if not target:
            return False
        
        target.banned = False
        print(f"Unbanned {target_id}")
        return True
    
    def kick_user(self, actor_id: str, target_id: str) -> bool:
        """Kick user (temporary disconnect)"""
        if not self.has_permission(actor_id, Permission.KICK_USER):
            return False
        
        target = self._users.get(target_id)
        if not target:
            return False
        
        # Cannot kick owner
        if target.role == 'owner':
            return False
        
        print(f"Kicked {target_id}")
        # In real implementation, would send disconnect message
        return True
    
    def list_users(self, actor_id: str) -> List[Dict]:
        """List all users (requires VIEW_USERS permission)"""
        if not self.has_permission(actor_id, Permission.VIEW_USERS):
            return []
        
        return [
            {
                'node_id': user.node_id,
                'role': user.role,
                'banned': user.banned,
                'last_seen': user.last_seen
            }
            for user in self._users.values()
        ]
    
    def list_admins(self, actor_id: str) -> List[Dict]:
        """List all administrators"""
        if not self.has_permission(actor_id, Permission.VIEW_ADMINS):
            return []
        
        return [
            {
                'node_id': user.node_id,
                'role': user.role,
                'permissions': str(user.role)
            }
            for user in self._users.values()
            if user.role in ['admin', 'superadmin', 'owner']
        ]
    
    def create_custom_role(self, actor_id: str, name: str,
                          permissions: Permission,
                          description: str = "") -> bool:
        """Create custom role (owner only)"""
        if actor_id != self._owner_id:
            return False
        
        if name in self._roles:
            return False
        
        self._roles[name] = Role(
            name=name,
            permissions=permissions,
            description=description
        )
        
        print(f"Created custom role: {name}")
        return True
    
    def get_server_stats(self, actor_id: str) -> Dict:
        """Get server statistics"""
        if not self.has_permission(actor_id, Permission.VIEW_SERVER_STATS):
            return {}
        
        now = time.time()
        
        return {
            'total_users': len(self._users),
            'active_users': sum(1 for u in self._users.values() if now - u.last_seen < 300),
            'banned_users': sum(1 for u in self._users.values() if u.banned),
            'admins': sum(1 for u in self._users.values() if u.role in ['admin', 'superadmin']),
            'owner': self._owner_id,
            'roles': list(self._roles.keys())
        }


class AuthManager:
    """Authentication manager for admin access"""
    
    def __init__(self, access_control: AccessControl):
        self.ac = access_control
        self._sessions: Dict[str, Dict] = {}
    
    def authenticate(self, node_id: str, signature: bytes, 
                    public_key: bytes) -> bool:
        """Authenticate user with signature"""
        # Register user if not exists
        user = self.ac.register_user(node_id, public_key)
        
        # In real implementation, verify signature against challenge
        # For now, accept if we have public key
        user.public_key = public_key
        user.update_seen()
        
        return not user.banned
    
    def create_session(self, node_id: str) -> Optional[str]:
        """Create session token"""
        user = self.ac.get_user(node_id)
        if not user or user.banned:
            return None
        
        # Generate session token
        import secrets
        token = secrets.token_hex(32)
        
        self._sessions[token] = {
            'node_id': node_id,
            'created': time.time(),
            'expires': time.time() + 3600  # 1 hour
        }
        
        return token
    
    def validate_session(self, token: str) -> Optional[str]:
        """Validate session token, returns node_id if valid"""
        session = self._sessions.get(token)
        if not session:
            return None
        
        if time.time() > session['expires']:
            del self._sessions[token]
            return None
        
        return session['node_id']
    
    def destroy_session(self, token: str) -> None:
        """Destroy session"""
        self._sessions.pop(token, None)
