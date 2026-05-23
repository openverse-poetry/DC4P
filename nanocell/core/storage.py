"""
NanoCell Core - LSM-tree storage engine
Compact, fast key-value store optimized for write-heavy workloads
"""

import os
import struct
import threading
from typing import Optional, Dict, List, Tuple, Iterator, Any
from dataclasses import dataclass
from pathlib import Path
import msgpack


@dataclass
class Entry:
    """Key-value entry with timestamp"""
    key: bytes
    value: bytes
    timestamp: int
    deleted: bool = False
    
    def to_bytes(self) -> bytes:
        """Serialize entry to bytes"""
        data = msgpack.packb({
            'k': self.key,
            'v': self.value,
            't': self.timestamp,
            'd': self.deleted
        })
        return struct.pack('>I', len(data)) + data
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'Entry':
        """Deserialize entry from bytes"""
        length = struct.unpack('>I', data[:4])[0]
        packed = msgpack.unpackb(data[4:4+length], raw=False)
        return cls(
            key=packed['k'],
            value=packed['v'],
            timestamp=packed['t'],
            deleted=packed.get('d', False)
        )


class SkipList:
    """In-memory skip list for MemTable"""
    
    MAX_LEVEL = 4
    
    def __init__(self):
        self._heads: List[Optional['_Node']] = [None] * self.MAX_LEVEL
        self._size = 0
        self._lock = threading.RLock()
    
    def _random_level(self) -> int:
        """Generate random level with geometric distribution"""
        level = 1
        while level < self.MAX_LEVEL and (hash(str(level)) % 2) == 0:
            level += 1
        return level
    
    def put(self, key: bytes, entry: Entry) -> None:
        """Insert or update entry"""
        with self._lock:
            level = self._random_level()
            new_node = _Node(key, entry, level)
            
            updates = [_Update(None, None) for _ in range(level)]
            current = self._heads[0]
            
            for i in reversed(range(level)):
                while current and current.forward[i] and current.forward[i].key < key:
                    current = current.forward[i]
                updates[i] = _Update(current, current.forward[i] if current else None)
            
            # Insert node
            for i in range(level):
                new_node.forward[i] = updates[i].next_node
                if updates[i].prev_node:
                    updates[i].prev_node.forward[i] = new_node
                else:
                    self._heads[i] = new_node
            
            self._size += 1
    
    def get(self, key: bytes) -> Optional[Entry]:
        """Get entry by key"""
        with self._lock:
            current = self._heads[0]
            
            for i in reversed(range(self.MAX_LEVEL)):
                while current and i < len(current.forward) and current.forward[i] and current.forward[i].key <= key:
                    current = current.forward[i]
            
            if current and current.key == key:
                return current.entry
            return None
    
    def delete(self, key: bytes) -> bool:
        """Mark entry as deleted"""
        with self._lock:
            entry = self.get(key)
            if entry:
                entry.deleted = True
                return True
            return False
    
    def iter_range(self, start: bytes, end: bytes) -> Iterator[Entry]:
        """Iterate over entries in range [start, end)"""
        with self._lock:
            current = self._heads[0]
            
            # Find start position
            while current and current.key < start:
                current = current.forward[0]
            
            # Yield entries until end
            while current and current.key < end:
                yield current.entry
                current = current.forward[0]
    
    def __len__(self) -> int:
        return self._size


@dataclass
class _Node:
    """Skip list node"""
    key: bytes
    entry: Entry
    forward: List[Optional['_Node']]
    
    def __init__(self, key: bytes, entry: Entry, level: int):
        self.key = key
        self.entry = entry
        self.forward = [None] * level


@dataclass
class _Update:
    """Update helper for skip list"""
    prev_node: Optional[_Node]
    next_node: Optional[_Node]


class MemTable:
    """In-memory table (write buffer)"""
    
    def __init__(self, max_size: int = 4 * 1024 * 1024):
        self._skiplist = SkipList()
        self._max_size = max_size
        self._current_size = 0
        self._lock = threading.Lock()
    
    def put(self, key: bytes, value: bytes, deleted: bool = False) -> None:
        """Add entry to memtable"""
        entry = Entry(
            key=key,
            value=value,
            timestamp=self._timestamp(),
            deleted=deleted
        )
        
        with self._lock:
            old_entry = self._skiplist.get(key)
            if old_entry:
                self._current_size -= len(old_entry.key) + len(old_entry.value)
            
            self._skiplist.put(key, entry)
            self._current_size += len(key) + len(value)
    
    def get(self, key: bytes) -> Optional[Entry]:
        """Get entry from memtable"""
        entry = self._skiplist.get(key)
        if entry and not entry.deleted:
            return entry
        return None
    
    def delete(self, key: bytes) -> None:
        """Mark key as deleted"""
        self.put(key, b'', deleted=True)
    
    def is_full(self) -> bool:
        """Check if memtable needs flushing"""
        return self._current_size >= self._max_size
    
    def flush_to_sst(self, path: Path) -> 'SSTable':
        """Flush memtable to SSTable file"""
        entries = []
        for entry in self._skiplist.iter_range(b'', b'\xff' * 64):
            entries.append(entry)
        
        sst = SSTable.create(path, entries)
        
        # Reset memtable
        with self._lock:
            self._skiplist = SkipList()
            self._current_size = 0
        
        return sst
    
    def iter_all(self) -> Iterator[Entry]:
        """Iterate all entries"""
        return self._skiplist.iter_range(b'', b'\xff' * 64)
    
    @staticmethod
    def _timestamp() -> int:
        import time
        return int(time.time() * 1000000)


class SSTable:
    """Sorted String Table (immutable file on disk)"""
    
    def __init__(self, path: Path, index: Dict[bytes, int]):
        self.path = path
        self._index = index
        self._file = open(path, 'rb')
        self._lock = threading.Lock()
    
    @classmethod
    def create(cls, path: Path, entries: List[Entry]) -> 'SSTable':
        """Create SSTable from sorted entries"""
        # Sort entries by key
        entries.sort(key=lambda e: e.key)
        
        index = {}
        with open(path, 'wb') as f:
            for entry in entries:
                offset = f.tell()
                index[entry.key] = offset
                f.write(entry.to_bytes())
            
            # Write index at end
            index_offset = f.tell()
            index_data = msgpack.packb(index)
            f.write(struct.pack('>I', len(index_data)))
            f.write(index_data)
            f.write(struct.pack('>Q', index_offset))
        
        return cls(path, index)
    
    @classmethod
    def load(cls, path: Path) -> 'SSTable':
        """Load SSTable from file"""
        with open(path, 'rb') as f:
            # Read index location
            f.seek(-20, 2)  # Last 20 bytes: index_length(4) + index_offset(8) + padding
            index_offset = struct.unpack('>Q', f.read(8))[0]
            
            # Read index
            f.seek(index_offset)
            index_data = f.read()
            index_length = struct.unpack('>I', index_data[:4])[0]
            index = msgpack.unpackb(index_data[4:4+index_length], raw=False)
            
            # Convert keys to bytes
            index = {k.encode() if isinstance(k, str) else k: v for k, v in index.items()}
        
        return cls(path, index)
    
    def get(self, key: bytes) -> Optional[Entry]:
        """Get entry by key"""
        if key not in self._index:
            return None
        
        with self._lock:
            offset = self._index[key]
            self._file.seek(offset)
            
            # Read entry length
            length_data = self._file.read(4)
            if len(length_data) < 4:
                return None
            
            length = struct.unpack('>I', length_data)[0]
            entry_data = self._file.read(length)
            
            if len(entry_data) < length:
                return None
            
            entry = Entry.from_bytes(struct.pack('>I', length) + entry_data)
            return entry if not entry.deleted else None
    
    def close(self) -> None:
        """Close SSTable file"""
        self._file.close()
    
    def __del__(self):
        if hasattr(self, '_file'):
            self._file.close()


class LSMTree:
    """LSM-tree storage engine"""
    
    def __init__(self, db_path: str, max_memtable_size: int = 4 * 1024 * 1024):
        self.db_path = Path(db_path)
        self.db_path.mkdir(parents=True, exist_ok=True)
        
        self._memtable = MemTable(max_memtable_size)
        self._imm_memtable: Optional[MemTable] = None
        self._sstables: List[SSTable] = []
        self._lock = threading.RLock()
        
        # Load existing SSTables
        self._load_sstables()
        
        # Start compaction thread
        self._running = True
        self._compact_thread = threading.Thread(target=self._compaction_loop, daemon=True)
        self._compact_thread.start()
    
    def _load_sstables(self) -> None:
        """Load existing SSTables from disk"""
        sst_files = sorted(self.db_path.glob('*.sst'))
        for sst_file in sst_files:
            try:
                sst = SSTable.load(sst_file)
                self._sstables.append(sst)
            except Exception as e:
                print(f"Failed to load SSTable {sst_file}: {e}")
    
    def put(self, key: bytes, value: bytes) -> None:
        """Put key-value pair"""
        with self._lock:
            self._memtable.put(key, value)
            
            # Check if flush needed
            if self._memtable.is_full():
                self._flush_memtable()
    
    def get(self, key: bytes) -> Optional[bytes]:
        """Get value by key"""
        # Check memtable first
        entry = self._memtable.get(key)
        if entry:
            return entry.value if not entry.deleted else None
        
        # Check immutable memtable
        if self._imm_memtable:
            entry = self._imm_memtable.get(key)
            if entry:
                return entry.value if not entry.deleted else None
        
        # Check SSTables (newest first)
        for sst in reversed(self._sstables):
            entry = sst.get(key)
            if entry:
                return entry.value if not entry.deleted else None
        
        return None
    
    def delete(self, key: bytes) -> None:
        """Delete key"""
        self.put(key, b'')  # Tombstone
    
    def _flush_memtable(self) -> None:
        """Flush memtable to SSTable"""
        if self._imm_memtable:
            return  # Already flushing
        
        self._imm_memtable = self._memtable
        self._memtable = MemTable(self._memtable._max_size)
        
        # Flush in background
        thread = threading.Thread(target=self._do_flush, daemon=True)
        thread.start()
    
    def _do_flush(self) -> None:
        """Perform flush operation"""
        try:
            sst_name = f"{self._timestamp()}.sst"
            sst_path = self.db_path / sst_name
            
            sst = self._imm_memtable.flush_to_sst(sst_path)
            
            with self._lock:
                self._sstables.append(sst)
                self._imm_memtable = None
        except Exception as e:
            print(f"Flush failed: {e}")
            with self._lock:
                self._imm_memtable = None
    
    def _compaction_loop(self) -> None:
        """Background compaction"""
        while self._running:
            import time
            time.sleep(10)
            
            with self._lock:
                if len(self._sstables) > 4:
                    self._compact()
    
    def _compact(self) -> None:
        """Merge SSTables"""
        # Take first 2 SSTables
        if len(self._sstables) < 2:
            return
        
        sst1 = self._sstables.pop(0)
        sst2 = self._sstables.pop(0)
        
        # Merge entries
        entries = {}
        for sst in [sst1, sst2]:
            for key in sst._index.keys():
                entry = sst.get(key)
                if entry:
                    entries[key] = entry
        
        # Create merged SSTable
        merged_entries = list(entries.values())
        sst_name = f"{self._timestamp()}_merged.sst"
        sst_path = self.db_path / sst_name
        
        new_sst = SSTable.create(sst_path, merged_entries)
        self._sstables.append(new_sst)
        
        # Close and remove old SSTables
        sst1.close()
        sst2.close()
        sst1.path.unlink(missing_ok=True)
        sst2.path.unlink(missing_ok=True)
    
    def close(self) -> None:
        """Close database"""
        self._running = False
        
        # Flush remaining data
        with self._lock:
            if self._memtable and len(self._memtable._skiplist) > 0:
                self._flush_memtable()
                import time
                time.sleep(0.5)  # Wait for flush
        
        # Close SSTables
        for sst in self._sstables:
            sst.close()
    
    @staticmethod
    def _timestamp() -> int:
        import time
        return int(time.time() * 1000000)
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
