"""
polyglot/python/ics_honeypot_server.py

A high-interaction Modbus/DNP3 ICS honeypot server that logs attacker 
register reads/writes as structured JSON. Uses asyncio for non-blocking
concurrency and thread-safe logging.

Usage:
    python -m polyglot.python.ics_honeypot_server --port 502 --log-dir ./logs
"""

import asyncio
import base64
import collections
import dataclasses
import datetime
import enum
import hashlib
import json
import logging
import os
import queue
import random
import socket
import struct
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# =============================================================================
# CONSTANTS & CONFIGURATION
# =============================================================================

DEFAULT_PORT = 502
DEFAULT_LOG_DIR = "./logs"
DEFAULT_TIMEOUT = 30.0  # seconds per connection
DEFAULT_MAX_CONNECTIONS = 1000
BROADCAST_ADDR = "255.255.255.255"
UNIT_ID_BROADCAST = 0

# Modbus register types for realistic responses
MODBUS_HOLDING_REGISTERS = {
    # Common ICS registers (simulated)
    40001: {"name": "Plant_Status", "type": "int32"},
    40002: {"name": "Pump_1_Speed", "type": "float"},
    40003: {"name": "Tank_Level_Pct", "type": "float"},
    40004: {"name": "Pressure_Psi", "type": "float"},
    40005: {"name": "Flow_Rate_GPM", "type": "float"},
    40101: {"name": "Valve_1_Position", "type": "int32"},
    40102: {"name": "Valve_2_Position", "type": "int32"},
    # Add more as needed...
}

# =============================================================================
# DATA MODELS
# =============================================================================

class EventType(enum.Enum):
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    READ_HOLDING_REGISTERS = "read_holding_registers"
    WRITE_SINGLE_REGISTER = "write_single_register"
    WRITE_MULTI_REGISTERS = "write_multi_registers"
    PRESET_MULTIPLE_REGS = "preset_multiple_registers"
    REPORT_SLAVE_ID = "report_slave_id"

@dataclasses.dataclass(frozen=True)
class ConnectionMetadata:
    """Thread-safe connection metadata."""
    client_ip: str
    client_port: int
    unit_id: int
    connect_time: datetime.datetime
    last_activity: datetime.datetime
    events: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclasses.dataclass(frozen=True)
class EventRecord:
    """A single logged event."""
    timestamp: datetime.datetime
    client_ip: str
    unit_id: int
    event_type: str
    register_address: Optional[int] = None
    quantity: Optional[int] = None  # For reads/writes
    value_read: Optional[bytes] = None  # What was read back
    value_written: Optional[bytes] = None  # What was written
    response_length: int = 0
    duration_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.value_read:
            d["value_read_hex"] = self.value_read.hex()
        if self.value_written:
            d["value_written_hex"] = self.value_written.hex()
        return d

# =============================================================================
# THREAD-SAFE LOGGING
# =============================================================================

class ThreadSafeLogQueue:
    """Thread-safe queue for collecting events from async workers."""
    
    def __init__(self, max_size: int = 100_000):
        self.queue: asyncio.Queue[EventRecord] = asyncio.Queue(maxsize=max_size)
        self.lock = threading.Lock()
        self.running = True
        
    def put_nowait(self, record: EventRecord) -> bool:
        """Add to queue without blocking."""
        try:
            self.queue.put_nowait(record)
            return True
        except asyncio.QueueFull:
            return False
            
    async def get_all(self, timeout: float = 1.0) -> List[EventRecord]:
        """Get all items currently in queue."""
        records = []
        while not self.queue.empty():
            try:
                records.append(self.queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return records
        
    async def drain(self, timeout: float = 1.0) -> int:
        """Drain queue and return count."""
        count = 0
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
                count += 1
            except asyncio.QueueEmpty:
                break
        return count

# =============================================================================
# MODBUS TCP PARSER (SYNCHRONOUS)
# =============================================================================

class ModbusParser:
    """Parse incoming Modbus TCP frames."""
    
    # Transaction ID, Protocol ID, Unit ID, Length, Checksum
    HEADER_SIZE = 6
    
    @classmethod
    def parse_header(cls, data: bytes) -> Tuple[int, int, int, int]:
        """Extract header fields from raw TCP payload."""
        if len(data) < cls.HEADER_SIZE:
            return -1, -1, -1, -1
            
        transaction_id = struct.unpack(">H", data[0:2])[0]
        protocol_id = struct.unpack(">H", data[2:4])[0]
        unit_id = data[4]
        length = struct.unpack(">H", data[5:7])[0]
        
        return transaction_id, protocol_id, unit_id, length
        
    @classmethod
    def parse_read_holding_registers(cls, 
                                     data: bytes,
                                     header_offset: int) -> Optional[Tuple[int, int]]:
        """Parse PDU for Read Holding Registers."""
        if len(data) < header_offset + 6:
            return None
            
        # Function code at offset 0 (relative to PDU start)
        func_code = data[header_offset]
        
        if func_code == 3:  # Read Holding Registers
            quantity = struct.unpack(">H", data[header_offset+1:header_offset+3])[0]
            starting_address = struct.unpack(">H", 
                                            data[header_offset+3:header_offset+5])[0]
            return (starting_address, quantity)
            
        elif func_code == 6:  # Write Single Register
            address = struct.unpack(">H", data[header_offset+1:header_offset+3])[0]
            value = struct.unpack(">h", data[header_offset+3:header_offset+5])[0]
            return ("write_single", address, value)
            
        elif func_code == 16:  # Write Multiple Registers
            quantity = struct.unpack(">H", 
                                    data[header_offset+1:header_offset+3])[0]
            starting_address = struct.unpack(">H", 
                                            data[header_offset+3:header_offset+5])[0]
            return ("write_multi", starting_address, quantity)
            
        elif func_code == 23:  # Preset Multiple Registers
            quantity = struct.unpack(">H", 
                                    data[header_offset+1:header_offset+3])[0]
            starting_address = struct.unpack(">H", 
                                            data[header_offset+3:header_offset+5])[0]
            return ("preset_multi", starting_address, quantity)
            
        elif func_code == 24:  # Report Slave ID
            unit_id = struct.unpack(">H", data[header_offset+1:header_offset+3])[0]
            return ("report_slave_id", unit_id)
            
        return None

# =============================================================================
# RESPONSE GENERATOR (REALISTIC DATA)
# =============================================================================

class ResponseGenerator:
    """Generate realistic responses for various register types."""
    
    def __init__(self):
        self._base_values = {
            "int32": lambda: random.randint(-2147483648, 2147483647),
            "float": lambda: round(random.uniform(0.0, 10000.0), 2),
            "bool": lambda: random.choice([True, False]),
        }
        
    def generate_response(self, 
                         register_type: str,
                         quantity: int = 1) -> bytes:
        """Generate a response for the given register type."""
        if register_type == "float":
            # Floats are stored as 32-bit IEEE 754
            value = self._base_values["float"]()
            packed = struct.pack(">f", value)
            return b"\x01" + packed  # Function code 1 (Read Coils - for float test)
            
        elif register_type == "int32":
            value = self._base_values["int32"]()
            packed = struct.pack(">i", value)
            return b"\x03" + packed  # Function code 3
            
        elif register_type == "bool":
            byte_val = 1 if self._base_values["bool"]() else 0
            return b"\x01" + bytes([byte_val])
            
        # Default: return zeros (safe fallback)
        response = b"\x03\x00"  # Function code 3, quantity 0
        for _ in range(quantity):
            response += struct.pack(">h", 0)
        return response

# =============================================================================
# ASYNC MODBUS SERVER
# =============================================================================

class AsyncModbusServer:
    """Async Modbus TCP server with thread-safe logging."""
    
    def __init__(self, 
                 port: int = DEFAULT_PORT,
                 log_dir: str = DEFAULT_LOG_DIR,
                 timeout: float = DEFAULT_TIMEOUT):
        self.port = port
        self.timeout = timeout
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Thread-safe components
        self.log_queue = ThreadSafeLogQueue()
        self.metadata_lock = threading.Lock()
        self.active_connections: Dict[int, ConnectionMetadata] = {}
        
        # Generator for responses
        self.response_gen = ResponseGenerator()
        
        # Server socket
        self.server_socket: Optional[socket.socket] = None
        
    def _get_metadata(self) -> ConnectionMetadata:
        """Get or create metadata for current connection."""
        with self.metadata_lock:
            if not self.active_connections:
                return ConnectionMetadata(
                    client_ip="0.0.0.0",
                    client_port=0,
                    unit_id=UNIT_ID_BROADCAST,
                    connect_time=datetime.datetime.now(),
                    last_activity=datetime.datetime.now()
                )
            
        # Return the most recent (simplified - in production use proper tracking)
        return list(self.active_connections.values())[-1] if self.active_connections else \
               ConnectionMetadata(
                   client_ip="0.0.0.0",
                   client_port=0,
                   unit_id=UNIT_ID_BROADCAST,
                   connect_time=datetime.datetime.now(),
                   last_activity=datetime.datetime.now()
                )
                
    def _create_response(self, 
                        func_code: int,
                        starting_address: int = 0,
                        quantity: int = 1) -> bytes:
        """Create a Modbus response for the given function code."""
        # Build header (transaction ID, protocol ID, unit ID, length)
        transaction_id = random.randint(1, 65535)
        protocol_id = 0
        unit_id = self._get_metadata().unit_id
        
        # Calculate required response size
        func_code_response_size = {
            1: 2 + quantity,           # Read Coils
            2: 2 + quantity,           # Read Discrete Inputs  
            3: 2 + (quantity * 2),     # Read Holding Registers
            4: 2 + (quantity * 2),     # Read Input Registers
            6: 5,                      # Write Single Register
            10: 7 + (quantity * 2),    # Write Multiple Registers
            15: 9 + (quantity * 2),    # Preset Multiple Registers
            23: 11 + (quantity * 2),   # Report Slave ID
        }.get(func_code, 2)
        
        length = func_code_response_size - 2
        
        header = struct.pack(">HHHBH", 
                           transaction_id, protocol_id, unit_id, length)
                           
        pdu = bytes([func_code])
        
        if func_code in (1, 2):  # Coils/Discrete Inputs
            pdu += struct.pack(">H", starting_address)
            pdu += struct.pack(">H", quantity)
            
        elif func_code == 3:  # Holding Registers
            pdu += struct.pack(">H", starting_address)
            pdu += struct.pack(">H", quantity)
            
        elif func_code in (4, 10):  # Input Registers / Multi Write
            pdu += struct.pack(">H", starting_address)
            pdu += struct.pack(">H", quantity)
            
        elif func_code == 6:  # Single Write
            pdu += struct.pack(">h", 0)  # Default value
            
        elif func_code in (15, 23):  # Preset / Report Slave ID
            pdu += struct.pack(">H", starting_address)
            pdu += struct.pack(">H", quantity)
            
        return header + pdu
        
    async def _handle_client(self, 
                            reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter,
                            addr: Tuple[str, int],
                            unit_id: int = UNIT_ID_BROADCAST):
        """Handle a single client connection."""
        
        # Create metadata for this connection
        meta = ConnectionMetadata(
            client_ip=addr[0],
            client_port=addr[1],
            unit_id=unit_id,
            connect_time=datetime.datetime.now(),
            last_activity=datetime.datetime.now()
        )
        
        try:
            # Read transaction ID from first packet
            header_data = await reader.read(6)
            if len(header_data) < 6:
                return
                
            trans_id, proto_id, conn_unit_id, length = ModbusParser.parse_header(header_data)
            
            with self.metadata_lock:
                meta.unit_id = conn_unit_id
            
            # Main read loop
            while True:
                try:
                    chunk = await reader.read(length + 20)  # Extra for safety
                    
                    if not chunk or len(chunk) < 6:
                        break
                        
                    # Parse PDU (skip header)
                    pdu_start = 6
                    pdu_data = chunk[pdu_start:]
                    
                    parsed = ModbusParser.parse_read_holding_registers(pdu_data, pdu_start)
                    
                    event_type = "unknown"
                    register_addr = None
                    quantity = 1
                    
                    if parsed:
                        event_type, addr_info = parsed
                        
                        # Extract address and quantity based on type
                        if isinstance(addr_info, tuple):
                            register_addr, quantity = addr_info
                            
                    # Generate response
                    response = self._create_response(3, register_addr or 0, quantity)
                    
                    # Send response back
                    await writer.write(response)
                    await writer.drain()
                    
                    # Update metadata and log event
                    meta.last_activity = datetime.datetime.now()
                    
                    duration_ms = (datetime.datetime.now() - 
                                  meta.connect_time).total_seconds() * 1000
                    
                    record = EventRecord(
                        timestamp=datetime.datetime.now(),
                        client_ip=meta.client_ip,
                        unit_id=meta.unit_id,
                        event_type=event_type,
                        register_address=register_addr,
                        quantity=quantity,
                        response_length=len(response),
                        duration_ms=duration_ms
                    )
                    
                    self.log_queue.put_nowait(record)
                    
                except asyncio.IncompleteReadError:
                    break
                    
        except ConnectionResetError:
            pass
        except OSError as e:
            pass
            
    async def start(self):
        """Start the server."""
        print(f"Starting ICS Honeypot on port {self.port}...")
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, 
                                      socket.SO_REUSEADDR, 1)
        self.server_socket.bind((BROADCAST_ADDR, self.port))
        self.server_socket.listen(DEFAULT_MAX_CONNECTIONS)
        
        print(f"Listening on {BROADCAST_ADDR}:{self.port}")
        print("Press Ctrl+C to stop...")
        
        while True:
            try:
                client_sock, addr = self.server_socket.accept()
                
                # Wrap in asyncio streams
                reader = asyncio.StreamReader()
                writer = asyncio.StreamWriter(client_sock, 
                                            reader, 
                                            lambda data: None,