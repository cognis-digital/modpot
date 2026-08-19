"""
modpot/modbus_dnp3_parser.py

A high-interaction ICS honeypot parser for Modbus and DNP3 protocols.
Parses register reads/writes into structured JSON events suitable for analysis.

Usage:
    from modbus_dnp3_parser import EventCollector, ModbusEvent, DNP3Event
    
    collector = EventCollector()
    
    # Parse a Modbus read request
    data = b'\x01\x03\x00\x00\x00\x06'  # FC=03 (Read Holding Registers)
    event = collector.parse(data, protocol='modbus')
    
    # Output as JSON
    print(event.to_json())
"""

from __future__ import annotations
import struct
import json
import logging
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from typing import Optional, Dict, Any, List, Callable, Union
from datetime import datetime, timezone
from collections import defaultdict

# Configure logging
logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS & ENUMS
# =============================================================================

class ModbusFunctionCode(Enum):
    """Standard Modbus function codes."""
    READ_COILS = 0x01
    READ_HOLDING_REGISTERS = 0x03
    WRITE_SINGLE_REGISTER = 0x06
    WRITE_MULTI_REGISTERS = 0x10
    READ_INPUT_REGISTERS = 0x04
    WRITE_SINGLE_COIL = 0x05

class DNP3FunctionCode(Enum):
    """Common DNP3 application layer function codes."""
    # Transaction Initiation (TI)
    TI_REQUEST = auto()
    TI_RESPONSE = auto()
    
    # Transaction Response (TR)
    TR_REQUEST = auto()
    TR_RESPONSE = auto()
    
    # Transaction Event (TE)
    TE_REQUEST = auto()
    TE_RESPONSE = auto()

class ProtocolType(Enum):
    """Supported protocol types."""
    MODBUS_RTU = "modbus-rtu"
    MODBUS_TCP = "modbus-tcp"
    DNP3 = "dnp3"


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class BaseEvent:
    """Base event model for all protocol events."""
    timestamp: str  # ISO format with timezone
    protocol: ProtocolType
    transaction_id: Optional[int] = None
    
    def to_json(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class ModbusEvent(BaseEvent):
    """Parsed Modbus event."""
    function_code: int
    starting_address: int
    quantity_of_bytes: int
    data: Optional[bytes] = None
    
    # Computed fields
    register_count: int = 0
    is_read: bool = False
    is_write: bool = False
    is_response: bool = False
    
    def to_json(self) -> Dict[str, Any]:
        result = super().to_json()
        result.update({
            "function_code": self.function_code,
            "starting_address": self.starting_address,
            "quantity_of_bytes": self.quantity_of_bytes,
            "register_count": self.register_count,
            "is_read": self.is_read,
            "is_write": self.is_write,
            "is_response": self.is_response,
        })
        if self.data:
            result["data_hex"] = self.data.hex()
        return result


@dataclass
class DNP3Event(BaseEvent):
    """Parsed DNP3 event."""
    transaction_type: str  # TI/TR/TE/etc.
    sequence_number: int
    transaction_counter: int
    pdu_length: int
    
    # Computed fields
    is_request: bool = False
    is_response: bool = False
    
    def to_json(self) -> Dict[str, Any]:
        result = super().to_json()
        result.update({
            "transaction_type": self.transaction_type,
            "sequence_number": self.sequence_number,
            "transaction_counter": self.transaction_counter,
            "pdu_length": self.pdu_length,
            "is_request": self.is_request,
            "is_response": self.is_response,
        })
        return result


@dataclass
class HoneypotEvent:
    """Unified event for the honeypot collector."""
    timestamp: str
    source_ip: Optional[str] = None
    target_port: int = 502  # Default Modbus port
    
    # Protocol-specific data
    modbus_event: Optional[ModbusEvent] = None
    dnp3_event: Optional[DNP3Event] = None
    
    # Computed fields
    event_type: str = ""
    direction: str = "unknown"  # request, response, unknown
    register_address: Optional[int] = None
    value_read: Optional[Union[int, bytes]] = None
    value_written: Optional[Union[int, bytes]] = None
    
    def to_json(self) -> Dict[str, Any]:
        result = {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip or "",
            "target_port": self.target_port,
            "event_type": self.event_type,
            "direction": self.direction,
            "register_address": self.register_address,
            "value_read": self.value_read,
            "value_written": self.value_written,
        }
        
        if self.modbus_event:
            result["modbus"] = self.modbus_event.to_json()
        elif self.dnp3_event:
            result["dnp3"] = self.dnp3_event.to_json()
            
        return result


# =============================================================================
# MODBUS PARSER
# =============================================================================

class ModbusParser:
    """Parse Modbus RTU/TCP frames."""
    
    # Common function codes mapping
    FUNCTION_CODE_MAP = {
        0x01: "ReadCoils",
        0x03: "ReadHoldingRegisters",
        0x04: "ReadInputRegisters",
        0x05: "WriteSingleCoil",
        0x06: "WriteSingleRegister",
        0x10: "WriteMultipleRegisters",
    }
    
    @classmethod
    def parse(cls, data: bytes, protocol: ProtocolType = ProtocolType.MODBUS_RTU) -> Optional[ModbusEvent]:
        if len(data) < 6:
            return None
        
        # Parse common header
        transaction_id = struct.unpack(">H", data[:2])[0]
        
        if protocol == ProtocolType.MODBUS_TCP:
            # TCP has additional 2-byte length field
            if len(data) < 4:
                return None
            tcp_length = struct.unpack(">H", data[2:4])[0]
            actual_data = data[4:]
            expected_pdu_len = tcp_length - 2  # Subtract transaction ID and length
        else:
            actual_data = data[2:]
        
        if len(actual_data) < 3:
            return None
        
        # Parse PDU header (function code + address + quantity)
        function_code = actual_data[0]
        starting_address = struct.unpack(">H", actual_data[1:3])[0]
        quantity_of_bytes = struct.unpack(">H", actual_data[3:5])[0]
        
        # Extract data payload if present (excluding CRC for RTU)
        pdu_length = 5 + len(actual_data) - 5
        data_payload = actual_data[5:pdu_length] if len(actual_data) > 5 else b""
        
        return ModbusEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            protocol=protocol,
            transaction_id=transaction_id,
            function_code=function_code,
            starting_address=starting_address,
            quantity_of_bytes=quantity_of_bytes,
            data=data_payload if data_payload else None,
        )


# =============================================================================
# DNP3 PARSER (Simplified but functional)
# =============================================================================

class DNP3Parser:
    """Parse DNP3 frames. Simplified implementation focusing on common cases."""
    
    # Magic bytes for DNP3 over TCP/IP
    DNP3_MAGIC = b'\x06\x08'  # Link Layer Control Field
    
    @classmethod
    def parse(cls, data: bytes) -> Optional[DNP3Event]:
        if len(data) < 12:
            return None
        
        # Parse LLCF (Link Layer Control Field) - first 4 bytes
        llcf = data[:4]
        
        try:
            # Extract fields from LLCF
            # Format: [Version(1)][ALP(1)][Transaction Counter(2)][Sequence Number(2)]
            version = llcf[0]
            alp = llcf[1]
            transaction_counter = struct.unpack(">H", llcf[2:4])[0]
            sequence_number = struct.unpack(">H", llcf[4:6])[0]
            
            # Determine PDU type from ALP (Application Layer Protocol)
            pdu_type_map = {
                0x01: "TI_REQUEST",
                0x02: "TI_RESPONSE", 
                0x03: "TR_REQUEST",
                0x04: "TR_RESPONSE",
                0x05: "TE_REQUEST",
                0x06: "TE_RESPONSE",
            }
            
            pdu_type = pdu_type_map.get(alp, f"UNKNOWN_{alp}")
            
            # Determine if this is a request or response based on ALP and sequence
            # TI/TE requests have even sequence numbers, responses are odd (simplified)
            is_request = sequence_number % 2 == 0
            
        except Exception as e:
            logger.warning(f"DNP3 parse error: {e}")
            return None
        
        return DNP3Event(
            timestamp=datetime.now(timezone.utc).isoformat(),
            transaction_type=pdu_type,
            sequence_number=sequence_number,
            transaction_counter=transaction_counter,
            pdu_length=len(data),
            is_request=is_request,
            is_response=not is_request,
        )


# =============================================================================
# EVENT COLLECTOR & ROUTER
# =============================================================================

class EventCollector:
    """Collect and route events from multiple protocol parsers."""
    
    def __init__(self):
        self.events: List[HoneypotEvent] = []
        self.event_handlers: Dict[str, Callable[[HoneypotEvent], None]] = {}
        
        # Register default handlers
        self._register_default_handlers()
    
    def _register_default_handlers(self) -> None:
        """Register built-in event handlers."""
        
        def handle_modbus(event: HoneypotEvent):
            if not event.modbus_event:
                return
            
            fc = event.modbus_event.function_code
            is_read = fc in (0x03, 0x04)  # Read operations
            is_write = fc in (0x06, 0x10)  # Write operations
            
            if is_read:
                register_addr = event.modbus_event.starting_address
                reg_count = event.modbus_event.quantity_of_bytes // 2
                value_read = f"Registers {register_addr}-{register_addr + reg_count - 1}"
            else:
                register_addr = event.modbus_event.starting_address
                if fc == 0x06:
                    # Single write
                    value_written = struct.unpack(">H", event.modbus_event.data[:2])[0] if event.modbus_event.data else None
                else:
                    # Multi write - simplified
                    value_written = f"Multi-register write to {register_addr}"
            
            event.event_type = "ModbusRead" if is_read else ("ModbusWriteSingle" if fc == 0x06 else "ModbusWriteMulti")
            event.direction = "request" if not event.modbus_event.is_response else "response"
            event.register_address = register_addr
            event.value_read = value_read
            event.value_written = value_written
            
        def handle_dnp3(event: HoneypotEvent):
            if not event.dnp3_event:
                return
            
            # Determine direction from is_request flag
            event.event_type = "DNP3" + (event.dnp3_event.transaction_type.replace("_", "") or "UNKNOWN")
            event.direction = "request" if event.dnp3_event.is_request else "response"
            
        self.event_handlers["modbus"] = handle_modbus
        self.event_handlers["dnp3"] = handle_dnp3
    
    def parse(self, data: bytes, protocol: ProtocolType = ProtocolType.MODBUS_RTU) -> Optional[HoneypotEvent]:
        """Parse incoming data and route to appropriate handler."""
        
        event = HoneypotEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            target_port=502 if protocol in (ProtocolType.MODBUS_RTU, ProtocolType.MODBUS_TCP) else 20000,
        )
        
        # Try Modbus first
        modbus_event = ModbusParser.parse(data, protocol)
        if modbus_event:
            event.modbus_event = modbus_event
            self.event_handlers["modbus"](event)
            return event
        
        # Then try DNP3
        dnp3_event = DNP3Parser.parse(data)
        if dnp3_event:
            event.dnp3_event = dnp3_event
            self.event_handlers["dnp3"](event)
            return event
        
        return None
    
    def add_handler(self, protocol: str, handler: Callable[[HoneypotEvent], None]) -> None:
        """Add a custom event handler for a specific protocol."""
        key = protocol.lower()
        self.event_handlers[key] = handler
    
    def get_events(self) -> List[Dict[str, Any]]:
        """Get all collected events as JSON-serializable dicts."""
        return [e.to_json() for e in self.events]
    
    def clear(self) -> None:
        """Clear the event buffer."""
        self.events.clear()


# =============================================================================
# DEMO & TESTING
# =============================================================================

def main():
    """Demo showing parser capabilities with sample payloads."""
    
    collector = EventCollector()
    
    # Sample Modbus RTU: Read Holding Registers (FC=03)
    # Transaction ID, Protocol ID, Length, Function Code, Address, Quantity
    modbus_read = bytes([
        0x01, 0x02,  # Transaction ID
        0x00, 0x03,  # Protocol ID (Modbus RTU) + Length
        0x03,        # Function Code: Read Holding Registers
        0x00, 0x06,  # Starting Address
        0x00, 0x02,  # Quantity of Bytes
    ])
    
    print("=" * 50)
    print("Sample 1: Modbus RTU Read Holding Registers")
    print(f"Raw bytes: {modbus_read.hex()}")
    print()
    
    event = collector.parse(modbus_read, ProtocolType.MODBUS_RTU)
    if event and event.modbus_event:
        print(f"Parsed as: {event.event_type}")
        print(f"Function Code: 0x{event.modbus_event.function_code:02X} ({ModbusFunctionCode(event.modbus_event.function_code).name})")
        print(f"Starting Address: {event.modbus_event.starting_address}")
        print(f"Quantity of Bytes: {event.modbus_event.quantity_of_bytes}")
        print(f"Register Count: {event.modbus_event.register_count}")
        print(f"Direction: {event.direction}")
        print()
    
    # Sample Modbus TCP: Write Single Register (FC=06)
    modbus_write = bytes([
        0x01, 0x02,  # Transaction ID
        0x00, 0x04,  # Protocol ID + Length (TCP)
        0x03,        # Function Code: Write Single Register
        0x00, 0x06,  # Starting Address
        0x00, 0x02,  # Quantity of Bytes
        0x12, 0x34,  # Data (register value)
    ])
    
    print("=" * 50)
    print("Sample 2: Modbus TCP Write Single Register")
    print(f"Raw bytes: {modbus_write.hex()}")
    print()
    
    event = collector.parse(modbus_write, ProtocolType.MODBUS_TCP)
    if event