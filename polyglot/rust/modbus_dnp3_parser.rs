modbus_dnp3_parser.rs

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use serde::{Serialize, Serializer};
use thiserror::Error;

// ============================================================================
// ERROR TYPES
// ============================================================================

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Modbus CRC mismatch at offset {0}: expected 0x{1:04X}, got 0x{2:04X}")]
    CrcMismatch(usize, u16, u16),
    
    #[error("Modbus function code {0} not implemented for honeypot logging")]
    UnknownFunction(u8),
    
    #[error("DNP3 frame length mismatch: expected {0}, got {1}")]
    Dnp3LengthMismatch(usize, usize),
    
    #[error("DNP3 control link header corrupted")]
    Dnp3ControlHeader,
    
    #[error("DNP3 data link header corrupted")]
    Dnp3DataHeader,
    
    #[error("Invalid register address: {0}")]
    InvalidRegister(u16),
    
    #[error("Unexpected EOF in middle of frame")]
    UnexpectedEof,
}

// ============================================================================
// CONFIGURATION
// ============================================================================

#[derive(Debug, Clone)]
pub struct HoneypotConfig {
    pub log_level: LogLevel,
    pub max_frame_size: usize,
    pub include_payload: bool,
    pub output_format: OutputFormat,
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            log_level: LogLevel::Info,
            max_frame_size: 1024 * 64, // 64KB
            include_payload: true,
            output_format: OutputFormat::Json,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub enum LogLevel {
    #[default]
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum OutputFormat {
    #[default]
    Json,
    Csv,
}

// ============================================================================
// JSON LOG STRUCTURES
// ============================================================================

#[derive(Serialize, Debug, Clone)]
pub struct ModbusEvent {
    pub timestamp: u64,
    pub source_ip: String,
    pub function_code: u8,
    pub register_address: u16,
    pub operation: OperationType,
    pub value_bytes: Vec<u8>,
    pub payload_hex: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct Dnp3Event {
    pub timestamp: u64,
    pub source_ip: String,
    pub frame_type: FrameType,
    pub control_link_header: Option<ControlLinkHeader>,
    pub data_link_header: Option<DataLinkHeader>,
    pub payload_hex: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct ControlLinkHeader {
    pub sequence_number: u16,
    pub length: u16,
    pub flags: u8,
}

#[derive(Serialize, Debug, Clone)]
pub struct DataLinkHeader {
    pub source_id: u32,
    pub target_id: u32,
    pub sequence_number: u16,
    pub length: u16,
}

#[derive(Serialize, Debug, Clone)]
pub enum OperationType {
    ReadHoldingRegisters,
    WriteSingleRegister,
    WriteMultipleRegisters,
    ReadInputRegisters,
    ReadCoils,
    WriteCoil,
    WriteMultipleCoils,
    ReadDiscreteInputs,
}

#[derive(Serialize, Debug, Clone)]
pub enum FrameType {
    ControlLink,
    DataLink,
    ApplicationLayer,
}

// ============================================================================
// MODBUS PARSER
// ============================================================================

pub struct ModbusParser {
    config: HoneypotConfig,
    buffer: VecDeque<u8>,
}

impl ModbusParser {
    pub fn new(config: HoneypotConfig) -> Self {
        Self {
            config,
            buffer: VecDeque::new(),
        }
    }

    /// Process incoming bytes and extract events
    pub fn process(&mut self, data: &[u8]) -> Result<Vec<ModbusEvent>, ParseError> {
        let mut events = Vec::new();
        
        for chunk in data.chunks(16) {
            self.buffer.extend_from_slice(chunk);
            
            while self.buffer.len() >= 3 { // Minimum: ADU header + CRC
                if let Some(event) = self.parse_frame()? {
                    events.push(event);
                } else {
                    break;
                }
            }
        }

        Ok(events)
    }

    /// Parse a single Modbus frame from the buffer
    fn parse_frame(&mut self) -> Result<Option<ModbusEvent>, ParseError> {
        if self.buffer.len() < 3 {
            return Ok(None);
        }

        // Extract ADU header: slave ID (1 byte) + function code (1 byte)
        let slave_id = self.buffer[0];
        let function_code = self.buffer[1];
        
        // Calculate expected CRC for the header
        let mut crc = 0xFFFF;
        for &byte in &self.buffer[..2] {
            crc = crc_little_endian(crc, byte);
        }
        
        if self.buffer.len() < 4 || self.buffer[2..=3] != [crc as u8, (crc >> 8) as u8] {
            return Err(ParseError::CrcMismatch(0, crc, self.buffer[2].into()));
        }

        // Process based on function code
        let event = match function_code {
            0x01 => self.parse_read_coils(slave_id),
            0x02 => self.parse_read_discrete_inputs(slave_id),
            0x03 => self.parse_read_holding_registers(slave_id),
            0x04 => self.parse_read_input_registers(slave_id),
            0x05 => self.parse_write_coil(slave_id),
            0x06 => self.parse_write_single_register(slave_id),
            0x10 => self.parse_write_multiple_coils(slave_id),
            0x15 | 0x16 => self.parse_write_multiple_registers(slave_id),
            _ => return Ok(None), // Unknown or response codes
        };

        if let Some(event) = event {
            // Consume the frame from buffer
            let consumed = 4 + event.payload_len;
            self.buffer.drain(..consumed);
            
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    fn parse_read_holding_registers(&mut self, slave_id: u8) -> Option<ModbusEvent> {
        if self.buffer.len() < 6 {
            return None;
        }

        let start = 2; // After header + CRC
        let address = u16::from_le_bytes([self.buffer[start], self.buffer[start + 1]]);
        let quantity = u16::from_le_bytes([self.buffer[start + 2], self.buffer[start + 3]]);

        if address > 0xFFFF || quantity == 0 {
            return None;
        }

        let payload_len = (4 * quantity) as usize;
        if self.buffer.len() < start + 4 + payload_len {
            return None;
        }

        let value_bytes: Vec<u8> = self.buffer[start + 4..start + 4 + payload_len].to_vec();
        
        Some(ModbusEvent {
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            source_ip: "0.0.0.0".to_string(), // Will be set by caller
            function_code: 0x03,
            register_address: address,
            operation: OperationType::ReadHoldingRegisters,
            value_bytes,
            payload_hex: hex::encode(&value_bytes),
        })
    }

    fn parse_read_input_registers(&mut self, slave_id: u8) -> Option<ModbusEvent> {
        if self.buffer.len() < 6 {
            return None;
        }

        let start = 2;
        let address = u16::from_le_bytes([self.buffer[start], self.buffer[start + 1]]);
        let quantity = u16::from_le_bytes([self.buffer[start + 2], self.buffer[start + 3]]);

        if address > 0xFFFF || quantity == 0 {
            return None;
        }

        let payload_len = (4 * quantity) as usize;
        if self.buffer.len() < start + 4 + payload_len {
            return None;
        }

        let value_bytes: Vec<u8> = self.buffer[start + 4..start + 4 + payload_len].to_vec();
        
        Some(ModbusEvent {
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            source_ip: "0.0.0.0".to_string(),
            function_code: 0x04,
            register_address: address,
            operation: OperationType::ReadInputRegisters,
            value_bytes,
            payload_hex: hex::encode(&value_bytes),
        })
    }

    fn parse_read_coils(&mut self, slave_id: u8) -> Option<ModbusEvent> {
        if self.buffer.len() < 6 {
            return None;
        }

        let start = 2;
        let address = u16::from_le_bytes([self.buffer[start], self.buffer[start + 1]]);
        let quantity = u16::from_le_bytes([self.buffer[start + 2], self.buffer[start + 3]]);

        if address > 0xFFFF || quantity == 0 {
            return None;
        }

        let payload_len = (quantity / 8) as usize;
        if self.buffer.len() < start + 4 + payload_len {
            return None;
        }

        let value_bytes: Vec<u8> = self.buffer[start + 4..start + 4 + payload_len].to_vec();
        
        Some(ModbusEvent {
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            source_ip: "0.0.0.0".to_string(),
            function_code: 0x01,
            register_address: address,
            operation: OperationType::ReadCoils,
            value_bytes,
            payload_hex: hex::encode(&value_bytes),
        })
    }

    fn parse_read_discrete_inputs(&mut self, slave_id: u8) -> Option<ModbusEvent> {
        if self.buffer.len() < 6 {
            return None;
        }

        let start = 2;
        let address = u16::from_le_bytes([self.buffer[start], self.buffer[start + 1]]);
        let quantity = u16::from_le_bytes([self.buffer[start + 2], self.buffer[start + 3]]);

        if address > 0xFFFF || quantity == 0 {
            return None;
        }

        let payload_len = (quantity / 8) as usize;
        if self.buffer.len() < start + 4 + payload_len {
            return None;
        }

        let value_bytes: Vec<u8> = self.buffer[start + 4..start + 4 + payload_len].to_vec();
        
        Some(ModbusEvent {
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            source_ip: "0.0.0.0".to_string(),
            function_code: 0x02,
            register_address: address,
            operation: OperationType::ReadDiscreteInputs,
            value_bytes,
            payload_hex: hex::encode(&value_bytes),
        })
    }

    fn parse_write_coil(&mut self, slave_id: u8) -> Option<ModbusEvent> {
        if self.buffer.len() < 6 {
            return None;
        }

        let start = 2;
        let address = u16::from_le_bytes([self.buffer[start], self.buffer[start + 1]]);
        let value = self.buffer[3];

        if address > 0xFFFF {
            return None;
        }

        Some(ModbusEvent {
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            source_ip: "0.0.0.0".to_string(),
            function_code: 0x05,
            register_address: address,
            operation: OperationType::WriteCoil,
            value_bytes: vec![value],
            payload_hex: format!("0x{:X}", value),
        })
    }

    fn parse_write_single_register(&mut self, slave_id: u8) -> Option<ModbusEvent> {
        if self.buffer.len() < 7 {
            return None;
        }

        let start = 2;
        let address = u16::from_le_bytes([self.buffer[start], self.buffer[start + 1]]);
        let value = u16::from_le_bytes([self.buffer[3], self.buffer[4]]);

        if address > 0xFFFF {
            return None;
        }

        Some(ModbusEvent {
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            source_ip: "0.0.0.0".to_string(),
            function_code: 0x06,
            register_address: address,
            operation: OperationType::WriteSingleRegister,
            value_bytes: vec![value as u8, (value >> 8) as u8],
            payload_hex: format!("0x{:X}", value),
        })
    }

    fn parse_write_multiple_coils(&mut self, slave_id: u8) -> Option<ModbusEvent> {
        if self.buffer.len() < 7 {
            return None;
        }

        let start = 2;
        let address = u16::from_le_bytes([self.buffer[start], self.buffer[start + 1]]);
        let quantity = u16::from_le_bytes([self.buffer[3], self.buffer[4]]);
        let byte_count = self.buffer[5];

        if address > 0xFFFF || quantity == 0 {
            return None;
        }

        let payload_len = byte_count as usize;
        if self.buffer.len() < start + 6 + payload_len {
            return None;
        }

        let value_bytes: Vec<u8> = self.buffer[start + 6..start + 6 + payload_len].to_vec();
        
        Some(ModbusEvent {
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            source_ip: "0.0.0.0".to_string(),
            function_code: 0x10,
            register_address: address,
            operation: OperationType::WriteMultipleCoils,
            value_bytes,
            payload_hex: hex::encode(&value_bytes),
        })
    }

    fn parse_write_multiple_registers(&mut self, slave_id: u8) -> Option<ModbusEvent> {
        if self.buffer.len() < 9 {
            return None;
        }

        let start = 2;
        let address = u16::from_le_bytes([self.buffer[start], self.buffer[start + 1]]);
        let quantity = u16::from_le_bytes([self.buffer[3], self.buffer[4]]);
        let byte_count = u16::from_le_bytes([self.buffer[5], self.buffer[6]]);

        if address > 0xFFFF || quantity == 0 {
            return None;
        }

        let payload_len = (byte_count as usize) / 2 * 4; // 32-bit registers
        if self.buffer.len() < start + 7 + payload_len {
            return None;
        }

        let value_bytes: Vec<u8> = self.buffer[start + 7..start + 7 + payload_len].to_vec();
        
        Some(ModbusEvent {
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            source_ip: "0.0.0.0".to_string(),
            function_code: 0x15, // Write Multiple Registers (response)
            register_address: address,
            operation: OperationType::WriteMultipleRegisters,
            value_bytes,
            payload_hex: hex::encode(&value_bytes),
        })
    }

    fn payload_len(&self, function_code: u8) -> usize {
        match function_code {
            0x01 | 0x02 => (self.buffer[3] as usize / 8) + 4,
            0x0