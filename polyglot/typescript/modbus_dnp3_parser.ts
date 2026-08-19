import { EventEmitter } from 'events';
import net from 'net';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

interface ModbusFrameHeader {
  transactionId?: number;
  unitId: number;
  functionCode: number;
  payloadLength: number;
}

interface Dnp3FrameHeader {
  stationId: number;
  sequenceNumber: number;
  controlCode: number;
  length: number;
}

interface ModbusEvent {
  timestamp: string;
  sourceIp: string;
  protocol: 'modbus';
  subProtocol: 'tcp' | 'rtu';
  unitId: number;
  functionCode: number;
  pduLength: number;
  transactionId?: number;
  registerAddress?: number;
  registerCount?: number;
  valueRead?: string;
  valueWritten?: string;
  direction: 'read' | 'write';
  rawHex: string;
}

interface Dnp3Event {
  timestamp: string;
  sourceIp: string;
  protocol: 'dnp3';
  stationId: number;
  sequenceNumber: number;
  controlCode: number;
  pduLength: number;
  direction: 'read' | 'write';
  rawHex: string;
}

interface ParserConfig {
  port?: number;
  unitId?: number;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  enableTcp: boolean;
  enableRtu: boolean;
}

// ============================================================================
// MODBUS PARSER
// ============================================================================

class ModbusParser {
  private config: ParserConfig;
  private readonly FUNCTION_CODES = new Map<number, string>([
    [1, 'Read Coils'],
    [2, 'Read Discrete Inputs'],
    [3, 'Read Holding Registers'],
    [4, 'Read Input Registers'],
    [5, 'Test On/Off Coil'],
    [6, 'Preset Single Register'],
    [7, 'Preset Multiple Registers'],
    [8, 'Read Write Multiple Registers'],
  ]);

  constructor(config: Partial<ParserConfig> = {}) {
    this.config = {
      port: config.port || 502,
      unitId: config.unitId || 1,
      logLevel: config.logLevel || 'info',
      enableTcp: config.enableTcp !== false,
      enableRtu: config.enableRtu !== false,
    };
  }

  private static crc16(data: Uint8Array): number {
    let crc = 0xFFFF;
    for (let i = 0; i < data.length; i++) {
      crc ^= data[i];
      for (let j = 0; j < 8; j++) {
        if ((crc & 0x80) !== 0) {
          crc = (crc << 1) ^ 0x1021;
        } else {
          crc <<= 1;
        }
      }
    }
    return crc >>> 0;
  }

  private static validateCrc(data: Uint8Array, expectedCrc?: number): boolean {
    if (expectedCrc === undefined) return true;
    const calculated = ModbusParser.crc16(data);
    return calculated === expectedCrc;
  }

  private static parseModbusTcpHeader(buffer: Uint8Array): ModbusFrameHeader | null {
    if (buffer.length < 2) return null;

    const transactionId = buffer[0] << 8 | buffer[1];
    const unitId = buffer[2];
    const functionCode = buffer[3];

    let payloadLength: number;
    if (functionCode === 8 || functionCode === 15) {
      // Read/Write Multiple - length is in high byte of function code area
      payloadLength = (buffer[4] << 8 | buffer[5]) + 6; // +6 for header
    } else {
      payloadLength = 6; // Standard functions: 2+1+1+2=6 bytes header
    }

    return { transactionId, unitId, functionCode, payloadLength };
  }

  private static parseModbusRtuFrame(buffer: Uint8Array): ModbusFrameHeader | null {
    if (buffer.length < 4) return null;

    const unitId = buffer[0];
    const functionCode = buffer[1];
    
    // CRC is last 2 bytes, validate first
    const payloadWithoutCrc = buffer.slice(0, -2);
    const expectedCrc = (buffer[buffer.length - 2] << 8) | buffer[buffer.length - 1];
    if (!ModbusParser.validateCrc(payloadWithoutCrc, expectedCrc)) {
      return null; // CRC failed
    }

    let payloadLength: number;
    if (functionCode === 8 || functionCode === 15) {
      payloadLength = ((buffer[2] << 8) | buffer[3]) + 4;
    } else {
      payloadLength = 4;
    }

    return { unitId, functionCode, payloadLength };
  }

  private static parseRegisterAddress(buffer: Uint8Array, offset: number): number | null {
    if (buffer.length < offset + 2) return null;
    // High byte first for Modbus
    return (buffer[offset] << 8) | buffer[offset + 1];
  }

  private static parseRegisterCount(buffer: Uint8Array, offset: number): number | null {
    if (buffer.length < offset + 4) return null;
    // High byte first for Modbus
    return (buffer[offset] << 24) | (buffer[offset + 1] << 16) | 
           (buffer[offset + 2] << 8) | buffer[offset + 3];
  }

  private static parseRegisterValue(buffer: Uint8Array, offset: number): string {
    if (buffer.length < offset + 4) return '---';
    // High byte first for Modbus
    const high = (buffer[offset] << 24) | (buffer[offset + 1] << 16) | 
                 (buffer[offset + 2] << 8) | buffer[offset + 3];
    const low = (buffer[offset + 4] << 24) | (buffer[offset + 5] << 16) | 
                (buffer[offset + 6] << 8) | buffer[offset + 7];
    return ((high & 0xFFFF) << 16) | (low & 0xFFFF).toString(16);
  }

  private static parseModbusPayload(buffer: Uint8Array, header: ModbusFrameHeader): {
    address?: number;
    count?: number;
    value?: string;
    direction: 'read' | 'write';
    rawHex: string;
  } {
    let offset = 6; // Skip standard header

    const result = {
      rawHex: buffer.slice(0).toString('hex'),
      direction: 'read',
    };

    switch (header.functionCode) {
      case 1: // Read Coils
        if (buffer.length >= offset + 4) {
          result.address = (buffer[offset] << 8) | buffer[offset + 1];
          result.count = (buffer[offset + 2] << 8) | buffer[offset + 3];
          offset += 4;
        }
        break;

      case 2: // Read Discrete Inputs
        if (buffer.length >= offset + 4) {
          result.address = (buffer[offset] << 8) | buffer[offset + 1];
          result.count = (buffer[offset + 2] << 8) | buffer[offset + 3];
          offset += 4;
        }
        break;

      case 3: // Read Holding Registers
        if (buffer.length >= offset + 4) {
          result.address = ModbusParser.parseRegisterAddress(buffer, offset);
          result.count = ModbusParser.parseRegisterCount(buffer, offset + 2);
          offset += 6;
        }
        break;

      case 4: // Read Input Registers
        if (buffer.length >= offset + 4) {
          result.address = ModbusParser.parseRegisterAddress(buffer, offset);
          result.count = ModbusParser.parseRegisterCount(buffer, offset + 2);
          offset += 6;
        }
        break;

      case 5: // Test On/Off Coil
        if (buffer.length >= offset) {
          result.address = (buffer[offset] << 8) | buffer[offset + 1];
          result.value = 'ON';
          offset += 2;
        }
        break;

      case 6: // Preset Single Register
        if (buffer.length >= offset + 4) {
          result.address = ModbusParser.parseRegisterAddress(buffer, offset);
          result.value = ModbusParser.parseRegisterValue(buffer, offset + 2);
          offset += 6;
        }
        break;

      case 7: // Preset Multiple Registers
        if (buffer.length >= offset + 10) {
          result.address = ModbusParser.parseRegisterAddress(buffer, offset);
          result.count = ModbusParser.parseRegisterCount(buffer, offset + 2);
          result.value = 'MULTIPLE';
          offset += 10;
        }
        break;

      case 8: // Read/Write Multiple Registers (Read)
        if (buffer.length >= offset + 4) {
          result.address = ModbusParser.parseRegisterAddress(buffer, offset);
          result.count = ModbusParser.parseRegisterCount(buffer, offset + 2);
          result.value = 'MULTIPLE';
          offset += 6;
        }
        break;

      case 15: // Read/Write Multiple Registers (Write)
        if (buffer.length >= offset + 4) {
          result.address = ModbusParser.parseRegisterAddress(buffer, offset);
          result.count = ModbusParser.parseRegisterCount(buffer, offset + 2);
          result.value = 'MULTIPLE';
          offset += 6;
        }
        break;

      case 16: // Write Single Coil
        if (buffer.length >= offset) {
          result.address = (buffer[offset] << 8) | buffer[offset + 1];
          result.value = buffer[offset + 2] ? 'ON' : 'OFF';
          offset += 3;
        }
        break;

      case 17: // Preset Single Coil
        if (buffer.length >= offset) {
          result.address = (buffer[offset] << 8) | buffer[offset + 1];
          result.value = buffer[offset + 2] ? 'ON' : 'OFF';
          offset += 3;
        }
        break;

      case 20: // Preset Multiple Coils
        if (buffer.length >= offset + 4) {
          result.address = (buffer[offset] << 8) | buffer[offset + 1];
          result.count = (buffer[offset + 2] << 8) | buffer[offset + 3];
          result.value = 'MULTIPLE';
          offset += 4;
        }
        break;

      case 22: // Read/Write Multiple Coils
        if (buffer.length >= offset + 4) {
          result.address = (buffer[offset] << 8) | buffer[offset + 1];
          result.count = (buffer[offset + 2] << 8) | buffer[offset + 3];
          result.value = 'MULTIPLE';
          offset += 4;
        }
        break;

      case 23: // Read/Write Multiple Registers
        if (buffer.length >= offset + 10) {
          result.address = ModbusParser.parseRegisterAddress(buffer, offset);
          result.count = ModbusParser.parseRegisterCount(buffer, offset + 2);
          result.value = 'MULTIPLE';
          offset += 10;
        }
        break;

      case 43: // Read FIFO Queue
        if (buffer.length >= offset + 4) {
          result.address = (buffer[offset] << 8) | buffer[offset + 1];
          result.count = (buffer[offset + 2] << 8) | buffer[offset + 3];
          result.value = 'FIFO';
          offset += 4;
        }
        break;

      case 63: // Write FIFO Queue
        if (buffer.length >= offset + 4) {
          result.address = (buffer[offset] << 8) | buffer[offset + 1];
          result.count = (buffer[offset + 2] << 8) | buffer[offset + 3];
          result.value = 'FIFO';
          offset += 4;
        }
        break;

      case 65: // Read/Write FIFO Queue
        if (buffer.length >= offset + 4) {
          result.address = (buffer[offset] << 8) | buffer[offset + 1];
          result.count = (buffer[offset + 2] << 8) | buffer[offset + 3];
          result.value = 'FIFO';
          offset += 4;
        }
        break;

      case 97: // Read/Write Multiple Registers (Extended)
        if (buffer.length >= offset + 10) {
          result.address = ModbusParser.parseRegisterAddress(buffer, offset);
          result.count = ModbusParser.parseRegisterCount(buffer, offset + 2);
          result.value = 'EXTENDED';
          offset += 10;
        }
        break;

      case 98: // Read/Write Multiple Coils (Extended)
        if (buffer.length >= offset + 4) {
          result.address = (buffer[offset] << 8) | buffer[offset + 1];
          result.count = (buffer[offset + 2] << 8) | buffer[offset + 3];
          result.value = 'EXTENDED';
          offset += 4;
        }
        break;

      case 99: // Read/Write Multiple Coils (Extended)
        if (buffer.length >= offset + 4) {
          result.address = (buffer[offset] << 8) | buffer[offset + 1];
          result.count = (buffer[offset + 2] << 8) | buffer[offset + 3];
          result.value = 'EXTENDED';
          offset += 4;
        }
        break;

      case 100: // Read/Write Multiple Registers (Extended)
        if (buffer.length >= offset + 10) {
          result.address = ModbusParser.parseRegisterAddress(buffer, offset);
          result.count = ModbusParser.parseRegisterCount(buffer, offset + 2);
          result.value = 'EXTENDED';
          offset += 10;
        }
        break;

      case 101: // Read/Write Multiple Registers (Extended)
        if (buffer.length >= offset + 10) {
          result.address = ModbusParser.parseRegisterAddress(buffer, offset);
          result.count = ModbusParser.parseRegisterCount(buffer, offset + 2);
          result.value = 'EXTENDED';
          offset += 10;
        }
        break;

      case 102: // Read/Write Multiple Registers (Extended)
        if (buffer.length >= offset + 10) {
          result.address = ModbusParser.parseRegisterAddress(buffer, offset);
          result.count = ModbusParser.parseRegisterCount(buffer, offset + 2);
          result.value = 'EXTENDED';
          offset += 10;
        }
        break;

      case 103: // Read/Write Multiple Registers (Extended)
        if (buffer.length >= offset + 10) {
          result.address = ModbusParser.parseRegisterAddress(buffer, offset);
          result.count = ModbusParser.parseRegisterCount(buffer, offset + 2);
          result.value = 'EXTENDED';
          offset += 10;
        }
        break;

      case 104: // Read/Write Multiple Registers (Extended)
        if (buffer.length >= offset + 10) {
          result.address = ModbusParser.parseRegisterAddress(buffer, offset);
          result.count = ModbusParser.parseRegisterCount(buffer, offset + 2);
          result.value = 'EXTENDED';
          offset += 10;
        }
        break;

      case 105: // Read/Write Multiple Registers (Extended)
        if