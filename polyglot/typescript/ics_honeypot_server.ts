import * as net from 'net';
import { EventEmitter } from 'events';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  source: string;
  message: string;
  data?: Record<string, unknown>;
}

interface VirtualRegister {
  address: number;
  dataType: 'uint16' | 'int32' | 'float32' | 'string';
  defaultValue: number | string;
  readOnly: boolean;
  description: string;
}

interface VirtualPLCConfig {
  name: string;
  registers: VirtualRegister[];
  ipPrefix?: string;
}

interface ConnectionState {
  id: string;
  remoteAddress: string;
  connectedAt: Date;
  protocol: 'modbus' | 'dnp3';
  lastActivity: Date;
}

// ============================================================================
// CONFIGURATION & CONSTANTS
// ============================================================================

const DEFAULT_PORT = 502; // Standard Modbus TCP port
const DEFAULT_LOG_LEVEL: LogLevel = 'info';
const MAX_CONNECTIONS = 100;
const CONNECTION_TIMEOUT_MS = 30000;
const LOG_FILE_PATH = './ics_honeypot.log';

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function generateConnectionId(): string {
  return `conn_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;
}

function formatTimestamp(): string {
  const now = new Date();
  return now.toISOString();
}

function createLogger(source: string): { debug: (msg: string, data?: unknown) => void; info: (msg: string, data?: unknown) => void; warn: (msg: string, data?: unknown) => void; error: (msg: string, data?: unknown) => void; } {
  return {
    debug: (message: string, data?: unknown) => console.debug(`[${source}] [DEBUG] ${message}`, data),
    info: (message: string, data?: unknown) => console.info(`[${source}] [INFO] ${message}`, data),
    warn: (message: string, data?: unknown) => console.warn(`[${source}] [WARN] ${message}`, data),
    error: (message: string, data?: unknown) => console.error(`[${source}] [ERROR] ${message}`, data),
  };
}

// ============================================================================
// MODBUS PROTOCOL PARSER
// ============================================================================

interface ModbusFrame {
  transactionId: number;
  protocolIdentifier: number;
  length: number;
  unitId: number;
  functionCode: number;
  payload: Uint8Array;
}

function parseModbusTCPHeader(buffer: Uint8Array): ModbusFrame | null {
  if (buffer.length < 6) return null;

  const transactionId = buffer.readUInt16BE(0);
  const protocolIdentifier = buffer.readUInt16BE(2);
  const length = buffer.readUInt16BE(4);
  const unitId = buffer.readUInt8(6);

  if (protocolIdentifier !== 0 && protocolIdentifier !== 0x0001) {
    return null; // Not Modbus TCP
  }

  const payloadStart = 7 + length;
  if (buffer.length < payloadStart) return null;

  const payload = buffer.slice(payloadStart);

  return {
    transactionId,
    protocolIdentifier,
    length,
    unitId,
    functionCode: payload[0],
    payload: payload.slice(1),
  };
}

function calculateCRC(buffer: Uint8Array): number {
  let crc = 0xFFFF;
  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    crc ^= byte << 8;
    for (let j = 0; j < 8; j++) {
      if ((crc & 0x8000) !== 0) {
        crc = (crc << 1) ^ 0x1021;
      } else {
        crc <<= 1;
      }
    }
  }
  return crc >>> 8 | crc & 0xFF;
}

// ============================================================================
// DNP3 PROTOCOL PARSER (Simplified for Honeypot)
// ============================================================================

interface Dnp3Frame {
  version: number;
  length: number;
  sequenceNumber: number;
  controlCode: number;
  payload: Uint8Array;
}

function parseDnp3Header(buffer: Uint8Array): Dnp3Frame | null {
  if (buffer.length < 4) return null;

  const version = buffer[0];
  const length = buffer.readUInt16BE(1);
  const sequenceNumber = buffer.readUInt16BE(3);
  const controlCode = buffer.readUInt8(5);

  const payloadStart = 6 + length;
  if (buffer.length < payloadStart) return null;

  const payload = buffer.slice(payloadStart);

  // Control code 0x01 = Request, 0x02 = Response
  if ((controlCode & 0x03) === 0x01 || (controlCode & 0x03) === 0x02) {
    return { version, length, sequenceNumber, controlCode, payload };
  }

  return null;
}

// ============================================================================
// VIRTUAL PLC IMPLEMENTATION
// ============================================================================

class VirtualPLC {
  private config: VirtualPLCConfig;
  private registerMap: Map<number, VirtualRegister>;
  private connections: Map<string, ConnectionState> = new Map();

  constructor(config: VirtualPLCConfig) {
    this.config = config;
    this.registerMap = new Map(
      config.registers.map(r => [r.address, r])
    );
  }

  getRegister(address: number): VirtualRegister | undefined {
    return this.registerMap.get(address);
  }

  readRegister(address: number): Uint8Array {
    const register = this.registerMap.get(address);
    if (!register) {
      // Return zero for unknown registers (default behavior)
      return Buffer.alloc(2, 0);
    }

    let value: number;
    switch (register.dataType) {
      case 'uint16':
        value = register.defaultValue as number;
        break;
      case 'int32':
        value = register.defaultValue as number & 0xFFFF; // Truncate to uint16
        break;
      case 'float32':
        value = Math.round((register.defaultValue as number) * 100) / 100;
        break;
      default:
        return Buffer.alloc(2, 0);
    }

    // Convert to Modbus binary format (big-endian uint16)
    const buffer = Buffer.alloc(2);
    buffer.writeUInt16BE(value & 0xFFFF, 0);
    return buffer;
  }

  writeRegister(address: number, value: Uint8Array): boolean {
    const register = this.registerMap.get(address);
    if (!register) return false;

    if (register.readOnly) {
      // Log the attempted read-only write
      console.warn(`Read-only attempt at address ${address}`);
      return false;
    }

    let newValue: number;
    switch (register.dataType) {
      case 'uint16':
        newValue = value.readUInt16BE(0);
        break;
      default:
        return false;
    }

    register.defaultValue = newValue & 0xFFFF;
    this.info(`Wrote ${newValue} to address ${address}`);
    return true;
  }

  private info(message: string): void {
    console.log(`[PLC] ${message}`);
  }
}

// ============================================================================
// CONNECTION MANAGER
// ============================================================================

class ConnectionManager extends EventEmitter {
  private server: net.Server;
  private plc: VirtualPLC;
  private logger = createLogger('ConnectionManager');
  private readonly maxConnections = MAX_CONNECTIONS;

  constructor(server: net.Server, plc: VirtualPLC) {
    super();
    this.server = server;
    this.plc = plc;
  }

  handleConnection(socket: net.Socket): void {
    if (this.connections.size >= this.maxConnections) {
      socket.write('Max connections reached\n');
      return;
    }

    const connectionId = generateConnectionId();
    const remoteAddress = `${socket.remoteAddress}:${socket.remotePort}`;

    const state: ConnectionState = {
      id: connectionId,
      remoteAddress,
      connectedAt: new Date(),
      protocol: 'modbus', // Default, can be detected from first frame
      lastActivity: new Date(),
    };

    this.connections.set(connectionId, state);

    socket.on('data', (data) => {
      this.handleData(socket, data, connectionId);
    });

    socket.on('end', () => {
      this.disconnect(connectionId);
    });

    socket.on('error', (err) => {
      this.logger.error(`Connection error: ${err.message}`, state);
      this.disconnect(connectionId);
    });

    socket.setTimeout(CONNECTION_TIMEOUT_MS, () => {
      this.logger.warn(`Timeout for ${connectionId}`);
      this.disconnect(connectionId);
    });

    this.info(`New connection from ${remoteAddress} (${connectionId})`);
  }

  private handleData(socket: net.Socket, data: Buffer, connectionId: string): void {
    const state = this.connections.get(connectionId);
    if (!state) return;

    state.lastActivity = new Date();

    // Try to parse as Modbus TCP first
    const modbusFrame = parseModbusTCPHeader(data);
    
    if (modbusFrame) {
      socket.setEncoding('utf8');
      socket.write(`Response: ${this.buildModbusResponse(modbusFrame)}\n`);
      
      // Log the interaction
      this.logger.info(
        `Modbus request from ${state.remoteAddress}`,
        {
          transactionId: modbusFrame.transactionId,
          unitId: modbusFrame.unitId,
          functionCode: modbusFrame.functionCode,
          payloadLength: modbusFrame.payload.length,
          buffer: Array.from(modbusFrame.payload),
        }
      );

      return;
    }

    // Try DNP3 parsing
    const dnp3Frame = parseDnp3Header(data);
    
    if (dnp3Frame) {
      socket.setEncoding('utf8');
      socket.write(`Response: ${this.buildDnp3Response(dnp3Frame)}\n`);

      this.logger.info(
        `DNP3 request from ${state.remoteAddress}`,
        {
          sequenceNumber: dnp3Frame.sequenceNumber,
          controlCode: dnp3Frame.controlCode,
          payloadLength: dnp3Frame.payload.length,
          buffer: Array.from(dnp3Frame.payload),
        }
      );

      return;
    }

    // Unknown protocol - echo back for debugging
    this.logger.warn(`Unknown protocol from ${state.remoteAddress}`);
  }

  private buildModbusResponse(frame: ModbusFrame): string {
    const response = Buffer.alloc(6 + frame.length + 2);
    
    // Header
    response.writeUInt16BE(frame.transactionId, 0);
    response.writeUInt16BE(0x0001, 2); // Protocol identifier
    response.writeUInt16BE(frame.length, 4);
    response.writeUInt8(frame.unitId, 6);

    // PDU - Echo the function code and payload back
    const pdu = Buffer.alloc(frame.length + 1);
    pdu.writeUInt8(frame.functionCode, 0);
    pdu.write(frame.payload, 1);

    // Calculate CRC for RTU-style (even though this is TCP)
    const crc = calculateCRC(response.slice(0, response.length - 2));
    response.writeUInt16BE(crc, response.length - 2);

    return `Transaction ${frame.transactionId}, Unit ID ${frame.unitId}, Function ${frame.functionCode}`;
  }

  private buildDnp3Response(frame: Dnp3Frame): string {
    const response = Buffer.alloc(6 + frame.length + 1);
    
    // Echo header with incremented sequence number
    response.writeUInt8(frame.version, 0);
    response.writeUInt16BE(frame.length, 1);
    response.writeUInt16BE((frame.sequenceNumber + 1) & 0xFFFF, 3);
    response.writeUInt8(frame.controlCode | 0x02, 5); // Response flag

    const pdu = Buffer.alloc(frame.length + 1);
    pdu.write(frame.payload, 0);
    
    return `Seq ${frame.sequenceNumber}, Control ${(frame.controlCode & 0x03) === 0x01 ? 'Request' : 'Response'}`;
  }

  private disconnect(connectionId: string): void {
    const state = this.connections.get(connectionId);
    if (!state) return;

    this.logger.info(`Disconnected ${connectionId}`, {
      remoteAddress: state.remoteAddress,
      connectedDuration: Date.now() - new Date(state.connectedAt).getTime(),
    });

    this.connections.delete(connectionId);
  }

  getActiveConnections(): ConnectionState[] {
    return Array.from(this.connections.values());
  }

  close(): void {
    this.server.close(() => {
      this.logger.info('Server closed');
    });
  }
}

// ============================================================================
// MAIN HONEYPOT SERVER CLASS
// ============================================================================

interface IcsHoneypotConfig {
  port: number;
  plcConfig?: VirtualPLCConfig;
  logLevel?: LogLevel;
  host?: string;
}

class IcsHoneypotServer {
  private server: net.Server | null = null;
  private connectionManager: ConnectionManager | null = null;
  private plc: VirtualPLC | null = null;
  private config: IcsHoneypotConfig;
  private logger = createLogger('HoneypotServer');

  constructor(config: IcsHoneypotConfig) {
    this.config = {
      port: DEFAULT_PORT,
      plcConfig: {
        name: 'Default PLC',
        registers: [
          // Simulated temperature sensor (read-only)
          { address: 0x0001, dataType: 'float32', defaultValue: 68.5, readOnly: true, description: 'Main Reactor Temperature' },
          // Pressure gauge (read-write)
          { address: 0x0002, dataType: 'uint16', defaultValue: 1013, readOnly: false, description: 'System Pressure (kPa)' },
          // Valve position (read-write, limited range)
          { address: 0x0003, dataType: 'uint16', defaultValue: 50, readOnly: false, description: 'Main Valve Position (0-100%)' },
          // Pump status (read-only boolean as uint16)
          { address: 0x0004, dataType: 'uint16', defaultValue: 255, readOnly: true, description: 'Pump A Status (255=running)' },
          // Analog input 1
          { address: 0x0010, dataType: 'float32', defaultValue: 45.2, readOnly: true, description: 'Analog Input 1' },
          // Analog output 1
          { address: 0x0011, dataType: 'uint16', defaultValue: 800, readOnly: false, description: 'Analog Output 1 (mA)' },
        ],
      },
      logLevel: DEFAULT_LOG_LEVEL,
      host: '0.0.0.0',
    };

    if (config.plcConfig) {
      this.config.plcConfig = config.plcConfig;
    }

    if (config.logLevel) {
      this.logger.info = createLogger('HoneypotServer').info.bind(createLogger('HoneypotServer'));
    }
  }

  start(): void {
    const host = this.config.host || '0.0.0.0';
    const port