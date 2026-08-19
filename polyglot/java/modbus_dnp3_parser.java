package polyglot.java;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Arrays;

/**
 * Modbus/DNP3 Parser for ICS Honeypot (modpot)
 * 
 * Parses incoming protocol frames and produces structured JSON logs.
 */
public class modbus_dnp3_parser {

    // ==================== ENUMS & CONSTANTS ====================

    public enum ProtocolType {
        MODBUS, DNP3
    }

    public enum ModbusFunctionCode {
        READ_COILS(0x01),
        READ_DISCRETE_INPUTS(0x02),
        READ_HOLDING_REGISTERS(0x03),
        READ_INPUT_REGISTERS(0x04),
        WRITE_SINGLE_COIL(0x05),
        WRITE_SINGLE_REGISTER(0x06),
        WRITE_MULTI_COILS(0x10),
        WRITE_MULTI_REGISTERS(0x16);

        private final int code;

        ModbusFunctionCode(int code) { this.code = code; }

        public int getCode() { return code; }

        public static ModbusFunctionCode fromInt(int code) {
            for (ModbusFunctionCode f : values()) {
                if (f.code == code) return f;
            }
            return UNKNOWN;
        }

        public static final ModbusFunctionCode UNKNOWN = new ModbusFunctionCode(-1);
    }

    // ==================== DATA CLASSES ====================

    /**
     * Represents a single parsed protocol event.
     */
    public static class ParsedEvent {
        private final Instant timestamp;
        private final ProtocolType protocol;
        private final String sourceIp;
        private final ModbusFunctionCode functionCode;
        private final int registerAddress;
        private final int dataLength;
        private final String payloadHex;
        private final boolean isRead;

        public ParsedEvent(Instant ts, ProtocolType proto, String srcIp, 
                          ModbusFunctionCode fc, int regAddr, int len, 
                          byte[] rawPayload, boolean read) {
            this.timestamp = ts;
            this.protocol = proto;
            this.sourceIp = srcIp;
            this.functionCode = fc;
            this.registerAddress = regAddr;
            this.dataLength = len;
            this.payloadHex = (rawPayload != null ? 
                Arrays.toString(rawPayload) : "null");
            this.isRead = read;
        }

        public Map<String, Object> toJson() {
            Map<String, Object> json = new HashMap<>();
            
            json.put("timestamp", timestamp.toEpochMilli());
            json.put("protocol", protocol.name().toLowerCase());
            json.put("source_ip", sourceIp);
            json.put("function_code", functionCode != null ? 
                       functionCode.code : -1);
            json.put("register_address", registerAddress);
            json.put("data_length", dataLength);
            json.put("payload_hex", payloadHex);
            json.put("direction", isRead ? "read" : "write");
            
            return json;
        }

        @Override
        public String toString() {
            return toJson().toString();
        }
    }

    // ==================== MODBUS PARSER ====================

    /**
     * Parses a Modbus TCP frame.
     * 
     * Frame structure:
     *   Transaction ID (2 bytes)
     *   Protocol ID (2 bytes, usually 0x0000 for TCP)
     *   Length (2 bytes)
     *   PDU (Protocol Data Unit) - where the actual command lives
     */
    public static List<ParsedEvent> parseModbus(ByteBuffer buffer, String sourceIp) {
        List<ParsedEvent> events = new ArrayList<>();

        if (!buffer.hasRemaining()) return events;

        // Skip TCP header (8 bytes: trans_id + proto_id + length)
        int pduOffset = 8;
        
        if (buffer.remaining() < pduOffset) {
            return events;
        }

        // Extract PDU
        byte[] pduBytes = new byte[buffer.remaining()];
        buffer.get(pduBytes);

        // Parse Modbus PDU
        int offset = 0;
        
        if (pduBytes.length < 2) {
            return events;
        }

        ModbusFunctionCode fc = ModbusFunctionCode.fromInt(pduBytes[0]);
        boolean isRead = false;

        // Determine read vs write based on function code
        switch (fc) {
            case READ_COILS:
            case READ_DISCRETE_INPUTS:
            case READ_HOLDING_REGISTERS:
            case READ_INPUT_REGISTERS:
                isRead = true;
                break;
            case WRITE_SINGLE_COIL:
            case WRITE_SINGLE_REGISTER:
            case WRITE_MULTI_COILS:
            case WRITE_MULTI_REGISTERS:
                isRead = false;
                break;
        }

        // Extract register address (usually bytes 2-3 of PDU)
        int regAddress = -1;
        if (pduBytes.length >= 4) {
            regAddress = ((pduBytes[2] & 0xFF) << 8) | (pduBytes[3] & 0xFF);
        }

        // Extract data length (bytes after address, typically 2-4 bytes for reads)
        int dataLen = Math.max(0, pduBytes.length - 4);

        events.add(new ParsedEvent(
            Instant.now(),
            ProtocolType.MODBUS,
            sourceIp,
            fc,
            regAddress,
            dataLen,
            pduBytes,
            isRead
        ));

        return events;
    }

    // ==================== DNP3 PARSER ====================

    /**
     * Parses a DNP3 frame.
     * 
     * Simplified DNP3 TCP framing:
     *   Transaction ID (2 bytes)
     *   Protocol ID (2 bytes, usually 0x0001 for DNP3)
     *   Length (2 bytes)
     *   PDU - where the actual command lives
     */
    public static List<ParsedEvent> parseDnp3(ByteBuffer buffer, String sourceIp) {
        List<ParsedEvent> events = new ArrayList<>();

        if (!buffer.hasRemaining()) return events;

        // Skip TCP header (8 bytes)
        int pduOffset = 8;
        
        if (buffer.remaining() < pduOffset) {
            return events;
        }

        byte[] pduBytes = new byte[buffer.remaining()];
        buffer.get(pduBytes);

        if (pduBytes.length < 4) {
            return events;
        }

        // DNP3 PDU structure:
        //   Control Field (2 bytes): Function Code, Sequence Number, etc.
        //   Data Field (variable)
        
        int controlField = ((pduBytes[0] & 0xFF) << 8) | (pduBytes[1] & 0xFF);
        int funcCode = (controlField >> 4) & 0x0F;

        // Common DNP3 function codes for ICS:
        //   0x04 - Read, 0x15 - Write
        boolean isRead = false;
        
        switch (funcCode) {
            case 0x04:
                isRead = true;
                break;
            case 0x15:
                isRead = false;
                break;
            default:
                // Unknown or other function - still log it
                isRead = (funcCode & 0x08) != 0;
                break;
        }

        // Extract data length from control field
        int dataLen = controlField & 0x0F;

        events.add(new ParsedEvent(
            Instant.now(),
            ProtocolType.DNP3,
            sourceIp,
            ModbusFunctionCode.UNKNOWN,
            -1,
            dataLen,
            pduBytes,
            isRead
        ));

        return events;
    }

    // ==================== MAIN PARSER FACTORY ====================

    /**
     * Factory method to choose the right parser.
     */
    public static List<ParsedEvent> parse(ByteBuffer buffer, String sourceIp) {
        if (buffer.remaining() < 8) {
            return new ArrayList<>();
        }

        // Check protocol ID from TCP header
        int protocolId = ((buffer.get(3) & 0xFF) << 8) | 
                        ((buffer.get(4) & 0xFF));

        if (protocolId == 0x0000) {
            return parseModbus(buffer, sourceIp);
        } else if (protocolId == 0x0001 || protocolId == 0x0002) {
            // DNP3 typically uses 0x0001 or 0x0002
            return parseDnp3(buffer, sourceIp);
        }

        // Default to Modbus if unsure (most common in ICS)
        return parseModbus(buffer, sourceIp);
    }

    // ==================== DEMO / ENTRY POINT ====================

    public static void main(String[] args) {
        System.out.println("=== modpot: Modbus/DNP3 Parser Demo ===\n");

        // Create sample TCP headers + PDU
        ByteBuffer buildTcpHeader(int transId, int protoId, int length) {
            ByteBuffer buf = ByteBuffer.allocate(8 + length);
            buf.putShort((short)transId);
            buf.putShort((short)protoId);
            buf.putShort((short)length);
            return buf;
        }

        // --- Sample 1: Modbus Read Holding Registers (0x03) ---
        {
            byte[] pdu = new byte[8];
            pdu[0] = 0x03;           // Function code: Read Holding Registers
            pdu[1] = 0x00;           // Starting register address (low byte)
            pdu[2] = 0x00;           // Starting register address (high byte)
            pdu[3] = 0x00;           // Number of registers to read (low byte)
            pdu[4] = 0x01;           // Number of registers to read (high byte)
            
            ByteBuffer tcpBuf = buildTcpHeader(1234, 0x0000, 8);
            tcpBuf.put(pdu);

            List<ParsedEvent> events = parse(tcpBuf, "192.168.1.100");
            System.out.println("Sample 1: Modbus Read Holding Registers");
            for (ParsedEvent e : events) {
                System.out.println(e.toJson());
            }
        }

        // --- Sample 2: Modbus Write Single Register (0x06) ---
        {
            byte[] pdu = new byte[8];
            pdu[0] = 0x06;           // Function code: Write Single Register
            pdu[1] = 0x00;           // Starting register address
            pdu[2] = 0x00;
            pdu[3] = 0x00;           // Value to write (low byte)
            pdu[4] = 0x00;           // Value to write (high byte)

            ByteBuffer tcpBuf = buildTcpHeader(1235, 0x0000, 8);
            tcpBuf.put(pdu);

            List<ParsedEvent> events = parse(tcpBuf, "192.168.1.101");
            System.out.println("\nSample 2: Modbus Write Single Register");
            for (ParsedEvent e : events) {
                System.out.println(e.toJson());
            }
        }

        // --- Sample 3: DNP3 Read (Function Code 0x04) ---
        {
            byte[] pdu = new byte[6];
            pdu[0] = 0x04;           // Function code: Read
            pdu[1] = 0x01;           // Sequence number
            pdu[2] = 0x00;           // Data length (low byte)
            pdu[3] = 0x02;           // Data length (high byte)

            ByteBuffer tcpBuf = buildTcpHeader(5678, 0x0001, 6);
            tcpBuf.put(pdu);

            List<ParsedEvent> events = parse(tcpBuf, "192.168.1.102");
            System.out.println("\nSample 3: DNP3 Read");
            for (ParsedEvent e : events) {
                System.out.println(e.toJson());
            }
        }

        // --- Sample 4: Edge case - malformed frame ---
        {
            ByteBuffer tcpBuf = buildTcpHeader(9999, 0x0000, 2);
            
            List<ParsedEvent> events = parse(tcpBuf, "192.168.1.103");
            System.out.println("\nSample 4: Malformed Frame (only 2 bytes in PDU)");
            for (ParsedEvent e : events) {
                System.out.println(e.toJson());
            }
        }

        // --- Sample 5: Empty buffer ---
        {
            ByteBuffer tcpBuf = buildTcpHeader(1, 0x0000, 0);
            
            List<ParsedEvent> events = parse(tcpBuf, "192.168.1.104");
            System.out.println("\nSample 5: Empty Buffer");
            for (ParsedEvent e : events) {
                System.out.println(e.toJson());
            }
        }

        System.out.println("\n=== Demo Complete ===");
    }
}