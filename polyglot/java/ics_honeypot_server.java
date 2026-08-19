package polyglot.java;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/**
 * High-interaction Modbus/DNP3 ICS Honeypot Server.
 * 
 * Features:
 * - Full Modbus TCP protocol implementation (RTU over TCP)
 * - Simulated register database with configurable delays
 * - Structured JSON logging of all interactions
 * - Session tracking and statistics
 * - Graceful shutdown with cleanup
 */

public class ics_honeypot_server {

    // Configuration defaults
    private static final int DEFAULT_PORT = 502;
    private static final String DEFAULT_LOG_DIR = "logs";
    private static final long DEFAULT_READ_DELAY_MS = 10;
    private static final long DEFAULT_WRITE_DELAY_MS = 25;
    private static final int MAX_REGISTERS = 65536;

    // Runtime state
    private ServerSocket serverSocket;
    private volatile boolean running = true;
    private final AtomicLong totalReads = new AtomicLong(0);
    private final AtomicLong totalWrites = new AtomicLong(0);
    private final AtomicLong totalBytesReceived = new AtomicLong(0);

    // Thread-safe session tracking
    private static final ConcurrentHashMap<String, HoneypotSession> sessions = 
        new ConcurrentHashMap<>();

    // Simulated register database (default: 40001-40500)
    private final Map<Integer, RegisterEntry> registers;

    // Logging
    private PrintWriter logWriter;
    private String logFilePath;

    public static void main(String[] args) {
        int port = DEFAULT_PORT;
        String logDir = DEFAULT_LOG_DIR;
        
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.out.println("Usage: java polyglot.java.ics_honeypot_server <port> [log_dir]");
                System.exit(1);
            }
        }
        
        if (args.length > 1) {
            logDir = args[1];
        }

        new HoneypotServer(port, logDir).start();
    }

    private HoneypotServer(int port, String logDir) {
        this.serverSocket = null;
        this.logFilePath = normalizePath(logDir + "/ics_honeypot_" + System.currentTimeMillis() + ".jsonl");
        this.registers = new HashMap<>();
        
        // Initialize simulated register database
        for (int i = 40001; i <= 40500; i++) {
            registers.put(i, new RegisterEntry(
                i, 
                "Temperature Sensor " + (i - 40001),
                20.5f,
                DEFAULT_READ_DELAY_MS
            ));
        }

        // Setup logging
        File logFile = new File(logFilePath);
        if (!logFile.getParentFile().exists()) {
            logFile.getParentFile().mkdirs();
        }
        
        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(logFile, true), "UTF-8"))) {
            this.logWriter = new PrintWriter(writer);
        } catch (IOException e) {
            System.err.println("Warning: Could not open log file: " + e.getMessage());
        }

        // Print startup banner
        printBanner();
    }

    private void start() {
        try {
            serverSocket = new ServerSocket(DEFAULT_PORT);
            while (running) {
                Socket client = null;
                try {
                    client = serverSocket.accept();
                    acceptClient(client);
                } catch (IOException e) {
                    if (!running) break;
                }
            }
        } finally {
            shutdown();
        }
    }

    private void printBanner() {
        System.out.println("============================================================");
        System.out.println("  ICS HONEYPOT SERVER v1.0");
        System.out.println("  Protocol: Modbus TCP (RTU over TCP)");
        System.out.println("  Listening on port: " + DEFAULT_PORT);
        System.out.println("  Log file: " + logFilePath);
        System.out.println("  Simulated registers: 40001-40500");
        System.out.println("============================================================");
    }

    private void acceptClient(Socket client) {
        String remoteAddr = client.getInetAddress().getHostAddress();
        HoneypotSession session = new HoneypotSession(
            remoteAddr, 
            client.getInputStream(), 
            client.getOutputStream()
        );
        
        sessions.put(session.id, session);

        // Start protocol handler thread
        Thread t = new Thread(() -> {
            try {
                processSession(session);
            } catch (IOException e) {
                System.out.println("[SESSION] " + session.id + 
                    " | Error: " + e.getMessage());
            } finally {
                sessions.remove(session.id);
                session.close();
            }
        });
        
        t.setDaemon(true);
        t.setName("HoneypotSession-" + remoteAddr);
        t.start();
    }

    private void processSession(HoneypotSession session) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(256);
        byte[] frameBuffer = new byte[256];
        
        while (running && !session.isClosed()) {
            // Read incoming Modbus frame
            int bytesRead = 0;
            
            try {
                bytesRead = session.read(buffer, 1024);
            } catch (IOException e) {
                if (!session.isClosed() && !running) break;
                continue;
            }

            if (bytesRead > 0) {
                buffer.flip();
                
                // Parse Modbus frame header
                int slaveId = buffer.get() & 0xFF;
                byte functionCode = buffer.get();
                short transactionId = (short)((buffer.get() << 8) | (buffer.get() & 0xFF));
                short startingAddress = (short)((buffer.get() << 8) | (buffer.get() & 0xFF));
                
                // Calculate expected payload length for function codes
                int expectedPayloadLen;
                switch (functionCode) {
                    case 3: // Read Holding Registers
                    case 4: // Read Input Registers
                        expectedPayloadLen = 2 + 1; // address + count
                        break;
                    case 6: // Write Single Register
                    case 10: // Write Multiple Registers
                        expectedPayloadLen = 2 + 1; // value + count
                        break;
                    default:
                        expectedPayloadLen = 2; // just address for unknown codes
                }

                // Read payload if needed
                int remainingBytes = buffer.remaining();
                int totalRead = bytesRead;
                
                while (remainingBytes > 0 && totalRead < 1024) {
                    int toRead = Math.min(remainingBytes, 64);
                    frameBuffer[totalRead] = buffer.get();
                    remainingBytes -= toRead;
                    totalRead += toRead;
                }

                // Log the interaction
                logInteraction(session.id, slaveId, functionCode, 
                    startingAddress, frameBuffer, totalRead);

                // Process command and send response
                byte[] response = processCommand(slaveId, functionCode, 
                    startingAddress, frameBuffer, totalRead);
                
                if (response != null) {
                    session.write(response);
                    
                    long latencyMs = System.currentTimeMillis() - session.lastActivityTime;
                    logResponse(session.id, slaveId, functionCode, 
                        startingAddress, response.length, latencyMs);
                }

                // Reset buffer for next frame
                buffer.clear();
            } else {
                // Connection closed by peer or EOF
                break;
            }
        }
    }

    private byte[] processCommand(int slaveId, byte functionCode, 
                                  short startingAddress, byte[] payload, int totalRead) {
        
        switch (functionCode) {
            case 3: // Read Holding Registers
                return readRegisters(slaveId, startingAddress, payload);
            
            case 4: // Read Input Registers  
                return readInputRegisters(slaveId, startingAddress, payload);
            
            case 6: // Write Single Register
                return writeSingleRegister(slaveId, startingAddress, payload);
            
            case 10: // Write Multiple Registers
                return writeMultipleRegisters(slaveId, startingAddress, payload);
            
            case 23: // Read/Write Multiple Registers (Holding)
                return readWriteMultipleRegisters(slaveId, startingAddress, payload);
            
            default:
                // Unknown function code - echo back as error
                return buildErrorResponse(1, functionCode, 
                    "Unknown function code", 0x82);
        }
    }

    private byte[] readRegisters(int slaveId, short address, byte[] payload) {
        int count = (payload.length > 2) ? 
            ((payload[2] << 8) | payload[3]) : 1;
        
        // Simulate realistic response delay
        try {
            Thread.sleep(DEFAULT_READ_DELAY_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Build response: transactionId, slaveId, byteCount, data...
        ByteBuffer response = ByteBuffer.allocate(4 + count * 2);
        
        response.putShort((short)(0x83 | ((address & 0xFF00) >> 8)));
        response.putShort(slaveId & 0xFF);
        response.putShort((short)((count - 1) << 8)); // byteCount = count - 1
        
        // Return simulated register values
        for (int i = 0; i < count && address + i <= 40500; i++) {
            RegisterEntry reg = registers.get(address + i);
            if (reg != null) {
                response.putShort((short)(reg.value & 0xFFFF));
            } else {
                // Default value for unknown registers
                response.putShort((short)0x1234);
            }
        }

        return response.array();
    }

    private byte[] readInputRegisters(int slaveId, short address, byte[] payload) {
        int count = (payload.length > 2) ? 
            ((payload[2] << 8) | payload[3]) : 1;
        
        try {
            Thread.sleep(DEFAULT_READ_DELAY_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        ByteBuffer response = ByteBuffer.allocate(4 + count * 2);
        response.putShort((short)(0x84 | ((address & 0xFF00) >> 8)));
        response.putShort(slaveId & 0xFF);
        response.putShort((short)((count - 1) << 8));
        
        for (int i = 0; i < count && address + i <= 40500; i++) {
            RegisterEntry reg = registers.get(address + i);
            if (reg != null) {
                response.putShort((short)(reg.value & 0xFFFF));
            } else {
                response.putShort((short)0x1234);
            }
        }

        return response.array();
    }

    private byte[] writeSingleRegister(int slaveId, short address, byte[] payload) {
        int value = (payload.length > 2) ? 
            ((payload[2] << 8) | payload[3]) : 0;
        
        try {
            Thread.sleep(DEFAULT_WRITE_DELAY_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Update simulated register value
        if (address >= 40001 && address <= 40500) {
            registers.put(address, 
                new RegisterEntry(address, "Updated", value, DEFAULT_WRITE_DELAY_MS));
        }

        ByteBuffer response = ByteBuffer.allocate(6);
        response.putShort((short)(0x86 | ((address & 0xFF00) >> 8)));
        response.putShort(slaveId & 0xFF);
        response.putShort((short)((value - 1) << 8));

        return response.array();
    }

    private byte[] writeMultipleRegisters(int slaveId, short address, byte[] payload) {
        int count = (payload.length > 2) ? 
            ((payload[2] << 8) | payload[3]) : 1;
        
        try {
            Thread.sleep(DEFAULT_WRITE_DELAY_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        ByteBuffer response = ByteBuffer.allocate(4 + count * 2);
        response.putShort((short)(0x8A | ((address & 0xFF00) >> 8)));
        response.putShort(slaveId & 0xFF);
        response.putShort((short)((count - 1) << 8));

        for (int i = 0; i < count && address + i <= 40500; i++) {
            RegisterEntry reg = registers.get(address + i);
            if (reg != null) {
                response.putShort((short)(reg.value & 0xFFFF));
            } else {
                response.putShort((short)0x1234);
            }
        }

        return response.array();
    }

    private byte[] readWriteMultipleRegisters(int slaveId, short address, byte[] payload) {
        int readCount = (payload.length > 4) ? 
            ((payload[4] << 8) | payload[5]) : 1;
        int writeCount = (payload.length > 6) ? 
            ((payload[6] << 8) | payload[7]) : 1;

        try {
            Thread.sleep(DEFAULT_WRITE_DELAY_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // First, write the values
        for (int i = 0; i < writeCount && address + i <= 40500; i++) {
            int value = ((payload[8 + i*2] << 8) | payload[9 + i*2]);
            registers.put(address + i, 
                new RegisterEntry(address + i, "Updated", value, DEFAULT_WRITE_DELAY_MS));
        }

        // Then read back
        ByteBuffer response = ByteBuffer.allocate(4 + readCount * 2);
        response.putShort((short)(0x8B | ((address & 0xFF00) >> 8)));
        response.putShort(slaveId & 0xFF);
        response.putShort((short)((readCount - 1) << 8));

        for (int i = 0; i < readCount && address + i <= 40500; i++) {
            RegisterEntry reg = registers.get(address + i);
            if (reg != null) {
                response.putShort((short)(reg.value & 0xFFFF));
            } else {
                response.putShort((short)0x1234);
            }
        }

        return response.array();
    }

    private byte[] buildErrorResponse(int slaveId, byte functionCode, 
                                      String reason, int code) {
        ByteBuffer response = ByteBuffer.allocate(6);
        
        // Error frame: transactionId | slaveId | byteCount (0x8X) | error code
        response.putShort((short)(0x80 | ((functionCode & 0xFF00) >> 8)));
        response.putShort(slaveId & 0xFF);
        response.putShort((short)((code - 1) << 8));

        return response.array();
    }

    private void logInteraction(String sessionId, int slaveId, byte