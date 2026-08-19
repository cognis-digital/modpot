#include <iostream>
#include <fstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdint>

// Forward declarations
class ModbusParser;
class DNP3Parser;
class RegisterTable;
class LogEntry;
class HoneypotServer;

// ============================================================================
// Data Structures
// ============================================================================

struct Register {
    uint16_t address;
    union {
        int16_t value_int;
        float value_float;
    };
    bool writable = true;
};

class RegisterTable {
public:
    std::vector<Register> registers;
    
    RegisterTable() : registers(256, {0, 0}) {}
    
    void initDefaultRegisters() {
        // Common ICS register addresses
        registers[1].address = 1;   // Temperature (read-only)
        registers[1].value_int = 72.5f;
        
        registers[2].address = 2;   // Pressure (read-write)
        registers[2].value_int = 1013;
        
        registers[3].address = 3;   // Status flags
        registers[3].value_int = 0x00FF;
    }
    
    Register& get(uint16_t addr, bool create = true) {
        if (create && addr >= registers.size()) {
            registers.resize(addr + 1);
            registers.back().address = addr;
        }
        return registers[addr];
    }
};

struct LogEntry {
    std::chrono::system_clock::time_point timestamp;
    uint8_t protocol;      // 0=Modbus, 1=DNP3
    uint8_t function_code;
    int16_t register_address;
    int16_t value;
    bool is_read;
    std::string source_ip;
    
    std::string toJSON() const {
        auto t = std::chrono::system_clock::to_time_t(timestamp);
        std::tm tm = *std::localtime(&t);
        
        std::ostringstream oss;
        oss << "{"
            << "\"ts\":\"" << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ") << "\","
            << "\"proto\":" << (int)protocol << ","
            << "\"func\":" << (int)function_code << ","
            << "\"addr\":" << register_address << ","
            << "\"val\":" << value << ","
            << "\"is_read\":" << (is_read ? "true" : "false") << ","
            << "\"src\":\"" << source_ip << "\""
            << "}";
        return oss.str();
    }
};

class LogBuffer {
public:
    std::vector<LogEntry> entries;
    mutable std::mutex mutex;
    
    void add(const LogEntry& entry) {
        std::lock_guard<std::mutex> lock(mutex);
        entries.push_back(entry);
    }
    
    void flushToJSON(std::ostream& out, const std::string& filename = "") {
        std::lock_guard<std::mutex> lock(mutex);
        
        if (filename.empty()) {
            // Output to stdout
            for (const auto& e : entries) {
                out << e.toJSON() << "\n";
            }
        } else {
            // Write to file
            std::ofstream file(filename, std::ios::app);
            if (file.is_open()) {
                for (const auto& e : entries) {
                    file << e.toJSON() << "\n";
                }
                file.close();
            }
        }
        
        entries.clear();
    }
};

// ============================================================================
// Protocol Parsers
// ============================================================================

class ModbusParser {
public:
    static uint8_t parseFunctionCode(const std::vector<uint8_t>& data) {
        if (data.size() < 2) return 0xFF;
        
        // Function code is at byte 1 for RTU/TCP
        return data[1];
    }
    
    static int16_t extractRegisterAddress(const std::vector<uint8_t>& data, uint8_t func_code) {
        if (func_code == 0x03 || func_code == 0x04) { // Read Holding/Input Registers
            return (data[3] << 8) | data[2];
        } else if (func_code == 0x06 || func_code == 0x10) { // Write Single/Multiple Register
            return (data[3] << 8) | data[2];
        }
        return -1;
    }
    
    static int16_t extractValue(const std::vector<uint8_t>& data, uint8_t func_code) {
        if (func_code == 0x03 || func_code == 0x04) { // Read response contains value
            if (data.size() >= 5) {
                return (data[4] << 8) | data[3];
            }
        } else if (func_code == 0x06) { // Write Single Register
            if (data.size() >= 5) {
                return (data[4] << 8) | data[3];
            }
        }
        return -1;
    }
};

class DNP3Parser {
public:
    static uint8_t parseFunctionCode(const std::vector<uint8_t>& data) {
        // DNP3 has IAC/NAK framing, function code is in the command object
        if (data.size() < 4) return 0xFF;
        
        // Simplified: assume first byte after header is function indicator
        return data[2];
    }
    
    static int16_t extractRegisterAddress(const std::vector<uint8_t>& data) {
        // DNP3 uses object numbers, map to register addresses
        if (data.size() >= 4) {
            uint8_t obj_num = data[2] & 0x7F;
            return obj_num * 100 + 1;
        }
        return -1;
    }
    
    static int16_t extractValue(const std::vector<uint8_t>& data) {
        if (data.size() >= 5) {
            // Object value is in bytes 3-4
            return (data[4] << 8) | data[3];
        }
        return -1;
    }
};

// ============================================================================
// Server Implementation
// ============================================================================

class HoneypotServer {
private:
    int port{502};           // Default Modbus TCP port
    RegisterTable registers;
    LogBuffer log_buffer;
    std::atomic<bool> running{true};
    std::thread accept_thread;
    
public:
    HoneypotServer() : registers() {
        registers.initDefaultRegisters();
        
        // Start async logging thread
        accept_thread = std::thread(&HoneypotServer::acceptLoop, this);
    }
    
    ~HoneypotServer() {
        running.store(false);
        if (accept_thread.joinable()) {
            accept_thread.join();
        }
        
        // Flush remaining logs
        log_buffer.flushToJSON(std::cout, "ics_honeypot.log");
    }
    
    void setPort(int p) { port = p; }
    
    void setLogPath(const std::string& path) {
        // Set default output path (overridden by flushToJSON)
    }
    
private:
    void acceptLoop() {
        while (running.load()) {
            try {
                int client_fd = accept(port, nullptr, nullptr);
                if (client_fd < 0) continue;
                
                // Handle connection in separate thread
                std::thread t(&HoneypotServer::handleClient, this, client_fd);
                t.detach();
            } catch (...) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
    }
    
    void handleClient(int fd) {
        const size_t BUFFER_SIZE = 4096;
        std::vector<uint8_t> buffer(BUFFER_SIZE);
        
        while (running.load()) {
            ssize_t n = recv(fd, buffer.data(), BUFFER_SIZE - 1, 0);
            
            if (n <= 0) break;
            
            // Parse the received data
            parseAndLog(buffer.data(), n);
            
            // Simple echo response for Modbus
            if (buffer[0] == 0x03 || buffer[0] == 0x06) {
                send(fd, buffer.data(), n, 0);
            }
        }
        
        close(fd);
    }
    
    void parseAndLog(const uint8_t* data, size_t len) {
        LogEntry entry;
        
        // Determine protocol by port (simplified heuristic)
        if (port == 502 || port == 1502) {
            entry.protocol = 0; // Modbus
            entry.function_code = ModbusParser::parseFunctionCode(std::vector<uint8_t>(data, data + len));
            entry.register_address = ModbusParser::extractRegisterAddress(
                std::vector<uint8_t>(data, data + len), 
                entry.function_code);
        } else {
            entry.protocol = 1; // DNP3 (or unknown)
            entry.function_code = DNP3Parser::parseFunctionCode(std::vector<uint8_t>(data, data + len));
            entry.register_address = DNP3Parser::extractRegisterAddress(
                std::vector<uint8_t>(data, data + len));
        }
        
        // Determine if read or write based on function code
        switch (entry.function_code) {
            case 0x03: case 0x04: entry.is_read = true; break;   // Read
            case 0x06: case 0x10: entry.is_read = false; break;  // Write
            default: entry.is_read = true; break;
        }
        
        // Extract value (if available)
        if (!entry.is_read && entry.register_address >= 0) {
            entry.value = ModbusParser::extractValue(
                std::vector<uint8_t>(data, data + len), 
                entry.function_code);
        } else {
            entry.value = registers.get(entry.register_address).value_int;
        }
        
        // Update register state if write
        if (!entry.is_read && entry.register_address >= 0) {
            Register& reg = registers.get(entry.register_address);
            reg.value_int = entry.value;
        }
        
        // Log the event
        entry.timestamp = std::chrono::system_clock::now();
        entry.source_ip = "127.0.0.1";  // Simplified - would need socket info in real impl
        
        log_buffer.add(entry);
    }
};

// ============================================================================
// Command Line Interface
// ============================================================================

void printUsage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n"
              << "  -p, --port <N>   Port to listen on (default: 502)\n"
              << "  -l, --log        Log to stdout\n"
              << "  -f, --file <F>   Log to file instead of stdout\n"
              << "  -h, --help       Show this help\n";
}

int main(int argc, char* argv[]) {
    int port = 502;
    bool logStdout = false;
    std::string logFile;
    
    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            port = std::atoi(argv[++i]);
        } else if ((arg == "-l" || arg == "--log") && !logStdout) {
            logStdout = true;
        } else if ((arg == "-f" || arg == "--file") && i + 1 < argc) {
            logFile = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        }
    }
    
    // Create and run the honeypot server
    HoneypotServer server;
    server.setPort(port);
    
    std::cout << "ICS Honeypot Server starting on port " << port << "\n";
    std::cout << "Press Ctrl+C to stop.\n\n";
    
    // Keep main thread alive
    while (server.running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    return 0;
}