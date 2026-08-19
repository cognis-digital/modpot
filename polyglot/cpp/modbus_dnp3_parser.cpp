#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <iostream>
#include <memory>

namespace modpot {

class ModbusDnp3Parser {
public:
    enum class ProtocolType : uint8_t {
        MODBUS = 0,
        DNP3 = 1
    };

    struct ParseResult {
        bool success;
        ProtocolType protocol;
        std::string error_message;
        
        // Modbus-specific fields
        uint16_t transaction_id = 0;
        uint16_t starting_address = 0;
        uint16_t quantity = 0;
        uint8_t function_code = 0;
        std::vector<uint8_t> payload;
        
        // DNP3-specific fields
        uint8_t control_code = 0;
        uint16_t data_link_length = 0;
    };

    static ParseResult parseModbus(const std::string& raw_data) {
        if (raw_data.empty()) {
            return {false, ProtocolType::MODBUS, "Empty input"};
        }

        // Modbus transaction is at least: ID(2) + Addr(2) + Qty(2) = 6 bytes minimum
        if (raw_data.size() < 6) {
            return {false, ProtocolType::MODBUS, "Too short for valid Modbus frame"};
        }

        // Extract fields using little-endian interpretation
        uint16_t transaction_id = static_cast<uint16_t>(raw_data[0]) | 
                                 (static_cast<uint16_t>(raw_data[1]) << 8);
        uint16_t starting_address = static_cast<uint16_t>(raw_data[2]) | 
                                  (static_cast<uint16_t>(raw_data[3]) << 8);
        uint16_t quantity = static_cast<uint16_t>(raw_data[4]) | 
                          (static_cast<uint16_t>(raw_data[5]) << 8);

        // Validate reasonable bounds
        if (transaction_id > 0xFFFF || starting_address > 0xFFFF || quantity > 0x7FFF) {
            return {false, ProtocolType::MODBUS, "Out of range values"};
        }

        uint8_t function_code = raw_data[6];
        
        // Check for valid Modbus function codes (read operations)
        if (function_code != 0x01 && 
            function_code != 0x02 && 
            function_code != 0x03 && 
            function_code != 0x04) {
            return {false, ProtocolType::MODBUS, "Unknown read function code"};
        }

        // Extract payload (response data after the header)
        std::vector<uint8_t> payload;
        if (raw_data.size() > 7) {
            payload.insert(payload.end(), raw_data.begin() + 7, raw_data.end());
        }

        return {true, ProtocolType::MODBUS, 
                "", transaction_id, starting_address, quantity, function_code, std::move(payload)};
    }

    static ParseResult parseDnp3(const std::string& raw_data) {
        if (raw_data.empty()) {
            return {false, ProtocolType::DNP3, "Empty input"};
        }

        // DNP3 frame structure:
        // Control Code (1 byte) + Data Link Layer Header (2 bytes length field) + Payload
        
        if (raw_data.size() < 4) {
            return {false, ProtocolType::DNP3, "Too short for valid DNP3 frame"};
        }

        uint8_t control_code = raw_data[0];
        
        // Data Link Layer Header: bytes 1-2 are length field (little-endian)
        uint16_t data_link_length = static_cast<uint16_t>(raw_data[1]) | 
                                  (static_cast<uint16_t>(raw_data[2]) << 8);

        // Validate reasonable bounds
        if (control_code > 0xFF || data_link_length > 0xFFFF) {
            return {false, ProtocolType::DNP3, "Out of range values"};
        }

        // Extract payload (after the 3-byte header)
        std::vector<uint8_t> payload;
        if (raw_data.size() > 3) {
            payload.insert(payload.end(), raw_data.begin() + 3, raw_data.end());
        }

        return {true, ProtocolType::DNP3, "", 
                control_code, data_link_length, 0, 0, 0, std::move(payload)};
    }

    static ParseResult parse(const std::string& raw_data) {
        // Try Modbus first (more common in ICS environments)
        auto modbus_result = parseModbus(raw_data);
        
        if (modbus_result.success) {
            return modbus_result;
        }

        // Fall back to DNP3 parsing
        auto dnp3_result = parseDnp3(raw_data);
        
        if (dnp3_result.success) {
            return dnp3_result;
        }

        // Both failed - return the last error
        return dnp3_result;
    }

    static std::string formatTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        std::tm* tm_now = std::localtime(&time_t_now);
        
        std::ostringstream oss;
        oss << std::put_time(tm_now, "%Y-%m-%dT%H:%M:%S");
        return oss.str();
    }

    static std::string formatJSON(const ParseResult& result) {
        std::ostringstream json;
        auto ts = formatTimestamp();
        
        // Determine readable function code name
        const char* func_name = "Unknown";
        switch (result.function_code) {
            case 0x01: func_name = "ReadCoils"; break;
            case 0x02: func_name = "ReadDiscreteInputs"; break;
            case 0x03: func_name = "ReadHoldingRegisters"; break;
            case 0x04: func_name = "ReadInputRegisters"; break;
        }

        // Determine readable control code name (DNP3)
        const char* ctrl_name = "Unknown";
        switch (result.control_code) {
            case 0x10: ctrl_name = "Indication"; break;
            case 0x14: ctrl_name = "Request"; break;
        }

        json << "{"
             << "\"timestamp\": \"" << ts << "\","
             << "\"protocol\": \"" << (result.protocol == ProtocolType::MODBUS ? 
                                      "Modbus" : "DNP3") << "\","
             << "\"success\": " << (result.success ? "true" : "false");

        if (!result.error_message.empty()) {
            json << ", \"error\": \"" << result.error_message << "\"";
        }

        // Modbus-specific fields
        if (result.protocol == ProtocolType::MODBUS) {
            json << ", \"transaction_id\":" << result.transaction_id
                 << ", \"starting_address\":" << result.starting_address
                 << ", \"quantity\":" << result.quantity
                 << ", \"function_code\": " << static_cast<int>(result.function_code);

            if (!func_name == "Unknown") {
                json << ", \"function_name\": \"" << func_name << "\"";
            }
        }

        // DNP3-specific fields
        if (result.protocol == ProtocolType::DNP3) {
            json << ", \"control_code\":" << static_cast<int>(result.control_code);

            if (!ctrl_name == "Unknown") {
                json << ", \"control_name\": \"" << ctrl_name << "\"";
            }
        }

        // Payload as hex string
        std::ostringstream hex;
        for (size_t i = 0; i < result.payload.size(); ++i) {
            if (i > 0) hex << ":";
            hex << std::setw(2) << std::setfill('0') 
                << std::hex << static_cast<int>(result.payload[i]);
        }

        json << ", \"payload_hex\": \"" << hex.str() << "\"";

        // Truncate payload if very large (default 4KB limit)
        const size_t MAX_PAYLOAD_HEX = 8192;
        if (result.payload.size() * 3 > MAX_PAYLOAD_HEX) {
            json << ", \"payload_truncated\": true, \"payload_size\":" 
                 << result.payload.size();
        }

        json << "}";

        return json.str();
    }
};

// Simple JSON logger for the honeypot
class HoneypotLogger {
public:
    static void log(const ModbusDnp3Parser::ParseResult& result) {
        std::string json = ModbusDnp3Parser::formatJSON(result);
        
        // Output to stdout (can be redirected or piped)
        std::cout << json << "\n";

        // Also output as structured key-value for quick parsing
        if (result.success) {
            std::cout << "[LOG] " 
                      << result.protocol == ModbusDnp3Parser::ProtocolType::MODBUS ? "MODBUS" : "DNP3"
                      << " | FC/CC: 0x" << std::setw(2) << std::setfill('0') 
                      << std::hex << result.function_code << "/" 
                      << static_cast<int>(result.control_code)
                      << " | Addr: 0x" << std::setw(4) << std::setfill('0')
                      << std::hex << result.starting_address
                      << " | Qty: " << result.quantity;

            if (!result.payload.empty()) {
                std::cout << " | Data: " << result.payload.size() << " bytes";
            }
            
            std::cout << "\n";
        } else {
            std::cerr << "[ERR] " << result.error_message << "\n";
        }
    }

    static void log(const ModbusDnp3Parser::ParseResult& result, 
                   const char* context = nullptr) {
        if (context) {
            std::cout << "[CONTEXT: " << context << "] ";
        }
        log(result);
    }
};

// Demo/test harness - can be removed for production build
#if 1 // Keep demo enabled
int main() {
    using namespace modpot;

    std::cout << "=== Modbus/DNP3 Parser Demo ===\n\n";

    // Test 1: Valid Modbus Read Holding Registers (Function Code 0x03)
    // Format: ID(2) + Addr(2) + Qty(2) + FC(1) + Data...
    std::string modbus_request = "\x00\x01"   // Transaction ID = 1
                                "\x00\x06"   // Starting address = 6
                                "\x00\x03"   // Quantity = 3 registers
                                "\x03";      // Function Code 0x03

    std::string modbus_response = "\x00\x01"  // Transaction ID echo
                                 "\x00\x04"   // Starting address echo  
                                 "\x00\x02"   // Quantity = 2 registers (3*2-1)
                                 "\x03";      // Function Code echo

    std::cout << "Test 1: Modbus Request\n";
    HoneypotLogger::log(ModbusDnp3Parser::parse(modbus_request));

    std::cout << "\nTest 2: Modbus Response\n";
    HoneypotLogger::log(ModbusDnp3Parser::parse(modbus_response));

    // Test 3: Valid DNP3 Indication (Control Code 0x10)
    // Format: Control Code(1) + DL Length(2) + Payload...
    std::string dnp3_indication = "\x10"       // Control Code: Indication
                                 "\x00\x05"   // Data Link Layer Length = 5 bytes
                                 "\x00\x06"   // Starting address = 6
                                 "\x00\x02";  // Quantity = 2 registers

    std::cout << "\nTest 3: DNP3 Indication\n";
    HoneypotLogger::log(ModbusDnp3Parser::parse(dnp3_indication));

    // Test 4: Edge case - empty input
    std::cout << "\nTest 4: Empty Input\n";
    HoneypotLogger::log(ModbusDnp3Parser::parse(""));

    // Test 5: Edge case - very short input
    std::cout << "\nTest 5: Short Input (2 bytes)\n";
    HoneypotLogger::log(ModbusDnp3Parser::parse("\x01\x02"));

    // Test 6: Large payload truncation test
    std::vector<uint8_t> large_payload(4096, 0xFF);
    std::string large_modbus = "\x00\x01" + "\x00\x00" + "\x00\x01" + 
                              "\x03"; // ID=1, Addr=0, Qty=1, FC=0x03
    for (auto b : large_payload) {
        large_modbus += static_cast<char>(b);
    }

    std::cout << "\nTest 6: Large Payload (4KB)\n";
    HoneypotLogger::log(ModbusDnp3Parser::parse(large_modbus));

    // Test 7: Realistic attack simulation - rapid register scan
    std::cout << "\nTest 7: Simulated Attack Pattern\n";
    
    for (int i = 0; i < 5; ++i) {
        // Attacker scanning common ICS addresses
        uint16_t addr = 40001 + (i * 10); // Common Modbus starting points
        
        std::string scan_request = "\x00\x0" + 
                                  std::to_string(i % 256) + "\x00" +
                                  std::to_string(addr & 0xFF) + 
                                  std::to_string((addr >> 8) & 0xFF) +
                                  "\x00\x01" + "\x03"; // Scan 1 register
        
        HoneypotLogger::log(ModbusDnp3Parser::parse(scan_request), 
                          "ATTACK_SCAN_" + std::to_string(addr));
    }

    std::cout << "\n=== Demo Complete ===\n";
    
    return 0;
}
#endif