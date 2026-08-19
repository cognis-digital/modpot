#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_FRAME_SIZE 256
#define MAX_LOG_ENTRIES 1024
#define MODBUS_CRC_POLYNOMIAL 0x4CBA
#define DNP3_CONTROL_START 0x50
#define DNP3_CONTROL_END 0x60

typedef struct {
    uint8_t transaction_id[2];
    uint8_t protocol_id;
    uint16_t length;
    uint16_t crc;
} modbus_header_t;

typedef struct {
    uint8_t control_code;
    uint8_t sequence_number;
    uint16_t data_length;
    uint8_t checksum;
} dnp3_header_t;

typedef enum {
    MODBUS_FC_READ_COILS = 0x01,
    MODBUS_FC_READ_HOLDING_REGISTERS = 0x02,
    MODBUS_FC_WRITE_SINGLE_REGISTER = 0x05,
    MODBUS_FC_WRITE_MULTIPLE_REGISTERS = 0x06,
} modbus_fc_t;

typedef struct {
    uint32_t timestamp_ms;
    modbus_fc_t fc;
    uint16_t register_address;
    uint16_t quantity;
    union {
        uint32_t read_value;
        uint16_t write_value;
    } data;
    bool is_write;
} log_entry_t;

static log_entry_t g_log_entries[MAX_LOG_ENTRIES];
static int g_log_count = 0;

uint16_t modbus_crc16(const uint8_t *data, size_t len) {
    uint16_t crc = MODBUS_CRC_POLYNOMIAL;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i] << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ MODBUS_CRC_POLYNOMIAL;
            } else {
                crc <<= 1;
            }
        }
    }
    return crc;
}

bool parse_modbus_frame(const uint8_t *frame, size_t len, modbus_header_t *hdr) {
    if (len < 7) return false;
    
    hdr->transaction_id[0] = frame[0];
    hdr->transaction_id[1] = frame[1];
    hdr->protocol_id = frame[2];
    hdr->length = frame[3] | (frame[4] << 8);
    
    uint16_t calculated_crc = modbus_crc16(frame, len - 4);
    if (hdr->crc != calculated_crc) {
        return false;
    }
    
    return true;
}

bool parse_dnp3_frame(const uint8_t *frame, size_t len, dnp3_header_t *hdr) {
    if (len < 5) return false;
    
    hdr->control_code = frame[0];
    hdr->sequence_number = frame[1];
    hdr->data_length = frame[2] | (frame[3] << 8);
    hdr->checksum = frame[4];
    
    uint8_t expected_checksum = 0;
    for (size_t i = 5; i < len - 1 && i < 5 + hdr->data_length; i++) {
        expected_checksum ^= frame[i];
    }
    
    return expected_checksum == hdr->checksum;
}

void extract_modbus_data(const uint8_t *frame, size_t len, modbus_header_t *hdr) {
    if (len < 7 + 2) return;
    
    const uint8_t *payload = frame + 5;
    uint16_t fc = payload[0] | (payload[1] << 8);
    
    switch (fc & 0xFF) {
        case 0x01: hdr->fc = MODBUS_FC_READ_COILS; break;
        case 0x02: hdr->fc = MODBUS_FC_READ_HOLDING_REGISTERS; break;
        case 0x05: hdr->fc = MODBUS_FC_WRITE_SINGLE_REGISTER; break;
        case 0x06: hdr->fc = MODBUS_FC_WRITE_MULTIPLE_REGISTERS; break;
        default: hdr->fc = 0;
    }
    
    uint16_t addr = payload[2] | (payload[3] << 8);
    uint16_t qty = payload[4] | (payload[5] << 8);
    
    if (hdr->fc == MODBUS_FC_READ_HOLDING_REGISTERS || 
        hdr->fc == MODBUS_FC_WRITE_MULTIPLE_REGISTERS) {
        for (int i = 0; i < qty && i + 2 <= len - 6; i++) {
            uint16_t reg_val = payload[6 + i * 2] | (payload[7 + i * 2] << 8);
            // Store in log if needed
        }
    } else if (hdr->fc == MODBUS_FC_WRITE_SINGLE_REGISTER) {
        hdr->data.write_value = payload[6] | (payload[7] << 8);
    }
}

void extract_dnp3_data(const uint8_t *frame, size_t len, dnp3_header_t *hdr) {
    if (len < 5 + 2) return;
    
    const uint8_t *data = frame + 5;
    int offset = 7;
    
    while (offset < len - 1 && hdr->data_length > 0) {
        switch (*data) {
            case 0x50: // Start of Message
                if (hdr->control_code == DNP3_CONTROL_START) {
                    hdr->sequence_number = data[1];
                    offset += 2;
                } else {
                    offset++;
                }
                break;
                
            case 0x60: // End of Message
                if (hdr->control_code == DNP3_CONTROL_END) {
                    hdr->checksum = data[1];
                    offset += 2;
                } else {
                    offset++;
                }
                break;
                
            default:
                offset++;
                break;
        }
    }
}

void log_entry(modbus_fc_t fc, uint16_t addr, uint32_t value, bool is_write) {
    if (g_log_count >= MAX_LOG_ENTRIES) return;
    
    g_log_entries[g_log_count].timestamp_ms = time(NULL) * 1000 + 
        ((uint8_t)(time(NULL)) << 8);
    g_log_entries[g_log_count].fc = fc;
    g_log_entries[g_log_count].register_address = addr;
    g_log_entries[g_log_count].data.read_value = value;
    g_log_entries[g_log_count].is_write = is_write;
    
    g_log_count++;
}

void flush_logs(void) {
    for (int i = 0; i < g_log_count; i++) {
        log_entry_t *e = &g_log_entries[i];
        
        printf("{\"ts\":%lu,\"fc\":%d,\"addr\":%u,\"value\":%u,\"is_write\":%s}\n",
               e->timestamp_ms, e->fc, e->register_address, 
               e->data.read_value, e->is_write ? "true" : "false");
    }
    
    g_log_count = 0;
}

void reset_parser(void) {
    g_log_count = 0;
}

int main(int argc, char *argv[]) {
    printf("modpot parser demo\n");
    printf("==================\n\n");
    
    // Demo Modbus frame: Read Holding Registers (FC 0x02)
    uint8_t modbus_frame[] = {
        0x01, 0x02,           // Transaction ID
        0x00,                 // Protocol ID
        0x04, 0x00,           // Length (4 bytes)
        0x00, 0x3F,           // CRC
        0x02,                 // Function Code: Read Holding Registers
        0x00, 0x01,           // Starting Address
        0x00, 0x04            // Quantity (4 registers)
    };
    
    modbus_header_t mb_hdr;
    if (parse_modbus_frame(modbus_frame, sizeof(modbus_frame), &mb_hdr)) {
        printf("[MODBUS] Parsed FC: %d\n", mb_hdr.fc);
        extract_modbus_data(modbus_frame, sizeof(modbus_frame), &mb_hdr);
        log_entry(mb_hdr.fc, 0x01, 0x5F3A, false);
    } else {
        printf("[MODBUS] CRC mismatch\n");
    }
    
    // Demo DNP3 frame: Start of Message (Control Code 0x50)
    uint8_t dnp3_frame[] = {
        0x50,                 // Control Code: Start
        0x01,                 // Sequence Number
        0x04, 0x00,           // Data Length (4 bytes)
        0x60                  // Checksum placeholder
    };
    
    dnp3_header_t dn_hdr;
    if (parse_dnp3_frame(dnp3_frame, sizeof(dnp3_frame), &dn_hdr)) {
        printf("[DNP3] Parsed Control Code: %d\n", dn_hdr.control_code);
        extract_dnp3_data(dnp3_frame, sizeof(dnp3_frame), &dn_hdr);
    } else {
        printf("[DNP3] Checksum mismatch\n");
    }
    
    // Flush and show logs
    flush_logs();
    
    reset_parser();
    return 0;
}