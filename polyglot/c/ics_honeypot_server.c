#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>

#define DEFAULT_PORT 502
#define MAX_BUFFER_SIZE 4096
#define MAX_CLIENTS 1024
#define LOG_FILE "/var/log/modpot/ics_honeypot.log"

static int g_running = 1;
static int g_server_fd = -1;

typedef struct {
    int client_fd;
    char ip[INET_ADDRSTRLEN];
} ClientInfo;

static void log_json(int fd, const char *ip, unsigned char func_code, 
                     uint32_t reg_addr, uint32_t value) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", tm_info);
    
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        fprintf(f, "{\"ts\":\"%s\",\"src_ip\":\"%s\",\"fd\":%d,"
                "\"func_code\":0x%02X,\"reg_addr\":%u,\"value\":%u}\n",
                timestamp, ip, fd, func_code, reg_addr, value);
        fclose(f);
    }
}

static void handle_modbus_read(int fd, const char *ip, unsigned char func_code) {
    uint32_t addr = 0;
    
    if (func_code == 0x03 || func_code == 0x06) {
        addr = 1000; // Default holding register for demo
        log_json(fd, ip, func_code, addr, 0);
        
        char response[256];
        int len = snprintf(response, sizeof(response),
            "{\"type\":\"MODBUS_READ\",\"func\":%d,\"addr\":%u}\n",
            func_code, addr);
        
        if (write(fd, response, len) > 0) {
            log_json(fd, ip, func_code, addr, 1);
        }
    }
}

static void handle_modbus_write(int fd, const char *ip, unsigned char func_code) {
    uint32_t addr = 0;
    uint32_t value = 0;
    
    if (func_code == 0x08 || func_code == 0x0F) {
        addr = 1000;
        value = 42; // Demo write value
        
        log_json(fd, ip, func_code, addr, value);
        
        char response[256];
        int len = snprintf(response, sizeof(response),
            "{\"type\":\"MODBUS_WRITE\",\"func\":%d,\"addr\":%u,\"val\":%u}\n",
            func_code, addr, value);
        
        if (write(fd, response, len) > 0) {
            log_json(fd, ip, func_code, addr, 1);
        }
    }
}

static void handle_dnp3(int fd, const char *ip, unsigned char cmd_type) {
    uint32_t reg_addr = 0;
    
    if (cmd_type == 0x03 || cmd_type == 0x04) {
        reg_addr = 1000; // Default ICS register
        
        log_json(fd, ip, cmd_type, reg_addr, 0);
        
        char response[256];
        int len = snprintf(response, sizeof(response),
            "{\"type\":\"DNP3_CMD\",\"cmd\":%d,\"addr\":%u}\n",
            cmd_type, reg_addr);
        
        if (write(fd, response, len) > 0) {
            log_json(fd, ip, cmd_type, reg_addr, 1);
        }
    }
}

static void parse_and_dispatch(int fd, const char *ip, unsigned char *buf, 
                              size_t len) {
    if (len < 2) return;
    
    unsigned char func = buf[0];
    uint32_t addr = 0;
    int modbus_read = 0, modbus_write = 0, dnp3_cmd = 0;
    
    // Modbus function code detection
    if (func == 0x01 || func == 0x02) {
        modbus_read = 1;
    } else if (func == 0x03 || func == 0x06) {
        modbus_read = 1;
        addr = buf[4] | (buf[5] << 8); // Extract register address
    } else if (func == 0x08 || func == 0x0F) {
        modbus_write = 1;
        addr = buf[4] | (buf[5] << 8);
    }
    
    // DNP3 command type detection
    if (func >= 0x03 && func <= 0x06) {
        dnp3_cmd = 1;
    }
    
    // Dispatch to appropriate handler
    if (modbus_read || modbus_write) {
        handle_modbus_read(fd, ip, func);
    } else if (dnp3_cmd) {
        handle_dnp3(fd, ip, func);
    }
}

static void client_handler(int fd, const char *ip) {
    char buffer[MAX_BUFFER_SIZE];
    
    while (g_running && read(fd, buffer, sizeof(buffer)) > 0) {
        parse_and_dispatch(fd, ip, (unsigned char*)buffer, strlen(buffer));
        
        // Simple response to keep connection alive
        if (write(fd, "OK\r\n", 4) < 0) break;
    }
    
    close(fd);
}

static void signal_handler(int sig) {
    g_running = 0;
    printf("Shutting down honeypot...\n");
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    struct sockaddr_in server_addr;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--log-file") == 0 && i + 1 < argc) {
            LOG_FILE = argv[++i];
        }
    }
    
    // Setup signal handlers for graceful shutdown
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    
    // Create server socket
    g_server_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (g_server_fd < 0) {
        perror("socket");
        return 1;
    }
    
    int opt = 1;
    setsockopt(g_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(g_server_fd, (struct sockaddr*)&server_addr, 
             sizeof(server_addr)) < 0) {
        perror("bind");
        close(g_server_fd);
        return 1;
    }
    
    if (listen(g_server_fd, MAX_CLIENTS) < 0) {
        perror("listen");
        close(g_server_fd);
        return 1;
    }
    
    printf("modpot honeypot listening on port %d\n", port);
    printf("Log file: %s\n", LOG_FILE);
    
    // Main server loop
    while (g_running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(g_server_fd, &readfds);
        
        struct timeval timeout = {1, 0};
        
        int ret = select(g_server_fd + 1, &readfds, NULL, NULL, &timeout);
        if (ret < 0) {
            perror("select");
            continue;
        } else if (ret == 0) {
            // Timeout - continue loop
            continue;
        }
        
        if (FD_ISSET(g_server_fd, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            
            int client_fd = accept(g_server_fd, 
                                  (struct sockaddr*)&client_addr,
                                  &addr_len);
            
            if (client_fd < 0) continue;
            
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
            
            client_handler(client_fd, ip);
        }
    }
    
    close(g_server_fd);
    printf("Honeypot stopped.\n");
    return 0;
}

/*
 * Demo / Test Mode - Run without network socket
 */
#ifdef TEST_MODE
int main_test(void) {
    printf("Running modpot in test mode...\n\n");
    
    // Simulate some incoming packets
    unsigned char test_packets[] = {
        0x03, 0x01, 0x02, 0x00, 0x05, 0x00, 0x00, 0x0F, 0x80, // Modbus Read
        0x06, 0x03, 0x04, 0x00, 0x12, 0x00, 0x05, 0x00, 0x0F, 0x80, // Modbus Write
        0x04, 0x03, 0x01, 0x02, 0x00, 0x05, 0x00, 0x0F, 0x80, // DNP3 Command
    };
    
    for (int i = 0; test_packets[i]; i++) {
        printf("Packet: ");
        for (int j = 0; j < 12 && test_packets[i + j]; j++) {
            printf("%02X ", test_packets[i + j]);
        }
        printf("\n");
        
        // Process packet
        parse_and_dispatch(99, "192.168.1.100", 
                         (unsigned char*)test_packets, 12);
    }
    
    printf("Test complete.\n");
    return 0;
}
#endif

/*
 * Compile: gcc -o modpot ics_honeypot_server.c -DTEST_MODE
 * Run: ./modpot -p 502 --log-file /tmp/modpot.log
 */