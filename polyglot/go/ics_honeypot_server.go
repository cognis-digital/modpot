package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"
)

// Config holds server configuration.
type Config struct {
	Port     int    `json:"port"`
	LogFile  string `json:"log_file"`
	Protocol string `json:"protocol"` // "modbus" or "dnp3"
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Port:     502,          // Standard Modbus TCP port
		LogFile:  "/var/log/modpot/honeypot.log",
		Protocol: "modbus",
	}
}

// LogEntry represents a single log record.
type LogEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	ClientID     string    `json:"client_id"`
	IPAddress    string    `json:"ip_address"`
	RegisterAddr uint16    `json:"register_address,omitempty"`
	RegisterType string    `json:"register_type,omitempty"` // "Holding", "Input", etc.
	Operation    string    `json:"operation"`              // "READ", "WRITE"
	Value        any       `json:"value,omitempty"`
	Unit         string    `json:"unit,omitempty"`
	Delayed      bool      `json:"delayed,omitempty"`
}

// HoneypotState maintains shared state across connections.
type HoneypotState struct {
	mu          sync.Mutex
	clientCount int
	activeClients map[string]*ClientSession
	logFile     *os.File
	logger       *log.Logger
	config       Config
	shutdown    chan struct{}
}

// ClientSession tracks a single TCP connection.
type ClientSession struct {
	ID         string
	Conn       net.Conn
	Mu         sync.Mutex
	RegisterMap map[uint16]*RegisterState
	LastSeen   time.Time
	Connected  bool
}

// RegisterState tracks per-register statistics.
type RegisterState struct {
	ReadCount    int64
	WriteCount   int64
	LastReadTime  time.Time
	LastWriteTime time.Time
	TotalBytes    int64
}

// NewHoneypot creates a new honeypot instance.
func NewHoneypot(cfg *Config) (*HoneypotState, error) {
	state := &HoneypotState{
		config:       *cfg,
		activeClients: make(map[string]*ClientSession),
		shutdown:     make(chan struct{}),
	}

	var err error
	if cfg.LogFile != "" {
		state.logFile, err = os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			state.logger = log.New(state.logFile, "", log.LstdFlags)
		} else {
			state.logger = log.New(os.Stdout, "", log.LstdFlags)
		}
	}

	return state, err
}

// ClientSession returns or creates a session for the given connection.
func (s *HoneypotState) GetOrCreateSession(conn net.Conn) (*ClientSession, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ip := conn.RemoteAddr().String()
	if _, exists := s.activeClients[ip]; !exists {
		session := &ClientSession{
			ID:         ip,
			Conn:       conn,
			RegisterMap: make(map[uint16]*RegisterState),
			Connected:  true,
			LastSeen:   time.Now(),
		}
		s.activeClients[ip] = session
		s.clientCount++
		return session, ip
	}

	session := s.activeClients[ip]
	session.Conn = conn
	session.LastSeen = time.Now()
	return session, ip
}

// CloseSession removes a client from active tracking.
func (s *HoneypotState) CloseSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sess, exists := s.activeClients[sessionID]; exists {
		delete(s.activeClients, sessionID)
		s.clientCount--
	}
}

// LogActivity writes a structured log entry.
func (s *HoneypotState) LogActivity(entry LogEntry) {
	entry.Timestamp = time.Now()
	
	if s.logger != nil {
		data, _ := json.Marshal(entry)
		s.logger.Write(data)
	} else if s.logFile == nil {
		fmt.Printf("%+v\n", entry)
	}
}

// HandleConnection processes a single TCP connection.
func (s *HoneypotState) HandleConnection(sessionID string, session *ClientSession) {
	reader := bufio.NewReader(session.Conn)
	
	for {
		select {
		case <-s.shutdown:
			return
		default:
			buf, err := reader.ReadBytes(0x0D) // Read until CR (Modbus delimiter)
			
			if err == nil && len(buf) > 1 {
				s.handleFrame(sessionID, session, buf)
				session.LastSeen = time.Now()
			} else if err != nil {
				if err.Error() == "EOF" || err.Error() == "closed network connection" {
					return
				}
				log.Printf("Error reading from %s: %v", sessionID, err)
				return
			}
		}
	}
}

// handleFrame parses and responds to an incoming Modbus frame.
func (s *HoneypotState) handleFrame(sessionID string, session *ClientSession, buf []byte) {
	if len(buf) < 4 {
		return // Need at least header + 1 byte of data
	}

	// Parse Modbus TCP header: Transaction ID (2 bytes), Protocol ID (1 byte = 0x00 for Modbus)
	transID := binary.BigEndian.Uint16(buf[0:2])
	protoID := buf[3]

	if protoID != 0 {
		return // Not a Modbus frame
	}

	// Extract PDU (Protocol Data Unit) - everything after header
	pduOffset := 4
	pduLen := len(buf) - pduOffset
	
	if pduLen < 2 {
		return
	}

	// Parse function code and register address from PDU
	funcCode := buf[pduOffset]
	registerAddr := binary.BigEndian.Uint16(buf[pduOffset+1 : pduOffset+3])

	// Create a default response header
	respHeader := make([]byte, 4)
	binary.BigEndian.PutUint16(respHeader[0:2], transID)
	respHeader[3] = 0x00

	var respPDU []byte
	var logEntry LogEntry

	switch funcCode {
	case 0x03: // Read Holding Registers
		s.handleReadRegisters(session, registerAddr, pduOffset+3, &respPDU, &logEntry)
	case 0x04: // Read Input Registers
		s.handleReadRegisters(session, registerAddr, pduOffset+3, &respPDU, &logEntry)
	case 0x01: // Write Single Coil (treat as bit write)
		s.handleWriteCoil(session, registerAddr, buf[pduOffset+3], pduOffset+3, &respPDU, &logEntry)
	case 0x05: // Write Single Register
		if len(buf) > pduOffset+4 {
			value := binary.BigEndian.Uint16(buf[pduOffset+3 : pduOffset+5])
			s.handleWriteRegister(session, registerAddr, value, pduOffset+4, &respPDU, &logEntry)
		}
	case 0x10: // Write Multiple Registers
		if len(buf) > pduOffset+6 {
			valueLen := buf[pduOffset+5]
			if valueLen > 0 && len(buf) >= pduOffset+6+int(valueLen)*2 {
				startAddr := binary.BigEndian.Uint16(buf[pduOffset+3 : pduOffset+5])
				values := make([]uint16, valueLen)
				for i := 0; i < int(valueLen); i++ {
					offset := pduOffset + 6 + (i * 2)
					values[i] = binary.BigEndian.Uint16(buf[offset : offset+2])
				}
				s.handleWriteRegisters(session, startAddr, values, &respPDU, &logEntry)
			}
		}
	default:
		respPDU = []byte{funcCode, 0x83} // Function code with error response
		logEntry.Operation = fmt.Sprintf("UNKNOWN_FUNC_%d", funcCode)
		s.LogActivity(logEntry)
	}

	// Build complete response
	fullResponse := make([]byte, len(respHeader)+len(respPDU))
	copy(fullResponse, respHeader)
	copy(fullResponse[4:], respPDU)

	// Send response back to client
	session.Mu.Lock()
	if _, err := session.Conn.Write(fullResponse); err == nil {
		s.LogActivity(LogEntry{
			Timestamp:    time.Now(),
			ClientID:     session.ID,
			IPAddress:    session.ID,
			RegisterAddr: registerAddr,
			Operation:    logEntry.Operation,
			Value:        fmt.Sprintf("%d", len(fullResponse)),
		})
	} else {
		s.LogActivity(LogEntry{
			Timestamp:    time.Now(),
			ClientID:     session.ID,
			IPAddress:    session.ID,
			Operation:    "RESPONSE_ERROR",
			Value:        err.Error(),
		})
	}
	session.Mu.Unlock()
}

// handleReadRegisters processes a read request and builds response.
func (s *HoneypotState) handleReadRegisters(session *ClientSession, registerAddr uint16, pduOffset int, respPDU *[]byte, logEntry *LogEntry) {
	// Default Modbus response: 2 bytes header + 4 bytes per register
	numRegs := 1 // Default to 1 register for simplicity
	
	// Build response data - simulate some interesting values
	var data []byte
	for i := 0; i < numRegs*2; i++ {
		data = append(data, byte(i%256))
	}

	// Response header: Function code + Byte count
	header := make([]byte, 4)
	header[0] = 0x03 // Read Holding Registers
	header[1] = byte(len(data))
	
	*respPDU = append(*respPDU, header...)
	*respPDU = append(*respPDU, data...)

	logEntry.RegisterAddr = registerAddr
	logEntry.RegisterType = "Holding"
	logEntry.Operation = "READ"
	logEntry.Value = fmt.Sprintf("%d registers", numRegs)
	s.LogActivity(*logEntry)
}

// handleWriteCoil processes a single coil write.
func (s *HoneypotState) handleWriteCoil(session *ClientSession, registerAddr uint16, value byte, pduOffset int, respPDU *[][]byte, logEntry *LogEntry) {
	*respPDU = make([]byte, 4)
	// Response: Function code + Status (0x00 for success)
	(*respPDU)[0] = 0x01 // Write Single Coil
	(*respPDU)[1] = 0x00 // Success

	logEntry.RegisterAddr = registerAddr
	logEntry.RegisterType = "Coil"
	logEntry.Operation = fmt.Sprintf("WRITE_COIL_%d", value)
	s.LogActivity(*logEntry)
}

// handleWriteRegister processes a single register write.
func (s *HoneypotState) handleWriteRegister(session *ClientSession, registerAddr uint16, value uint16, pduOffset int, respPDU *[]byte, logEntry *LogEntry) {
	*respPDU = make([]byte, 4)
	// Response: Function code + Status (0x06 for success)
	(*respPDU)[0] = 0x05 // Write Single Register
	(*respPDU)[1] = 0x06 // Success

	logEntry.RegisterAddr = registerAddr
	logEntry.RegisterType = "Holding"
	logEntry.Operation = fmt.Sprintf("WRITE_%d", value)
	s.LogActivity(*logEntry)
}

// handleWriteRegisters processes multiple register writes.
func (s *HoneypotState) handleWriteRegisters(session *ClientSession, registerAddr uint16, values []uint16, respPDU *[]byte, logEntry *LogEntry) {
	*respPDU = make([]byte, 4)
	// Response: Function code + Byte count + Status
	byteCount := len(values) * 2
	header := make([]byte, 3)
	header[0] = 0x10 // Write Multiple Registers
	header[1] = byte(byteCount)
	header[2] = 0x06 // Success
	
	*respPDU = append(*respPDU, header...)
	
	logEntry.RegisterAddr = registerAddr
	logEntry.RegisterType = "Holding"
	logEntry.Operation = fmt.Sprintf("WRITE_MULTIPLE_%d_regs", len(values))
	s.LogActivity(*logEntry)
}

// Run starts the honeypot server.
func (s *HoneypotState) Run() error {
	addr := fmt.Sprintf(":%d", s.config.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind address %s: %w", addr, err)
	}

	defer func() {
		if err := listener.Close(); err != nil {
			log.Printf("Error closing listener: %v", err)
		}
	}()

	s.logger.Printf("Modbus TCP honeypot listening on %s (protocol: %s)", addr, s.config.Protocol)
	
	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, os.Kill)
	
	select {
	case <-sigChan:
		s.logger.Println("Received interrupt signal, shutting down...")
	case <-s.shutdown:
		s.logger.Println("Shutdown channel closed")
	}

	return nil
}

// Shutdown gracefully stops the server.
func (s *HoneypotState) Shutdown() {
	close(s.shutdown)
	if s.logFile != nil {
		s.logFile.Close()
	}
}

// Main entry point with command-line parsing and demo functionality.
func main() {
	cfg := DefaultConfig()
	
	flag.IntVar(&cfg.Port, "port", cfg.Port, "TCP port to listen on")
	flag.StringVar(&cfg.LogFile, "log", cfg.LogFile, "Path to JSON log file")
	flag.StringVar(&cfg.Protocol, "proto", cfg.Protocol, "Protocol type (modbus|dnp3)")
	
	// Demo flags for testing without network
	flag.BoolVar(&cfg.Port, "demo-port", 5021, "Demo port when not running as server")
	flag.BoolVar(&cfg.LogFile, "demo-log", "/tmp/modpot_demo.log", "Demo log file path")

	flag.Parse()

	// Override with demo values if requested (for testing)
	if flag.NFlag() > 5 { // Heuristic: user likely wants demo mode
		cfg.Port = 5021
		cfg.LogFile = "/tmp/modpot_demo.log"
	}

	honeypot, err := NewHoneypot(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize honeypot: %v", err)
	}

	// Start server in goroutine
	go func() {
		if err := honeypot.Run(); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	// Keep main alive and handle shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, os.Kill)
	
	select {
	case <-sigChan:
		honeypot.Shutdown()
		log.Println("Honeypot server stopped gracefully")
	}

	// Demo mode: simulate some activity if running with demo flags
	if cfg.Port