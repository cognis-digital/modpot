package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// =============================================================================
// CONFIGURATION & TYPES
// =============================================================================

const (
	DefaultPort       = 502 // Modbus default port
	HoneypotAddress   = "192.168.1.100:502"
	LogFile           = "/var/log/modpot/interactions.jsonl"
	MaxLogSizeMB      = 100
)

type Interaction struct {
	Timestamp    time.Time `json:"timestamp"`
	SourceIP     string    `json:"source_ip"`
	Transport    string    `json:"transport"` // "rtu", "ascii", "tcp"
	Protocol     string    `json:"protocol"`  // "modbus", "dnp3"
	FunctionCode uint8     `json:"function_code"`
	RegisterAddr int        `json:"register_address"`
	RegisterType string    `json:"register_type"` // "holding", "input", "coil", "discrete_input"
	Operation    string    `json:"operation"`    // "read", "write"
	Data         []byte     `json:"data,omitempty"`
	Value        interface{} `json:"value,omitempty"`
	TransactionID uint16   `json:"transaction_id"`
	DNP3Frame    *DNP3Frame `json:"dnp3_frame,omitempty"`
}

type DNP3Frame struct {
	Version      uint8  `json:"version"`
	ControlCode  uint8  `json:"control_code"`
	ICode        uint16 `json:"icode"`
	SequenceNum  uint8  `json:"sequence_number"`
	PayloadLen   int    `json:"payload_length"`
}

type ParserConfig struct {
	LogDir      string
	MaxLogSize  int64 // bytes
	BufferSize  int
	Timeout     time.Duration
}

// =============================================================================
// LOGGING SYSTEM - Thread-safe, rotating buffer
// =============================================================================

var (
	logMu          sync.Mutex
	interactions   []Interaction
	currentOffset  int64 = 0
)

func initLogDir() error {
	dir := "/var/log/modpot"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir log dir: %w", err)
	}
	return nil
}

func appendInteraction(interaction Interaction) error {
	logMu.Lock()
	defer logMu.Unlock()

	entry, err := json.Marshal(interaction)
	if err != nil {
		return fmt.Errorf("marshal interaction: %w", err)
	}

	file, err := os.OpenFile(LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("open log file: %v", err)
		return err
	}
	defer file.Close()

	n, err := file.Write(entry)
	if err != nil {
		return fmt.Errorf("write to log: %w", err)
	}

	currentOffset += int64(n)
	
	// Simple size check - in prod use proper rotation library
	if currentOffset > MaxLogSizeMB*1024*1024 {
		log.Printf("log file exceeded %dMB, truncating", MaxLogSizeMB)
		file.Truncate(0)
		currentOffset = 0
	}

	return nil
}

// =============================================================================
// MODBUS RTU PARSER - Core Protocol Logic
// =============================================================================

type ModbusRTUPacket struct {
	TxID        uint16
	PDULength   int
	FunctionCode uint8
	DataLen     int
	Data        []byte
	Parity      bool // true = even parity, false = odd
}

func parseModbusRTU(data []byte) (*ModbusRTUPacket, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("packet too short for Modbus RTU header")
	}

	txID := binary.BigEndian.Uint16(data[0:2])
	pduLen := int(data[2])
	
	if pduLen > len(data)-3 {
		return nil, fmt.Errorf("PDU length exceeds remaining data")
	}

	functionCode := data[3]
	dataStart := 4 + pduLen
	dataEnd := len(data) - (1 if functionCode == 0x06 else 2) // write single vs multiple
	
	if dataEnd < dataStart {
		return nil, fmt.Errorf("invalid data range")
	}

	pkt := &ModbusRTUPacket{
		TxID:        txID,
		PDULength:   pduLen,
		FunctionCode: functionCode,
		DataLen:     dataEnd - dataStart,
		Data:        make([]byte, 0),
	}

	if pkt.DataLen > 0 {
		pkt.Data = append(pkt.Data, data[dataStart:dataEnd]...)
	}

	return pkt, nil
}

func getRegisterType(fc uint8) string {
	switch fc {
	case 0x01: return "coil"
	case 0x02: return "discrete_input"
	case 0x03: return "holding"
	case 0x04: return "input"
	default: return fmt.Sprintf("unknown(%d)", fc)
	}
}

func getOperation(fc uint8, dataLen int) string {
	switch fc {
	case 0x01, 0x02: // Read Coils/Discrete Inputs
		return "read"
	case 0x03, 0x04: // Read Holding/Input Registers
		return "read"
	case 0x05: return "write_single"
	case 0x06: return "write_multiple"
	case 0x10: return "read_holding_registers_response"
	default:
		if fc >= 0x80 {
			return fmt.Sprintf("response(%d)", fc)
		}
		return fmt.Sprintf("unknown(%d)", fc)
	}
}

// =============================================================================
// DNP3 PARSER - Application Layer Protocol
// =============================================================================

type ModbusDNP3Parser struct {
	config    ParserConfig
	mu        sync.Mutex
	buffer    [256]byte
	offset    int
}

func NewModbusDNP3Parser(cfg ParserConfig) *ModbusDNP3Parser {
	return &ModbusDNP3Parser{
		config: cfg,
		buffer: [256]byte{},
		offset: 0,
	}
}

func (p *ModbusDNP3Parser) Reset() {
	p.offset = 0
	copy(p.buffer[:], p.buffer[p.offset:])
	p.offset = 0
}

// DNP3 Control Link Layer Frame Structure
type CLLFrame struct {
	Version      uint8
	ControlCode  uint8
	SequenceNum  uint8
	PayloadLen   int
	ICode        uint16
	Timestamp    time.Time
}

func (p *ModbusDNP3Parser) ParseCLL(data []byte) (*CLLFrame, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("CLL frame too short")
	}

	version := data[0]
	controlCode := data[1]
	seqNum := data[2]
	payloadLen := int(binary.BigEndian.Uint16(data[3:5]))

	if payloadLen > len(data)-5 {
		return nil, fmt.Errorf("payload length exceeds remaining data")
	}

	pkt := &CLLFrame{
		Version:      version,
		ControlCode:  controlCode,
		SequenceNum:  seqNum,
		PayloadLen:   payloadLen,
		Timestamp:    time.Now(),
	}

	return pkt, nil
}

func (p *ModbusDNP3Parser) ParseALP(payload []byte) (*DNP3Frame, error) {
	if len(payload) < 2 {
		return nil, fmt.Errorf("ALP payload too short")
	}

	// ALP header: ICODE (16-bit), Sequence Number (8-bit)
	icode := binary.BigEndian.Uint16(payload[0:2])
	seqNum := uint8(payload[2])

	pkt := &DNP3Frame{
		Version:      5, // DNP3 V5 is most common
		ControlCode:  payload[3],
		ICode:        icode,
		SequenceNum:  seqNum,
		PayloadLen:   len(payload) - 4,
	}

	return pkt, nil
}

// =============================================================================
// HONEYPOT SERVICE - HTTP Interface for Attacker Interaction
// =============================================================================

type HoneypotServer struct {
	parser    *ModbusDNP3Parser
	config    ParserConfig
	httpMux   http.ServeMux
	mu        sync.Mutex
	listener  net.Listener
}

func NewHoneypotServer(cfg ParserConfig) (*HoneypotServer, error) {
	if err := initLogDir(); err != nil {
		return nil, fmt.Errorf("init log dir: %w", err)
	}

	server := &HoneypotServer{
		parser:  NewModbusDNP3Parser(cfg),
		config:  cfg,
		httpMux: http.NewServeMux(),
	}

	return server, nil
}

func (s *HoneypotServer) Start(port int) error {
	addr := fmt.Sprintf(":%d", port)
	
	s.listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("bind to %s: %w", addr, err)
	}

	log.Printf("Modpot honeypot listening on %s", s.listener.Addr())

	go func() {
		if err := http.Serve(s.listener, &http.Server{Handler: s.httpMux}); err != nil && err != http.ErrClosedClient {
			log.Printf("server stopped: %v", err)
		}
	}()

	return nil
}

func (s *HoneypotServer) Stop() error {
	if s.listener != nil {
		s.listener.Close()
	}
	return nil
}

// =============================================================================
// HTTP HANDLERS - Simulate Modbus/TCP responses
// =============================================================================

type ResponseWriter struct {
	http.ResponseWriter
	status int
	size   int64
}

func (rw *ResponseWriter) WriteHeader(code int) {
	if rw.status == 0 {
		rw.status = code
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *ResponseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.size += int64(n)
	return n, err
}

type ModbusTCPHandler struct {
	server    *HoneypotServer
	response  ResponseWriter
	timestamp time.Time
}

func NewModbusTCPHandler(s *HoneypotServer) *ModbusTCPHandler {
	return &ModbusTCPHandler{server: s, response: ResponseWriter{s.httpMux}}
}

func (h *ModbusTCPHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	h.response = ResponseWriter{rw, 0, 0}

	// Read Modbus TCP header (2 bytes transaction ID)
	var txID uint16
	if err := binary.Read(&h.response, binary.BigEndian); err != nil {
		log.Printf("read TX ID: %v", err)
		h.sendErrorResponse(0x83, "communication error") // 4.5 Communication Exception
		return
	}

	// Read PDU length (2 bytes)
	var pduLen uint16
	if err := binary.Read(&h.response, binary.BigEndian); err != nil {
		log.Printf("read PDU length: %v", err)
		h.sendErrorResponse(0x83, "communication error")
		return
	}

	// Read function code and data
	var fc uint8
	if err := binary.Read(&h.response, binary.BigEndian); err != nil {
		log.Printf("read function code: %v", err)
		h.sendErrorResponse(0x83, "communication error")
		return
	}

	fc = h.response.Byte()

	// Parse the PDU data
	pkt, err := parseModbusRTU(h.response.Bytes())
	if err != nil {
		log.Printf("parse RTU: %v", err)
		h.sendErrorResponse(0x83, "protocol error")
		return
	}

	// Create interaction log entry
	interaction := Interaction{
		Timestamp:    time.Now(),
		SourceIP:     req.RemoteAddr,
		Transport:    "tcp",
		Protocol:     "modbus",
		FunctionCode: fc,
		RegisterType: getRegisterType(fc),
		Operation:    getOperation(fc, pkt.DataLen),
		Data:         pkt.Data,
		TransactionID: txID,
	}

	// Extract register address from data (for read operations)
	if fc == 0x03 || fc == 0x04 { // Read Holding/Input Registers
		if len(pkt.Data) >= 2 {
			interaction.RegisterAddr = int(binary.BigEndian.Uint16(pkt.Data[0:2]))
		}
	}

	// Log the interaction
	if err := appendInteraction(interaction); err != nil {
		log.Printf("log interaction: %v", err)
	}

	// Simulate response - echo back with transaction ID + 1
	responseTxID := txID + 1
	h.response.WriteUint16(responseTxID)
	h.response.WriteUint8(0x03) // Read Holding Registers Response
	h.response.WriteUint8(uint8(pkt.PDULength))

	// Build response PDU
	respPDU := make([]byte, pkt.PDULength+2)
	copy(respPDU[1:], pkt.Data)
	
	if fc == 0x03 {
		binary.BigEndian.PutUint16(respPDU[1:3], uint16(pkt.DataLen))
	}

	h.response.Write(respPDU)
	log.Printf("response sent to %s, FC=%d, len=%d", req.RemoteAddr, fc, pkt.PDULength)
}

func (h *ModbusTCPHandler) sendErrorResponse(fc uint8, msg string) {
	h.response.WriteUint16(0) // TX ID 0 for error
	h.response.WriteUint8(0x83)
	h.response.WriteUint8(uint8(fc))
	h.response.WriteUint8(uint8(len(msg)))
	h.response.Write([]byte(msg))
}

// =============================================================================
// MAIN - Entry Point with Demo
// =============================================================================

func main() {
	// Configure parser
	cfg := ParserConfig{
		LogDir:   "/tmp/modpot",
		MaxLogSize: 10 * 1024 * 1024, // 10MB
		BufferSize: 256,
		Timeout:  time.Second * 30,
	}

	server, err := NewHoneypotServer(cfg)
	if err != nil {
		log.Fatalf("create server: %v", err)
	}

	// Setup HTTP handlers for Modbus TCP simulation
	modbusHandler := NewModbusTCPHandler(server)
	
	http.HandleFunc("/modbus/", func(rw http.ResponseWriter, req *http.Request) {
		handler := modbusHandler
		handler.ServeHTTP(rw, req)
	})

	// Add a simple health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "running",
			"port":   DefaultPort,
		})
	})

	// Start the server
	if err := server.Start(DefaultPort); err != nil {
		log.Fatalf("start server: %v", err)
	}

	// Demo: Simulate some interactions
	fmt.Println("\n=== Modpot Honeypot Started ===")
	fmt.Printf("Listening on port %d\n", DefaultPort)
	fmt.Printf("Log file: %s\n", LogFile)
	
	// Simulate a few interactions for demo
	demoInteractions()

	// Keep server running
	select {}
}

func demoInteractions() {
	fmt.Println("\n--- Demo Interactions ---")
	
	// Simulate reading holding registers (FC 0x03)
	simReadRegisters()
	
	// Simulate writing a single register (FC 0x06)
	simWriteRegister()
	
	// Simulate DNP3 frame parsing
	simDNP3Frame()

	fmt.Println("\n--- Demo Complete ---")
}

func simReadRegisters() {
	fmt.Println("1. Reading Holding Registers...")
	
	pkt := &ModbusRTUPacket{
		TxID: