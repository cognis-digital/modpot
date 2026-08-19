require 'json'
require 'socket'
require 'time'

module Modpot
  # Configuration constants
  class Config
    MAX_LOG_SIZE = 10 * 1024 * 1024
    LOG_FILE = File.expand_path('../logs/modbus_dnp3.log', __dir__)
    
    def self.reset!
      @total_transactions = 0
      @unique_ips = Set.new
      @recent_attacks = []
    end
    
    def self.total_transactions
      @total_transactions || 0
    end
    
    def self.unique_ip_count
      @unique_ips.size
    end
  end

  # Modbus Transaction ID - must match for response validation
  class ModbusTransactionID < Struct.new(:id, :source_port)
    def to_json(*args)
      { id: id, source_port: source_port }.to_json
    end
    
    def self.from_json(json_str)
      data = JSON.parse(json_str)
      new(data['id'], data['source_port'])
    end
  end

  # Modbus Function Codes with descriptions
  class ModbusFunctionCode < Struct.new(:code, :name, :description)
    CODES = {
      0x01 => { name: 'Read Coils', description: 'Read coil status' },
      0x02 => { name: 'Read Discrete Inputs', description: 'Read discrete input status' },
      0x03 => { name: 'Read Holding Registers', description: 'Read holding registers (most common)' },
      0x04 => { name: 'Read Input Registers', description: 'Read analog inputs' },
      0x05 => { name: 'Write Single Coil', description: 'Write single coil' },
      0x06 => { name: 'Write Single Register', description: 'Write single register' },
      0x15 => { name: 'Read/Write Multiple Registers', description: 'Combined read/write operation' }
    }.freeze
    
    def self.find(code)
      CODES[code] || { name: 'Unknown', description: 'Function code not recognized' }
    end
    
    def to_json(*args)
      data = { code: code, **find(code) }
      data[:description].nil? ? data.delete(:description) : data
    end
  end

  # Modbus PDU Parser - handles the protocol-specific portion
  class ModbusPduParser
    def self.parse(data, source_ip:, source_port:)
      return { error: 'Empty or too short for Modbus header', raw: data } if data.length < 2
      
      transaction_id = (data[0] << 8 | data[1]) & 0xFFFF
      function_code = data[2]
      
      result = {
        protocol: :modbus,
        source_ip:,
        source_port:,
        timestamp: Time.now.iso8601,
        transaction_id:,
        function_code: ModbusFunctionCode.find(function_code),
        pdu_length: data.length - 2
      }
      
      if function_code == 0x03 || function_code == 0x04 # Read registers
        result[:start_address] = (data[3] << 8 | data[4]) & 0xFFFF
        result[:quantity] = (data[5] << 8 | data[6]) & 0xFFFF
      elsif function_code == 0x15 # Read/Write Multiple
        result[:start_address] = (data[3] << 8 | data[4]) & 0xFFFF
        result[:quantity] = (data[5] << 8 | data[6]) & 0xFFFF
      end
      
      if function_code == 0x01 || function_code == 0x02 # Coils/Discrete Inputs
        result[:start_address] = (data[3] << 8 | data[4]) & 0xFFFF
        result[:quantity] = (data[5] << 8 | data[6]) & 0xFFFF
      end
      
      if function_code == 0x05 || function_code == 0x06 # Write operations
        result[:start_address] = (data[3] << 8 | data[4]) & 0xFFFF
        result[:value] = parse_write_value(data, 5)
      end
      
      result[:raw_pdu] = data.dup
      
      result
    rescue StandardError => e
      { error: "Modbus PDU parsing failed", raw: data, exception: e.message }
    end
    
    private
    
    def self.parse_write_value(data, offset)
      # Simple 16-bit value extraction for write operations
      (data[offset] << 8 | data[offset + 1]) & 0xFFFF
    end
  end

  # DNP3 Frame Parser - handles the protocol-specific portion
  class Dnp3FrameParser
    # Common Control Codes
    CC_READ_WRITE_REQ = 0x15
    CC_READ_WRITE_RESP = 0x16
    
    def self.parse(data, source_ip:, source_port:)
      return { error: 'Empty or too short for DNP3 header', raw: data } if data.length < 4
      
      control_code = data[0]
      sequence_number = (data[1] << 8 | data[2]) & 0xFFFF
      length = (data[3] << 8 | data[4]) & 0xFFFF
      checksum = (data[5] << 8 | data[6]) & 0xFFFF
      
      result = {
        protocol: :dnp3,
        source_ip:,
        source_port:,
        timestamp: Time.now.iso8601,
        control_code: Dnp3ControlCode.find(control_code),
        sequence_number:,
        frame_length: data.length - 7, # Header length
        checksum: { received: checksum }
      }
      
      if control_code == CC_READ_WRITE_REQ || control_code == CC_READ_WRITE_RESP
        result[:object_list] = parse_object_list(data[7..-1])
      end
      
      result[:raw_frame] = data.dup
      
      result
    rescue StandardError => e
      { error: "DNP3 Frame parsing failed", raw: data, exception: e.message }
    end
    
    def self.parse_object_list(payload)
      objects = []
      
      # DNP3 object list uses 16-bit length prefix for each object
      offset = 0
      
      while offset + 4 <= payload.length
        obj_length = (payload[offset] << 8 | payload[offset + 1]) & 0xFFFF
        
        if offset + 4 + obj_length > payload.length
          break # Truncated frame
        end
        
        object_data = payload[offset + 2..offset + 3 + obj_length - 1]
        
        objects << {
          raw_length: obj_length,
          data: object_data.dup,
          hex: object_data.map { |b| sprintf('%02X', b) }.join(' ')
        }
        
        offset += 4 + obj_length
      end
      
      result = { count: objects.size }
      
      # Try to identify common object types
      if objects.any?
        result[:identified] = parse_object_types(objects)
      end
      
      result
    rescue StandardError => e
      { error: "Object list parsing failed", exception: e.message }
    end
    
    def self.parse_object_types(objects)
      identified = []
      
      # Common DNP3 object types (simplified identification)
      type_patterns = [
        { pattern: /0x15/, name: 'Read/Write Request' },
        { pattern: /0x16/, name: 'Read/Write Response' },
        { pattern: /0x24/, name: 'Analog Input (AI)' },
        { pattern: /0x25/, name: 'Analog Output (AO)' },
        { pattern: /0x30/, name: 'Binary Input (BI)' },
        { pattern: /0x31/, name: 'Binary Output (BO)' }
      ]
      
      objects.each do |obj|
        obj_type = type_patterns.find { |p| p[:pattern].match?(obj[:hex]) }
        identified << { hex: obj[:hex], type: obj_type&.fetch(:name, 'Unknown') || 'Raw' }
      end
      
      identified
    rescue StandardError => e
      objects.map { |o| { raw: o[:hex], error: e.message } }
    end
    
    def self.find(code)
      CASES = {
        0x15 => { name: 'Read/Write Request', description: 'Request to read/write registers' },
        0x16 => { name: 'Read/Write Response', description: 'Response to read/write request' },
        0x24 => { name: 'Analog Input', description: 'Analog input value' },
        0x25 => { name: 'Analog Output', description: 'Analog output value' }
      }.freeze
      
      CASES[code] || { name: 'Unknown CC', description: 'Control code not recognized' }
    end
    
    def self.to_json(*args)
      data = { control_code: control_code, **find(control_code) }
      data[:description].nil? ? data.delete(:description) : data
    end
  end

  # Main Honeypot Logger - coordinates parsing and logging
  class ModbusDnp3HoneypotLogger
    include Singleton
    
    def initialize(options = {})
      @options = options.merge(Config.new)
      reset_stats!
      
      setup_logging if @options[:log_file]
    end
    
    def self.reset_stats!
      Config.reset!
    end
    
    def log_modbus(data, source_ip:, source_port:)
      parsed = ModbusPduParser.parse(data, source_ip: source_ip, source_port: source_port)
      
      if parsed[:error]
        @options[:total_transactions] += 1
        @log_error(parsed)
        return parsed
      end
      
      # Extract unique IP for tracking
      ip_key = "#{source_ip}:#{source_port}"
      Config.unique_ips << ip_key
      
      result = {
        **parsed,
        attacker_ip: source_ip,
        attacker_port: source_port,
        is_write: parsed[:function_code] && 
                   (parsed[:function_code].code == 0x05 || parsed[:function_code].code == 0x06),
        register_count: calculate_register_count(parsed)
      }
      
      @options[:total_transactions] += 1
      
      # Detect rapid scanning behavior
      if detect_rapid_scan?(source_ip, result)
        result[:flagged_as_scan] = true
        result[:scan_rate] = calculate_scan_rate(source_ip)
      end
      
      @log_success(result)
      
      result
    rescue StandardError => e
      { error: "Modbus logging failed", raw: data, exception: e.message }
    end
    
    def log_dnp3(data, source_ip:, source_port:)
      parsed = Dnp3FrameParser.parse(data, source_ip: source_ip, source_port: source_port)
      
      if parsed[:error]
        @options[:total_transactions] += 1
        @log_error(parsed)
        return parsed
      end
      
      ip_key = "#{source_ip}:#{source_port}"
      Config.unique_ips << ip_key
      
      result = {
        **parsed,
        attacker_ip: source_ip,
        attacker_port: source_port,
        is_request: Dnp3FrameParser::CC_READ_WRITE_REQ == parsed[:control_code].code,
        object_count: parsed[:object_list]&.fetch(:count, 0)
      }
      
      @options[:total_transactions] += 1
      
      # Detect rapid scanning behavior
      if detect_rapid_scan?(source_ip, result)
        result[:flagged_as_scan] = true
        result[:scan_rate] = calculate_scan_rate(source_ip)
      end
      
      @log_success(result)
      
      result
    rescue StandardError => e
      { error: "DNP3 logging failed", raw: data, exception: e.message }
    end
    
    private
    
    def setup_logging
      FileUtils.mkdir_p(File.dirname(Config::LOG_FILE)) unless File.exist?(Config::LOG_FILE)
    end
    
    def calculate_register_count(parsed)
      return 0 if parsed[:error] || !parsed[:quantity]
      
      case parsed[:function_code].code
      when 0x03, 0x04 # Read registers
        parsed[:quantity] * 2 # Each register is 16 bits = 2 bytes
      when 0x15 # Read/Write Multiple
        parsed[:quantity] * 2
      else
        0
      end
    end
    
    def calculate_scan_rate(ip, result)
      return 0 if !result[:register_count] || result[:register_count].zero?
      
      # Estimate time window from timestamp (assume ~1 second for demo)
      rate = result[:register_count] / 1.0
      rate.round(2)
    end
    
    def detect_rapid_scan?(ip, result)
      return false if !result[:flagged_as_scan] || result[:register_count].nil?
      
      # Flag if reading more than 100 registers in quick succession
      result[:register_count] > 100
    end
    
    def @log_success(result)
      # In production, this would write to a file or send to a queue
      # For demo, we just track stats
      puts "[MODPOT] #{result[:protocol].upcase} - #{result[:function_code]&.fetch(:name, result[:control_code]&.fetch(:name, 'Unknown') || 'Transaction')} " \
           "from #{result[:attacker_ip]}:#{result[:attacker_port]}" \
           "(regs: #{result[:register_count] || 0})" if ENV['DEBUG'] == '1'
    end
    
    def @log_error(error)
      puts "[MODPOT ERROR] #{error[:error]}" if ENV['DEBUG'] == '1'
    end
  end

  # Convenience module for quick parsing
  module ModbusDnp3Utils
    extend self
    
    def parse_any(data, source_ip:, source_port:)
      result = { raw: data.dup, protocol: :unknown }
      
      # Try Modbus first (more common in ICS)
      modbus_result = ModbusPduParser.parse(data, source_ip: source_ip, source_port: source_port)
      if !modbus_result[:error]
        result.merge!(modbus_result)
        return result
      end
      
      # Try DNP3
      dnp3_result = Dnp3FrameParser.parse(data, source_ip: source_ip, source_port: source_port)
      if !dnp3_result[:error]
        result.merge!(dnp3_result)
        return result
      end
      
      result[:error] = 'No recognized protocol'
    rescue StandardError => e
      { error: "General parsing failed", raw: data, exception: e.message }
    end
    
    def create_sample_modbus_read_registers(ip:, port:)
      # Sample Modbus Read Holding Registers (Function Code 0x03)
      [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, # Transaction ID + Function Code
        0x00, 0x0A, 0x01, 0x0F, 0x02, 0x00, 0x00, 0x00, # Start Address (10) + Quantity (2)
        0x48, 0x59, 0x6A, 0x7B, 0x8C, 0x9D, 0xAE, 0xBF  # Sample register data
      ].pack('C*')
    end
    
    def create_sample_dnp3_read_write(ip:, port:)
      # Sample DNP3 Read/Write Request (Control Code 0x15)
      [
        0x15, 0x00, 0x01, 0x0A, 0x07, 0x00, 0xAB, 0xCD, # CC + Seq + Length + Checksum
        0x24, 0x00, 0x01, 0x0F, 0x00, 0x00, 0x00, 0x00  # Object: Analog Input at address 31
      ].pack('C*')
    end
    
    def create_sample_modbus_write_register(ip:, port:)
      # Sample Modbus Write