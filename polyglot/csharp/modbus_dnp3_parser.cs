using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace modpot
{
    /// <summary>
    /// Represents a parsed Modbus transaction.
    </summary>
    public class ModbusTransaction
    {
        public byte SlaveId { get; }
        public ushort FunctionCode { get; }
        public uint? StartAddress { get; }
        public ushort? Quantity { get; }
        public List<byte>? Data { get; }
        public bool IsRead { get; }
        public bool IsWrite { get; }

        public ModbusTransaction(byte slaveId, ushort functionCode, 
            uint? startAddress = null, ushort? quantity = null, 
            List<byte>? data = null)
        {
            SlaveId = slaveId;
            FunctionCode = functionCode;
            StartAddress = startAddress;
            Quantity = quantity;
            Data = data;
            
            IsRead = (functionCode == 0x01 || functionCode == 0x02 || 
                     functionCode == 0x03 || functionCode == 0x04);
            IsWrite = (functionCode == 0x05 || functionCode == 0x06 || 
                       functionCode == 0x0F || functionCode == 0x10);
        }

        public override string ToString() => 
            $"Modbus:{SlaveId} FC{FunctionCode:X2} Addr{StartAddress} Qty{Quantity}";
    }

    /// <summary>
    /// Represents a parsed DNP3 control code transaction.
    </summary>
    public class Dnp3Transaction
    {
        public byte ControlCode { get; }
        public uint? SequenceNumber { get; }
        public List<byte>? DataBlock { get; }
        public bool IsCommand { get; }

        public Dnp3Transaction(byte controlCode, uint? sequence = null, 
            List<byte>? dataBlock = null)
        {
            ControlCode = controlCode;
            SequenceNumber = sequence;
            DataBlock = dataBlock;
            IsCommand = (controlCode >= 0x80);
        }

        public override string ToString() => 
            $"DNP3:CC{ControlCode:X2} Seq{SequenceNumber}";
    }

    /// <summary>
    /// Core Modbus RTU/ASCII parser for honeypot traffic.
    </summary>
    public class ModbusFrameParser
    {
        private readonly List<ModbusTransaction> _transactions = new();
        private byte? _pendingSlaveId;
        private ushort? _pendingFunctionCode;
        private uint? _pendingStartAddress;
        private ushort? _pendingQuantity;
        private List<byte>? _pendingData;

        public IReadOnlyList<ModbusTransaction> Transactions => _transactions.AsReadOnly();

        /// <summary>
        /// Parse raw bytes as Modbus RTU. Returns true if complete frame(s) found.
        </summary>
        public bool TryParse(byte[] buffer, out int bytesRead)
        {
            bytesRead = 0;
            var pos = 0;
            
            while (pos + 2 <= buffer.Length)
            {
                // Check for valid slave ID range (1-247)
                if (_pendingSlaveId == null || 
                    (buffer[pos] >= 1 && buffer[pos] <= 247))
                {
                    _pendingSlaveId = buffer[pos];
                    pos++;
                    
                    // Read function code and data length
                    if (pos + 1 > buffer.Length) break;
                    
                    var fc = buffer[pos];
                    var len = buffer[pos + 1];
                    
                    _pendingFunctionCode = fc;
                    _pendingStartAddress = null;
                    _pendingQuantity = null;
                    _pendingData = new List<byte>();

                    pos += 2;

                    // Read data payload
                    if (pos + len > buffer.Length) break;
                    
                    for (int i = 0; i < len; i++)
                    {
                        _pendingData.Add(buffer[pos]);
                        pos++;
                    }

                    // Calculate CRC16
                    var crc = CalculateCrc16(buffer, 0, pos - 2);
                    if (crc != buffer[pos] || (buffer.Length > pos + 1 && 
                        crc ^ 0xFF != buffer[pos + 1]))
                    {
                        _pendingSlaveId = null; // Invalid CRC, reset
                        continue;
                    }

                    // Valid frame - create transaction
                    var txn = new ModbusTransaction(
                        (byte)_pendingSlaveId!, 
                        (ushort)_pendingFunctionCode!,
                        _pendingStartAddress,
                        _pendingQuantity,
                        _pendingData?.Count > 0 ? _pendingData : null);

                    _transactions.Add(txn);
                    
                    // Reset for next frame
                    _pendingSlaveId = null;
                    pos += 2; // Skip CRC bytes
                }
                else
                {
                    _pendingSlaveId = null;
                    pos++;
                }
            }

            bytesRead = pos > 0 ? pos : 1;
            return _transactions.Count > 0 || (_pendingSlaveId != null && 
                _pendingFunctionCode != null);
        }

        /// <summary>
        /// Parse Modbus ASCII (RTU over ASCII).
        </summary>
        public bool TryParseAscii(byte[] buffer, out int bytesRead)
        {
            var sb = new StringBuilder();
            bytesRead = 0;
            
            while (bytesRead + 1 < buffer.Length && 
                   !char.IsControl(buffer[bytesRead]))
            {
                sb.Append((char)buffer[bytesRead]);
                bytesRead++;
            }

            if (sb.Length == 0 || sb[sb.Length - 1] != '\r' && sb[sb.Length - 1] != '\n')
            {
                return false;
            }

            var str = sb.ToString().Trim();
            if (str.Length < 4) return false;

            // Parse ASCII frame: SlaveID Length FC Data CRC1 CRC2
            try
            {
                var slaveId = byte.Parse(str.Substring(0, 2));
                var len = byte.Parse(str.Substring(2, 2));
                var fc = byte.Parse(str.Substring(4, 2));

                if (len + 6 > str.Length) return false;

                var dataStart = 6;
                var crc1 = byte.Parse(str.Substring(dataStart + len - 2, 2));
                var crc2 = byte.Parse(str.Substring(dataStart + len - 1, 2));

                // Reconstruct binary for CRC check
                var binary = new List<byte>();
                binary.Add(slaveId);
                binary.Add(len);
                binary.Add(fc);
                
                for (int i = 0; i < len; i++)
                {
                    if (dataStart + i * 2 > str.Length) break;
                    var hi = byte.Parse(str.Substring(dataStart + i * 2, 2));
                    var lo = byte.Parse(str.Substring(dataStart + i * 2 + 2, 2));
                    binary.Add(hi);
                    binary.Add(lo);
                }

                // Verify CRC
                var calcCrc = CalculateCrc16(binary.ToArray(), 0, binary.Count - 2);
                
                if (calcCrc == crc1 && (calcCrc ^ 0xFF) == crc2)
                {
                    _transactions.Add(new ModbusTransaction(
                        slaveId, fc, null, null, 
                        new List<byte>(binary.Skip(3))));
                    return true;
                }
            }
            catch
            {
                // Invalid ASCII format
            }

            return false;
        }

        private ushort CalculateCrc16(byte[] buffer, int offset, int length)
        {
            var crc = 0xFFFF;
            for (int i = offset; i < offset + length - 2; i++)
            {
                byte dataByte = buffer[i];
                crc ^= dataByte << 8;
                
                for (int j = 0; j < 8; j++)
                {
                    if ((crc & 0x8000) != 0)
                        crc = (crc << 1) ^ 0x4021;
                    else
                        crc <<= 1;
                }
            }

            return (ushort)(crc & 0xFFFF);
        }
    }

    /// <summary>
    /// DNP3 control code parser for ICS traffic.
    </summary>
    public class Dnp3FrameParser
    {
        private readonly List<Dnp3Transaction> _transactions = new();
        private byte? _pendingControlCode;
        private uint? _sequenceNumber;

        /// <summary>
        /// Parse raw DNP3 control code bytes.
        </summary>
        public bool TryParse(byte[] buffer, out int bytesRead)
        {
            bytesRead = 0;
            
            // Control codes are typically 1-2 bytes followed by data block
            while (bytesRead + 4 <= buffer.Length)
            {
                var cc = buffer[bytesRead];
                
                // Check for valid control code range
                if (cc >= 0x80 && cc < 0xFF)
                {
                    _pendingControlCode = cc;
                    bytesRead++;

                    // Read sequence number (4 bytes, big-endian)
                    if (bytesRead + 4 <= buffer.Length)
                    {
                        var seqBytes = new byte[4];
                        for (int i = 0; i < 4; i++)
                            seqBytes[i] = buffer[bytesRead + i];

                        _sequenceNumber = BitConverter.ToUInt32(seqBytes, 0);
                        bytesRead += 4;

                        // Read data block length (1 byte)
                        if (bytesRead > buffer.Length) break;
                        
                        var dataLen = buffer[bytesRead];
                        bytesRead++;

                        // Read data block
                        if (bytesRead + dataLen <= buffer.Length)
                        {
                            var dataBlock = new List<byte>();
                            for (int i = 0; i < dataLen; i++)
                                dataBlock.Add(buffer[bytesRead + i]);
                            
                            bytesRead += dataLen;

                            _transactions.Add(new Dnp3Transaction(
                                (byte)_pendingControlCode!, 
                                _sequenceNumber,
                                dataBlock.Count > 0 ? dataBlock : null));

                            // Reset for next transaction
                            _pendingControlCode = null;
                        }
                    }
                }
                else
                {
                    _pendingControlCode = null;
                    bytesRead++;
                }
            }

            return _transactions.Count > 0 || (_pendingControlCode != null && 
                _sequenceNumber != null);
        }

        public IReadOnlyList<Dnp3Transaction> Transactions => _transactions.AsReadOnly();
    }

    /// <summary>
    /// Unified parser that handles both Modbus and DNP3.
    </summary>
    public class IcsHoneypotParser
    {
        private readonly ModbusFrameParser _modbus = new();
        private readonly Dnp3FrameParser _dnp3 = new();

        public IReadOnlyList<ModbusTransaction> ModbusTransactions => 
            _modbus.Transactions;

        public IReadOnlyList<Dnp3Transaction> Dnp3Transactions => 
            _dnp3.Transactions;

        /// <summary>
        /// Parse mixed ICS traffic (attempts both protocols).
        </summary>
        public bool TryParse(byte[] buffer, out int bytesConsumed)
        {
            // First try Modbus RTU (most common for SCADA)
            if (_modbus.TryParse(buffer, out var mbBytes))
            {
                bytesConsumed = mbBytes;
                return true;
            }

            // Then try DNP3
            if (_dnp3.TryParse(buffer, out var dnp3Bytes))
            {
                bytesConsumed = dnp3Bytes;
                return true;
            }

            bytesConsumed = 0;
            return false;
        }

        /// <summary>
        /// Get all parsed transactions.
        </summary>
        public IReadOnlyList<object> GetAllTransactions()
        {
            var result = new List<object>();
            
            foreach (var txn in _modbus.Transactions)
                result.Add(txn);
            
            foreach (var txn in _dnp3.Transactions)
                result.Add(txn);

            return result.AsReadOnly();
        }

        /// <summary>
        /// Get summary statistics.
        </summary>
        public IcsSummary GetSummary()
        {
            var modbusCount = _modbus.Transactions.Count;
            var dnp3Count = _dnp3.Transactions.Count;
            
            return new IcsSummary(modbusCount, dnp3Count);
        }

        /// <summary>
        /// Clear parsed state.
        </summary>
        public void Reset()
        {
            _modbus = new ModbusFrameParser();
            _dnp3 = new Dnp3FrameParser();
        }
    }

    /// <summary>
    /// Summary statistics for parsed traffic.
    */
    public class IcsSummary
    {
        public int ModbusTransactions { get; }
        public int Dnp3Transactions { get; }
        public DateTime? LastModbusTime { get; }
        public DateTime? LastDnp3Time { get; }

        public IcsSummary(int modbusCount, int dnp3Count)
        {
            ModbusTransactions = modbusCount;
            Dnp3Transactions = dnp3Count;
        }

        public override string ToString() => 
            $"ICS Summary: Modbus={ModbusTransactions}, DNP3={Dnp3Transactions}";
    }

    /// <summary>
    /// JSON logger for honeypot events.
    */
    public class HoneypotLogger
    {
        private readonly string _logPath;
        private readonly int _maxSize = 10_000_000; // 10MB

        public HoneypotLogger(string logPath) => 
            _logPath = Path.Combine(logPath, "ics_honeypot.log");

        /// <summary>
        /// Log a Modbus transaction.
        */
        public void LogModbus(ModbusTransaction txn)
        {
            var json = CreateJson(txn);
            AppendLine(json);
        }

        /// <summary>
        /// Log a DNP3 transaction.
        */
        public void LogDnp3(Dnp3Transaction txn)
        {
            var json = CreateJson(txn);
            AppendLine(json);
        }

        private string CreateJson(ModbusTransaction txn)
        {
            return $"{{\"type\":\"modbus\",\"slaveId\":{txn.SlaveId}," +
                   "\"functionCode\":0x{txn.FunctionCode:X2}," +
                   "\"startAddress\":" + 
                   (txn.StartAddress.HasValue ? $"{txn.StartAddress.Value}," : "null,") +
                   "\"quantity\":" + 
                   (txn.Quantity.HasValue ? $"{txn.Quantity.Value}," : "null,") +
                   "\"isRead\":{txn.IsRead}," +
                   "\"isWrite\":{txn.IsWrite}}}" +
                   (txn.Data != null && txn.Data.Count > 0 ?
                    $"\"data\":[{string.Join(", ", txn.Data.Select(b => b.ToString()))}]" : "");
        }

        private string CreateJson(Dnp3Transaction txn)
        {
            return $"{{\"type\":\"dnp3\",\"controlCode\":0x{txn.ControlCode:X2}," +
                   "\"isCommand\":{txn.IsCommand}}}" +
                   (txn.SequenceNumber.HasValue ? 
                    $",\"sequenceNumber\":" + txn.SequenceNumber.Value : "") +
                   (txn.DataBlock != null && txn.DataBlock.Count > 0 ?
                    $"\"dataBlock\":[{string.Join(", ", txn.DataBlock.Select(b => b.ToString()))}]" : "");
        }

        private void AppendLine(string line)
        {
            var timestamp = DateTime.UtcNow.ToString("o");
            
            // Check size before writing
            if (File.Exists(_logPath))
            {
                var existingSize = new FileInfo(_logPath).Length;
                if (existingSize + line.Length > _maxSize)
                {
                    File.Delete(_logPath);
                }
            }

            using (var writer = new StreamWriter(_logPath, append: true))
            {
                writer.WriteLine($"[{timestamp}] {line}");
            }
        }

        public void Flush() => Thread.Sleep(100); // Simple flush for demo
    }

    /// <summary>
    /// Main entry point with demonstration.
    */
    public class Program
    {
        private static IcsHoneypotParser _parser = new();
        private static Honeypot