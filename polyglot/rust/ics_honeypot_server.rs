use std::collections::{HashMap, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::net::UnixListener as TokioUnixListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};

// =============================================================================
// CONFIGURATION
// =============================================================================

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: String,
    pub default_register_count: u16,
    pub log_dir: PathBuf,
    pub connection_timeout: Duration,
    pub heartbeat_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:502".to_string(),
            default_register_count: 1024,
            log_dir: PathBuf::from("./logs"),
            connection_timeout: Duration::from_secs(30),
            heartbeat_interval: Duration::from_millis(500),
        }
    }
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

#[derive(Debug, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub event_type: EventType,
    #[serde(rename = "client_id")]
    pub client_address: String,
    pub start_address: u16,
    pub quantity: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_read: Option<Vec<u16>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_written: Option<Vec<u16>>,
    pub response_code: u8,
    pub bytes_sent: usize,
    pub bytes_received: usize,
}

#[derive(Debug, Clone, Serialize)]
pub enum EventType {
    ConnectionStart(String),
    ReadCoils(u16, u16),
    ReadDiscreteInputs(u16, u16),
    ReadHoldingRegisters(u16, u16),
    ReadInputRegisters(u16, u16),
    WriteSingleCoil { address: u16, value: bool },
    WriteSingleRegister { address: u16, value: u16 },
    WriteMultipleRegisters { start: u16, quantity: u16, data: Vec<u16> },
    ReadHoldingRegistersResponse(u16, u16),
    Error(String),
    Disconnect(String),
}

#[derive(Debug)]
pub struct ConnectionState {
    pub client_id: String,
    pub start_address: u16,
    pub quantity: u16,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub last_activity: SystemTime,
    pub read_buffer: VecDeque<u8>,
}

#[derive(Debug)]
pub struct RegisterMap {
    registers: HashMap<u16, u16>,
    default_value: u16,
}

impl Default for RegisterMap {
    fn default() -> Self {
        Self::new(0x0001) // Default value of 1 (ON)
    }
}

impl RegisterMap {
    pub fn new(default_value: u16) -> Self {
        let mut registers = HashMap::new();
        
        // Initialize holding registers with default values
        for i in 0..Self::DEFAULT_REGISTER_COUNT {
            registers.insert(i, default_value);
        }
        
        // Add some interesting "factory" data at known addresses
        self.add_factory_data(&mut registers);
        
        Self { registers, default_value }
    }

    const DEFAULT_REGISTER_COUNT: u16 = 4096;

    fn add_factory_data(&self, registers: &mut HashMap<u16, u16>) {
        // Simulated sensor readings at predictable addresses
        let sensors_start = 40001;
        for i in 0..20 {
            if let Some(addr) = sensors_start.checked_add(i as u16) {
                registers.insert(
                    addr,
                    (i * 173 + 42).wrapping_mul(self.default_value),
                );
            }
        }

        // Simulated control outputs
        let controls_start = 40081;
        for i in 0..5 {
            if let Some(addr) = controls_start.checked_add(i as u16) {
                registers.insert(addr, (i + 1) * 255);
            }
        }

        // Simulated analog inputs
        let ai_start = 40101;
        for i in 0..10 {
            if let Some(addr) = ai_start.checked_add(i as u16) {
                registers.insert(
                    addr,
                    (i * 37 + 128).wrapping_mul(self.default_value),
                );
            }
        }

        // Simulated digital inputs
        let di_start = 40151;
        for i in 0..32 {
            if let Some(addr) = di_start.checked_add(i as u16) {
                registers.insert(
                    addr,
                    (i % 8).wrapping_mul(self.default_value),
                );
            }
        }

        // Simulated analog outputs
        let ao_start = 40251;
        for i in 0..8 {
            if let Some(addr) = ao_start.checked_add(i as u16) {
                registers.insert(
                    addr,
                    (i * 43 + 64).wrapping_mul(self.default_value),
                );
            }
        }

        // Simulated control outputs
        let co_start = 40281;
        for i in 0..16 {
            if let Some(addr) = co_start.checked_add(i as u16) {
                registers.insert(
                    addr,
                    (i % 2).wrapping_mul(self.default_value),
                );
            }
        }

        // Simulated status/flags
        let flags_start = 40351;
        for i in 0..8 {
            if let Some(addr) = flags_start.checked_add(i as u16) {
                registers.insert(
                    addr,
                    (i % 2).wrapping_mul(self.default_value),
                );
            }
        }

        // Simulated PID controller parameters
        let pid_start = 40381;
        for i in 0..6 {
            if let Some(addr) = pid_start.checked_add(i as u16) {
                registers.insert(
                    addr,
                    (i * 79 + 256).wrapping_mul(self.default_value),
                );
            }
        }

        // Simulated setpoint values
        let sp_start = 40421;
        for i in 0..4 {
            if let Some(addr) = sp_start.checked_add(i as u16) {
                registers.insert(
                    addr,
                    (i * 197 + 512).wrapping_mul(self.default_value),
                );
            }
        }

        // Simulated alarm thresholds
        let al_start = 40451;
        for i in 0..8 {
            if let Some(addr) = al_start.checked_add(i as u16) {
                registers.insert(
                    addr,
                    (i * 239 + 768).wrapping_mul(self.default_value),
                );
            }
        }

        // Simulated timestamp (epoch seconds)
        let ts_start = 40501;
        if let Some(addr) = ts_start.checked_add(0) {
            registers.insert(
                addr,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs(),
            );
        }

        // Simulated system uptime (epoch seconds)
        let up_start = 40511;
        if let Some(addr) = up_start.checked_add(0) {
            registers.insert(
                addr,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs(),
            );
        }

        // Simulated memory usage (KB)
        let mem_start = 40521;
        if let Some(addr) = mem_start.checked_add(0) {
            registers.insert(addr, 512);
        }

        // Simulated CPU load (percentage * 256)
        let cpu_start = 40531;
        if let Some(addr) = cpu_start.checked_add(0) {
            registers.insert(addr, 75);
        }

        // Simulated I/O status
        let io_start = 40541;
        for i in 0..2 {
            if let Some(addr) = io_start.checked_add(i as u16) {
                registers.insert(
                    addr,
                    (i % 3).wrapping_mul(self.default_value),
                );
            }
        }

        // Simulated network status
        let net_start = 40551;
        for i in 0..2 {
            if let Some(addr) = net_start.checked_add(i as u16) {
                registers.insert(
                    addr,
                    (i % 3).wrapping_mul(self.default_value),
                );
            }
        }

        // Simulated batch counter
        let bc_start = 40571;
        if let Some(addr) = bc_start.checked_add(0) {
            registers.insert(addr, 1234);
        }

        // Simulated sequence number
        let sn_start = 40581;
        if let Some(addr) = sn_start.checked_add(0) {
            registers.insert(addr, 6789);
        }

        // Simulated checksum (simple sum of all register values mod 2^16)
        let cs_start = 40591;
        if let Some(addr) = cs_start.checked_add(0) {
            let total: u32 = self.registers.values().map(|v| *v as u32).sum();
            registers.insert(addr, (total % 65536) as u16);
        }

        // Simulated CRC-16 (polynomial 0x8005, init 0xFFFF)
        let crc_start = 40601;
        if let Some(addr) = crc_start.checked_add(0) {
            let mut crc: u16 = 0xFFFF;
            for &val in self.registers.values() {
                crc ^= (val as u32);
                for _ in 0..8 {
                    if crc & 0x8000 != 0 {
                        crc = (crc << 1) ^ 0x1021;
                    } else {
                        crc <<= 1;
                    }
                }
            }
            registers.insert(addr, crc);
        }

        // Simulated event log count
        let el_start = 40611;
        if let Some(addr) = el_start.checked_add(0) {
            registers.insert(addr, 98765);
        }

        // Simulated error code (0 = no errors)
        let ec_start = 40621;
        if let Some(addr) = ec_start.checked_add(0) {
            registers.insert(addr, 0);
        }

        // Simulated configuration revision
        let cr_start = 40631;
        if let Some(addr) = cr_start.checked_add(0) {
            registers.insert(addr, 256);
        }

        // Simulated firmware version (major * 256 + minor)
        let fv_start = 40641;
        if let Some(addr) = fv_start.checked_add(0) {
            registers.insert(addr, 3 << 8 | 7); // v3.7
        }

        // Simulated hardware revision
        let hr_start = 40651;
        if let Some(addr) = hr_start.checked_add(0) {
            registers.insert(addr, 128);
        }

        // Simulated serial number (lower 16 bits)
        let sn_reg_start = 40661;
        if let Some(addr) = sn_reg_start.checked_add(0) {
            registers.insert(addr, 0x12345678);
        }

        // Simulated MAC address (lower 16 bits of first octet pair)
        let mac_start = 40671;
        if let Some(addr) = mac_start.checked_add(0) {
            registers.insert(addr, 0xABCD);
        }

        // Simulated IP configuration
        let ip_start = 40681;
        for i in 0..4 {
            if let Some(addr) = ip_start.checked_add(i as u16) {
                registers.insert(
                    addr,
                    (i * 255 + 192).wrapping_mul(self.default_value),
                );
            }
        }

        // Simulated subnet mask
        let sm_start = 40701;
        if let Some(addr) = sm_start.checked_add(0) {
            registers.insert(addr, 0xFFFF);
        }

        // Simulated gateway IP
        let gw_start = 40711;
        if let Some(addr) = gw_start.checked_add(0) {
            registers.insert(addr, 0x0A01);
        }

        // Simulated DNS servers (2 entries)
        let dns_start = 40721;
        for i in 0..2 {
            if let Some(addr) = dns_start.checked_add(i as u16) {
                registers.insert(
                    addr,
                    (i * 8 + 9).wrapping_mul(self.default_value),
                );
            }
        }

        // Simulated NTP server
        let ntp_start = 40751;
        if let Some(addr) = ntp_start.checked_add(0) {
            registers.insert(addr, 0x0C32); // 192.32.0.0
        }

        // Simulated boot time (epoch seconds)
        let bt_start = 40761;
        if let Some(addr) = bt_start.checked_add(0) {
            registers.insert(
                addr,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs(),
            );
        }

        // Simulated last restart (epoch seconds)
        let lr_start = 40771;
        if let Some(addr) = lr_start.checked_add(0) {
            registers.insert(
                addr,