//! Driver library for the NSCCN wCopy Smart Reader (PN532-based USB-HID).
//!
//! Protocol reverse-engineered from `nfcPro_x64.exe` and validated on hardware
//! (see `../RE_NOTES.md`). This crate is designed to be embedded (e.g. in a GUI): the core
//! never prints — every operation returns `Result<_, Error>`.
//!
//! # Two-layer wire format
//! Inner (vendor PN532): `FF 00 00 00 | len(cmd)+1 | D4 | cmd...`   (`D4` = TFI host->PN532)
//! Outer HID report (64 B): `01 | len(inner)+6 | seqLo seqHi | inner... | cksum | FE`, where
//! `cksum = ~sum(bytes[0..cksum_pos])` — the sum includes the leading `0x01`/`0x02` marker.
//! The report is unnumbered; hidapi prepends/strips a leading `0x00` report-id, so we send
//! `00` + the 64-byte content (which starts at the `0x01` marker).
//! Reply: `02 | LEN | seq(2) | D5 | cmd+1 | data... | cksum | FD`; the MCU appends a
//! `90 00` status suffix to every reply's PN532 data.
//!
//! The `hidapi` crate statically links the C hidapi from source (macOS: IOKit/CoreFoundation
//! frameworks), so binaries are self-contained — no `DYLD_LIBRARY_PATH`.

use hidapi::HidDevice;
use std::fmt;

pub use hidapi::HidApi;

/// Create a long-lived [`HidApi`]. Keep exactly one alive per process (hidapi requirement)
/// — e.g. for the lifetime of a GUI's device worker — and pass `&api` to [`find_readers`]
/// and [`WCopy::open_with`].
pub fn new_hidapi() -> Result<HidApi> {
    Ok(HidApi::new()?)
}

// --------------------------------------------------------------------------- //
// Constants
// --------------------------------------------------------------------------- //
/// VID:PID pairs seen for this reader; `0x2518:0x6018` is the one that responds.
pub const CANDIDATES: &[(u16, u16)] = &[
    (0x2518, 0x6018),
    (0x2518, 0x6022),
    (0x0416, 0x8020),
    (0x0416, 0x8120),
    (0x0416, 0xB030),
    (0x0416, 0xB031),
];

const REPORT_LEN: usize = 0x40; // 64
const MAX_INNER: usize = 0x30; // transport caps the inner frame at 48 bytes

// PN532 opcodes
const CMD_GET_FIRMWARE_VERSION: u8 = 0x02;
const CMD_READ_REGISTER: u8 = 0x06;
const CMD_WRITE_REGISTER: u8 = 0x08;
const CMD_SET_PARAMETERS: u8 = 0x12;
const CMD_RF_CONFIGURATION: u8 = 0x32;
const CMD_IN_LIST_PASSIVE: u8 = 0x4A;
const CMD_IN_COMMUNICATE_THRU: u8 = 0x42;

// PN532 CIU registers
const REG_TX_MODE: u16 = 0x6302; // bit7 = TxCRCEn
const REG_RX_MODE: u16 = 0x6303; // bit7 = RxCRCEn
const REG_BIT_FRAMING: u16 = 0x633D; // bits[2:0] = TxLastBits

// Gen1a "magic" card
const GEN1A_UNLOCK_1: u8 = 0x40; // 7-bit frame
const GEN1A_UNLOCK_2: u8 = 0x43;
const MF_WRITE: u8 = 0xA0;
const MF_HALT: [u8; 2] = [0x50, 0x00];

// MIFARE Classic (via InDataExchange 0x40)
const CMD_IN_DATA_EXCHANGE: u8 = 0x40;
const MFC_READ: u8 = 0x30;
const MFC_WRITE_BLOCK: u8 = 0xA0;

/// A 6-byte MIFARE Classic sector key.
pub type MifareKey = [u8; 6];

/// Well-known default MIFARE Classic keys, tried by the dictionary attack.
pub const DEFAULT_KEYS: &[MifareKey] = &[
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5],
    [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7],
    [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
    [0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD],
    [0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A],
    [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    [0x71, 0x4C, 0x5C, 0x88, 0x6E, 0x97],
    [0x58, 0x7E, 0xE5, 0xF9, 0x35, 0x0F],
    [0xA0, 0x47, 0x8C, 0xC3, 0x90, 0x91],
    [0x53, 0x3C, 0xB6, 0xC7, 0x23, 0xF6],
    [0x8F, 0xD0, 0xA4, 0xF2, 0x56, 0xE9],
];

/// MIFARE Classic authentication key slot.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum KeyType {
    A,
    B,
}

impl KeyType {
    fn cmd(self) -> u8 {
        match self {
            KeyType::A => 0x60,
            KeyType::B => 0x61,
        }
    }
    pub fn label(self) -> char {
        match self {
            KeyType::A => 'A',
            KeyType::B => 'B',
        }
    }
}

// --------------------------------------------------------------------------- //
// Errors
// --------------------------------------------------------------------------- //
#[derive(Debug)]
pub enum Error {
    NoDevice(String),
    Hid(hidapi::HidError),
    Reply(String),
    BadArg(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoDevice(m) => write!(f, "no device: {m}"),
            Error::Hid(e) => write!(f, "hid error: {e}"),
            Error::Reply(m) => write!(f, "bad reply: {m}"),
            Error::BadArg(m) => write!(f, "bad argument: {m}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<hidapi::HidError> for Error {
    fn from(e: hidapi::HidError) -> Self {
        Error::Hid(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// --------------------------------------------------------------------------- //
// Value objects
// --------------------------------------------------------------------------- //
#[derive(Debug, Clone, Copy)]
pub struct FirmwareInfo {
    pub ic: u8,
    pub ver: u8,
    pub rev: u8,
    pub support: u8,
}

impl FirmwareInfo {
    pub fn ic_name(&self) -> String {
        if self.ic == 0x32 {
            "NXP PN532".into()
        } else {
            format!("IC 0x{:02X}", self.ic)
        }
    }
}
impl fmt::Display for FirmwareInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} v{}.{} (support 0x{:02X})",
            self.ic_name(),
            self.ver,
            self.rev,
            self.support
        )
    }
}

#[derive(Debug, Clone)]
pub struct Tag {
    pub atqa: [u8; 2],
    pub sak: u8,
    pub uid: Vec<u8>,
}

impl Tag {
    pub fn uid_hex(&self) -> String {
        self.uid.iter().map(|b| format!("{b:02X}")).collect()
    }
    pub fn type_name(&self) -> &'static str {
        match self.sak {
            0x08 => "Mifare Classic 1K",
            0x09 => "Mifare Mini",
            0x18 => "Mifare Classic 4K",
            0x10 => "Mifare Plus 2K",
            0x11 => "Mifare Plus 4K",
            0x00 => "Mifare Ultralight / NTAG",
            0x20 => "ISO14443-4 (DESFire/JCOP)",
            0x28 => "SmartMX/JCOP (ISO14443-4)",
            _ => "Unknown SAK",
        }
    }
}
impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uid: Vec<String> = self.uid.iter().map(|b| format!("{b:02X}")).collect();
        write!(
            f,
            "{}  UID={}  ATQA={:02X}{:02X}  SAK=0x{:02X}",
            self.type_name(),
            uid.join(":"),
            self.atqa[0],
            self.atqa[1],
            self.sak
        )
    }
}

/// The keys recovered for one MIFARE Classic sector.
#[derive(Debug, Clone, Copy, Default)]
pub struct SectorKeys {
    pub key_a: Option<MifareKey>,
    pub key_b: Option<MifareKey>,
}

/// Result of dumping a MIFARE Classic 1K (16 sectors, 64 blocks).
#[derive(Debug, Clone)]
pub struct MifareDump {
    pub uid: Vec<u8>,
    pub sak: u8,
    pub keys: Vec<SectorKeys>,      // one per sector
    pub blocks: Vec<Option<[u8; 16]>>, // one per block (None = unreadable)
}

impl MifareDump {
    /// Render as an mfd-style hex dump (16 bytes/line, block index prefixed).
    pub fn to_text(&self) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        let _ = writeln!(
            s,
            "UID {}  SAK 0x{:02X}",
            self.uid.iter().map(|b| format!("{b:02X}")).collect::<String>(),
            self.sak
        );
        for (i, blk) in self.blocks.iter().enumerate() {
            let sector = i / 4;
            let trailer = i % 4 == 3;
            let body = match blk {
                Some(b) => b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" "),
                None => "-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --".into(),
            };
            let tag = if trailer { " (trailer)" } else { "" };
            let _ = writeln!(s, "blk {i:2} [S{sector:2}]{tag}: {body}");
        }
        s
    }
}

// --------------------------------------------------------------------------- //
// Pure framing helpers (no I/O -> unit-testable)
// --------------------------------------------------------------------------- //
/// Vendor-PN532 inner frame: `FF 00 00 00 (len+1) D4 <cmd>`.
pub fn build_inner(cmd: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF, 0x00, 0x00, 0x00, (cmd.len() as u8).wrapping_add(1), 0xD4];
    v.extend_from_slice(cmd);
    v
}

/// Wrap a raw transport payload into the 65-byte HID write buffer
/// (`00 | 01 LEN seq <payload> ~cksum FE`, zero-padded). No PN532 `D4` wrapper — this is the
/// vendor MCU command scheme (payload like `FF 00 <op> ...`). Most code wants [`build_report`].
pub fn build_report_raw(payload: &[u8], seq: u16) -> Result<[u8; REPORT_LEN + 1]> {
    if payload.len() > MAX_INNER {
        return Err(Error::BadArg(format!(
            "payload too large: {} > {}",
            payload.len(),
            MAX_INNER
        )));
    }
    let mut content: Vec<u8> = Vec::with_capacity(REPORT_LEN);
    content.push(0x01);
    content.push((payload.len() as u8).wrapping_add(6));
    content.push((seq & 0xFF) as u8);
    content.push((seq >> 8) as u8);
    content.extend_from_slice(payload);
    let sum: u32 = content.iter().map(|&b| b as u32).sum();
    content.push((!(sum as u8)) & 0xFF);
    content.push(0xFE);
    content.resize(REPORT_LEN, 0);
    let mut buf = [0u8; REPORT_LEN + 1];
    buf[0] = 0x00;
    buf[1..].copy_from_slice(&content);
    Ok(buf)
}

/// Full 65-byte HID write buffer: `0x00` report-id + 64-byte report content.
pub fn build_report(cmd: &[u8], seq: u16) -> Result<[u8; REPORT_LEN + 1]> {
    let inner = build_inner(cmd);
    if inner.len() > MAX_INNER {
        return Err(Error::BadArg(format!(
            "command too large: inner {} > {}",
            inner.len(),
            MAX_INNER
        )));
    }
    let mut content: Vec<u8> = Vec::with_capacity(REPORT_LEN);
    content.push(0x01);
    content.push((inner.len() as u8).wrapping_add(6));
    content.push((seq & 0xFF) as u8);
    content.push((seq >> 8) as u8);
    content.extend_from_slice(&inner);
    let sum: u32 = content.iter().map(|&b| b as u32).sum();
    content.push((!(sum as u8)) & 0xFF);
    content.push(0xFE);
    content.resize(REPORT_LEN, 0);

    let mut buf = [0u8; REPORT_LEN + 1];
    buf[0] = 0x00; // report-id (hidapi strips it on macOS)
    buf[1..].copy_from_slice(&content);
    Ok(buf)
}

/// Validate an IN report and return the PN532 response data (trailing `90 00` stripped).
pub fn parse_reply(raw: &[u8], req_cmd: u8) -> Result<Vec<u8>> {
    if raw.is_empty() {
        return Err(Error::Reply("no reply (timeout)".into()));
    }
    if raw[0] != 0x02 {
        return Err(Error::Reply(format!("bad start 0x{:02X}", raw[0])));
    }
    let length = raw[1] as usize;
    if length < 8 || raw.len() < 6 + (length - 8) {
        return Err(Error::Reply(format!("bad LEN {length}")));
    }
    if raw[4] != 0xD5 {
        return Err(Error::Reply(format!("bad TFI 0x{:02X}", raw[4])));
    }
    if raw[5] != req_cmd.wrapping_add(1) {
        return Err(Error::Reply(format!(
            "resp code 0x{:02X} != 0x{:02X}",
            raw[5],
            req_cmd.wrapping_add(1)
        )));
    }
    let mut data = raw[6..6 + (length - 8)].to_vec();
    if data.len() >= 2 && data[data.len() - 2..] == [0x90, 0x00] {
        data.truncate(data.len() - 2);
    }
    Ok(data)
}

/// Validate a vendor-MCU IN report (`02 LEN seqLo seqHi <data...> cksum FD`, no PN532 `D5`
/// TFI layer) and return its data bytes. Checksum is `(!sum(bytes[0..cksum_pos])) & 0xFF` —
/// the sum includes the leading `0x02` marker byte — the same running-checksum scheme
/// [`build_report_raw`] uses when writing, confirmed
/// against real captures of both a short "no tag" reply (`02 07 .. 00 .. FD`, 1 data byte)
/// and a 6-byte EM4100 ID reply.
pub fn parse_vendor_reply(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.is_empty() {
        return Err(Error::Reply("no reply (timeout)".into()));
    }
    if raw[0] != 0x02 {
        return Err(Error::Reply(format!("bad start 0x{:02X}", raw[0])));
    }
    let len = raw[1] as usize;
    if len < 7 || raw.len() < len {
        return Err(Error::Reply(format!("bad LEN {len}")));
    }
    if raw[len - 1] != 0xFD {
        return Err(Error::Reply(format!("bad terminator 0x{:02X}", raw[len - 1])));
    }
    let sum: u32 = raw[0..len - 2].iter().map(|&b| b as u32).sum();
    let expect = !(sum as u8);
    if raw[len - 2] != expect {
        return Err(Error::Reply(format!(
            "bad checksum 0x{:02X} != 0x{expect:02X}",
            raw[len - 2]
        )));
    }
    Ok(raw[4..len - 2].to_vec())
}

/// Assemble a 4-byte-UID block 0: `UID | BCC | SAK | ATQA(2) | 8 manufacturer bytes`.
pub fn build_block0(uid: &[u8], sak: u8, atqa: [u8; 2], manufacturer: [u8; 8]) -> Result<[u8; 16]> {
    if uid.len() != 4 {
        return Err(Error::BadArg("only 4-byte UIDs supported".into()));
    }
    let bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3];
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(uid);
    b[4] = bcc;
    b[5] = sak;
    b[6] = atqa[0];
    b[7] = atqa[1];
    b[8..16].copy_from_slice(&manufacturer);
    Ok(b)
}

/// Default manufacturer/filler bytes for `build_block0`.
pub const DEFAULT_MANUFACTURER: [u8; 8] = [0xC0, 0xDE, 0xCA, 0xFE, 0x11, 0x22, 0x33, 0x44];

// --------------------------------------------------------------------------- //
// Enumeration
// --------------------------------------------------------------------------- //
#[derive(Debug, Clone)]
pub struct ReaderInfo {
    pub vid: u16,
    pub pid: u16,
    pub product: String,
    pub path: std::ffi::CString,
}

/// Filter an existing [`HidApi`]'s device list for candidate readers.
///
/// Use this (with a long-lived `HidApi`) from an application such as a GUI, where a fresh
/// `HidApi` per call is undesirable. Call [`HidApi::refresh_devices`] first to pick up
/// hot-plugged readers.
pub fn find_readers(api: &HidApi) -> Vec<ReaderInfo> {
    api.device_list()
        .filter(|d| CANDIDATES.contains(&(d.vendor_id(), d.product_id())))
        .map(|d| ReaderInfo {
            vid: d.vendor_id(),
            pid: d.product_id(),
            product: d.product_string().unwrap_or("").to_string(),
            path: d.path().to_owned(),
        })
        .collect()
}

/// List connected candidate readers (creates a one-shot [`HidApi`]).
pub fn list_readers() -> Result<Vec<ReaderInfo>> {
    Ok(find_readers(&HidApi::new()?))
}

// --------------------------------------------------------------------------- //
// The driver
// --------------------------------------------------------------------------- //
/// A session with one wCopy reader.
///
/// ```no_run
/// let mut dev = wcopy::WCopy::open_first()?;
/// println!("{}", dev.get_firmware()?);
/// if let Some(tag) = dev.read_tag(true)? { println!("{tag}"); }
/// # Ok::<(), wcopy::Error>(())
/// ```
pub struct WCopy {
    dev: HidDevice,
    seq: u16,
    /// Read timeout in milliseconds for command replies.
    pub timeout_ms: i32,
    on_log: Option<Box<dyn Fn(&str) + Send>>,
}

impl WCopy {
    /// Open the first connected candidate reader.
    pub fn open_first() -> Result<Self> {
        let readers = list_readers()?;
        let first = readers
            .into_iter()
            .next()
            .ok_or_else(|| Error::NoDevice("no wCopy reader found".into()))?;
        Self::open(&first)
    }

    /// Open a specific reader (from [`list_readers`]) with a one-shot [`HidApi`].
    pub fn open(info: &ReaderInfo) -> Result<Self> {
        let api = HidApi::new()?;
        Self::open_with(&api, info)
    }

    /// Open a specific reader using a caller-owned [`HidApi`] (keep it alive for the
    /// session). Preferred for long-running apps such as a GUI.
    pub fn open_with(api: &HidApi, info: &ReaderInfo) -> Result<Self> {
        let dev = api.open_path(&info.path)?;
        Ok(WCopy {
            dev,
            seq: 0,
            timeout_ms: 1500,
            on_log: None,
        })
    }

    /// Install a progress-log callback (e.g. a GUI status sink). Optional.
    pub fn set_logger(&mut self, f: impl Fn(&str) + Send + 'static) {
        self.on_log = Some(Box::new(f));
    }

    // -- low-level transport --------------------------------------------- //
    fn flush(&self) {
        let mut buf = [0u8; REPORT_LEN];
        for _ in 0..8 {
            match self.dev.read_timeout(&mut buf, 1) {
                Ok(n) if n > 0 => {}
                _ => break,
            }
        }
    }

    /// Send one PN532 command and return its validated response data.
    pub fn transceive(&mut self, cmd: &[u8]) -> Result<Vec<u8>> {
        self.transceive_timeout(cmd, self.timeout_ms)
    }

    pub fn transceive_timeout(&mut self, cmd: &[u8], timeout_ms: i32) -> Result<Vec<u8>> {
        self.flush();
        let report = build_report(cmd, self.seq)?;
        self.dev.write(&report)?;
        self.seq = self.seq.wrapping_add(2);
        let mut buf = [0u8; REPORT_LEN];
        let n = self.dev.read_timeout(&mut buf, timeout_ms)?;
        parse_reply(&buf[..n], cmd[0])
    }

    /// Send a RAW transport payload (no PN532 `D4` wrapper) and return the raw 64-byte reply
    /// (unparsed). For experimenting with the vendor MCU command family (`FF 00 <op> ...`),
    /// e.g. hunting for a buzzer command. Returns fewer than 64 bytes only on timeout.
    pub fn transceive_raw(&mut self, payload: &[u8], timeout_ms: i32) -> Result<Vec<u8>> {
        self.flush();
        let report = build_report_raw(payload, self.seq)?;
        self.dev.write(&report)?;
        self.seq = self.seq.wrapping_add(2);
        let mut buf = [0u8; REPORT_LEN];
        let n = self.dev.read_timeout(&mut buf, timeout_ms)?;
        Ok(buf[..n].to_vec())
    }

    // -- verified PN532 primitives --------------------------------------- //
    pub fn get_firmware(&mut self) -> Result<FirmwareInfo> {
        let d = self.transceive(&[CMD_GET_FIRMWARE_VERSION])?;
        if d.len() < 4 {
            return Err(Error::Reply("short firmware reply".into()));
        }
        Ok(FirmwareInfo {
            ic: d[0],
            ver: d[1],
            rev: d[2],
            support: d[3],
        })
    }

    pub fn read_register(&mut self, addr: u16) -> Result<u8> {
        let d = self.transceive(&[CMD_READ_REGISTER, (addr >> 8) as u8, addr as u8])?;
        d.first()
            .copied()
            .ok_or_else(|| Error::Reply("empty ReadRegister".into()))
    }

    pub fn write_register(&mut self, addr: u16, value: u8) -> Result<()> {
        self.transceive(&[CMD_WRITE_REGISTER, (addr >> 8) as u8, addr as u8, value])?;
        Ok(())
    }

    pub fn update_register(&mut self, addr: u16, mask: u8, value: u8) -> Result<u8> {
        let old = self.read_register(addr)?;
        let new = (old & !mask) | (value & mask);
        if new != old {
            self.write_register(addr, new)?;
        }
        Ok(new)
    }

    pub fn set_parameters(&mut self, value: u8) -> Result<()> {
        self.transceive(&[CMD_SET_PARAMETERS, value])?;
        Ok(())
    }

    pub fn rf_field(&mut self, on: bool) -> Result<()> {
        self.transceive(&[CMD_RF_CONFIGURATION, 0x01, if on { 0x01 } else { 0x00 }])?;
        Ok(())
    }

    pub fn rf_max_retries(&mut self, atr: u8, psl: u8, passive: u8) -> Result<()> {
        self.transceive(&[CMD_RF_CONFIGURATION, 0x05, atr, psl, passive])?;
        Ok(())
    }

    /// InCommunicateThru (0x42). Returns `(status, card_bytes)`; status 0 == OK.
    pub fn communicate_thru(&mut self, payload: &[u8]) -> Result<(u8, Vec<u8>)> {
        let mut cmd = vec![CMD_IN_COMMUNICATE_THRU];
        cmd.extend_from_slice(payload);
        let d = self.transceive(&cmd)?;
        if d.is_empty() {
            return Err(Error::Reply("empty InCommunicateThru".into()));
        }
        Ok((d[0], d[1..].to_vec()))
    }

    // -- card discovery -------------------------------------------------- //
    /// InListPassiveTarget (0x4A) for one 106 kbps ISO14443A tag. `None` if no tag.
    pub fn read_tag(&mut self, power_cycle: bool) -> Result<Option<Tag>> {
        if power_cycle {
            self.rf_field(false)?;
            self.rf_field(true)?;
        }
        let d = self.transceive_timeout(&[CMD_IN_LIST_PASSIVE, 0x01, 0x00], 3000)?;
        if d.len() < 6 || d[0] < 1 {
            return Ok(None);
        }
        let sak = d[4];
        let nfclen = d[5] as usize;
        if d.len() < 6 + nfclen {
            return Err(Error::Reply("truncated UID".into()));
        }
        Ok(Some(Tag {
            atqa: [d[2], d[3]],
            sak,
            uid: d[6..6 + nfclen].to_vec(),
        }))
    }

    // -- Gen1a "UID" magic write ----------------------------------------- //
    fn set_crc(&mut self, tx: bool, rx: bool) -> Result<()> {
        self.write_register(REG_TX_MODE, if tx { 0x80 } else { 0x00 })?;
        self.write_register(REG_RX_MODE, if rx { 0x80 } else { 0x00 })
    }

    fn restore_ciu(&mut self) -> Result<()> {
        self.set_crc(true, true)?;
        self.write_register(REG_BIT_FRAMING, 0x00)
    }

    /// Non-destructive probe: does the tag answer the Gen1a backdoor? Restores registers.
    pub fn probe_gen1a(&mut self) -> Result<bool> {
        let ok = self.gen1a_unlock().is_ok();
        let _ = self.restore_ciu();
        Ok(ok)
    }

    /// HALT + Gen1a magic backdoor (7-bit `0x40`, then `0x43`). Errs if not unlocked.
    pub fn gen1a_unlock(&mut self) -> Result<()> {
        let _ = self.communicate_thru(&MF_HALT); // card does not ACK HALT; ignore
        self.set_crc(false, false)?;
        self.write_register(REG_BIT_FRAMING, 0x07)?; // 7 TX bits
        let (st1, r1) = self.communicate_thru(&[GEN1A_UNLOCK_1])?;
        self.write_register(REG_BIT_FRAMING, 0x00)?; // back to 8 bits
        if st1 != 0 || r1.first() != Some(&0x0A) {
            return Err(Error::Reply(format!("gen1a unlock1 failed (st={st1})")));
        }
        let (st2, r2) = self.communicate_thru(&[GEN1A_UNLOCK_2])?;
        if st2 != 0 || r2.first() != Some(&0x0A) {
            return Err(Error::Reply(format!("gen1a unlock2 failed (st={st2})")));
        }
        Ok(())
    }

    /// Write a 16-byte block on an already-unlocked Gen1a card (CRC on TX, off RX).
    pub fn write_block(&mut self, block: u8, data: &[u8]) -> Result<()> {
        if data.len() != 16 {
            return Err(Error::BadArg("block data must be 16 bytes".into()));
        }
        self.set_crc(true, false)?;
        let (st, ack) = self.communicate_thru(&[MF_WRITE, block])?;
        if st != 0 || ack.first() != Some(&0x0A) {
            return Err(Error::Reply(format!("write cmd not ACKed (st={st})")));
        }
        let (st, ack) = self.communicate_thru(data)?;
        if st != 0 || ack.first() != Some(&0x0A) {
            return Err(Error::Reply(format!("write data not ACKed (st={st})")));
        }
        Ok(())
    }

    /// Write a 4-byte UID to a Gen1a card and verify by re-reading. Restores registers.
    pub fn write_uid(&mut self, uid: &[u8]) -> Result<Tag> {
        self.write_uid_full(uid, 0x08, [0x04, 0x00], DEFAULT_MANUFACTURER)
    }

    pub fn write_uid_full(
        &mut self,
        uid: &[u8],
        sak: u8,
        atqa: [u8; 2],
        manufacturer: [u8; 8],
    ) -> Result<Tag> {
        let block0 = build_block0(uid, sak, atqa, manufacturer)?;
        let write_res = self
            .gen1a_unlock()
            .and_then(|_| self.write_block(0, &block0));
        let _ = self.restore_ciu();
        write_res?;
        match self.read_tag(true)? {
            Some(tag) if tag.uid == uid => Ok(tag),
            other => Err(Error::Reply(format!(
                "verify failed: read back {}",
                other.map(|t| t.uid_hex()).unwrap_or_else(|| "none".into())
            ))),
        }
    }

    // -- MIFARE Classic (feature 1) -------------------------------------- //
    /// InDataExchange (0x40) with target Tg=1. Returns the response data after the status
    /// byte; errors if the PN532/card status is non-zero.
    fn indata(&mut self, mifare: &[u8]) -> Result<Vec<u8>> {
        let mut cmd = vec![CMD_IN_DATA_EXCHANGE, 0x01];
        cmd.extend_from_slice(mifare);
        let d = self.transceive(&cmd)?;
        if d.is_empty() {
            return Err(Error::Reply("empty InDataExchange".into()));
        }
        if d[0] != 0 {
            return Err(Error::Reply(format!("InDataExchange status 0x{:02X}", d[0])));
        }
        Ok(d[1..].to_vec())
    }

    /// Select one ISO14443A tag (InListPassiveTarget). Errors if none is present.
    pub fn select(&mut self, power_cycle: bool) -> Result<Tag> {
        self.read_tag(power_cycle)?
            .ok_or_else(|| Error::Reply("no tag to select".into()))
    }

    /// Authenticate a block's sector with a key (requires a freshly selected tag).
    pub fn mfc_auth(&mut self, block: u8, kt: KeyType, key: &MifareKey, uid: &[u8]) -> Result<()> {
        if uid.len() < 4 {
            return Err(Error::BadArg("MIFARE auth needs a 4-byte UID".into()));
        }
        let mut m = vec![kt.cmd(), block];
        m.extend_from_slice(key);
        m.extend_from_slice(&uid[uid.len() - 4..]); // last 4 UID bytes
        self.indata(&m)?;
        Ok(())
    }

    /// Read a 16-byte block (sector must already be authenticated).
    pub fn mfc_read_block(&mut self, block: u8) -> Result<[u8; 16]> {
        let d = self.indata(&[MFC_READ, block])?;
        if d.len() < 16 {
            return Err(Error::Reply(format!("short block read ({} bytes)", d.len())));
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&d[..16]);
        Ok(out)
    }

    /// Write a 16-byte block (sector must already be authenticated).
    pub fn mfc_write_block(&mut self, block: u8, data: &[u8; 16]) -> Result<()> {
        let mut m = vec![MFC_WRITE_BLOCK, block];
        m.extend_from_slice(data);
        self.indata(&m)?;
        Ok(())
    }

    /// Dictionary attack: find a working key for a block's sector, re-selecting the tag
    /// before each attempt (a failed auth halts the card). `None` if no dict key works.
    pub fn mfc_find_key(
        &mut self,
        block: u8,
        kt: KeyType,
        dict: &[MifareKey],
    ) -> Result<Option<MifareKey>> {
        for key in dict {
            let tag = self.select(true)?;
            if self.mfc_auth(block, kt, key, &tag.uid).is_ok() {
                return Ok(Some(*key));
            }
        }
        Ok(None)
    }

    /// Dump a MIFARE Classic 1K: dictionary-crack each sector's keys, then read its blocks.
    pub fn mfc_dump(&mut self, dict: &[MifareKey]) -> Result<MifareDump> {
        let tag = self.select(true)?;
        let uid = tag.uid.clone();
        let sak = tag.sak;
        let mut keys = vec![SectorKeys::default(); 16];
        let mut blocks: Vec<Option<[u8; 16]>> = vec![None; 64];

        for sector in 0u8..16 {
            let trailer = sector * 4 + 3;
            let key_a = self.mfc_find_key(trailer, KeyType::A, dict)?;
            let key_b = self.mfc_find_key(trailer, KeyType::B, dict)?;
            keys[sector as usize] = SectorKeys { key_a, key_b };
            self.log(format!(
                "sector {sector:2}: key A {}  key B {}",
                key_a.map(hexk).unwrap_or_else(|| "----------  (not found)".into()),
                key_b.map(hexk).unwrap_or_else(|| "----------  (not found)".into()),
            ));

            // read the 4 blocks using whichever key we found
            let (kt, key) = match (key_a, key_b) {
                (Some(k), _) => (KeyType::A, k),
                (None, Some(k)) => (KeyType::B, k),
                (None, None) => continue,
            };
            let tag = self.select(true)?;
            if self.mfc_auth(trailer, kt, &key, &tag.uid).is_ok() {
                for b in (sector * 4)..(sector * 4 + 4) {
                    if let Ok(data) = self.mfc_read_block(b) {
                        blocks[b as usize] = Some(data);
                    }
                }
            }
        }
        Ok(MifareDump {
            uid,
            sak,
            keys,
            blocks,
        })
    }

    /// Find a working key for a block's sector, trying key A then key B over `dict`.
    fn mfc_find_any_key(
        &mut self,
        trailer: u8,
        dict: &[MifareKey],
    ) -> Result<Option<(KeyType, MifareKey)>> {
        if let Some(k) = self.mfc_find_key(trailer, KeyType::A, dict)? {
            return Ok(Some((KeyType::A, k)));
        }
        if let Some(k) = self.mfc_find_key(trailer, KeyType::B, dict)? {
            return Ok(Some((KeyType::B, k)));
        }
        Ok(None)
    }

    /// Dictionary-auth a block's sector, then read the block. One-call convenience.
    pub fn mfc_read_block_auto(&mut self, block: u8, dict: &[MifareKey]) -> Result<[u8; 16]> {
        let trailer = (block / 4) * 4 + 3;
        let (kt, key) = self
            .mfc_find_any_key(trailer, dict)?
            .ok_or_else(|| Error::Reply(format!("no dictionary key for sector {}", block / 4)))?;
        let tag = self.select(true)?;
        self.mfc_auth(trailer, kt, &key, &tag.uid)?;
        self.mfc_read_block(block)
    }

    /// Dictionary-auth a block's sector, write the block, and read it back to verify.
    /// Returns the read-back bytes.
    pub fn mfc_write_block_auto(
        &mut self,
        block: u8,
        data: &[u8; 16],
        dict: &[MifareKey],
    ) -> Result<[u8; 16]> {
        let trailer = (block / 4) * 4 + 3;
        let (kt, key) = self
            .mfc_find_any_key(trailer, dict)?
            .ok_or_else(|| Error::Reply(format!("no dictionary key for sector {}", block / 4)))?;
        let tag = self.select(true)?;
        self.mfc_auth(trailer, kt, &key, &tag.uid)?;
        self.mfc_write_block(block, data)?;
        self.mfc_read_block(block)
    }

    fn log(&self, msg: String) {
        if let Some(cb) = &self.on_log {
            cb(&msg);
        }
    }
}

// --------------------------------------------------------------------------- //
// 125 kHz LF side (vendor MCU command family, `FF 00 <op> ...`, no PN532 `D4`
// wrapper). Reverse-engineered from a USB capture of the vendor's Windows tool
// reading/beeping an EM4100 card; see README "125 kHz (LF) support" section.
// --------------------------------------------------------------------------- //
const LF_OP_DEVICE_INFO: u8 = 0x68;
const LF_OP_SERIAL: u8 = 0x69;
const LF_OP_INIT: u8 = 0x62;
const LF_OP_READ_EM4100: u8 = 0x65;
const LF_OP_WRITE_EM4100: u8 = 0x66;
const LF_OP_BEEP: u8 = 0x40;
/// Fixed 6-byte prefix every `0x66` (LF write) param blob starts with, before the
/// command-specific suffix. Meaning unknown; byte-identical across every real capture.
const LF_WRITE_PREFIX: [u8; 6] = [0x00, 0x1E, 0x48, 0xE8, 0x01, 0x00];

/// 5-byte EM4100/EM4102 125 kHz tag ID: 1 version/customer byte + 4 ID bytes.
pub type LfId = [u8; 5];

impl WCopy {
    /// Send a vendor-MCU payload (`FF 00 <op> <params...>`) and return the reply's data
    /// bytes (the 4-byte `02 LEN seqLo seqHi` header and trailing checksum/terminator
    /// stripped off). Unlike [`WCopy::transceive`], there is no PN532 `D4`/`D5` TFI layer
    /// here — these are talking straight to the reader's own MCU firmware.
    fn transceive_vendor(&mut self, op: u8, params: &[u8], timeout_ms: i32) -> Result<Vec<u8>> {
        let mut payload = vec![0xFF, 0x00, op];
        payload.extend_from_slice(params);
        let raw = self.transceive_raw(&payload, timeout_ms)?;
        parse_vendor_reply(&raw)
    }

    /// Vendor device/version string, e.g. `"wCopy NSR121-IDIC V705N2"`.
    pub fn lf_device_info(&mut self) -> Result<String> {
        let d = self.transceive_vendor(LF_OP_DEVICE_INFO, &[], 1500)?;
        Ok(String::from_utf8_lossy(&d).trim_end_matches('\0').to_string())
    }

    /// Vendor serial number string, e.g. `"T39190010249"`.
    pub fn lf_serial(&mut self) -> Result<String> {
        let d = self.transceive_vendor(LF_OP_SERIAL, &[], 1500)?;
        Ok(String::from_utf8_lossy(&d).trim_end_matches('\0').to_string())
    }

    /// Two-step LF init/config handshake the vendor tool always sends once at connect,
    /// before the first `lf_read_em4100`. Exact meaning of the parameter bytes is not
    /// understood; they are fixed values copied from a real capture.
    pub fn lf_init(&mut self) -> Result<()> {
        self.transceive_vendor(LF_OP_INIT, &[0x01, 0x00], 1500)?;
        self.transceive_vendor(
            LF_OP_INIT,
            &[0x01, 0x06, 0x00, 0x00, 0x1f, 0x01, 0xfa, 0x00],
            1500,
        )?;
        Ok(())
    }

    /// Read a 125 kHz EM4100/EM4102 tag's ID. Returns `None` if no tag is on the reader
    /// (the device replies with a single `0x00` byte). Call [`WCopy::lf_init`] once first.
    pub fn lf_read_em4100(&mut self) -> Result<Option<LfId>> {
        let d = self.transceive_vendor(
            LF_OP_READ_EM4100,
            &[0x05, 0x1e, 0x48, 0xe8, 0x01, 0x00, 0x81, 0x01, 0x18, 0x01],
            1500,
        )?;
        if d.len() == 6 && d[0] == 0x05 {
            let mut id = [0u8; 5];
            id.copy_from_slice(&d[1..6]);
            Ok(Some(id))
        } else if d == [0x00] {
            // The device's own "no tag present" reply.
            Ok(None)
        } else {
            Err(Error::Reply(format!("unexpected LF read reply: {d:02X?}")))
        }
    }

    /// Buzzer + LED feedback (what the vendor tool fires after a successful read).
    pub fn beep(&mut self) -> Result<()> {
        self.transceive_vendor(LF_OP_BEEP, &[0x50, 0x04, 0x05, 0x01, 0x01, 0x01], 1500)?;
        Ok(())
    }

    /// Write a 5-byte EM4100 ID to a T5577/EM4305-family 125 kHz tag (the vendor tool's
    /// "WriteT5577/5200" button). Verified against real hardware across several different
    /// target IDs on a genuine T5577 blank, each confirmed by reading it back afterwards.
    ///
    /// **Caveat, confirmed on real hardware:** an `id` whose first byte (the EM4100
    /// version/customer byte) is very high — `0x98`/`0x99` tested — reliably fails and can
    /// leave the tag temporarily unreadable (recovered by writing a working ID again; no
    /// permanent damage seen). This reproduces identically through the **vendor's own**
    /// nfcPro tool, not just this reimplementation, so it looks like a real limitation of the
    /// tag/reader rather than a bug here. `0x00`, `0x07`, `0x12` all wrote fine; the exact
    /// cutoff wasn't determined. Treat a very high first byte as unsupported for now.
    ///
    /// Two of the raw block writes below (`block1`/`block2`) carry the **standard EM4100
    /// 64-bit encoded bitstream** for `id` — header + 10×(nibble + row parity) + column
    /// parity + stop bit, see [`em4100_bitstream`] — split into two 4-byte halves. This was
    /// confirmed by capturing three real successful writes (different IDs, same physical
    /// tag) and finding the computed bitstream matches those block bytes exactly every time;
    /// an earlier version of this function replayed one capture's bytes verbatim and, as
    /// expected once this was understood, only worked for that one specific ID.
    ///
    /// The rest (the four `"Tian"`-watermarked frames, and the `0000148050` config-block
    /// write) stayed byte-identical across all three captures and are replayed verbatim; their
    /// detailed meaning (likely a vendor signature + T5577 config word) wasn't decoded further.
    /// Does **not** work on a genuine (factory read-only) EM4100 tag — the vendor tool's own
    /// type-specific write buttons don't either, confirmed on real hardware (all of them fail
    /// the same way a plain EM4100 does).
    pub fn lf_write_em4100(&mut self, id: &LfId) -> Result<()> {
        let stream = em4100_bitstream(id);
        let (block1, block2) = (&stream[0..4], &stream[4..8]);

        let mut setup: Vec<Vec<u8>> = vec![
            vec![0x1F, 0x18, 0x01, 0xEF, 0x00, 0x9B, 0x00, 0x86, 0x01],
            vec![0x13, 0x00, 0x07, 0x54, 0x69, 0x61, 0x6E, 0xC0, 0xF5, 0x00, 0x9A],
            vec![0x13, 0x00, 0x07, 0x54, 0x69, 0x61, 0x6E, 0x00, 0x00, 0x00, 0x00],
            vec![0x13, 0x00, 0x07, 0x54, 0x69, 0x61, 0x6E, 0x19, 0x92, 0x04, 0x27],
            vec![0x13, 0x00, 0x07, 0x54, 0x69, 0x61, 0x6E, 0x1C, 0x0B, 0x58, 0x48],
        ];
        let mut block1_write = vec![0x12, 0x00, 0x01];
        block1_write.extend_from_slice(block1);
        setup.push(block1_write);
        let mut block1_verify = vec![0x13, 0x00, 0x01];
        block1_verify.extend_from_slice(block1);
        block1_verify.extend_from_slice(b"Tian");
        setup.push(block1_verify);
        let mut block2_write = vec![0x12, 0x00, 0x02];
        block2_write.extend_from_slice(block2);
        setup.push(block2_write);
        let mut block2_verify = vec![0x13, 0x00, 0x02];
        block2_verify.extend_from_slice(block2);
        block2_verify.extend_from_slice(b"Tian");
        setup.push(block2_verify);
        setup.push(vec![0x12, 0x00, 0x00, 0x00, 0x14, 0x80, 0x50]);
        setup.push(vec![
            0x13, 0x00, 0x00, 0x00, 0x14, 0x80, 0x50, 0x54, 0x69, 0x61, 0x6E,
        ]);
        setup.push(vec![0x00, 0x64, 0x00, 0x00]);

        for suffix in &setup {
            let mut params = LF_WRITE_PREFIX.to_vec();
            params.extend_from_slice(suffix);
            self.transceive_vendor(LF_OP_WRITE_EM4100, &params, 1500)?;
            // Real captures show ~30-100ms between these (the tag's own EEPROM write/settle
            // time, not just HID latency); sending them back-to-back silently fails on real
            // hardware even though every reply still parses OK.
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        // The vendor tool waits noticeably longer (~200ms) right before this final frame,
        // which is the one that actually commits the new ID.
        std::thread::sleep(std::time::Duration::from_millis(100));
        let mut params = LF_WRITE_PREFIX.to_vec();
        params.push(0x01);
        params.extend_from_slice(id);
        self.transceive_vendor(LF_OP_WRITE_EM4100, &params, 1500)?;
        self.beep()?;
        Ok(())
    }
}

/// First-byte threshold above which [`lf_id_likely_unsupported`] flags an ID. Confirmed
/// failing on real hardware at `0x98`/`0x99` (both through this driver and through the
/// vendor's own nfcPro tool); the exact cutoff below that wasn't determined, so this is a
/// conservative (possibly over-wide) guess, not a proven boundary.
pub const LF_WRITE_RISKY_FIRST_BYTE: u8 = 0x98;

/// True if `id`'s first byte (the EM4100 version/customer byte) is at or above
/// [`LF_WRITE_RISKY_FIRST_BYTE`], where [`WCopy::lf_write_em4100`] is known to reliably fail
/// and can leave the tag temporarily unreadable. Callers (the CLI, the GUI) should warn
/// before, or refuse to, write such an ID — this function doesn't refuse on its own, since
/// read-only diagnostics and future chip families may want to try anyway.
pub fn lf_id_likely_unsupported(id: &LfId) -> bool {
    id[0] >= LF_WRITE_RISKY_FIRST_BYTE
}

/// Standard EM4100/EM4102 64-bit encoded bitstream for a 5-byte (40-bit) tag ID: 9 header
/// bits of `1`, then the ID's 10 nibbles each followed by an even row-parity bit, then a
/// 4-bit even column-parity nibble, then a stop bit (`0`) — packed MSB-first into 8 bytes.
/// Confirmed against three real captured T5577 writes (see [`WCopy::lf_write_em4100`]).
pub fn em4100_bitstream(id: &LfId) -> [u8; 8] {
    let mut bits = [false; 64];
    for bit in bits.iter_mut().take(9) {
        *bit = true;
    }
    let mut col_parity = [false; 4];
    let mut pos = 9;
    for &byte in id {
        for nibble in [(byte >> 4) & 0xF, byte & 0xF] {
            let b = [(nibble >> 3) & 1, (nibble >> 2) & 1, (nibble >> 1) & 1, nibble & 1];
            let mut row_parity = false;
            for (i, &bit) in b.iter().enumerate() {
                let set = bit != 0;
                bits[pos + i] = set;
                row_parity ^= set;
                col_parity[i] ^= set;
            }
            bits[pos + 4] = row_parity;
            pos += 5;
        }
    }
    for (i, &p) in col_parity.iter().enumerate() {
        bits[pos + i] = p;
    }
    // bits[63] (stop bit) stays `false` == 0.
    let mut out = [0u8; 8];
    for (i, chunk) in bits.chunks(8).enumerate() {
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | (bit as u8);
        }
        out[i] = byte;
    }
    out
}

fn hexk(k: MifareKey) -> String {
    k.iter().map(|b| format!("{b:02X}")).collect()
}

// --------------------------------------------------------------------------- //
// Tests (framing only — no hardware needed)
// --------------------------------------------------------------------------- //
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_report_bytes() {
        let r = build_report(&[0x02], 0).unwrap();
        assert_eq!(r[0], 0x00);
        assert_eq!(
            &r[1..14],
            &[0x01, 0x0D, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x02, 0xD4, 0x02, 0x1A, 0xFE]
        );
        assert_eq!(r.len(), 65);
    }

    #[test]
    fn read_register_report_bytes() {
        let r = build_report(&[0x06, 0x63, 0x03], 0).unwrap();
        assert_eq!(
            &r[1..16],
            &[0x01, 0x0F, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x06, 0x63, 0x03, 0xAC, 0xFE]
        );
    }

    #[test]
    fn parse_firmware_reply() {
        let raw = [
            0x02, 0x0E, 0x01, 0x00, 0xD5, 0x03, 0x32, 0x01, 0x06, 0x07, 0x90, 0x00, 0x46, 0xFD,
        ];
        assert_eq!(parse_reply(&raw, 0x02).unwrap(), vec![0x32, 0x01, 0x06, 0x07]);
    }

    #[test]
    fn block0_bcc() {
        let b = build_block0(&[0xF0, 0x73, 0x63, 0x2C], 0x08, [0x04, 0x00], DEFAULT_MANUFACTURER)
            .unwrap();
        assert_eq!(b[4], 0xF0 ^ 0x73 ^ 0x63 ^ 0x2C);
        assert_eq!(b[5], 0x08);
        assert_eq!(&b[6..8], &[0x04, 0x00]);
    }

    // -- 125 kHz LF (vendor MCU) framing, bytes taken from a real USB capture of the
    // vendor's Windows tool reading an EM4100 card with ID 07 00 CD 6D 41. --------------- //

    #[test]
    fn lf_device_info_report_bytes() {
        // real OUT frame: 01 09 00 00 ff 00 68 8e fe
        let r = build_report_raw(&[0xFF, 0x00, 0x68], 0).unwrap();
        assert_eq!(r[0], 0x00);
        assert_eq!(&r[1..10], &[0x01, 0x09, 0x00, 0x00, 0xFF, 0x00, 0x68, 0x8E, 0xFE]);
    }

    #[test]
    fn lf_read_report_bytes() {
        // real OUT frame (seq=0x14): 01 13 14 00 ff 00 65 05 1e 48 e8 01 00 81 01 18 01 84 fe
        let r = build_report_raw(
            &[0xFF, 0x00, 0x65, 0x05, 0x1E, 0x48, 0xE8, 0x01, 0x00, 0x81, 0x01, 0x18, 0x01],
            0x14,
        )
        .unwrap();
        assert_eq!(
            &r[1..20],
            &[
                0x01, 0x13, 0x14, 0x00, 0xFF, 0x00, 0x65, 0x05, 0x1E, 0x48, 0xE8, 0x01, 0x00,
                0x81, 0x01, 0x18, 0x01, 0x84, 0xFE
            ]
        );
    }

    #[test]
    fn parse_vendor_reply_em4100_id() {
        // real IN frame: tag ID 07 00 CD 6D 41
        let raw = [
            0x02, 0x0C, 0x15, 0x00, 0x05, 0x07, 0x00, 0xCD, 0x6D, 0x41, 0x55, 0xFD,
        ];
        assert_eq!(parse_vendor_reply(&raw).unwrap(), vec![0x05, 0x07, 0x00, 0xCD, 0x6D, 0x41]);
    }

    #[test]
    fn parse_vendor_reply_no_tag() {
        // real IN frame: no card on reader
        let raw = [0x02, 0x07, 0x5F, 0x00, 0x00, 0x97, 0xFD];
        assert_eq!(parse_vendor_reply(&raw).unwrap(), vec![0x00]);
    }

    #[test]
    fn parse_vendor_reply_bad_checksum() {
        let mut raw = [0x02, 0x07, 0x5F, 0x00, 0x00, 0x97, 0xFD];
        raw[5] ^= 0xFF; // corrupt the checksum byte
        assert!(matches!(parse_vendor_reply(&raw), Err(Error::Reply(_))));
    }

    #[test]
    fn parse_vendor_reply_timeout() {
        assert!(matches!(parse_vendor_reply(&[]), Err(Error::Reply(_))));
    }

    #[test]
    fn em4100_bitstream_matches_three_real_captures() {
        // Each (id, expected block1||block2) pair is from a real successful WriteT5577/5200
        // capture, writing a different ID to the same physical T5577 tag each time.
        let cases: &[(&[u8; 5], &str)] = &[
            (&[0x00, 0x00, 0x00, 0x20, 0x49], "ff8000000050265e"),
            (&[0x00, 0x00, 0x00, 0x20, 0x50], "ff8000000050280e"),
            (&[0x00, 0x00, 0x00, 0x20, 0x51], "ff8000000050286c"),
        ];
        for (id, expect_hex) in cases {
            let got = em4100_bitstream(id);
            let expect = {
                let digits = expect_hex.as_bytes();
                let mut v = [0u8; 8];
                for i in 0..8 {
                    v[i] = u8::from_str_radix(
                        std::str::from_utf8(&digits[i * 2..i * 2 + 2]).unwrap(),
                        16,
                    )
                    .unwrap();
                }
                v
            };
            assert_eq!(got, expect, "id {:02X?} -> {:02X?}, expected {:02X?}", id, got, expect);
        }
    }

    #[test]
    fn lf_write_id_commit_frame_matches_real_capture() {
        // Real OUT frame from a verified-successful WriteT5577/5200 (wrote ID 00 00 00 20 49
        // to a genuine T5577 blank, confirmed by reading it back): seq=0x0206.
        // 01 15 06 02 ff 00 66 00 1e 48 e8 01 00 01 00 00 00 20 49 c3 fe
        let payload = [
            0xFF, 0x00, 0x66, 0x00, 0x1E, 0x48, 0xE8, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20,
            0x49,
        ];
        let r = build_report_raw(&payload, 0x0206).unwrap();
        assert_eq!(
            &r[1..21],
            &[
                0x01, 0x15, 0x06, 0x02, 0xFF, 0x00, 0x66, 0x00, 0x1E, 0x48, 0xE8, 0x01, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x20, 0x49, 0xC3
            ]
        );
        assert_eq!(r[21], 0xFE);
    }
}
