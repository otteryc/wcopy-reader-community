//! CLI for the wCopy reader driver. Mirrors the flags of the Python `wcopy.py`.
//! The library (`lib.rs`) does the work and never prints; all output happens here.

use std::process::ExitCode;
use wcopy::{list_readers, Error, WCopy};

fn print_usage() {
    eprintln!(
        "wcopy - NSCCN wCopy reader driver (statically linked hidapi)\n\
         \n\
         USAGE: wcopy [OPTIONS]\n\
         \n\
         OPTIONS:\n\
         \x20 --list                 list candidate readers and exit\n\
         \x20 --firmware             GetFirmwareVersion\n\
         \x20 --read                 read one ISO14443A tag (UID)\n\
         \x20 --probe-magic          test for a Gen1a magic card\n\
         \x20 --write-uid <HEX>      write a 4-byte UID, e.g. DEADBEEF\n\
         \x20 --dump                 MIFARE Classic 1K: crack keys (dictionary) + dump\n\
         \x20 --read-block <N>       read block N (dictionary-auth its sector first)\n\
         \x20 --write-block <N:HEX>  write block N (32 hex chars), dictionary-auth first\n\
         \x20 --raw-vendor <HEX>   send a raw MCU payload (no PN532 wrapper), e.g. \"FF 00 6B 30\"\n\
         \x20 --read-register <ADDR> ReadRegister, e.g. 0x6303\n\
         \x20 --cmd \"<HEX...>\"       raw PN532 command, e.g. \"06 63 03\"\n\
         \x20 -h, --help             this help\n\
         \n\
         With no action flag, prints firmware + tag."
    );
}

fn parse_u16(s: &str) -> Option<u16> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u16::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Parse space/comma-separated hex bytes, e.g. "06 63 03" or "0x06,0x63".
fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    s.replace(',', " ")
        .split_whitespace()
        .map(|t| u8::from_str_radix(t.trim_start_matches("0x"), 16).ok())
        .collect()
}

/// Parse a hex string of bytes with any separators, e.g. "95D38E72", "95 D3 8E 72",
/// "95:D3:8E:72". Requires an even number of hex digits.
fn parse_hex_str(s: &str) -> Option<Vec<u8>> {
    let digits: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if digits.is_empty() || digits.len() % 2 != 0 {
        return None;
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).ok())
        .collect()
}

fn run() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_usage();
        return Ok(());
    }

    // simple flag parser
    let mut do_list = false;
    let mut do_fw = false;
    let mut do_read = false;
    let mut do_probe = false;
    let mut do_dump = false;
    let mut read_block: Option<String> = None;
    let mut write_block: Option<String> = None;
    let mut write_uid: Option<String> = None;
    let mut read_reg: Option<String> = None;
    let mut raw_cmd: Option<String> = None;
    let mut raw_vendor: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--list" => do_list = true,
            "--firmware" => do_fw = true,
            "--read" => do_read = true,
            "--probe-magic" => do_probe = true,
            "--dump" => do_dump = true,
            "--read-block" => {
                i += 1;
                read_block = args.get(i).cloned();
            }
            "--write-block" => {
                i += 1;
                write_block = args.get(i).cloned();
            }
            "--write-uid" => {
                i += 1;
                write_uid = args.get(i).cloned();
            }
            "--read-register" => {
                i += 1;
                read_reg = args.get(i).cloned();
            }
            "--cmd" => {
                i += 1;
                raw_cmd = args.get(i).cloned();
            }
            "--raw-vendor" => {
                i += 1;
                raw_vendor = args.get(i).cloned();
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_usage();
                return Err(Error::BadArg(other.into()));
            }
        }
        i += 1;
    }

    let readers = list_readers()?;
    for (n, r) in readers.iter().enumerate() {
        println!("[{}] {:04X}:{:04X} {:?}", n + 1, r.vid, r.pid, r.product);
    }
    if do_list {
        return Ok(());
    }
    if readers.is_empty() {
        return Err(Error::NoDevice("no wCopy reader found".into()));
    }

    let mut dev = WCopy::open(&readers[0])?;
    let default = !(do_fw || do_read || do_probe || do_dump
        || read_block.is_some()
        || write_block.is_some()
        || write_uid.is_some()
        || read_reg.is_some()
        || raw_cmd.is_some()
        || raw_vendor.is_some());

    if do_fw || default {
        println!("Firmware: {}", dev.get_firmware()?);
    }
    if do_read || default {
        match dev.read_tag(true)? {
            Some(tag) => println!("Tag: {tag}"),
            None => println!("Tag: no tag on reader"),
        }
    }
    if do_probe {
        println!(
            "Gen1a magic card: {}",
            if dev.probe_gen1a()? { "YES" } else { "no" }
        );
    }
    if do_dump {
        dev.set_logger(|m| println!("  {m}"));
        println!("Dumping MIFARE Classic 1K (dictionary attack)…");
        let dump = dev.mfc_dump(wcopy::DEFAULT_KEYS)?;
        print!("{}", dump.to_text());
        let found = dump
            .keys
            .iter()
            .filter(|k| k.key_a.is_some() || k.key_b.is_some())
            .count();
        let readable = dump.blocks.iter().filter(|b| b.is_some()).count();
        println!("sectors with a key: {found}/16   blocks read: {readable}/64");
    }
    if let Some(n) = read_block {
        let blk: u8 = n.parse().map_err(|_| Error::BadArg(format!("bad block: {n}")))?;
        let sector = blk / 4;
        let trailer = sector * 4 + 3;
        match dev.mfc_find_key(trailer, wcopy::KeyType::A, wcopy::DEFAULT_KEYS)? {
            None => println!("block {blk}: no dictionary key for sector {sector}"),
            Some(key) => {
                let tag = dev.select(true)?;
                dev.mfc_auth(trailer, wcopy::KeyType::A, &key, &tag.uid)?;
                let data = dev.mfc_read_block(blk)?;
                let hexs: Vec<String> = data.iter().map(|b| format!("{b:02X}")).collect();
                println!(
                    "block {blk} (sector {sector}, key A {}): {}",
                    key.iter().map(|b| format!("{b:02X}")).collect::<String>(),
                    hexs.join(" ")
                );
            }
        }
    }
    if let Some(spec) = write_block {
        let (n, hex) = spec
            .split_once(':')
            .ok_or_else(|| Error::BadArg("use --write-block N:HEX32".into()))?;
        let blk: u8 = n.parse().map_err(|_| Error::BadArg(format!("bad block: {n}")))?;
        let bytes = parse_hex_str(hex).ok_or_else(|| Error::BadArg("bad hex data".into()))?;
        if bytes.len() != 16 {
            return Err(Error::BadArg(format!("need 16 bytes, got {}", bytes.len())));
        }
        let mut data = [0u8; 16];
        data.copy_from_slice(&bytes);
        let sector = blk / 4;
        let trailer = sector * 4 + 3;
        match dev.mfc_find_key(trailer, wcopy::KeyType::A, wcopy::DEFAULT_KEYS)? {
            None => println!("block {blk}: no dictionary key for sector {sector}"),
            Some(key) => {
                let tag = dev.select(true)?;
                dev.mfc_auth(trailer, wcopy::KeyType::A, &key, &tag.uid)?;
                dev.mfc_write_block(blk, &data)?;
                let back = dev.mfc_read_block(blk)?;
                let ok = back == data;
                println!(
                    "wrote block {blk}: {}  verify: {}",
                    back.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" "),
                    if ok { "OK" } else { "MISMATCH" }
                );
            }
        }
    }
    if let Some(hex) = write_uid {
        let uid =
            parse_hex_str(&hex).ok_or_else(|| Error::BadArg(format!("bad UID hex: {hex}")))?;
        let tag = dev.write_uid(&uid)?;
        println!("Wrote & verified: {tag}");
    }
    if let Some(a) = read_reg {
        let addr = parse_u16(&a).ok_or_else(|| Error::BadArg(format!("bad addr: {a}")))?;
        println!("Register 0x{:04X} = 0x{:02X}", addr, dev.read_register(addr)?);
    }
    if let Some(c) = raw_cmd {
        let cmd = parse_hex_bytes(&c).ok_or_else(|| Error::BadArg(format!("bad cmd: {c}")))?;
        let d = dev.transceive(&cmd)?;
        let hexs: Vec<String> = d.iter().map(|b| format!("{b:02X}")).collect();
        println!("Response: {}", hexs.join(" "));
    }
    if let Some(hex) = raw_vendor {
        let payload =
            parse_hex_bytes(&hex).ok_or_else(|| Error::BadArg(format!("bad payload: {hex}")))?;
        let reply = dev.transceive_raw(&payload, 1000)?;
        let hexs: Vec<String> = reply.iter().take(24).map(|b| format!("{b:02X}")).collect();
        println!(
            "sent {} -> reply[{}]: {}",
            payload.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" "),
            reply.len(),
            hexs.join(" ")
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(2)
        }
    }
}
