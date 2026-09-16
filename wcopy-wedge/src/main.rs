//! wcopy-wedge — turn the reader into a keyboard-wedge input device.
//!
//! Continuously polls the reader; when a tag is presented, "types" its UID as a decimal
//! number followed by Enter into whatever application currently has keyboard focus (using
//! OS-level key injection). One keystroke burst per presentation (debounced): the same tag
//! left on the reader is not re-typed until it is removed and presented again.
//!
//! macOS: key injection needs Accessibility permission — grant it to the app/terminal under
//! System Settings > Privacy & Security > Accessibility. Use `--dry-run` to print instead of
//! type (no permission needed).

use std::thread::sleep;
use std::time::Duration;

use enigo::{Direction, Enigo, Key, Keyboard, Settings};
use wcopy::WCopy;

struct Opts {
    little_endian: bool,
    dry_run: bool,
    interval_ms: u64,
    enter: bool,
    prefix: String,
    pad: usize,
    beep: bool,
    beep_settle_ms: u64,
}

fn parse_opts() -> Result<Opts, String> {
    let mut o = Opts {
        little_endian: false,
        dry_run: false,
        interval_ms: 200,
        enter: true,
        prefix: String::new(),
        pad: 0,
        beep: true,
        beep_settle_ms: 800,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--le" => o.little_endian = true,
            "--be" => o.little_endian = false,
            "--dry-run" => o.dry_run = true,
            "--no-enter" => o.enter = false,
            "--no-beep" => o.beep = false,
            "--beep-settle" => {
                o.beep_settle_ms = args
                    .next()
                    .and_then(|s| s.parse().ok())
                    .ok_or("--beep-settle needs a number (ms)")?;
            }
            "--interval" => {
                o.interval_ms = args
                    .next()
                    .and_then(|s| s.parse().ok())
                    .ok_or("--interval needs a number (ms)")?;
            }
            "--prefix" => o.prefix = args.next().ok_or("--prefix needs a string")?,
            "--pad" => {
                o.pad = args
                    .next()
                    .and_then(|s| s.parse().ok())
                    .ok_or("--pad needs a number")?;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(o)
}

fn print_help() {
    eprintln!(
        "wcopy-wedge - type a tag's UID (decimal) + Enter into the focused app\n\
         \n\
         USAGE: wcopy-wedge [OPTIONS]\n\
         \n\
         OPTIONS:\n\
         \x20 --be | --le        UID byte order for the decimal value (default --be)\n\
         \x20 --dry-run          print what would be typed instead of typing it\n\
         \x20 --no-enter         do not append Enter\n\
         \x20 --no-beep          do not trigger the reader's buzzer on a read\n\
         \x20 --beep-settle <MS> pause after the beep so it isn't cut off (default 800)\n\
         \x20 --prefix <STR>     type <STR> before the number\n\
         \x20 --pad <N>          zero-pad the decimal to at least N digits\n\
         \x20 --interval <MS>    poll interval in milliseconds (default 200)\n\
         \x20 -h, --help         this help\n\
         \n\
         macOS: real typing needs Accessibility permission; --dry-run needs none.\n\
         Stop with Ctrl-C."
    );
}

/// Interpret the UID bytes as an unsigned integer and render it as decimal.
fn uid_to_decimal(uid: &[u8], little_endian: bool) -> String {
    let mut v: u128 = 0;
    if little_endian {
        for b in uid.iter().rev() {
            v = (v << 8) | (*b as u128);
        }
    } else {
        for b in uid.iter() {
            v = (v << 8) | (*b as u128);
        }
    }
    v.to_string()
}

fn format_output(uid: &[u8], o: &Opts) -> String {
    let mut num = uid_to_decimal(uid, o.little_endian);
    if num.len() < o.pad {
        num = format!("{}{}", "0".repeat(o.pad - num.len()), num);
    }
    format!("{}{}", o.prefix, num)
}

fn main() {
    let o = match parse_opts() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error: {e}\n");
            print_help();
            std::process::exit(2);
        }
    };

    let mut dev = match WCopy::open_first() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };
    // Poll without power-cycling: bring the field up once and keep it on, so a present tag
    // is already powered when we poll. A few retries keep no-tag polls fast. (Power-cycling
    // every poll races the tag's power-up and misses detections.)
    let _ = dev.rf_max_retries(0x00, 0x01, 0x03);
    let _ = dev.rf_field(false); // reset any card left ACTIVE by a previous run -> IDLE
    sleep(Duration::from_millis(50));
    let _ = dev.rf_field(true);
    sleep(Duration::from_millis(50));

    // Key injector (skip in dry-run so no Accessibility permission is needed).
    let mut enigo = if o.dry_run {
        None
    } else {
        match Enigo::new(&Settings::default()) {
            Ok(e) => Some(e),
            Err(e) => {
                eprintln!(
                    "Error: could not init key injection: {e}\n\
                     On macOS grant Accessibility permission, or use --dry-run."
                );
                std::process::exit(1);
            }
        }
    };

    eprintln!(
        "wcopy-wedge running ({}, {} order){}. Present a tag; Ctrl-C to stop.",
        if o.dry_run { "dry-run" } else { "typing" },
        if o.little_endian { "little-endian" } else { "big-endian" },
        if o.enter { ", Enter appended" } else { "" },
    );

    let mut last: Option<Vec<u8>> = None;
    loop {
        match dev.read_tag(false) {
            Ok(Some(tag)) => {
                if last.as_deref() != Some(tag.uid.as_slice()) {
                    let out = format_output(&tag.uid, &o);
                    emit(enigo.as_mut(), &out, o.enter);
                    eprintln!("  UID {} -> \"{}\"", tag.uid_hex(), out);
                    // The magic-probe sequence makes the reader's buzzer sound — use it as the
                    // "successful read" beep. The buzzer plays asynchronously in the reader, so
                    // pause afterwards: the next read_tag poll would otherwise send RF commands
                    // that cut the beep short.
                    if o.beep {
                        let _ = dev.probe_gen1a();
                        sleep(Duration::from_millis(o.beep_settle_ms));
                    }
                    last = Some(tag.uid.clone());
                }
            }
            Ok(None) => last = None, // tag removed; allow the same tag to fire again
            Err(e) => {
                eprintln!("  read error: {e}");
                last = None;
            }
        }
        sleep(Duration::from_millis(o.interval_ms));
    }
}

/// Type `text` (and optionally Enter) via key injection, or print it in dry-run.
fn emit(enigo: Option<&mut Enigo>, text: &str, enter: bool) {
    match enigo {
        None => {
            // dry-run
            println!("{text}{}", if enter { " <ENTER>" } else { "" });
        }
        Some(e) => {
            if let Err(err) = e.text(text) {
                eprintln!("  type error: {err}");
                return;
            }
            if enter {
                let _ = e.key(Key::Return, Direction::Click);
            }
        }
    }
}
