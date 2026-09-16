# wcopy

A self-contained Rust driver and toolset for the **NSCCN wCopy Smart Reader** — a
PN532-based USB-HID NFC/RFID reader/writer ("copier"). The USB protocol was recovered by
reverse-engineering the vendor's Windows app; this project reimplements it cleanly so the
reader can be driven from macOS (and Linux/Windows) without the vendor software.

The `hidapi` C library is **statically linked**, so the binaries have no runtime library
dependency — on macOS they link only system frameworks (no `libhidapi.dylib`, no
`DYLD_LIBRARY_PATH`).

> **Scope / responsible use.** This is an interoperability driver for talking to your own
> reader and your own tags (including UID-changeable "magic" cards, which are designed to be
> rewritten). Use it only with credentials and cards you are authorised to work with.

## Features

- **Read a tag UID** (ISO14443A, via PN532 `InListPassiveTarget`).
- **Write a 4-byte UID** to Gen1a "magic" Mifare Classic cards (backdoor unlock + block-0 write,
  verified by read-back).
- **MIFARE Classic 1K**: dictionary key-recovery, full dump, and authenticated block read/write.
- **Keyboard wedge** (`wcopy-wedge`): types a presented tag's UID (decimal) + Enter into the
  focused app, and beeps the reader — turning it into an input device.
- **Native GUI** (`wcopy-gui`): egui desktop app for read/write UID and MIFARE operations.
- **Raw command access** for further protocol exploration.

## Repository layout

This is a Cargo workspace:

| Crate | Kind | What |
|-------|------|------|
| `wcopy` (root) | lib + bin | the driver library and the `wcopy` CLI |
| `wcopy-gui/`   | bin | native egui GUI (`wcopy-gui`) — see [`wcopy-gui/README.md`](wcopy-gui/README.md) |
| `wcopy-wedge/` | bin | keyboard-wedge tool (`wcopy-wedge`) — see [`wcopy-wedge/README.md`](wcopy-wedge/README.md) |
| `assets/`      | data | bundled Hack Nerd Font (embedded in the GUI) — see [`assets/LICENSE.md`](assets/LICENSE.md) |

## Requirements

- Rust (stable) — <https://rustup.rs>
- A C compiler/toolchain (the `hidapi` crate builds the C library from source).
- macOS: nothing else. Linux: libudev headers; udev rules for non-root HID access.

No prebuilt hidapi or `DYLD_LIBRARY_PATH` is needed — it's compiled in.

## Build

```bash
cargo build --release          # builds the CLI, GUI, and wedge
cargo test                     # framing/parse unit tests (no hardware needed)
```

Binaries land in `target/release/`. Confirm the CLI is self-contained on macOS with
`otool -L target/release/wcopy` (only `/System/...` and `/usr/lib/...`).

## CLI (`wcopy`)

```
--list                 list candidate readers
--firmware             GetFirmwareVersion (IC / version)
--read                 read one ISO14443A tag (UID)
--write-uid <HEX>      write a 4-byte UID to a Gen1a magic card, e.g. DEADBEEF or 95:D3:8E:72
--probe-magic          test whether the tag is a Gen1a magic card
--dump                 MIFARE Classic 1K: dictionary-crack keys, then dump all blocks
--read-block <N>       read block N (dictionary-auths its sector first)
--write-block <N:HEX>  write block N (32 hex chars = 16 bytes)
--read-register <ADDR> PN532 ReadRegister, e.g. 0x6303
--cmd "<HEX...>"       raw PN532 command, e.g. "06 63 03"
--raw-vendor <HEX>     raw vendor MCU payload (no PN532 wrapper), e.g. "FF 00 6B 30"
```

With no action flag, `wcopy` prints firmware + the current tag.

```bash
./target/release/wcopy --firmware --read
./target/release/wcopy --dump
./target/release/wcopy --write-uid DEADBEEF
```

## Library

The `wcopy` crate is also a library; the core never prints (returns `Result<_, wcopy::Error>`),
so it embeds cleanly in a GUI or service:

```rust
let mut dev = wcopy::WCopy::open_first()?;
println!("{}", dev.get_firmware()?);          // FirmwareInfo
if let Some(tag) = dev.read_tag(true)? {       // Option<Tag>
    println!("{tag}");
}
if dev.probe_gen1a()? {
    dev.write_uid(&[0xDE, 0xAD, 0xBE, 0xEF])?; // verified, or Err
}
let dump = dev.mfc_dump(wcopy::DEFAULT_KEYS)?; // crack + dump a 1K
```

Highlights: `list_readers`, `WCopy` (`get_firmware`, register read/write/RMW, `set_parameters`,
`rf_field`, `communicate_thru`, `read_tag`, `probe_gen1a`, `gen1a_unlock`, `write_block`,
`write_uid`, `mfc_auth`/`mfc_read_block`/`mfc_write_block`/`mfc_find_key`/`mfc_dump`,
`transceive`/`transceive_raw`), value types `Tag`/`FirmwareInfo`/`MifareDump`, and the pure,
unit-tested framing fns `build_inner`/`build_report`/`build_report_raw`/`parse_reply`/`build_block0`.

## Protocol (recovered)

The 13.56 MHz front-end is a genuine **NXP PN532** (GetFirmwareVersion IC byte `0x32`). All I/O
is 64-byte HID reports with **two nested framing layers**:

- **Outer HID transport:** `01 | len(inner)+6 | seqLo seqHi | <inner> | ~sum(bytes[1..]) | FE`
  (report is unnumbered; a leading `0x00` report-id is stripped by hidapi). Replies use start
  `0x02` / trailer `0xFD`, and the reader's MCU appends a `90 00` status suffix to reply data.
- **Inner vendor-PN532 frame:** `FF 00 00 00 | len(cmd)+1 | D4 | <cmd>` (`D4` = PN532 TFI
  host→controller). The payload is the standard PN53x command set (ReadRegister `0x06`,
  WriteRegister `0x08`, RFConfiguration `0x32`, InListPassiveTarget `0x4A`, InDataExchange `0x40`,
  InCommunicateThru `0x42`, …).

There is also a second, **vendor MCU command family** sent as the raw transport payload
`FF 00 <op> ...` (no PN532 `D4` wrapper; reply `02 | len | seq | <data> | cksum | FD`) used for
the 125 kHz LF side and device info (`FF 00 68` returns the device/version string). Reach it with
`--raw-vendor` / `WCopy::transceive_raw`.

## Supported cards

- **ISO14443A UID read** — any 13.56 MHz Type A tag.
- **Gen1a "magic" Mifare Classic** — UID rewrite (block-0 backdoor).
- **Mifare Classic 1K** — dictionary key recovery, dump, authenticated read/write.

Cryptographic key recovery (Crypto1 nested / Dark-Side) is **not** implemented — only the
dictionary attack over common default keys.

## Platform notes (macOS)

- **GUI**: package as a `.app` (so Finder doesn't open a Terminal) with `cargo bundle`
  (`cargo install cargo-bundle`, then `cargo bundle --release` in `wcopy-gui/`). Details in
  [`wcopy-gui/README.md`](wcopy-gui/README.md).
- **Wedge**: real keystroke injection needs Accessibility permission (System Settings → Privacy
  & Security → Accessibility). See [`wcopy-wedge/README.md`](wcopy-wedge/README.md).
- Ad-hoc-signed/unsigned apps may hit Gatekeeper on first launch — right-click → **Open**, or
  `xattr -dr com.apple.quarantine <app>`.

## Credits & license

- Protocol recovered by reverse-engineering the vendor's `nfcPro` Windows application, for
  interoperability. No vendor code or binaries are included in this repository.
- The GUI embeds **Hack Nerd Font** (Hack by Source Foundry, patched by Nerd Fonts) — see
  [`assets/LICENSE.md`](assets/LICENSE.md) and [`assets/README.md`](assets/README.md) for its
  license and version.
- Driver/source license: add a top-level `LICENSE` before distributing (MIT recommended).
