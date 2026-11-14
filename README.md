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
--lf-info              125 kHz: print device/version + serial strings
--lf-read              125 kHz: init + read one EM4100 tag ID (5 bytes)
--beep                 sound the reader's buzzer + LED
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
`transceive`/`transceive_raw`, `lf_device_info`/`lf_serial`/`lf_init`/`lf_read_em4100`/`beep`),
value types `Tag`/`FirmwareInfo`/`MifareDump`, and the pure, unit-tested framing fns
`build_inner`/`build_report`/`build_report_raw`/`parse_reply`/`parse_vendor_reply`/`build_block0`.

## Protocol (recovered)

The 13.56 MHz front-end is a genuine **NXP PN532** (GetFirmwareVersion IC byte `0x32`). All I/O
is 64-byte HID reports with **two nested framing layers**:

- **Outer HID transport:** `01 | len(inner)+6 | seqLo seqHi | <inner> | cksum | FE` (report is
  unnumbered; a leading `0x00` report-id is stripped by hidapi). Replies use start `0x02` /
  trailer `0xFD`, and the reader's MCU appends a `90 00` status suffix to PN532 reply data.
  `cksum = (!sum(bytes[0..cksum])) & 0xFF` on **both** directions — the sum includes the
  leading `0x01`/`0x02` marker byte itself, not just what follows it.
- **Inner vendor-PN532 frame:** `FF 00 00 00 | len(cmd)+1 | D4 | <cmd>` (`D4` = PN532 TFI
  host→controller). The payload is the standard PN53x command set (ReadRegister `0x06`,
  WriteRegister `0x08`, RFConfiguration `0x32`, InListPassiveTarget `0x4A`, InDataExchange `0x40`,
  InCommunicateThru `0x42`, …).

There is also a second, **vendor MCU command family** sent as the raw transport payload
`FF 00 <op> ...` (no PN532 `D4` wrapper; reply `02 | len | seqLo seqHi | <data> | cksum | FD`,
same checksum rule as above) used for the 125 kHz LF side and device info. Reach the family
generically via `--raw-vendor` / `WCopy::transceive_raw`, or through the typed wrappers below.

### 125 kHz (LF) support

Recovered the same way, from a capture of the vendor tool reading/beeping an EM4100 card:

| op (`FF 00 <op>`) | params | reply | meaning |
|---|---|---|---|
| `0x68` | – | ASCII, e.g. `"wCopy NSR121-IDIC V705N2"` | device/firmware string |
| `0x69` | – | ASCII, e.g. `"T39190010249"` | serial number |
| `0x62` | `01 00`, then `01 06 00 00 1F 01 FA 00` | — | init/config handshake (2 calls, meaning of the bytes not understood, sent once at connect) |
| `0x65` | `05 1E 48 E8 01 00 81 01 18 01` | `05 <5-byte ID>`, or a single `00` if no tag | read one EM4100/EM4102 125 kHz tag |
| `0x40` | `50 04 05 01 01 01` | `90 01` | buzzer + LED |
| `0x66` | see below | `00` | write to a T5577/5200-family tag (the vendor tool's "WriteT5577/5200" button) |

`WCopy::lf_device_info`/`lf_serial`/`lf_init`/`lf_read_em4100`/`beep` wrap the simple ones
(CLI: `--lf-info`, `--lf-read`, `--beep`).

**LF write** (`WCopy::lf_write_em4100`, CLI `--lf-write <10 hex digits>`) is a 13-frame `0x66`
sequence, each prefixed `00 1E 48 E8 01 00` (meaning unknown, fixed). Captured 3 real
successful writes of different IDs to the same T5577 blank (reading each one back to confirm)
and found 2 of the 13 frames vary with the target ID — and vary in exactly the way the
**standard EM4100 64-bit encoding** of that ID would (header + 10×(nibble + row parity) +
column parity + stop bit, see `em4100_bitstream`): split into two 4-byte halves and written to
block indices 1 and 2. The other frames (four watermarked with ASCII `"Tian"`, one writing a
`00 00 14 80 50` T5577 config word, and a final frame carrying the raw 5-byte ID again, which
is what actually commits it) stayed byte-identical across all three captures and are replayed
verbatim. A first version of this function just replayed one capture's bytes unchanged and, as
expected once this was understood, only worked for that one specific ID — don't do that if you
touch this code; recompute `block1`/`block2` from `id` instead.

Needs ~100ms between frames (sent back-to-back, every reply still parses fine but the write
silently doesn't take). Doesn't work on a genuine (factory read-only) EM4100 tag — none of the
vendor tool's own type-specific write buttons do either, confirmed on real hardware. **Also
confirmed failing, identically, through the vendor's own tool:** an `id` whose first byte (the
EM4100 version/customer byte) is very high (`0x98`/`0x99` tested) — can leave the tag
temporarily unreadable (recovered by writing a working ID again, no permanent damage seen in
testing). `0x00`/`0x07`/`0x12` all wrote fine; the exact cutoff wasn't determined.

LF write for `EM4305`/`EL8265`/other chip families: not attempted — no hardware to verify
against. The EM4100 bitstream math above is chip-agnostic and should carry over, but the outer
`0x66`-equivalent command framing for those families is unknown; don't guess at it blindly,
capture a real successful write first (see the three-ID technique above).

LF support in the tools: `wcopy-gui` has a "125 kHz (LF)" section (read, write, beep),
mirroring the CLI flags. `wcopy-wedge` does **not** have LF support yet — it only types a
presented tag's HF (Mifare/ISO14443A) UID; adding an EM4100 mode (poll with `lf_read_em4100`
instead of `read_tag`) would need the same kind of change `wcopy-gui` already got.

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
- The GUI embeds **Hack Nerd Font** (Hack by Source Foundry, patched by Nerd Fonts), which
  keeps its own license — see [`assets/LICENSE.md`](assets/LICENSE.md) and
  [`assets/README.md`](assets/README.md).
- The driver/source code is licensed under the **BSD 4-Clause License** — see
  [`LICENSE`](LICENSE). Note clause 3 (the "advertising clause"): products advertising use of
  this software must acknowledge it.
