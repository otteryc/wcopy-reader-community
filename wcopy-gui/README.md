# wcopy-gui

Native desktop GUI for the NSCCN wCopy Smart Reader, built on the `wcopy` library with
egui/eframe. Like the CLI, hidapi is **statically linked** — the binary depends only on
macOS system frameworks (no `libhidapi.dylib`, no `DYLD_LIBRARY_PATH`). Part of the
[wcopy](../README.md) workspace.

## Run

```bash
# from the repo root
cargo run --release -p wcopy-gui
# or the standalone binary (no env vars):
./target/release/wcopy-gui
```

It auto-connects to the first reader on startup; use **Connect / Refresh** after hot-plugging.

## Package as a macOS app (so Finder doesn't open a Terminal)

Double-clicking the bare `wcopy-gui` binary makes macOS launch it under Terminal. Wrap it in
a `.app` bundle instead — `cargo bundle` does this from the `[package.metadata.bundle]` block
in `Cargo.toml`:

```bash
cargo install cargo-bundle          # once
cd wcopy-gui && cargo bundle --release
open ../target/release/bundle/osx/wCopy.app     # or double-click it in Finder
```

This produces `target/release/bundle/osx/wCopy.app` (and a `…/dmg/wCopy.dmg`). The app is
self-contained and ad-hoc signed. First launch may hit Gatekeeper ("unidentified developer")
— right-click → **Open** once, or `xattr -dr com.apple.quarantine wCopy.app`. Add
`icon = ["icon.icns"]` under `[package.metadata.bundle]` to give it a custom icon.

## Features

1. **Read UID → register** — reads the tag on the reader and stores its UID in the on-screen
   *UID register*.
2. **Write register → tag** — writes the register's UID to the tag (Gen1a magic write) and
   verifies by re-reading.
3. **Manual UID** — type a UID as **hex** or **decimal** and either load it into the register
   or write it straight to a tag.
4. **Byte order** — hex/decimal input is interpreted as a 32-bit value laid out **big-endian**
   or **little-endian**; a live preview shows the exact 4 bytes that will be written (e.g.
   hex `95D38E72` → BE `95 D3 8E 72`, LE `72 8E D3 95`).

5. **MIFARE Classic (1K)** — **Dump** (dictionary-crack all 16 sectors + read all 64 blocks,
   shown in a collapsible hex view), **Read block** and **Write block** (block picker + 16-byte
   hex field; write is auto-authenticated and read-back-verified). Per-sector crack progress
   streams into the log live.

Also: firmware/connection status, a **Probe magic** button (is the tag UID-writable?), and a
scrolling log. The main panel scrolls when content exceeds the window.

## Fonts

The UI embeds **Hack Nerd Font** from `../assets/` (Propo for text, Mono for hex/log) via
`include_bytes!`, so Unicode glyphs (arrows, middots, em-dashes) render correctly and the
binary stays self-contained — the font is baked in, `assets/` is only needed at build time.
egui's default emoji fonts remain as fallbacks.

## Architecture

Device I/O runs on a worker thread that owns the `HidApi` + `wcopy::WCopy`; the UI thread
communicates with it over channels, so slow HID reads (tag polling can take seconds) never
freeze the window. All reader logic lives in the `wcopy` library — this crate is just the view.
