//! Native GUI for the NSCCN wCopy reader, built on the `wcopy` library.
//!
//! Features (per spec):
//!   1) Read the UID from a tag and save it to a register (the "UID register" slot).
//!   2) Write a tag with the UID captured in (1).
//!   3) Manually assign a UID in hex or decimal and write it to a tag.
//!   4) For hex (and decimal) input, choose big-endian or little-endian byte order.
//!
//! Device I/O runs on a dedicated worker thread that owns the `HidApi` + `WCopy`, so the
//! UI never blocks on HID reads (which can take up to a few seconds when polling for a tag).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::Duration;

use eframe::egui;
use wcopy::{find_readers, MifareDump, Tag, WCopy, DEFAULT_KEYS};

// --------------------------------------------------------------------------- //
// Worker protocol
// --------------------------------------------------------------------------- //
enum Cmd {
    Connect,
    Disconnect,
    ReadUid,          // read tag, report it (UI stores UID in the register)
    WriteUid(Vec<u8>),
    ProbeMagic,
    Dump,                        // MIFARE Classic 1K: crack + dump
    ReadBlock(u8),               // dictionary-auth + read block
    WriteBlock(u8, [u8; 16]),    // dictionary-auth + write block (+ verify)
}

enum Evt {
    Log(String),
    Connected { firmware: String },
    Disconnected,
    TagRead(Tag),
    WriteOk(Tag),
    Magic(bool),
    Dumped(MifareDump),
    Block { block: u8, data: [u8; 16] },
    BlockWritten { block: u8, ok: bool },
    Error(String),
}

fn worker(rx: Receiver<Cmd>, tx: Sender<Evt>, ctx: egui::Context) {
    let send = |e: Evt| {
        let _ = tx.send(e);
        ctx.request_repaint();
    };

    let mut api = match wcopy::new_hidapi() {
        Ok(a) => a,
        Err(e) => {
            send(Evt::Error(format!("hidapi init failed: {e}")));
            return;
        }
    };
    let mut dev: Option<WCopy> = None;

    for cmd in rx {
        match cmd {
            Cmd::Connect => {
                let _ = api.refresh_devices();
                match find_readers(&api).first() {
                    None => send(Evt::Error("no wCopy reader found".into())),
                    Some(info) => match WCopy::open_with(&api, info) {
                        Err(e) => send(Evt::Error(format!("open failed: {e}"))),
                        Ok(mut d) => {
                            // forward library progress logs (e.g. per-sector dump) to the UI
                            let ltx = tx.clone();
                            let lctx = ctx.clone();
                            d.set_logger(move |m| {
                                let _ = ltx.send(Evt::Log(m.to_string()));
                                lctx.request_repaint();
                            });
                            let fw = d
                                .get_firmware()
                                .map(|f| f.to_string())
                                .unwrap_or_else(|e| format!("<firmware error: {e}>"));
                            dev = Some(d);
                            send(Evt::Connected { firmware: fw });
                        }
                    },
                }
            }
            Cmd::Disconnect => {
                dev = None;
                send(Evt::Disconnected);
            }
            Cmd::ReadUid => match dev.as_mut() {
                None => send(Evt::Error("not connected".into())),
                Some(d) => match d.read_tag(true) {
                    Ok(Some(tag)) => send(Evt::TagRead(tag)),
                    Ok(None) => send(Evt::Error("no tag on reader".into())),
                    Err(e) => send(Evt::Error(format!("read failed: {e}"))),
                },
            },
            Cmd::WriteUid(uid) => match dev.as_mut() {
                None => send(Evt::Error("not connected".into())),
                Some(d) => {
                    send(Evt::Log(format!(
                        "writing UID {} …",
                        uid.iter().map(|b| format!("{b:02X}")).collect::<String>()
                    )));
                    match d.write_uid(&uid) {
                        Ok(tag) => send(Evt::WriteOk(tag)),
                        Err(e) => send(Evt::Error(format!("write failed: {e}"))),
                    }
                }
            },
            Cmd::ProbeMagic => match dev.as_mut() {
                None => send(Evt::Error("not connected".into())),
                Some(d) => match d.probe_gen1a() {
                    Ok(b) => send(Evt::Magic(b)),
                    Err(e) => send(Evt::Error(format!("probe failed: {e}"))),
                },
            },
            Cmd::Dump => match dev.as_mut() {
                None => send(Evt::Error("not connected".into())),
                Some(d) => {
                    send(Evt::Log("dumping MIFARE Classic 1K (dictionary attack)...".into()));
                    match d.mfc_dump(DEFAULT_KEYS) {
                        Ok(dump) => send(Evt::Dumped(dump)),
                        Err(e) => send(Evt::Error(format!("dump failed: {e}"))),
                    }
                }
            },
            Cmd::ReadBlock(n) => match dev.as_mut() {
                None => send(Evt::Error("not connected".into())),
                Some(d) => match d.mfc_read_block_auto(n, DEFAULT_KEYS) {
                    Ok(data) => send(Evt::Block { block: n, data }),
                    Err(e) => send(Evt::Error(format!("read block {n} failed: {e}"))),
                },
            },
            Cmd::WriteBlock(n, data) => match dev.as_mut() {
                None => send(Evt::Error("not connected".into())),
                Some(d) => match d.mfc_write_block_auto(n, &data, DEFAULT_KEYS) {
                    Ok(back) => send(Evt::BlockWritten {
                        block: n,
                        ok: back == data,
                    }),
                    Err(e) => send(Evt::Error(format!("write block {n} failed: {e}"))),
                },
            },
        }
    }
}

// --------------------------------------------------------------------------- //
// UID parsing (features 3 & 4)
// --------------------------------------------------------------------------- //
#[derive(PartialEq, Clone, Copy)]
enum Base {
    Hex,
    Dec,
}

#[derive(PartialEq, Clone, Copy)]
enum Order {
    Big,
    Little,
}

/// Parse a manual UID into 4 bytes. The 32-bit value is laid out big- or little-endian.
fn parse_uid(text: &str, base: Base, order: Order) -> Result<[u8; 4], String> {
    let t = text.trim();
    if t.is_empty() {
        return Err("enter a value".into());
    }
    let val: u32 = match base {
        Base::Hex => {
            let cleaned: String = t.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if cleaned.is_empty() {
                return Err("no hex digits".into());
            }
            if cleaned.len() > 8 {
                return Err("too many hex digits (max 8 = 4 bytes)".into());
            }
            u32::from_str_radix(&cleaned, 16).map_err(|e| e.to_string())?
        }
        Base::Dec => t
            .parse::<u32>()
            .map_err(|_| "not a 32-bit decimal number (0..4294967295)".to_string())?,
    };
    Ok(match order {
        Order::Big => val.to_be_bytes(),
        Order::Little => val.to_le_bytes(),
    })
}

fn hex_bytes(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse a hex string (any separators) into exactly N bytes.
fn parse_hex_n(s: &str, n: usize) -> Result<Vec<u8>, String> {
    let digits: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if digits.len() != n * 2 {
        return Err(format!("need {n} bytes ({} hex digits), got {}", n * 2, digits.len()));
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Install the bundled Hack Nerd Font (from `../assets/`) as the proportional + monospace
/// families. Nerd Font has full Unicode + icon coverage, so glyphs like arrows render.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "hack_propo".to_owned(),
        egui::FontData::from_static(include_bytes!("../../assets/HackNerdFontPropo-Regular.ttf")),
    );
    fonts.font_data.insert(
        "hack_mono".to_owned(),
        egui::FontData::from_static(include_bytes!("../../assets/HackNerdFontMono-Regular.ttf")),
    );
    // Put our fonts first in each family so they take priority for glyph coverage,
    // while egui's bundled emoji fonts remain as fallbacks.
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "hack_propo".to_owned());
    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .insert(0, "hack_mono".to_owned());
    ctx.set_fonts(fonts);
}

// --------------------------------------------------------------------------- //
// App
// --------------------------------------------------------------------------- //
struct App {
    tx: Sender<Cmd>,
    rx: Receiver<Evt>,

    connected: bool,
    busy: bool,
    firmware: Option<String>,

    last_tag: Option<Tag>,     // most recent read
    register: Option<Vec<u8>>, // the "UID register" (feature 1)

    // manual entry (features 3 & 4)
    manual_text: String,
    base: Base,
    order: Order,

    // MIFARE Classic
    last_dump: Option<MifareDump>,
    block_num: u8,
    block_data: String,

    log: Vec<String>,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<Cmd>();
        let (evt_tx, evt_rx) = std::sync::mpsc::channel::<Evt>();
        install_fonts(&cc.egui_ctx);
        let ctx = cc.egui_ctx.clone();
        thread::spawn(move || worker(cmd_rx, evt_tx, ctx));

        // try to connect at startup
        let _ = cmd_tx.send(Cmd::Connect);

        Self {
            tx: cmd_tx,
            rx: evt_rx,
            connected: false,
            busy: true,
            firmware: None,
            last_tag: None,
            register: None,
            manual_text: "DEADBEEF".to_string(),
            base: Base::Hex,
            order: Order::Big,
            last_dump: None,
            block_num: 1,
            block_data: "00000000000000000000000000000000".to_string(),
            log: vec!["connecting…".into()],
        }
    }

    fn log(&mut self, msg: impl Into<String>) {
        self.log.push(msg.into());
        if self.log.len() > 500 {
            let drop = self.log.len() - 500;
            self.log.drain(0..drop);
        }
    }

    fn send(&mut self, cmd: Cmd) {
        self.busy = true;
        let _ = self.tx.send(cmd);
    }

    fn drain_events(&mut self) {
        while let Ok(evt) = self.rx.try_recv() {
            match evt {
                Evt::Log(m) => self.log(m),
                Evt::Connected { firmware } => {
                    self.connected = true;
                    self.busy = false;
                    self.firmware = Some(firmware.clone());
                    self.log(format!("connected — {firmware}"));
                }
                Evt::Disconnected => {
                    self.connected = false;
                    self.busy = false;
                    self.firmware = None;
                    self.log("disconnected");
                }
                Evt::TagRead(tag) => {
                    self.busy = false;
                    self.register = Some(tag.uid.clone()); // feature 1: save to register
                    self.log(format!("read {tag}  → saved UID to register"));
                    self.last_tag = Some(tag);
                }
                Evt::WriteOk(tag) => {
                    self.busy = false;
                    self.log(format!("write verified: {tag}"));
                    self.last_tag = Some(tag);
                }
                Evt::Magic(b) => {
                    self.busy = false;
                    self.log(if b {
                        "Gen1a magic card: YES (UID is writable)"
                    } else {
                        "Gen1a magic card: no (UID not writable)"
                    });
                }
                Evt::Dumped(dump) => {
                    self.busy = false;
                    let found = dump
                        .keys
                        .iter()
                        .filter(|k| k.key_a.is_some() || k.key_b.is_some())
                        .count();
                    let readable = dump.blocks.iter().filter(|b| b.is_some()).count();
                    self.log(format!(
                        "dump complete: {found}/16 sectors keyed, {readable}/64 blocks read"
                    ));
                    self.last_dump = Some(dump);
                }
                Evt::Block { block, data } => {
                    self.busy = false;
                    self.log(format!("block {block}: {}", hex_bytes(&data)));
                }
                Evt::BlockWritten { block, ok } => {
                    self.busy = false;
                    self.log(format!(
                        "wrote block {block}: verify {}",
                        if ok { "OK" } else { "MISMATCH" }
                    ));
                }
                Evt::Error(e) => {
                    self.busy = false;
                    self.log(format!("error: {e}"));
                }
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();
        if self.busy {
            ctx.request_repaint_after(Duration::from_millis(150));
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("wCopy Smart Reader");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (dot, txt) = if self.connected {
                        (egui::Color32::from_rgb(60, 200, 90), "connected")
                    } else {
                        (egui::Color32::from_rgb(210, 80, 80), "disconnected")
                    };
                    ui.label(txt);
                    // draw the status dot as a shape (font-independent - no glyph needed)
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 5.0, dot);
                });
            });
            ui.label(
                self.firmware
                    .clone()
                    .unwrap_or_else(|| "firmware: —".into()),
            );
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Connect / Refresh"))
                    .clicked()
                {
                    self.send(Cmd::Connect);
                }
                if ui
                    .add_enabled(self.connected && !self.busy, egui::Button::new("Disconnect"))
                    .clicked()
                {
                    self.send(Cmd::Disconnect);
                }
                if ui
                    .add_enabled(self.connected && !self.busy, egui::Button::new("Probe magic"))
                    .clicked()
                {
                    self.send(Cmd::ProbeMagic);
                }
                if self.busy {
                    ui.spinner();
                    ui.label("working…");
                }
            });
            ui.add_space(4.0);
        });

        egui::TopBottomPanel::bottom("log")
            .resizable(true)
            .default_height(150.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.strong("Log");
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for line in &self.log {
                            ui.monospace(line);
                        }
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            let can_op = self.connected && !self.busy;
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {

            // -- The UID register ------------------------------------------------ //
            ui.group(|ui| {
                ui.strong("UID register");
                match &self.register {
                    Some(uid) => {
                        ui.horizontal(|ui| {
                            ui.monospace(hex_bytes(uid));
                            if uid.len() == 4 {
                                let v = u32::from_be_bytes([uid[0], uid[1], uid[2], uid[3]]);
                                ui.weak(format!("(dec BE: {v})"));
                            }
                        });
                    }
                    None => {
                        ui.weak("empty — read a tag or set a manual UID");
                    }
                }
            });

            ui.add_space(6.0);

            // -- 1) Read UID -> register ---------------------------------------- //
            ui.group(|ui| {
                ui.strong("1 · Read UID from tag");
                ui.label("Reads the tag on the reader and stores its UID in the register.");
                if ui
                    .add_enabled(can_op, egui::Button::new("Read UID → register"))
                    .clicked()
                {
                    self.send(Cmd::ReadUid);
                }
                if let Some(t) = &self.last_tag {
                    ui.weak(format!("last read: {t}"));
                }
            });

            ui.add_space(6.0);

            // -- 2) Write register -> tag --------------------------------------- //
            ui.group(|ui| {
                ui.strong("2 · Write register UID to tag");
                let reg4 = self
                    .register
                    .as_ref()
                    .filter(|u| u.len() == 4)
                    .map(|u| [u[0], u[1], u[2], u[3]]);
                match &self.register {
                    Some(u) if u.len() != 4 => {
                        ui.colored_label(
                            egui::Color32::from_rgb(200, 140, 40),
                            format!("register holds {} bytes; only 4-byte UID write is supported", u.len()),
                        );
                    }
                    _ => {}
                }
                if ui
                    .add_enabled(can_op && reg4.is_some(), egui::Button::new("Write register → tag"))
                    .clicked()
                {
                    if let Some(u) = reg4 {
                        self.send(Cmd::WriteUid(u.to_vec()));
                    }
                }
            });

            ui.add_space(6.0);

            // -- 3 & 4) Manual UID (hex/dec, BE/LE) ----------------------------- //
            ui.group(|ui| {
                ui.strong("3 · Manual UID");
                ui.horizontal(|ui| {
                    ui.label("Value:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.manual_text)
                            .desired_width(200.0)
                            .hint_text("e.g. DEADBEEF or 3735928559"),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Base:");
                    ui.radio_value(&mut self.base, Base::Hex, "Hex");
                    ui.radio_value(&mut self.base, Base::Dec, "Decimal");
                    ui.separator();
                    ui.label("Byte order:");
                    ui.radio_value(&mut self.order, Order::Big, "Big-endian");
                    ui.radio_value(&mut self.order, Order::Little, "Little-endian");
                });

                // live preview (feature 4 made visible)
                let parsed = parse_uid(&self.manual_text, self.base, self.order);
                match &parsed {
                    Ok(b) => {
                        ui.horizontal(|ui| {
                            ui.label("Resulting UID:");
                            ui.monospace(hex_bytes(b));
                        });
                    }
                    Err(e) => {
                        ui.colored_label(egui::Color32::from_rgb(210, 90, 90), format!("invalid: {e}"));
                    }
                }

                ui.horizontal(|ui| {
                    let ok = parsed.is_ok();
                    if ui
                        .add_enabled(ok, egui::Button::new("Load → register"))
                        .clicked()
                    {
                        if let Ok(b) = &parsed {
                            self.register = Some(b.to_vec());
                            let s = hex_bytes(b);
                            self.log(format!("manual UID {s} loaded into register"));
                        }
                    }
                    if ui
                        .add_enabled(can_op && ok, egui::Button::new("Write to tag"))
                        .clicked()
                    {
                        if let Ok(b) = &parsed {
                            self.send(Cmd::WriteUid(b.to_vec()));
                        }
                    }
                });
            });

            ui.add_space(6.0);

            // -- 4) MIFARE Classic 1K (dump / read / write block) --------------- //
            ui.group(|ui| {
                ui.strong("4 · MIFARE Classic (1K)");
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(can_op, egui::Button::new("Dump 1K (crack + read)"))
                        .clicked()
                    {
                        self.send(Cmd::Dump);
                    }
                    ui.weak("dictionary attack + read all 64 blocks");
                });

                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Block:");
                    ui.add(egui::DragValue::new(&mut self.block_num).range(0..=63u8));
                    if ui
                        .add_enabled(can_op, egui::Button::new("Read block"))
                        .clicked()
                    {
                        self.send(Cmd::ReadBlock(self.block_num));
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Data:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.block_data)
                            .desired_width(300.0)
                            .hint_text("32 hex chars = 16 bytes"),
                    );
                });
                let parsed_block = parse_hex_n(&self.block_data, 16);
                if let Err(e) = &parsed_block {
                    ui.colored_label(egui::Color32::from_rgb(210, 90, 90), format!("invalid: {e}"));
                }
                if ui
                    .add_enabled(
                        can_op && parsed_block.is_ok(),
                        egui::Button::new("Write block"),
                    )
                    .clicked()
                {
                    if let Ok(b) = &parsed_block {
                        let mut d = [0u8; 16];
                        d.copy_from_slice(b);
                        self.send(Cmd::WriteBlock(self.block_num, d));
                    }
                }

                if let Some(dump) = &self.last_dump {
                    ui.separator();
                    let uid: String = dump.uid.iter().map(|b| format!("{b:02X}")).collect();
                    egui::CollapsingHeader::new(format!("Dump result — UID {uid}"))
                        .default_open(true)
                        .show(ui, |ui| {
                            egui::ScrollArea::vertical()
                                .max_height(220.0)
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    ui.monospace(dump.to_text());
                                });
                        });
                }
            });
                }); // close ScrollArea
        });
    }
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([560.0, 720.0])
            .with_min_inner_size([460.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native(
        "wCopy Smart Reader",
        native_options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
