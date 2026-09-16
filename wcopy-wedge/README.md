# wcopy-wedge

Turns the wCopy reader into a **keyboard-wedge input device**: it polls for a tag and, when
one is presented, "types" its UID as a decimal number followed by Enter into whatever
application currently has keyboard focus (spreadsheet, text field, login box, …). Built on the
`wcopy` library; key injection via `enigo`. Part of the [wcopy](../README.md) workspace.

## Run

```bash
# from the repo root
cargo run --release -p wcopy-wedge -- --dry-run     # prints instead of typing (safe test)
cargo run --release -p wcopy-wedge                  # real typing
```

Then focus your target app and present a tag. Stop with Ctrl-C.

**macOS:** real key injection requires **Accessibility** permission — grant it to the
terminal (or the bundled app) under *System Settings > Privacy & Security > Accessibility*.
`--dry-run` needs no permission.

## Options

```
--be | --le        UID byte order for the decimal value (default --be)
--dry-run          print what would be typed instead of typing it
--no-enter         do not append Enter
--no-beep          do not sound the reader's buzzer on a read
--beep-settle <MS> pause after the beep so it isn't cut off (default 800)
--prefix <STR>     type <STR> before the number
--pad <N>          zero-pad the decimal to at least N digits
--interval <MS>    poll interval in milliseconds (default 200)
```

Example: UID `35 30 94 49` → `892376137` (big-endian) or `1234448437` (`--le`).

## Behavior

- **Beep on read:** the reader's own buzzer sounds on each successful read. No standalone beep
  command was found in the firmware, but the magic-card probe sequence (`probe_gen1a`) makes the
  reader buzz, so the wedge fires it as the beep. The buzzer plays asynchronously, so the wedge
  pauses `--beep-settle` ms (default 800) afterwards — otherwise the next poll's RF commands cut
  the beep short. Disable with `--no-beep`.
- **Debounced:** one keystroke burst per *presentation*. A tag left on the reader is not
  re-typed; remove it and present it again to fire again.
- **Non-blocking poll:** the RF field is brought up once and kept on; polling uses
  InListPassiveTarget with a low retry count so absent-tag polls return quickly. (Power-cycling
  the field every poll races the tag's power-up and misses reads.)

## Notes / ideas

- To run it as a background "device", package it with `cargo bundle` (add a
  `[package.metadata.bundle]` block like `wcopy-gui`) and set it as a macOS login item, or
  make it an `LSUIElement` agent.
- UID→decimal byte order is reader-dependent in the wild; pick `--be`/`--le` to match whatever
  system you're feeding, and use `--dry-run` to confirm before going live.
