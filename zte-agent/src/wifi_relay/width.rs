//! The upstream link width: reset to the negotiated width after each
//! association, and the `iw` channel line the hotspot code reads. Automatic
//! width tuning was retired (v6, `relay-mihomo-refactor-plan.md`); a saved
//! `auto` choice reads as keeping the negotiated width.
//!
//! B31's `iwpriv u60sta0 chwidth` survives disconnects, interface
//! re-creation and band changes: the readback shows the negotiated width
//! while the upstream AP still sends at an old narrow one. Re-sending the same
//! value does nothing, so the reset steps through a narrower width and back.
use std::time::Duration;

use super::{Cmd, IFACE};

/// Between two `iwpriv chwidth` writes; only 1 s was verified on the device.
const TOGGLE_PAUSE: Duration = Duration::from_secs(1);

/// `(primary MHz, width MHz, center1 MHz)` from `iw dev <if> info`.
pub(super) fn parse_channel(info: &str) -> Option<(u32, u32, u32)> {
    let line = info.lines().map(str::trim).find(|l| l.starts_with("channel "))?;
    let number = |key: &str| line.split_once(key)?.1.trim_start().split(|c: char| !c.is_ascii_digit()).next()?.parse().ok();
    Some((number("(")?, number("width:")?, number("center1:")?))
}

fn narrower(width: u32) -> Option<u32> {
    match width {
        160 => Some(80),
        80 => Some(40),
        40 => Some(20),
        _ => None,
    }
}

fn chwidth_code(width: u32) -> Option<&'static str> {
    match width {
        20 => Some("0"),
        40 => Some("1"),
        80 => Some("2"),
        160 => Some("3"),
        _ => None,
    }
}

/// The station's channel and width, as the reset needs them.
trait Link {
    fn channel(&mut self) -> Result<(u32, u32, u32), String>;
    fn apply(&mut self, width: u32) -> Result<(), String>;
    fn pause(&mut self);
}

struct Device;

fn query(cmd: Cmd) -> Result<String, String> {
    crate::net_tools::run(cmd.command(), Duration::from_secs(1))
}

impl Link for Device {
    fn channel(&mut self) -> Result<(u32, u32, u32), String> {
        parse_channel(&query(Cmd::new("iw", &["dev", IFACE, "info"]))?).ok_or_else(|| "Cannot read the upstream channel width".into())
    }

    fn apply(&mut self, width: u32) -> Result<(), String> {
        let code = chwidth_code(width).ok_or("Unsupported upstream channel width")?;
        query(Cmd::new("iwpriv", &[IFACE, "chwidth", code])).map(|_| ()).map_err(|_| "Cannot change the upstream channel width".into())
    }

    fn pause(&mut self) {
        std::thread::sleep(TOGGLE_PAUSE);
    }
}

/// After each new association: back to the negotiated width.
pub(super) fn reset_width() {
    crate::httpd::gate::debug_assert_may_block();
    match reset(&mut Device) {
        Ok(Some(width)) => crate::netlog!("[relay-width] upstream width reset to the negotiated {width} MHz"),
        Ok(None) => {}
        Err(e) => crate::netlog!("[relay-width] cannot reset the upstream width: {e}"),
    }
}

fn reset(io: &mut impl Link) -> Result<Option<u32>, String> {
    let (_, width, _) = io.channel()?;
    let Some(lower) = narrower(width) else { return Ok(None) };
    io.apply(lower)?;
    io.pause();
    io.apply(width)?;
    let (_, readback, _) = io.channel()?;
    if readback != width {
        return Err(format!("readback {readback} MHz, expected {width} MHz"));
    }
    Ok(Some(width))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mock {
        actual: u32,
        readback: bool,
        writes: Vec<u32>,
        pauses: usize,
    }

    impl Mock {
        fn new(actual: u32) -> Self {
            Self { actual, readback: true, writes: Vec::new(), pauses: 0 }
        }
    }

    impl Link for Mock {
        fn channel(&mut self) -> Result<(u32, u32, u32), String> {
            if self.readback { Ok((2412, self.actual, 2422)) } else { Err("missing".into()) }
        }
        fn apply(&mut self, width: u32) -> Result<(), String> {
            self.writes.push(width);
            self.actual = width;
            Ok(())
        }
        fn pause(&mut self) {
            self.pauses += 1;
        }
    }

    #[test]
    fn join_reset_goes_through_a_narrower_width_and_confirms_the_negotiated_one() {
        let mut io = Mock::new(40);
        assert_eq!(reset(&mut io), Ok(Some(40)));
        assert_eq!((io.writes.as_slice(), io.pauses), (&[20, 40][..], 1));
        let mut io = Mock::new(160);
        assert_eq!(reset(&mut io), Ok(Some(160)));
        assert_eq!(io.writes, [80, 160]);
        let mut io = Mock::new(20);
        assert_eq!(reset(&mut io), Ok(None), "nothing narrower to step through");
        assert!(io.writes.is_empty());
        let mut io = Mock::new(40);
        io.readback = false;
        assert!(reset(&mut io).is_err());
        assert!(io.writes.is_empty());
    }

    #[test]
    fn channel_lines_and_width_codes_parse() {
        assert_eq!(parse_channel("Interface u60sta0\n\tchannel 44 (5220 MHz), width: 160 MHz, center1: 5250 MHz\n"), Some((5220, 160, 5250)));
        assert_eq!(parse_channel("channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz"), Some((2437, 20, 2437)));
        assert_eq!(parse_channel("Interface u60sta0\n\ttype managed\n"), None);
        assert_eq!((chwidth_code(20), chwidth_code(160), chwidth_code(320)), (Some("0"), Some("3"), None));
    }
}
