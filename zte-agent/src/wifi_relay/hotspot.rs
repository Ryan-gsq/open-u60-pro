//! Owns relay changes to the existing hotspots. One preparation per band:
//! 2.4 GHz uses disable/set/enable (CSA cannot restore HT40 on B31);
//! 5 GHz always stages at non-DFS 20 MHz, then lets the driver follow STA.
//! Every changed runtime setting has a journaled undo. Owner OFF wins.
use super::{ap, dfs_switch, net, scan::Channels, Cmd, Step, Transaction, HOSTAPD};
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

pub(super) fn prepare(
    tx: &mut Transaction,
    upstream: u32,
    channels: &Channels,
) -> Result<(), String> {
    if upstream < 3000 {
        return prepare_2ghz(tx, upstream);
    }
    dfs_switch::allow();
    let before = Cmd::new("iw", &["dev", "wlan2", "info"]).run()?;
    let (frequency, bandwidth, center) =
        parse_channel(&before).ok_or("Cannot snapshot hotspot channel")?;
    let staging = staging(channels, frequency, bandwidth).ok_or("No enabled non-DFS hotspot staging channel")?;
    tx.apply(Step::new(
        command(staging, 20, staging),
        command(frequency, bandwidth, center),
    ))
}

/// A switch to another 5 GHz upstream keeps the session's hotspot journal,
/// whose undo still returns the hotspot to the owner's channel: the hotspot
/// only goes back to the non-DFS staging channel, where the next
/// association takes it along again. On the DFS channel it followed the
/// station to, a new association does not complete (B31, 2026-11-10), and
/// the owner's 160 MHz channel would first need a radar check of about
/// 60 s. Leaving a DFS channel needs none; nothing is journaled here.
pub(super) fn restage(channels: &Channels) -> Result<(), String> {
    dfs_switch::allow();
    let before = Cmd::new("iw", &["dev", "wlan2", "info"]).run()?;
    let (frequency, bandwidth, _) = parse_channel(&before).ok_or("Cannot read the hotspot channel")?;
    let staging = staging(channels, frequency, bandwidth).ok_or("No enabled non-DFS hotspot staging channel")?;
    command(staging, 20, staging).run().map(|_| ())
}

/// The non-DFS 20 MHz channel to stage at from `frequency`/`bandwidth`: a
/// switch that keeps the primary channel is refused (`switch_with`).
fn staging(channels: &Channels, frequency: u32, bandwidth: u32) -> Option<u32> {
    channels
        .staging_5ghz()
        .filter(|staging| *staging != frequency || bandwidth == 20)
        .or_else(|| channels.staging_5ghz_avoiding(frequency))
}

/// `(primary MHz, width MHz, center1 MHz)` from `iw dev <if> info`.
fn parse_channel(info: &str) -> Option<(u32, u32, u32)> {
    let line = info.lines().map(str::trim).find(|l| l.starts_with("channel "))?;
    let number = |key: &str| line.split_once(key)?.1.trim_start().split(|c: char| !c.is_ascii_digit()).next()?.parse().ok();
    Some((number("(")?, number("width:")?, number("center1:")?))
}

/// File reads only: the three-second relay watcher must not spawn extra UCI
/// processes. Missing configuration is unknown, not proof of an owner OFF.
pub(super) fn owner_off(iface: &str) -> bool {
    fs::read_to_string("/etc/config/wireless").is_ok_and(|text| configured_off(&text, iface))
}

/// Whether the hotspot is off by the owner's own choice, which cancels the
/// relay's restart choice, and not only off for now. The vendor keeps the
/// owner's Wi-Fi switch in `zte_mbb.wifi_onoff_by_user` (its boot and scan
/// scripts read that one) and the present state in `wifi_onoff`, which it
/// also sets to 0 where the owner turned nothing off: in power-off charging
/// mode after a low-battery shutdown, where it does not start Wi-Fi (B31,
/// 2026-11-12: the restart choice was cleared for it). A firmware without
/// the owner's key leaves only `wifi_onoff` to tell.
pub(super) fn off_by_owner(iface: &str) -> bool {
    fs::read_to_string("/etc/config/wireless").is_ok_and(|text| configured_off_by_owner(&text, iface))
}

fn sections(iface: &str) -> (&'static str, &'static str) {
    if iface == "wlan0" {
        ("wifi0", "main_2g")
    } else {
        ("wifi1", "main_5g")
    }
}

fn configured_off(text: &str, iface: &str) -> bool {
    let option = |section, key| crate::wifi_watchdog::config_option(text, section, key);
    let (radio, ssid) = sections(iface);
    option("zte_mbb", "wifi_onoff").as_deref() == Some("0")
        || option(radio, "disabled").as_deref() == Some("1")
        || option(ssid, "disabled").as_deref() == Some("1")
}

fn configured_off_by_owner(text: &str, iface: &str) -> bool {
    let option = |section, key| crate::wifi_watchdog::config_option(text, section, key);
    let (radio, ssid) = sections(iface);
    let switched_off = match option("zte_mbb", "wifi_onoff_by_user") {
        Some(by_user) => by_user == "0",
        None => option("zte_mbb", "wifi_onoff").as_deref() == Some("0"),
    };
    switched_off || option(radio, "disabled").as_deref() == Some("1") || option(ssid, "disabled").as_deref() == Some("1")
}

/// All hotspot undos (including journals from older releases) share this
/// policy. A removed/disabled hotspot no longer owns a runtime snapshot.
pub(crate) fn skip_undo(cmd: &Cmd) -> bool {
    let iface = if cmd.program == "@u60-relay-channel" {
        Some("wlan2")
    } else if cmd.program == "hostapd_cli" {
        cmd.args
            .windows(2)
            .find(|w| w[0] == "-i")
            .map(|w| w[1].as_str())
    } else {
        None
    };
    iface
        .filter(|i| matches!(*i, "wlan0" | "wlan2"))
        .is_some_and(|i| owner_off(i) || !Path::new(&format!("/sys/class/net/{i}")).exists())
}

fn prepare_2ghz(tx: &mut Transaction, frequency: u32) -> Result<(), String> {
    let iface = "wlan0";
    let channel =
        super::channel(frequency).ok_or("Only 2.4 GHz and 5 GHz upstreams are supported")?;
    let before = ap(iface, "status", &[])?;
    if net::key(&before, "state") != Some("ENABLED") {
        return Err("The matching main hotspot must be enabled".into());
    }
    let original = fs::read_to_string(format!("/data/vendor/wifi/hostapd-{iface}.conf"))
        .map_err(|_| "Cannot snapshot hotspot configuration")?;
    let ht = net::key(&original, "ht_capab").ok_or("Cannot snapshot hotspot HT capabilities")?;
    let mut pairs = vec![
        (
            "channel",
            channel.to_string(),
            net::key(&before, "channel")
                .ok_or("Cannot snapshot hotspot channel")?
                .to_owned(),
        ),
        ("ht_capab", "[SHORT-GI-20]".into(), ht.to_owned()),
    ];
    for key in [
        "vht_oper_chwidth",
        "vht_oper_centr_freq_seg0_idx",
        "he_oper_chwidth",
        "he_oper_centr_freq_seg0_idx",
        "eht_oper_chwidth",
        "eht_oper_centr_freq_seg0_idx",
    ] {
        let fallback = if key.ends_with("idx") {
            "vht_oper_centr_freq_seg0_idx"
        } else {
            "vht_oper_chwidth"
        };
        let found = net::key(&before, key)
            .or_else(|| net::key(&original, key))
            .or_else(|| net::key(&before, fallback));
        // A 2.4 GHz hotspot runs without VHT, so it has no `vht_oper_*` to snapshot or restore.
        let Some(old) = found else {
            if key.starts_with("vht_") {
                continue;
            }
            return Err("Cannot snapshot hotspot channel width".into());
        };
        pairs.push((
            key,
            if key.ends_with("idx") {
                channel.to_string()
            } else {
                "0".into()
            },
            old.into(),
        ));
    }
    let control = |action: &str, args: &[&str]| {
        let mut a = vec!["-p", HOSTAPD, "-i", iface, action];
        a.extend_from_slice(args);
        Cmd::new("hostapd_cli", &a)
    };
    tx.apply(Step::new(control("disable", &[]), control("enable", &[])))?;
    for (key, new, old) in &pairs {
        tx.apply(Step::new(
            control("set", &[key, new]),
            control("set", &[key, old]),
        ))?;
    }
    if owner_off(iface) {
        return Err("Hotspot was turned off while preparing relay".into());
    }
    tx.apply(Step::new(control("enable", &[]), control("disable", &[])))?;
    std::thread::sleep(Duration::from_secs(2));
    let after = ap(iface, "status", &[])?;
    let driver = Cmd::new("iw", &["dev", iface, "info"]).run()?;
    if net::key(&after, "state") != Some("ENABLED")
        || net::key(&after, "freq") != Some(&frequency.to_string())
        || !driver.contains(&format!("({frequency} MHz)"))
    {
        return Err("Hotspot channel change was not confirmed by the driver".into());
    }
    Ok(())
}

fn command(frequency: u32, bandwidth: u32, center: u32) -> Cmd {
    Cmd::new(
        "@u60-relay-channel",
        &[
            &frequency.to_string(),
            &bandwidth.to_string(),
            &center.to_string(),
        ],
    )
}

pub(crate) fn switch(args: &[String]) -> Result<(), String> {
    if owner_off("wlan2") {
        return Err("Hotspot was turned off during relay channel change".into());
    }
    let started = Instant::now();
    switch_with(
        args,
        |cmd| {
            if owner_off("wlan2") {
                return Err("Hotspot was turned off during relay channel change".into());
            }
            net::run(cmd.command(), Duration::from_secs(2))
        },
        || started.elapsed(),
        || std::thread::sleep(Duration::from_secs(1)),
        |avoid| {
            let phy = super::radio_phy().ok()?;
            let channels = Cmd::new("iw", &["phy", &phy, "channels"]).run().ok()?;
            Channels::parse(&channels).staging_5ghz_avoiding(avoid)
        },
    )
}

fn chan_switch(frequency: u32, bandwidth: u32, center: u32) -> Cmd {
    let low = center + 10 - bandwidth / 2;
    let mut args = vec![
        "-p".into(),
        HOSTAPD.into(),
        "-i".into(),
        "wlan2".into(),
        "chan_switch".into(),
        "5".into(),
        frequency.to_string(),
    ];
    if bandwidth > 20 {
        let offset = if ((frequency - low) / 20).is_multiple_of(2) { 1 } else { -1 };
        args.push(format!("sec_channel_offset={offset}"));
        args.push(format!("center_freq1={center}"));
    }
    args.push(format!("bandwidth={bandwidth}"));
    args.push("ht".into());
    if bandwidth >= 80 {
        args.push("vht".into());
    }
    Cmd { program: "hostapd_cli".into(), args }
}

fn switch_with(
    args: &[String],
    mut run: impl FnMut(&Cmd) -> Result<String, String>,
    mut elapsed: impl FnMut() -> Duration,
    mut wait: impl FnMut(),
    intermediate: impl FnOnce(u32) -> Option<u32>,
) -> Result<(), String> {
    let values: Vec<u32> = args.iter().filter_map(|s| s.parse().ok()).collect();
    let [frequency, bandwidth, center] = values.as_slice() else {
        return Err("Invalid hotspot recovery channel".into());
    };
    if args.len() != 3
        || !(5000..5900).contains(frequency)
        || ![20, 40, 80, 160].contains(bandwidth)
        || center.abs_diff(*frequency) >= bandwidth / 2
    {
        return Err("Invalid hotspot recovery channel".into());
    }
    let low = center + 10 - bandwidth / 2;
    if *frequency < low || !(frequency - low).is_multiple_of(20) {
        return Err("Invalid hotspot recovery channel".into());
    }
    let info = Cmd::new("iw", &["dev", "wlan2", "info"]);
    let status = Cmd::new("hostapd_cli", &["-p", HOSTAPD, "-i", "wlan2", "status"]);
    let target = (*frequency, *bandwidth, *center);
    let current = run(&info)?;
    let now = parse_channel(&current);
    if now != Some(target) {
        if crate::net_tools::key(&run(&status)?, "state") != Some("ENABLED") {
            return Err("Wait for the hotspot radar check before connecting relay".into());
        }
        // B31 rejects a CSA that keeps the primary channel and changes only
        // the width (CSA failed, -22): go through another non-DFS channel.
        if now.is_some_and(|(primary, _, _)| primary == *frequency) {
            let via = intermediate(*frequency).ok_or("No other non-DFS channel to change the hotspot width through")?;
            if run(&chan_switch(via, 20, via))?.lines().last() != Some("OK") {
                return Err("Hotspot refused the channel switch".into());
            }
            loop {
                if crate::net_tools::key(&run(&status)?, "state") == Some("ENABLED")
                    && parse_channel(&run(&info)?) == Some((via, 20, via))
                {
                    break;
                }
                if elapsed() >= Duration::from_secs(80) {
                    return Err("Hotspot channel switch or radar check did not finish; recovery retained".into());
                }
                wait();
            }
        }
        if run(&chan_switch(*frequency, *bandwidth, *center))?.lines().last() != Some("OK") {
            return Err("Hotspot refused the channel switch".into());
        }
    }
    // A return to a 160 MHz hotspot may need the full 60 s CAC. Confirm
    // completion before removing the journal; never skip radar checks.
    while elapsed() < Duration::from_secs(80) {
        if crate::net_tools::key(&run(&status)?, "state") == Some("ENABLED")
            && parse_channel(&run(&info)?) == Some(target)
        {
            return Ok(());
        }
        wait();
    }
    Err("Hotspot channel switch or radar check did not finish; recovery retained".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn a_handed_over_hotspot_leaves_its_dfs_channel_for_the_non_dfs_staging_one() {
        let channels = Channels::parse("\t* 5180 MHz [36]\n\t* 5200 MHz [40]\n\t* 5260 MHz [52]\n\t  Radar detection\n");
        assert_eq!(staging(&channels, 5260, 160), Some(5180), "from the channel the station took it to");
        assert_eq!(staging(&channels, 5180, 20), Some(5180), "already staged");
        assert_eq!(staging(&channels, 5180, 160), Some(5200), "a width-only switch is refused, so through another channel");
        let only = Channels::parse("\t* 5180 MHz [36]\n\t* 5260 MHz [52]\n\t  Radar detection\n");
        assert_eq!(staging(&only, 5180, 160), None);
    }

    #[test]
    fn channel_lines_parse() {
        assert_eq!(parse_channel("Interface ath20\n\tchannel 44 (5220 MHz), width: 160 MHz, center1: 5250 MHz\n"), Some((5220, 160, 5250)));
        assert_eq!(parse_channel("channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz"), Some((2437, 20, 2437)));
        assert_eq!(parse_channel("Interface ath20\n\ttype managed\n"), None);
    }

    #[test]
    fn external_off_wins_over_runtime_restore() {
        for text in [
            "config zte_mbb 'zte_mbb'\n option wifi_onoff '0'\n",
            "config wifi-device 'wifi1'\n option disabled '1'\n",
            "config wifi-iface 'main_5g'\n option disabled '1'\n",
        ] {
            assert!(configured_off(text, "wlan2"));
        }
        assert!(
            !configured_off("", "wlan2"),
            "unknown config is not owner OFF"
        );
        assert!(!configured_off(
            "config wifi-device 'wifi0'\n option disabled '1'\n",
            "wlan2"
        ));
        assert!(configured_off(
            "config wifi-device 'wifi0'\n option disabled '1'\n",
            "wlan0"
        ));
    }

    #[test]
    fn wifi_the_firmware_keeps_off_is_not_the_owners_off() {
        // Power-off charging mode on B31: the state is 0, the owner's switch still 1.
        let charging = "config zte_mbb 'zte_mbb'\n option wifi_onoff '0'\n option wifi_onoff_by_user '1'\n";
        assert!(configured_off(charging, "wlan2"), "the hotspot is off");
        assert!(!configured_off_by_owner(charging, "wlan2"), "but the restart choice stays");
        for text in [
            "config zte_mbb 'zte_mbb'\n option wifi_onoff '0'\n option wifi_onoff_by_user '0'\n",
            "config zte_mbb 'zte_mbb'\n option wifi_onoff '1'\n option wifi_onoff_by_user '0'\n",
            "config zte_mbb 'zte_mbb'\n option wifi_onoff '0'\n",
            "config wifi-device 'wifi1'\n option disabled '1'\n",
            "config zte_mbb 'zte_mbb'\n option wifi_onoff_by_user '1'\nconfig wifi-iface 'main_5g'\n option disabled '1'\n",
        ] {
            assert!(configured_off_by_owner(text, "wlan2"), "{text}");
        }
        assert!(!configured_off_by_owner("", "wlan2"), "unknown config is not owner OFF");
        assert!(!configured_off_by_owner("config zte_mbb 'zte_mbb'\n option wifi_onoff '1'\n option wifi_onoff_by_user '1'\n", "wlan2"));
    }

    #[test]
    fn recovery_deadline_includes_slow_commands() {
        let elapsed = Cell::new(Duration::ZERO);
        let calls = Cell::new(0);
        let result = switch_with(
            &["5180".into(), "160".into(), "5250".into()],
            |cmd| {
                calls.set(calls.get() + 1);
                elapsed.set(elapsed.get() + Duration::from_secs(2));
                Ok(if cmd.program == "iw" {
                    "channel 36 (5180 MHz), width: 160 MHz, center1: 5250 MHz"
                } else {
                    "state=DFS"
                }
                .into())
            },
            || elapsed.get(),
            || elapsed.set(elapsed.get() + Duration::from_secs(1)),
            |_| None,
        );
        assert!(result.unwrap_err().contains("recovery retained"));
        assert!(elapsed.get() <= Duration::from_secs(83));
        assert!(
            calls.get() < 30,
            "CAC must not launch hundreds of processes"
        );
    }
    #[test]
    fn dfs_join_staging_and_recovery_wait_for_the_real_channel() {
        let channels = Channels::parse(
            "* 5180 MHz [36]\n* 5260 MHz [52]\n  Radar detection\n* 5500 MHz [100] (disabled)\n",
        );
        assert_eq!(channels.staging_5ghz(), Some(5180));
        assert!(channels.contains(5260));
        assert!(!channels.contains(5500));
        let mut switched = false;
        let mut polls = 0;
        let waits = Cell::new(0);
        switch_with(
            &["5180".into(), "160".into(), "5250".into()],
            |cmd| {
                if cmd.program == "iw" {
                    return Ok(if switched {
                        "channel 36 (5180 MHz), width: 160 MHz, center1: 5250 MHz"
                    } else {
                        "channel 52 (5260 MHz), width: 160 MHz, center1: 5250 MHz"
                    }
                    .into());
                }
                if cmd.args.iter().any(|s| s == "chan_switch") {
                    assert!(cmd.args.contains(&"sec_channel_offset=1".into()));
                    assert!(cmd.args.contains(&"center_freq1=5250".into()));
                    switched = true;
                    return Ok("OK".into());
                }
                polls += 1;
                Ok(if switched && polls < 4 {
                    "state=DFS"
                } else {
                    "state=ENABLED"
                }
                .into())
            },
            || Duration::from_secs(waits.get()),
            || waits.set(waits.get() + 1),
            |_| None,
        )
        .unwrap();
        assert_eq!(waits.get(), 2);
        assert!(switch_with(
            &["5180".into(), "20".into(), "5180".into()],
            |cmd| {
                Ok(if cmd.program == "iw" {
                    "channel 52 (5260 MHz), width: 160 MHz, center1: 5250 MHz"
                } else if cmd.args.iter().any(|s| s == "chan_switch") {
                    "FAIL"
                } else {
                    "state=ENABLED"
                }
                .into())
            },
            || Duration::ZERO,
            || panic!("refused CSA must fail immediately"),
            |_| None
        )
        .is_err());
    }

    #[test]
    fn a_width_change_on_the_same_primary_goes_through_another_channel() {
        // 36/40 -> 36/20 is refused by the driver as one CSA (ret -22).
        let mut at = (5180, 40, 5190);
        let mut switches = Vec::new();
        switch_with(
            &["5180".into(), "20".into(), "5180".into()],
            |cmd| {
                if cmd.program == "iw" {
                    return Ok(format!("channel x ({} MHz), width: {} MHz, center1: {} MHz", at.0, at.1, at.2));
                }
                if cmd.args.iter().any(|s| s == "chan_switch") {
                    let frequency: u32 = cmd.args[6].parse().unwrap();
                    let width: u32 = cmd.args.iter().find_map(|a| a.strip_prefix("bandwidth=")).unwrap().parse().unwrap();
                    if frequency == at.0 {
                        return Ok("FAIL".into());
                    }
                    switches.push((frequency, width));
                    at = (frequency, width, frequency);
                    return Ok("OK".into());
                }
                Ok("state=ENABLED".into())
            },
            || Duration::ZERO,
            || {},
            |avoid| (avoid != 5200).then_some(5200),
        )
        .unwrap();
        assert_eq!(switches, [(5200, 20), (5180, 20)]);
        let channels = Channels::parse("* 5180 MHz [36]\n* 5200 MHz [40]\n* 5260 MHz [52]\n  Radar detection\n");
        assert_eq!(channels.staging_5ghz_avoiding(5180), Some(5200));
        assert_eq!(channels.staging_5ghz_avoiding(5260), Some(5180));
    }
}
