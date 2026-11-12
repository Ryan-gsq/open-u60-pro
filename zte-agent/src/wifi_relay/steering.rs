//! CPU-path help while relaying (owner decision 63): what IPA does not carry
//! (Mihomo, NAT66, the first packets of each connection, router traffic) is
//! received on the CPUs that service the Wi-Fi datapath interrupts. RPS moves
//! the rest of its processing to the other CPUs; a deeper backlog absorbs the
//! bursts RPS queues (softnet drops were seen at the default 1000).
//! Journaled with the session's network plan and restored at teardown.

use std::{fs, path::Path};

use super::{Internal, Resource, IFACE};

const DOWNSTREAM: &str = "wlan2";
const BACKLOG: &str = "/proc/sys/net/core/netdev_max_backlog";
const BACKLOG_FLOOR: u32 = 5000;

pub(super) fn plan() -> Vec<Resource> {
    let mut plan = Vec::new();
    if let Some(mask) = fs::read_to_string("/proc/interrupts").ok().and_then(|t| spare_cpus(&t)) {
        for iface in [IFACE, DOWNSTREAM] {
            if let Some(old) = rps(iface).filter(|old| *old != mask) {
                plan.push(Resource::Internal(Internal::new("@u60-relay-steer", super::words(&["rps", iface, &format!("{mask:x}")]), super::words(&["rps", iface, &format!("{old:x}")]))));
            }
        }
    }
    if let Some(old) = fs::read_to_string(BACKLOG).ok().and_then(|s| s.trim().parse::<u32>().ok()) {
        if old < BACKLOG_FLOOR {
            plan.push(Resource::Internal(Internal::new("@u60-relay-steer", super::words(&["backlog", &BACKLOG_FLOOR.to_string()]), super::words(&["backlog", &old.to_string()]))));
        }
    }
    plan
}

/// CPUs that took none of the Wi-Fi interrupts (B31: CPU0/1 take them).
fn spare_cpus(interrupts: &str) -> Option<u32> {
    let mut lines = interrupts.lines();
    let cpus = lines.next()?.split_whitespace().filter(|c| c.starts_with("CPU")).count();
    if !(2..32).contains(&cpus) {
        return None;
    }
    let mut busy = 0u32;
    for line in lines.filter(|l| l.contains("wlan")) {
        for (cpu, count) in line.split_whitespace().skip(1).take(cpus).enumerate() {
            if count.parse::<u64>().is_ok_and(|c| c > 0) {
                busy |= 1 << cpu;
            }
        }
    }
    Some(((1u32 << cpus) - 1) & !busy).filter(|m| *m != 0)
}

fn queues(iface: &str) -> Vec<std::path::PathBuf> {
    let mut queues: Vec<_> = fs::read_dir(format!("/sys/class/net/{iface}/queues"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_str().is_some_and(|n| n.starts_with("rx-")))
        .map(|e| e.path().join("rps_cpus"))
        .collect();
    queues.sort();
    queues
}

/// The interface's RPS mask when every receive queue has the same one.
fn rps(iface: &str) -> Option<u32> {
    let masks: Vec<u32> = queues(iface)
        .iter()
        .map(|q| fs::read_to_string(q).ok().and_then(|s| u32::from_str_radix(&s.trim().replace(',', ""), 16).ok()))
        .collect::<Option<_>>()?;
    masks.first().copied().filter(|m| masks.iter().all(|x| x == m))
}

/// `@u60-relay-steer rps <iface> <hex>` | `backlog <n>`.
pub(crate) fn command(args: &[String]) -> Result<(), String> {
    match args {
        [what, iface, mask] if what == "rps" && (iface == IFACE || iface == DOWNSTREAM) => {
            let mask = u32::from_str_radix(mask, 16).map_err(|_| "Invalid RPS mask")?;
            // Undo after the relay interface is gone: nothing left to restore.
            if !Path::new(&format!("/sys/class/net/{iface}")).exists() {
                return Ok(());
            }
            for queue in queues(iface) {
                fs::write(&queue, format!("{mask:x}")).map_err(|_| "Cannot set receive steering")?;
            }
            Ok(())
        }
        [what, value] if what == "backlog" => {
            let value: u32 = value.parse().ok().filter(|v| (1..=100_000).contains(v)).ok_or("Invalid backlog")?;
            fs::write(BACKLOG, value.to_string()).map_err(|_| "Cannot set the receive backlog".into())
        }
        _ => Err("Invalid receive steering".into()),
    }
}

/// Whether an applied `@u60-relay-steer` still holds.
pub(crate) fn present(args: &[String]) -> bool {
    match args {
        [what, iface, mask] if what == "rps" => {
            !Path::new(&format!("/sys/class/net/{iface}")).exists() || u32::from_str_radix(mask, 16).ok() == rps(iface)
        }
        [what, value] if what == "backlog" => fs::read_to_string(BACKLOG).is_ok_and(|v| v.trim() == value),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steering_avoids_the_cpus_that_take_wifi_interrupts() {
        let b31 = "           CPU0       CPU1       CPU2       CPU3\n\
            32:        132          0          0          0     GICv3 346 Level     ipa\n\
           159:    5908049    2200202          0          0  gic_msm_pci_msi 524293 Edge      pci0_wlan_ce_2\n\
           168:   22991343   10355904          0          0  gic_msm_pci_msi 524302 Edge      pci0_wlan_grp_dp_0\n\
           169:          0          0          0          0  gic_msm_pci_msi 524303 Edge      pci0_wlan_grp_dp_1\n";
        assert_eq!(spare_cpus(b31), Some(0xc));
        let all = "  CPU0 CPU1\n 1: 5 7 x wlan\n";
        assert_eq!(spare_cpus(all), None, "no spare CPU means no steering");
        assert!(command(&["rps".into(), "br-lan".into(), "c".into()]).is_err());
        assert!(command(&["backlog".into(), "0".into()]).is_err());
    }
}
