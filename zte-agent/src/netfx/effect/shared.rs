use std::cell::RefCell;
use std::fs;

use crate::net_tools::{Cmd, Probe};

#[derive(Default)]
pub struct Listings {
    read: Vec<(Cmd, Result<String, String>)>,
}

impl Listings {
    pub(crate) fn get(&mut self, listing: Cmd, probe: &mut impl Probe) -> Result<&str, String> {
        let index = match self.read.iter().position(|(command, _)| *command == listing) {
            Some(index) => index,
            None => {
                let text = probe.list(&listing).map_err(|error| format!("{} {}: {error}", listing.program, listing.args.join(" ")));
                self.read.push((listing, text));
                self.read.len() - 1
            }
        };
        self.read[index].1.as_deref().map_err(Clone::clone)
    }
}

thread_local! {
    static PASS: RefCell<Option<Listings>> = const { RefCell::new(None) };
    static NFT_READ: RefCell<Option<Result<String, String>>> = const { RefCell::new(None) };
    static PASS_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[must_use]
pub struct Pass {
    opened: bool,
}

impl Pass {
    pub fn open() -> Self {
        let opened = PASS_DEPTH.with(|depth| {
            let opened = depth.get() == 0;
            depth.set(depth.get() + 1);
            opened
        });
        if opened {
            PASS.with(|pass| *pass.borrow_mut() = Some(Listings::default()));
            NFT_READ.with(|read| read.borrow_mut().take());
        }
        Self { opened }
    }
}

impl Drop for Pass {
    fn drop(&mut self) {
        PASS_DEPTH.with(|depth| depth.set(depth.get() - 1));
        if self.opened {
            PASS.with(|pass| pass.borrow_mut().take());
            NFT_READ.with(|read| read.borrow_mut().take());
        }
    }
}

pub(crate) fn changed() {
    NFT_READ.with(|read| read.borrow_mut().take());
    PASS.with(|pass| {
        if let Some(listings) = pass.borrow_mut().as_mut() {
            *listings = Listings::default();
        }
    });
}

pub(crate) fn nft_ruleset(read: impl FnOnce() -> Result<String, String>) -> Result<String, String> {
    if PASS_DEPTH.with(|depth| depth.get() == 0) {
        return read();
    }
    NFT_READ.with(|cached| cached.borrow_mut().get_or_insert_with(read).clone())
}

pub(crate) fn with_listings<Result>(check: impl FnOnce(&mut Listings) -> Result) -> Result {
    let pass = Pass::open();
    let mut listings = PASS.with(|pass| pass.borrow_mut().take()).unwrap_or_default();
    let result = check(&mut listings);
    PASS.with(|pass| *pass.borrow_mut() = Some(listings));
    drop(pass);
    result
}

const ROUTE_TYPES: [&str; 9] = ["local", "broadcast", "throw", "unreachable", "prohibit", "blackhole", "nat", "anycast", "multicast"];

pub(crate) fn route_matches(listing: &str, kind: &str, destination: &str, table: &str, device: Option<&str>, gateway: Option<&str>, metric: Option<u32>) -> bool {
    listing.lines().any(|line| {
        let words: Vec<_> = line.split_whitespace().collect();
        let (listed, rest) = match words.as_slice() {
            [first, rest @ ..] if ROUTE_TYPES.contains(first) => (*first, rest),
            words => ("unicast", words),
        };
        let Some((to, rest)) = rest.split_first() else { return false };
        let value = |name| rest.windows(2).find(|pair| pair[0] == name).map(|pair| pair[1]);
        listed == kind
            && route_destination(to) == route_destination(destination)
            && route_table(value("table").unwrap_or("main")) == route_table(table)
            && device.is_none_or(|device| value("dev") == Some(device))
            && gateway.is_none_or(|gateway| value("via") == Some(gateway))
            && metric.is_none_or(|metric| value("metric").and_then(|value| value.parse::<u32>().ok()) == Some(metric))
    })
}

pub(crate) fn route_destination(text: &str) -> String {
    let (ip, length) = text.split_once('/').map_or((text, None), |(ip, length)| (ip, length.parse::<u8>().ok()));
    match ip.parse::<std::net::IpAddr>() {
        Ok(_) if length == Some(0) => "default".into(),
        Ok(ip) => format!("{ip}/{}", length.unwrap_or(if ip.is_ipv4() { 32 } else { 128 })),
        Err(_) => text.into(),
    }
}

pub(crate) fn route_table(name: &str) -> String {
    match name {
        "main" => "254".into(),
        "local" => "255".into(),
        "default" => "253".into(),
        _ => name.into(),
    }
}

pub(crate) fn addr_listed(listing: &str, device: &str, address: &str) -> bool {
    listing.lines().any(|line| {
        let mut words = line.split_whitespace();
        words.nth(1) == Some(device) && words.any(|word| word == address)
    })
}

pub(crate) fn sysctl_path(key: &str) -> Option<&'static str> {
    Some(match key {
        "tcp_pacing_ss_ratio" => "/proc/sys/net/ipv4/tcp_pacing_ss_ratio",
        "tcp_pacing_ca_ratio" => "/proc/sys/net/ipv4/tcp_pacing_ca_ratio",
        "bridge-nf-call-iptables" => "/proc/sys/net/bridge/bridge-nf-call-iptables",
        "bridge-nf-call-ip6tables" => "/proc/sys/net/bridge/bridge-nf-call-ip6tables",
        _ => return None,
    })
}

pub fn sysctl_read(key: &str) -> Result<String, String> {
    let path = sysctl_path(key).ok_or("Unknown kernel setting")?;
    Ok(fs::read_to_string(path).map_err(|_| "Cannot read a kernel setting")?.trim().to_owned())
}

pub(crate) fn sysctl_command(args: &[String]) -> Result<(), String> {
    match args {
        [key, value] => sysctl_write(key, value),
        _ => Err("Invalid kernel setting".into()),
    }
}

pub fn sysctl_write(key: &str, value: &str) -> Result<(), String> {
    if !value.parse::<u32>().is_ok_and(|value| value <= 100_000) {
        return Err("Invalid kernel setting".into());
    }
    let path = sysctl_path(key).ok_or("Unknown kernel setting")?;
    fs::write(path, value).map_err(|_| "Cannot set a kernel setting".into())
}
