//! China IPv4 ranges that bypass Mihomo in the kernel (owner choice, owner
//! decision 63): such connections use the kernel NAT, so on the relay they
//! can move to the IPA hardware path. Built from the core's own `GeoIP.dat`
//! (geodata mode). Connections whose domain rule would have picked a proxy
//! but whose address is in China go direct too. The set lives only while
//! the core runs; its restore input is prepared before the start.

use std::{
    fs,
    io::{BufReader, Read},
    net::Ipv4Addr,
    path::Path,
    process::Command,
    time::Duration,
};

use sha2::{Digest, Sha256};

use crate::net_tools::{self as net, Cmd};

pub(super) const FLAG: &str = "cn-direct";
pub(super) const SET: &str = "u60_mh_cn4";
const SOURCE: &str = "GeoIP.dat";
const INPUT: &str = "cn4.ipset";
/// A real list has thousands of ranges; fewer means a wrong or empty file.
const MIN_RANGES: usize = 1000;
const MAX_ENTRY: u64 = 64 * 1024 * 1024;

/// Writes the set's restore input; returns its digest, which identifies the
/// interception for conntrack resets.
pub(super) fn prepare(root: &Path) -> Result<String, String> {
    let file = fs::File::open(root.join(SOURCE))
        .map_err(|_| "China IP direct needs GeoIP.dat (geodata-mode with a GEOIP rule)")?;
    let ranges = china_v4(&mut BufReader::new(file))?;
    if ranges.len() < MIN_RANGES {
        return Err("GeoIP.dat has no usable China IPv4 ranges".into());
    }
    let input = restore_input(&ranges);
    net::write_private(&root.join(INPUT), input.as_bytes())?;
    Ok(format!("cn:{:x}", Sha256::digest(input.as_bytes()))[..19].to_owned())
}

fn restore_input(ranges: &[(Ipv4Addr, u8)]) -> String {
    let mut input = format!(
        "create {SET} hash:net family inet hashsize 4096 maxelem {}\nflush {SET}\n",
        (ranges.len() * 2).max(65536)
    );
    for (ip, prefix) in ranges {
        input.push_str(&format!("add {SET} {ip}/{prefix}\n"));
    }
    input
}

/// `@u60-mihomo-cn4 load|destroy`.
pub(crate) fn command(args: &[String]) -> Result<(), String> {
    match args {
        [a] if a == "load" => {
            let input = fs::read(Path::new(super::ROOT).join(INPUT)).map_err(|_| "China IP set input is missing")?;
            let mut cmd = Command::new("ipset");
            cmd.args(["-exist", "restore"]);
            net::run_input(cmd, Duration::from_secs(20), input).map(|_| ())
        }
        [a] if a == "destroy" => {
            // Undo of a set that never loaded (or ipset gone): nothing to do.
            if Cmd::new("ipset", &["list", "-n", SET]).run().is_err() {
                return Ok(());
            }
            Cmd::new("ipset", &["destroy", SET]).run().map(|_| ())
        }
        _ => Err("Invalid China IP set command".into()),
    }
}

fn varint(r: &mut impl Read) -> Result<Option<u64>, String> {
    let (mut value, mut shift) = (0u64, 0);
    let mut byte = [0u8];
    loop {
        if r.read(&mut byte).map_err(|_| "Cannot read GeoIP.dat")? == 0 {
            return if shift == 0 { Ok(None) } else { Err("GeoIP.dat is truncated".into()) };
        }
        if shift > 63 {
            return Err("GeoIP.dat is malformed".into());
        }
        value |= u64::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(Some(value));
        }
        shift += 7;
    }
}

/// Field number and payload (length-delimited only; varints are skipped).
type Raw = Option<(u64, Option<Vec<u8>>)>;

fn field(r: &mut impl Read) -> Result<Raw, String> {
    let Some(key) = varint(r)? else { return Ok(None) };
    let payload = match key & 7 {
        0 => {
            varint(r)?.ok_or("GeoIP.dat is truncated")?;
            None
        }
        2 => {
            let len = varint(r)?.ok_or("GeoIP.dat is truncated")?;
            if len > MAX_ENTRY {
                return Err("GeoIP.dat is malformed".into());
            }
            let mut bytes = Vec::new();
            r.take(len).read_to_end(&mut bytes).map_err(|_| "Cannot read GeoIP.dat")?;
            if bytes.len() as u64 != len {
                return Err("GeoIP.dat is truncated".into());
            }
            Some(bytes)
        }
        _ => return Err("GeoIP.dat is malformed".into()),
    };
    Ok(Some((key >> 3, payload)))
}

/// `GeoIPList { repeated GeoIP entry = 1 }`, `GeoIP { string country_code
/// = 1; repeated CIDR cidr = 2 }`, `CIDR { bytes ip = 1; uint32 prefix = 2 }`
/// (v2ray / meta-rules-dat). IPv4 ranges of the `CN` entry only.
fn china_v4(r: &mut impl Read) -> Result<Vec<(Ipv4Addr, u8)>, String> {
    let mut ranges = Vec::new();
    while let Some((number, payload)) = field(r)? {
        let (1, Some(entry)) = (number, payload) else { continue };
        let mut entry = entry.as_slice();
        let mut cn = false;
        let mut cidrs = Vec::new();
        while let Some((number, payload)) = field(&mut entry)? {
            match (number, payload) {
                (1, Some(code)) => cn = code.eq_ignore_ascii_case(b"cn"),
                (2, Some(cidr)) => cidrs.push(cidr),
                _ => {}
            }
        }
        if !cn {
            continue;
        }
        for cidr in cidrs {
            let (mut ip, mut prefix) = (None, 0u64);
            let mut cidr = cidr.as_slice();
            while let Some((number, payload)) = cidr_field(&mut cidr)? {
                match (number, payload) {
                    (1, Field::Bytes(bytes)) => ip = <[u8; 4]>::try_from(bytes.as_slice()).ok(),
                    (2, Field::Value(value)) => prefix = value,
                    _ => {}
                }
            }
            if let Some(ip) = ip.filter(|_| prefix <= 32) {
                let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
                ranges.push((Ipv4Addr::from(u32::from_be_bytes(ip) & mask), prefix as u8));
            }
        }
    }
    ranges.sort_unstable();
    ranges.dedup();
    Ok(ranges)
}

enum Field {
    Value(u64),
    Bytes(Vec<u8>),
}

/// A CIDR's fields keep their varint values (the prefix length).
fn cidr_field(r: &mut &[u8]) -> Result<Option<(u64, Field)>, String> {
    let Some(key) = varint(r)? else { return Ok(None) };
    let value = match key & 7 {
        0 => Field::Value(varint(r)?.ok_or("GeoIP.dat is truncated")?),
        2 => {
            let len = varint(r)?.ok_or("GeoIP.dat is truncated")? as usize;
            if len > r.len() {
                return Err("GeoIP.dat is truncated".into());
            }
            let (bytes, rest) = r.split_at(len);
            *r = rest;
            Field::Bytes(bytes.to_vec())
        }
        _ => return Err("GeoIP.dat is malformed".into()),
    };
    Ok(Some((key >> 3, value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(fields: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (number, bytes) in fields {
            out.push(number << 3 | 2);
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
        }
        out
    }

    fn cidr(ip: &[u8], prefix: u8) -> Vec<u8> {
        let mut out = message(&[(1, ip)]);
        out.extend([2 << 3, prefix]);
        out
    }

    #[test]
    fn only_the_china_entrys_ipv4_ranges_are_read_and_normalized() {
        let cn = message(&[(1, b"CN"), (2, &cidr(&[1, 0, 1, 7], 24)), (2, &cidr(&[0x24, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 32)), (2, &cidr(&[36, 0, 0, 0], 10))]);
        let us = message(&[(1, b"US"), (2, &cidr(&[8, 8, 8, 0], 24))]);
        let list = [message(&[(1, &us)]), message(&[(1, &cn)])].concat();
        let ranges = china_v4(&mut list.as_slice()).unwrap();
        assert_eq!(ranges, [("1.0.1.0".parse().unwrap(), 24), ("36.0.0.0".parse().unwrap(), 10)]);
        assert!(china_v4(&mut &list[..list.len() - 1]).is_err(), "truncated input is an error");
        let input = restore_input(&ranges);
        assert!(input.starts_with(&format!("create {SET} hash:net family inet")));
        assert!(input.ends_with(&format!("add {SET} 36.0.0.0/10\n")));
    }
}
