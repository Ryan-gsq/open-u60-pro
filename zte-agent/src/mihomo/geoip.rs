//! IPv4 ranges of `GEOIP` codes from the core's own `GeoIP.dat` (geodata
//! mode), for the kernel's rule chain (`routing`). Only the requested codes
//! are read; a code the file lacks is absent from the result.

use std::{
    collections::HashMap,
    fs,
    io::{BufReader, Read},
    net::Ipv4Addr,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::{Arc, Mutex},
};

const SOURCE: &str = "GeoIP.dat";
const MAX_ENTRY: u64 = 64 * 1024 * 1024;

/// Ranges per code (upper case) as nft elements; empty for a code with only
/// IPv6 ranges.
pub(super) type Lists = HashMap<String, Vec<String>>;

/// The last read, kept while the file and the requested codes are the same:
/// a mode or proxy-group change must not re-read 16 MB on the router.
#[derive(Default)]
pub(super) struct Cache(Mutex<Option<((u64, i64, u64), Vec<String>, Arc<Lists>)>>);

impl Cache {
    pub(super) fn get(&self, root: &Path, codes: &[String]) -> Result<Arc<Lists>, String> {
        if codes.is_empty() {
            return Ok(Arc::default());
        }
        let path = root.join(SOURCE);
        let stamp = fs::metadata(&path).map(|m| (m.len(), m.mtime(), m.ino())).map_err(|_| "GeoIP.dat is not available")?;
        let mut codes: Vec<String> = codes.iter().map(|c| c.to_ascii_uppercase()).collect();
        codes.sort();
        codes.dedup();
        let mut cache = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((at, read, lists)) = cache.as_ref() {
            if *at == stamp && *read == codes {
                return Ok(Arc::clone(lists));
            }
        }
        let file = fs::File::open(&path).map_err(|_| "Cannot read GeoIP.dat")?;
        let found = geoip_v4(&mut BufReader::new(file), &codes)?;
        let lists: Lists = found.into_iter().map(|(code, ranges)| (code, ranges.iter().map(|(ip, prefix)| format!("{ip}/{prefix}")).collect())).collect();
        let lists = Arc::new(lists);
        *cache = Some((stamp, codes, Arc::clone(&lists)));
        Ok(lists)
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
/// (v2ray / meta-rules-dat). IPv4 ranges of the `wanted` codes (upper case).
fn geoip_v4(r: &mut impl Read, wanted: &[String]) -> Result<HashMap<String, Vec<(Ipv4Addr, u8)>>, String> {
    let mut lists: HashMap<String, Vec<(Ipv4Addr, u8)>> = HashMap::new();
    while let Some((number, payload)) = field(r)? {
        let (1, Some(entry)) = (number, payload) else { continue };
        let mut entry = entry.as_slice();
        let mut code = None;
        let mut cidrs = Vec::new();
        while let Some((number, payload)) = field(&mut entry)? {
            match (number, payload) {
                (1, Some(name)) => code = Some(String::from_utf8_lossy(&name).to_ascii_uppercase()),
                (2, Some(cidr)) => cidrs.push(cidr),
                _ => {}
            }
        }
        let Some(code) = code.filter(|c| wanted.contains(c)) else { continue };
        let ranges = lists.entry(code).or_default();
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
    for ranges in lists.values_mut() {
        ranges.sort_unstable();
        ranges.dedup();
    }
    Ok(lists)
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
    fn only_the_wanted_entries_ipv4_ranges_are_read_and_normalized() {
        let cn = message(&[(1, b"CN"), (2, &cidr(&[1, 0, 1, 7], 24)), (2, &cidr(&[0x24, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 32)), (2, &cidr(&[36, 0, 0, 0], 10))]);
        let us = message(&[(1, b"us"), (2, &cidr(&[8, 8, 8, 0], 24))]);
        let jp = message(&[(1, b"JP"), (2, &cidr(&[1, 1, 1, 0], 24))]);
        let list = [message(&[(1, &us)]), message(&[(1, &cn)]), message(&[(1, &jp)])].concat();
        let lists = geoip_v4(&mut list.as_slice(), &["CN".into(), "US".into()]).unwrap();
        assert_eq!(lists["CN"], [("1.0.1.0".parse().unwrap(), 24), ("36.0.0.0".parse().unwrap(), 10)]);
        assert_eq!(lists["US"], [("8.8.8.0".parse().unwrap(), 24)], "codes compare case-insensitively");
        assert!(!lists.contains_key("JP"), "unrequested codes are skipped");
        assert!(geoip_v4(&mut &list[..list.len() - 1], &["CN".into()]).is_err(), "truncated input is an error");
    }

    #[test]
    fn a_code_without_ipv4_is_present_and_empty() {
        let v6 = message(&[(1, b"V6ONLY"), (2, &cidr(&[0x24, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 32))]);
        let list = message(&[(1, &v6)]);
        let lists = geoip_v4(&mut list.as_slice(), &["V6ONLY".into(), "XX".into()]).unwrap();
        assert_eq!(lists.get("V6ONLY"), Some(&Vec::new()), "never matches IPv4");
        assert!(!lists.contains_key("XX"), "missing: its rules cannot be checked");
    }

    #[test]
    fn no_codes_need_no_file() {
        let lists = Cache::default().get(Path::new("/nonexistent"), &[]).unwrap();
        assert!(lists.is_empty());
        assert!(Cache::default().get(Path::new("/nonexistent"), &["CN".into()]).is_err());
    }
}
