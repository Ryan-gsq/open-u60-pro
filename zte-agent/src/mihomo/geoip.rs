//! IPv4 ranges of `GEOIP` codes from the core's own `GeoIP.dat` (geodata
//! mode), for the kernel's rule chain (`routing`). Only the requested codes
//! are read; a code the file lacks is absent from the result.

use std::{
    collections::{BTreeSet, HashMap},
    fs,
    io::{BufReader, Read},
    net::Ipv4Addr,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::{Arc, Mutex},
};

const SOURCE: &str = "GeoIP.dat";
const MAX_ENTRY: u64 = 64 * 1024 * 1024;
const MAX_CACHE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CACHE_CODES: usize = 1024;

/// Ranges per code (upper case) as nft elements; empty for a code with only
/// IPv6 ranges.
pub(super) type Lists = HashMap<String, Vec<String>>;

#[derive(Default)]
pub(super) struct Cache(Mutex<Option<Cached>>);

struct Cached {
    stamp: (u64, i64, i64, u64, u64),
    loaded: BTreeSet<String>,
    lists: Arc<Lists>,
    bytes: usize,
}

impl Cache {
    pub(super) fn get(&self, root: &Path, codes: &[String]) -> Result<Arc<Lists>, String> {
        if codes.is_empty() {
            return Ok(Arc::default());
        }
        let path = root.join(SOURCE);
        let stamp = fs::metadata(&path).map(|m| (m.len(), m.mtime(), m.mtime_nsec(), m.dev(), m.ino())).map_err(|_| "GeoIP.dat is not available")?;
        let mut codes: Vec<String> = codes.iter().map(|c| c.to_ascii_uppercase()).collect();
        codes.sort();
        codes.dedup();
        let mut cache = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.as_ref().is_none_or(|cached| cached.stamp != stamp) {
            *cache = Some(Cached { stamp, loaded: BTreeSet::new(), lists: Arc::default(), bytes: 0 });
        }
        let cached = cache.as_mut().unwrap();
        let missing: Vec<String> = codes.iter().filter(|code| !cached.loaded.contains(*code)).cloned().collect();
        let mut lists = Lists::new();
        if !missing.is_empty() {
            let file = fs::File::open(&path).map_err(|_| "Cannot read GeoIP.dat")?;
            let found = geoip_v4(&mut BufReader::new(file), &missing)?;
            lists = found.into_iter().map(|(code, ranges)| (code, ranges.iter().map(|(ip, prefix)| format!("{ip}/{prefix}")).collect())).collect();
            for code in missing {
                let ranges = lists.get(&code);
                let bytes = code.capacity() * 2 + ranges.map_or(0, |ranges| ranges.capacity() * std::mem::size_of::<String>() + ranges.iter().map(String::capacity).sum::<usize>());
                if cached.loaded.len() < MAX_CACHE_CODES && bytes <= MAX_CACHE_BYTES - cached.bytes {
                    cached.bytes += bytes;
                    cached.loaded.insert(code.clone());
                    if let Some(ranges) = ranges {
                        Arc::make_mut(&mut cached.lists).insert(code, ranges.clone());
                    }
                }
            }
        }
        if codes.len() == cached.loaded.len() && codes.iter().all(|code| cached.loaded.contains(code)) {
            return Ok(Arc::clone(&cached.lists));
        }
        for code in codes {
            if let Some(ranges) = cached.lists.get(&code) {
                lists.entry(code).or_insert_with(|| ranges.clone());
            }
        }
        Ok(Arc::new(lists))
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
        let mut fields = entry.as_slice();
        let mut code = None;
        while let Some((number, payload)) = cidr_field(&mut fields, MAX_ENTRY)? {
            if let (1, Field::Bytes(name)) = (number, payload) {
                code = Some(String::from_utf8_lossy(name).to_ascii_uppercase());
            }
        }
        let Some(code) = code.filter(|c| wanted.contains(c)) else { continue };
        let ranges = lists.entry(code).or_default();
        let mut fields = entry.as_slice();
        while let Some((number, payload)) = cidr_field(&mut fields, MAX_ENTRY)? {
            let (2, Field::Bytes(mut cidr)) = (number, payload) else { continue };
            let (mut ip, mut prefix) = (None, 0u64);
            while let Some((number, payload)) = cidr_field(&mut cidr, u64::MAX)? {
                match (number, payload) {
                    (1, Field::Bytes(bytes)) => ip = <[u8; 4]>::try_from(bytes).ok(),
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

enum Field<'a> {
    Value(u64),
    Bytes(&'a [u8]),
}

/// A CIDR's fields keep their varint values (the prefix length).
fn cidr_field<'a>(r: &mut &'a [u8], max_len: u64) -> Result<Option<(u64, Field<'a>)>, String> {
    let Some(key) = varint(r)? else { return Ok(None) };
    let value = match key & 7 {
        0 => Field::Value(varint(r)?.ok_or("GeoIP.dat is truncated")?),
        2 => {
            let len = varint(r)?.ok_or("GeoIP.dat is truncated")?;
            if len > max_len {
                return Err("GeoIP.dat is malformed".into());
            }
            let len = len as usize;
            if len > r.len() {
                return Err("GeoIP.dat is truncated".into());
            }
            let (bytes, rest) = r.split_at(len);
            *r = rest;
            Field::Bytes(bytes)
        }
        _ => return Err("GeoIP.dat is malformed".into()),
    };
    Ok(Some((key >> 3, value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
        while value >= 128 {
            out.push(value as u8 | 128);
            value >>= 7;
        }
        out.push(value as u8);
    }

    fn message(fields: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (number, bytes) in fields {
            out.push(number << 3 | 2);
            encode_varint(bytes.len() as u64, &mut out);
            out.extend_from_slice(bytes);
        }
        out
    }

    fn cidr(ip: &[u8], prefix: u8) -> Vec<u8> {
        let mut out = message(&[(1, ip)]);
        out.extend([2 << 3, prefix]);
        out
    }

    fn old_geoip_v4(r: &mut impl Read, wanted: &[String]) -> Result<HashMap<String, Vec<(Ipv4Addr, u8)>>, String> {
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
            let Some(code) = code.filter(|code| wanted.contains(code)) else { continue };
            let ranges = lists.entry(code).or_default();
            for cidr in cidrs {
                let (mut ip, mut prefix) = (None, 0u64);
                let mut cidr = cidr.as_slice();
                while let Some(key) = varint(&mut cidr)? {
                    match key & 7 {
                        0 => {
                            let value = varint(&mut cidr)?.ok_or("GeoIP.dat is truncated")?;
                            if key >> 3 == 2 {
                                prefix = value;
                            }
                        }
                        2 => {
                            let len = varint(&mut cidr)?.ok_or("GeoIP.dat is truncated")? as usize;
                            if len > cidr.len() {
                                return Err("GeoIP.dat is truncated".into());
                            }
                            let bytes = cidr[..len].to_vec();
                            cidr = &cidr[len..];
                            if key >> 3 == 1 {
                                ip = <[u8; 4]>::try_from(bytes.as_slice()).ok();
                            }
                        }
                        _ => return Err("GeoIP.dat is malformed".into()),
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

    fn synthetic(countries: usize, count: usize) -> Vec<u8> {
        let mut list = Vec::new();
        for country in 0..countries {
            let code = format!("C{country:03}");
            let mut entry = Vec::new();
            for index in 0..count {
                let ip = ((country as u32) << 24 | (index as u32) << 8).to_be_bytes();
                entry.extend(message(&[(2, &cidr(&ip, 24))]));
                if index % 4 == 0 {
                    entry.extend(message(&[(2, &cidr(&[0x20; 16], 32))]));
                }
            }
            entry.extend(message(&[(9, b"unknown"), (1, code.as_bytes())]));
            entry.extend([10 << 3, 7]);
            list.extend(message(&[(1, &entry)]));
        }
        list
    }

    #[test]
    fn loader_matches_reference_with_late_codes_unknown_fields_and_ipv6() {
        let mut list = synthetic(7, 40);
        let repeated = message(&[(1, b"ignored"), (2, &cidr(&[1, 2, 3, 4], 24)), (1, b"c002")]);
        list.extend(message(&[(1, &repeated), (8, b"unknown")]));
        for codes in [vec![], vec!["C002".into()], vec!["C000".into(), "C002".into(), "MISSING".into()]] {
            assert_eq!(geoip_v4(&mut list.as_slice(), &codes), old_geoip_v4(&mut list.as_slice(), &codes));
            for end in 0..list.len() {
                assert_eq!(geoip_v4(&mut &list[..end], &codes), old_geoip_v4(&mut &list[..end], &codes), "prefix {end}");
            }
        }
        let malformed_unwanted = message(&[(1, &message(&[(1, b"OTHER"), (2, &[0xff])]))]);
        assert_eq!(geoip_v4(&mut malformed_unwanted.as_slice(), &["C002".into()]), old_geoip_v4(&mut malformed_unwanted.as_slice(), &["C002".into()]));
        let config = serde_yaml_ng::from_str("geodata-mode: true\nrules: ['GEOIP,C000,DIRECT', 'GEOIP,C002,REJECT', 'GEOIP,C003,DIRECT', 'MATCH,REJECT']").unwrap();
        let compiled = super::super::routing::Routes::from(&config).compile(&Default::default(), Path::new("/unused"), &[]);
        let render = |lists: HashMap<String, Vec<(Ipv4Addr, u8)>>| {
            let lists: Lists = lists.into_iter().map(|(code, ranges)| (code, ranges.iter().map(|(ip, prefix)| format!("{ip}/{prefix}")).collect())).collect();
            compiled.render(&|code| lists.get(code).map(Vec::as_slice).ok_or_else(|| "missing".into()))
        };
        assert_eq!(render(geoip_v4(&mut list.as_slice(), &compiled.geoip).unwrap()), render(old_geoip_v4(&mut list.as_slice(), &compiled.geoip).unwrap()));
    }

    #[test]
    fn cached_subsets_and_later_full_requests_do_not_read_the_file() {
        let root = std::env::temp_dir().join(format!("mh-compute-cache-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join(SOURCE);
        fs::write(&path, synthetic(4, 12)).unwrap();
        let cache = Cache::default();
        let full = vec!["C000".into(), "C002".into(), "ABSENT".into()];
        let loaded = cache.get(&root, &full).unwrap();
        let stamp = cache.0.lock().unwrap().as_ref().unwrap().stamp;
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        cache.0.lock().unwrap().as_mut().unwrap().stamp = (metadata.len(), metadata.mtime(), metadata.mtime_nsec(), metadata.dev(), metadata.ino());
        assert_eq!(cache.get(&root, &["c002".into()]).unwrap().len(), 1);
        assert!(cache.get(&root, &["ABSENT".into()]).unwrap().is_empty());
        assert_eq!(*cache.get(&root, &full).unwrap(), *loaded);
        assert!(cache.get(&root, &["C003".into()]).is_err());
        fs::remove_dir(&path).unwrap();
        fs::write(&path, synthetic(4, 13)).unwrap();
        let refreshed = cache.get(&root, &full).unwrap();
        assert_ne!(*refreshed, *loaded);
        assert_ne!(cache.0.lock().unwrap().as_ref().unwrap().stamp, stamp);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cache_accumulates_codes_and_respects_its_limits() {
        let root = std::env::temp_dir().join(format!("mh-compute-bound-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(SOURCE), synthetic(4, 12)).unwrap();
        let cache = Cache::default();
        cache.get(&root, &["C000".into()]).unwrap();
        cache.get(&root, &["C001".into()]).unwrap();
        assert_eq!(cache.0.lock().unwrap().as_ref().unwrap().loaded.len(), 2);
        let missing: Vec<String> = (0..MAX_CACHE_CODES + 10).map(|index| format!("M{index}")).collect();
        assert!(cache.get(&root, &missing).unwrap().is_empty());
        {
            let cached = cache.0.lock().unwrap();
            assert_eq!(cached.as_ref().unwrap().loaded.len(), MAX_CACHE_CODES);
            assert!(cached.as_ref().unwrap().bytes <= MAX_CACHE_BYTES);
        }
        cache.0.lock().unwrap().as_mut().unwrap().bytes = MAX_CACHE_BYTES;
        assert_eq!(cache.get(&root, &["C003".into()]).unwrap()["C003"].len(), 12);
        assert!(!cache.0.lock().unwrap().as_ref().unwrap().loaded.contains("C003"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore]
    fn benchmark_first_geoip_plan() {
        let root = std::env::temp_dir().join(format!("mh-compute-bench-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let list = synthetic(250, 4250);
        fs::write(root.join(SOURCE), &list).unwrap();
        let config = serde_yaml_ng::from_str("geodata-mode: true\nrules: ['GEOIP,C000,DIRECT', 'GEOIP,C001,REJECT', 'MATCH,REJECT']").unwrap();
        let routes = super::super::routing::Routes::from(&config);
        let start = std::time::Instant::now();
        let compiled = routes.compile(&Default::default(), &root, &[]);
        let old = old_geoip_v4(&mut BufReader::new(fs::File::open(root.join(SOURCE)).unwrap()), &compiled.geoip).unwrap();
        let old: Lists = old.into_iter().map(|(code, ranges)| (code, ranges.iter().map(|(ip, prefix)| format!("{ip}/{prefix}")).collect())).collect();
        let old_chain = compiled.render(&|code| old.get(code).map(Vec::as_slice).ok_or_else(|| "missing".into()));
        let old_time = start.elapsed();
        let start = std::time::Instant::now();
        let compiled = routes.compile(&Default::default(), &root, &[]);
        let new = Cache::default().get(&root, &compiled.geoip).unwrap();
        let new_chain = compiled.render(&|code| new.get(code).map(Vec::as_slice).ok_or_else(|| "missing".into()));
        let new_time = start.elapsed();
        assert_eq!(old_chain, new_chain);
        println!("Mac first GeoIP plan: {} bytes, 250 countries, old={old_time:?}, new={new_time:?}", list.len());
        fs::remove_dir_all(root).unwrap();
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
