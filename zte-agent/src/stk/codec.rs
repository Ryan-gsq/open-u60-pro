//! ETSI CAT BER/comprehension TLVs. Never treat modem text as an AT command.
use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub struct Command {
    pub details: [u8; 3],
    pub title: String,
    pub text: String,
    pub items: Vec<(u8, String)>,
    pub min: u8,
    pub max: u8,
}

fn take<'a>(data: &mut &'a [u8], n: usize) -> Result<&'a [u8], String> {
    if data.len() < n {
        return Err("truncated CAT data".into());
    }
    let (value, rest) = data.split_at(n);
    *data = rest;
    Ok(value)
}

fn length(data: &mut &[u8]) -> Result<usize, String> {
    match take(data, 1)?[0] {
        0x81 => Ok(take(data, 1)?[0] as usize),
        0x82 => {
            let v = take(data, 2)?;
            Ok(u16::from_be_bytes([v[0], v[1]]) as usize)
        }
        n @ 0..=0x7f => Ok(n as usize),
        _ => Err("unsupported CAT length".into()),
    }
}

pub fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if !text.is_ascii() || !text.len().is_multiple_of(2) || text.len() > 16384 {
        return Err("invalid CAT hex".into());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|v| {
            let a = (v[0] as char).to_digit(16).ok_or("invalid CAT hex")?;
            let b = (v[1] as char).to_digit(16).ok_or("invalid CAT hex")?;
            Ok((a * 16 + b) as u8)
        })
        .collect()
}

pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02X}")).collect()
}

// GSM 03.38 default alphabet; alpha identifiers are unpacked, not UCS-2 by default.
const GSM: &str = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\u{1b}ÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà";

fn gsm(data: &[u8]) -> Result<String, String> {
    let table: Vec<char> = GSM.chars().collect();
    let mut out = String::new();
    let mut escape = false;
    for &b in data {
        if escape {
            out.push(match b {
                10 => '\u{c}',
                20 => '^',
                40 => '{',
                41 => '}',
                47 => '\\',
                60 => '[',
                61 => '~',
                62 => ']',
                64 => '|',
                101 => '€',
                _ => return Err("unknown GSM extension".into()),
            });
            escape = false;
        } else if b == 27 {
            escape = true;
        } else {
            out.push(*table.get(b as usize).ok_or("invalid GSM character")?);
        }
    }
    if escape {
        return Err("truncated GSM escape".into());
    }
    Ok(out)
}

fn ucs2(data: &[u8]) -> Result<String, String> {
    if !data.len().is_multiple_of(2) {
        return Err("odd UCS-2 length".into());
    }
    data.chunks_exact(2)
        .map(|v| {
            char::from_u32(u16::from_be_bytes([v[0], v[1]]) as u32)
                .ok_or_else(|| "invalid UCS-2".into())
        })
        .collect()
}

fn alpha(data: &[u8]) -> Result<String, String> {
    match data.first() {
        Some(0x80) => ucs2(&data[1..]),
        Some(0x81 | 0x82) => {
            let header = if data[0] == 0x81 { 3 } else { 4 };
            if data.len() < header {
                return Err("truncated alpha identifier".into());
            }
            let base = if header == 3 {
                (data[2] as u16) << 7
            } else {
                u16::from_be_bytes([data[2], data[3]])
            };
            let chars = data
                .get(header..header + data[1] as usize)
                .ok_or("truncated alpha identifier")?;
            let mut out = String::new();
            let mut i = 0;
            while i < chars.len() {
                let b = chars[i];
                if b & 0x80 != 0 {
                    out.push(
                        char::from_u32(base as u32 + (b & 0x7f) as u32)
                            .ok_or("invalid alpha character")?,
                    );
                } else if b == 27 {
                    out.push_str(&gsm(chars.get(i..i + 2).ok_or("truncated GSM escape")?)?);
                    i += 1;
                } else {
                    out.push_str(&gsm(&[b])?);
                }
                i += 1;
            }
            Ok(out)
        }
        _ => gsm(data),
    }
}

fn text_string(data: &[u8]) -> Result<String, String> {
    let Some((&dcs, data)) = data.split_first() else {
        return Ok(String::new());
    };
    match dcs {
        8 => ucs2(data),
        4 => gsm(data),
        0 => {
            let mut septets = Vec::new();
            for i in 0..data.len() * 8 / 7 {
                let bit = i * 7;
                let word = data[bit / 8] as u16
                    | ((data.get(bit / 8 + 1).copied().unwrap_or(0) as u16) << 8);
                septets.push(((word >> (bit % 8)) & 127) as u8);
            }
            gsm(&septets)
        }
        _ => Err("unsupported CAT text encoding".into()),
    }
}

impl Command {
    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        let mut data = raw;
        if take(&mut data, 1)?[0] != 0xd0 {
            return Err("expected proactive CAT command".into());
        }
        let n = length(&mut data)?;
        if n != data.len() {
            return Err("CAT envelope length mismatch".into());
        }
        let mut result = Self {
            details: [0; 3],
            title: String::new(),
            text: String::new(),
            items: Vec::new(),
            min: 0,
            max: 0,
        };
        let mut details = false;
        let mut devices = false;
        while !data.is_empty() {
            let tag = take(&mut data, 1)?[0];
            let n = length(&mut data)?;
            let val = take(&mut data, n)?;
            match tag & 0x7f {
                1 if n == 3 && !details => {
                    result.details.copy_from_slice(val);
                    details = true;
                }
                2 if val == [0x81, 0x82] && !devices => devices = true,
                5 => result.title = alpha(val)?,
                13 => result.text = text_string(val)?,
                15 if n > 0 => {
                    let id = val[0];
                    if id == 0 || result.items.iter().any(|(v, _)| *v == id) {
                        return Err("invalid CAT item ID".into());
                    }
                    result.items.push((id, alpha(&val[1..])?));
                }
                15 if n == 0 => {} // SET UP MENU removal
                17 if n == 2 => {
                    result.min = val[0];
                    result.max = val[1];
                }
                // Optional presentation hints. Unsupported required semantics must not be accepted.
                4 | 16 | 24 | 25 | 30 | 31 | 43 | 80 | 81 => {}
                _ if tag & 0x80 == 0 => {}
                _ => return Err(format!("unsupported required CAT tag {tag:02X}")),
            }
        }
        if !details || !devices {
            return Err("missing CAT command details or devices".into());
        }
        if result.details[1] == 0x24 && result.items.is_empty() {
            return Err("empty SELECT ITEM".into());
        }
        if result.details[1] == 0x23 && result.min > result.max {
            return Err("invalid input limits".into());
        }
        Ok(result)
    }

    pub fn view(&self) -> Value {
        let kind = match self.details[1] {
            0x25 | 0x24 => "menu",
            0x21 => "display",
            0x22 | 0x23 => "input",
            _ => "unsupported",
        };
        json!({"type": kind, "title": self.title, "text": self.text, "data": self.text,
            "items": self.items.iter().map(|(id,label)| json!({"id":id,"label":label})).collect::<Vec<_>>(),
            "root_menu": self.details[1] == 0x25,
            "input": {"min": if self.details[1] == 0x22 {1} else {self.min}, "max": if self.details[1] == 0x22 {1} else {self.max},
                "yes_no": self.details[1] == 0x22 && self.details[2] & 4 != 0,
                "hidden": self.details[1] == 0x23 && self.details[2] & 4 != 0,
                "digits_only": self.details[2] & 1 == 0}})
    }

    pub fn response(&self, result: u8, extra: &[u8]) -> Vec<u8> {
        let mut out = vec![0x81, 3];
        out.extend(self.details);
        out.extend([0x82, 2, 0x82, 0x81, 0x83, 1, result]);
        out.extend(extra);
        out
    }

    pub fn select(&self, item: u8) -> Result<(i32, Vec<u8>), String> {
        if !self.items.iter().any(|(id, _)| *id == item) {
            return Err("item is not in the current menu".into());
        }
        match self.details[1] {
            0x25 => Ok((69, vec![0xd3, 7, 0x82, 2, 1, 0x81, 0x90, 1, item])),
            0x24 => Ok((70, self.response(0, &[0x90, 1, item]))),
            _ => Err("no selectable menu".into()),
        }
    }

    pub fn input_response(&self, value: &Value) -> Result<Vec<u8>, String> {
        let q = self.details[2];
        if self.details[1] == 0x21 {
            return Ok(self.response(0, &[]));
        }
        if !matches!(self.details[1], 0x22 | 0x23) {
            return Err("no input request pending".into());
        }
        let bytes = if self.details[1] == 0x22 && q & 4 != 0 {
            vec![
                4,
                u8::from(value["yes"].as_bool().ok_or("yes must be a boolean")?),
            ]
        } else {
            let text = value["text"].as_str().ok_or("missing text")?;
            let count = text.chars().count();
            let (min, max) = if self.details[1] == 0x22 {
                (1, 1)
            } else {
                (self.min as usize, self.max as usize)
            };
            if count < min || count > max {
                return Err(format!("input must contain {min}–{max} characters"));
            }
            if q & 1 == 0 && !text.chars().all(|c| "0123456789*#+".contains(c)) {
                return Err("SIM requests digits only".into());
            }
            if q & 2 != 0 {
                let mut bytes = vec![8];
                for c in text.chars() {
                    let cp =
                        u16::try_from(c as u32).map_err(|_| "SIM requires UCS-2 characters")?;
                    bytes.extend(cp.to_be_bytes());
                }
                bytes
            } else {
                let mut septets = Vec::new();
                for c in text.chars() {
                    if let Some(i) = GSM.chars().position(|g| g == c && g != '\u{1b}') {
                        septets.push(i as u8);
                    } else {
                        return Err("character is not supported by the SIM's input alphabet".into());
                    }
                }
                if self.details[1] == 0x23 && q & 8 != 0 {
                    let mut packed = vec![0; (septets.len() * 7).div_ceil(8)];
                    for (i, b) in septets.iter().enumerate() {
                        let bit = i * 7;
                        packed[bit / 8] |= b << (bit % 8);
                        if bit % 8 > 1 {
                            packed[bit / 8 + 1] |= b >> (8 - bit % 8);
                        }
                    }
                    let mut bytes = vec![0];
                    bytes.extend(packed);
                    bytes
                } else {
                    let mut bytes = vec![4];
                    bytes.extend(septets);
                    bytes
                }
            }
        };
        if bytes.len() > 255 {
            return Err("encoded input exceeds CAT limit".into());
        }
        let mut extra = vec![0x8d];
        if bytes.len() >= 128 {
            extra.push(0x81);
        }
        extra.push(bytes.len() as u8);
        extra.extend(bytes);
        Ok(self.response(0, &extra))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_gsm_menu_and_builds_exact_envelope() {
        let menu = Command::parse(
            &unhex("D01C810301250082028182850453494D218F05014D656E758F040254776F").unwrap(),
        )
        .unwrap();
        assert_eq!(menu.title, "SIM!");
        assert_eq!(hex(&menu.select(2).unwrap().1), "D30782020181900102");
    }
    #[test]
    fn submenu_selection_is_a_terminal_response() {
        let cmd = Command::parse(&unhex("D00F8103092400820281828F04014F6E65").unwrap()).unwrap();
        assert_eq!(
            cmd.select(1).unwrap(),
            (70, unhex("810309240082028281830100900101").unwrap())
        );
        assert!(cmd.select(255).is_err());
    }
    #[test]
    fn rejects_truncated_and_non_ascii_payloads() {
        assert!(unhex("é00").is_err());
        assert!(Command::parse(&[0xd0, 0x81]).is_err());
        assert!(Command::parse(&unhex("D0098103012500820281").unwrap()).is_err());
    }
    #[test]
    fn decodes_alpha_encodings_without_guessing() {
        assert_eq!(alpha(&unhex("8000414E2D").unwrap()).unwrap(), "A中");
        assert_eq!(alpha(&[0x81, 2, 0x9c, b'A', 0xad]).unwrap(), "A中");
        assert_eq!(alpha(&[0x82, 2, 0x4e, 0, b'A', 0xad]).unwrap(), "A中");
        assert_eq!(gsm(&[27, 101]).unwrap(), "€");
    }
    #[test]
    fn accepts_long_form_lengths_and_tag_without_required_bit() {
        assert!(Command::parse(&unhex("D08109010301250002028182").unwrap()).is_ok());
    }
    #[test]
    fn validates_input_and_encodes_yes_no() {
        let cmd = Command::parse(&unhex("D009810301220482028182").unwrap()).unwrap();
        assert_eq!(
            hex(&cmd.input_response(&json!({"yes":false})).unwrap()),
            "8103012204820282818301008D020400"
        );
        assert!(cmd.input_response(&json!({"text":"yes"})).is_err());
    }
}
