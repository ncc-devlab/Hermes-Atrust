use std::collections::{HashMap, HashSet};
use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

pub(crate) enum Answer {
    Truncated,
    Addresses(Vec<Ipv4Addr>, Duration),
}
fn bad() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid DNS response")
}
fn word(bytes: &[u8], offset: usize) -> io::Result<u16> {
    let pair = bytes.get(offset..offset + 2).ok_or_else(bad)?;
    Ok(u16::from_be_bytes([pair[0], pair[1]]))
}

pub(crate) fn normalize(host: &str) -> io::Result<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.len() > 253
        || host.is_empty()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid DNS hostname",
        ));
    }
    Ok(host)
}

pub(crate) fn query(host: &str, id: u16) -> io::Result<Vec<u8>> {
    let host = normalize(host)?;
    let mut packet = vec![0; 12];
    packet[..2].copy_from_slice(&id.to_be_bytes());
    packet[2] = 1;
    packet[5] = 1;
    for label in host.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    Ok(packet)
}

fn name(bytes: &[u8], offset: &mut usize) -> io::Result<String> {
    let mut cursor = *offset;
    let mut jumped = false;
    let mut labels = Vec::new();
    for _ in 0..64 {
        let length = *bytes.get(cursor).ok_or_else(bad)?;
        if length & 0xc0 == 0xc0 {
            let pointer = (word(bytes, cursor)? & 0x3fff) as usize;
            if pointer >= cursor {
                return Err(bad());
            }
            if !jumped {
                *offset = cursor + 2;
                jumped = true;
            }
            cursor = pointer;
        } else if length == 0 {
            if !jumped {
                *offset = cursor + 1;
            }
            let value = labels.join(".");
            if value.len() > 253 {
                return Err(bad());
            }
            return Ok(value);
        } else {
            if length > 63 {
                return Err(bad());
            }
            cursor += 1;
            let label = bytes
                .get(cursor..cursor + length as usize)
                .ok_or_else(bad)?;
            labels.push(
                std::str::from_utf8(label)
                    .map_err(|_| bad())?
                    .to_ascii_lowercase(),
            );
            cursor += length as usize;
        }
    }
    Err(bad())
}

pub(crate) fn parse(bytes: &[u8], host: &str, id: u16) -> io::Result<Answer> {
    if bytes.len() < 12
        || word(bytes, 0)? != id
        || word(bytes, 2)? & 0xf800 != 0x8000
        || word(bytes, 4)? != 1
    {
        return Err(bad());
    }
    let mut cursor = 12;
    if name(bytes, &mut cursor)? != host
        || word(bytes, cursor)? != 1
        || word(bytes, cursor + 2)? != 1
    {
        return Err(bad());
    }
    cursor += 4;
    let flags = word(bytes, 2)?;
    if flags & 0x200 != 0 {
        return Ok(Answer::Truncated);
    }
    if flags & 15 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "DNS lookup was rejected",
        ));
    }
    let answers = word(bytes, 6)? as usize;
    let count = answers + word(bytes, 8)? as usize + word(bytes, 10)? as usize;
    if count > 512 {
        return Err(bad());
    }
    let mut aliases = HashMap::new();
    let mut addresses: HashMap<String, Vec<(Ipv4Addr, u32)>> = HashMap::new();
    for index in 0..count {
        let owner = name(bytes, &mut cursor)?;
        let kind = word(bytes, cursor)?;
        let class = word(bytes, cursor + 2)?;
        let ttl = ((word(bytes, cursor + 4)? as u32) << 16) | word(bytes, cursor + 6)? as u32;
        let length = word(bytes, cursor + 8)? as usize;
        cursor += 10;
        let data = bytes.get(cursor..cursor + length).ok_or_else(bad)?;
        if index < answers && class == 1 {
            if kind == 1 && length == 4 {
                addresses
                    .entry(owner)
                    .or_default()
                    .push((Ipv4Addr::new(data[0], data[1], data[2], data[3]), ttl));
            } else if kind == 5 {
                let mut end = cursor;
                let alias = name(bytes, &mut end)?;
                if end != cursor + length {
                    return Err(bad());
                }
                if let Some(previous) = aliases.insert(owner, (alias.clone(), ttl))
                    && previous.0 != alias
                {
                    return Err(bad());
                }
            }
        }
        cursor += length;
    }
    let mut owner = host.to_owned();
    let mut ttl = u32::MAX;
    let mut seen = HashSet::new();
    for _ in 0..16 {
        if !seen.insert(owner.clone()) {
            return Err(bad());
        }
        if let Some(values) = addresses.get(&owner) {
            let mut ips = Vec::new();
            for &(ip, lifetime) in values {
                ttl = ttl.min(lifetime);
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
            return Ok(Answer::Addresses(ips, Duration::from_secs(ttl as u64)));
        }
        let Some((alias, lifetime)) = aliases.get(&owner) else {
            break;
        };
        ttl = ttl.min(*lifetime);
        owner = alias.clone();
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "DNS response has no matching IPv4 answer",
    ))
}

#[cfg(test)]
pub(crate) fn test_answer(query: &[u8], truncated: bool) -> Vec<u8> {
    let mut reply = query.to_vec();
    reply[2] = if truncated { 0x83 } else { 0x81 };
    reply[3] = 0x80;
    if !truncated {
        reply[7] = 1;
        reply.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 2, 0, 4, 10, 0, 0, 7]);
    }
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn response_must_match_id_question_and_answer_owner() {
        let query = query("portal.test", 123).unwrap();
        let reply = test_answer(&query, false);
        assert!(
            matches!(parse(&reply,"portal.test",123).unwrap(), Answer::Addresses(ips,ttl)
            if ips == [Ipv4Addr::new(10,0,0,7)] && ttl == Duration::from_secs(2))
        );
        assert!(parse(&reply, "other.test", 123).is_err());
        assert!(parse(&reply, "portal.test", 124).is_err());
        for end in 0..reply.len() {
            assert!(parse(&reply[..end], "portal.test", 123).is_err());
        }
        let mut malicious = reply;
        malicious[12] = 0xc0;
        malicious[13] = 12;
        assert!(parse(&malicious, "portal.test", 123).is_err());
    }
}
