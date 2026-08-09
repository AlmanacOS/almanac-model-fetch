//! Git packfile parsing.
//!
//! A protocol-v2 fetch with `filter blob:none` and `deepen 1` returns a small
//! packfile holding the signed commit and the tree objects — the evidence the
//! bundle needs. This module turns those bytes into verified loose objects.
//!
//! Deliberately minimal: no pack indexes, no streaming, no thin packs. The
//! packs we consume are a few kilobytes (commit + trees, blobs filtered), so
//! everything is done in memory and every object's identity is recomputed and
//! recorded — nothing from the network is trusted by its claimed name.

use std::collections::HashMap;

use amf_verify::git::ObjectKind;
use sha1::{Digest, Sha1};

use crate::SourceError;

/// One object out of a pack, with its verified identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedObject {
    pub kind: ObjectKind,
    /// Computed from the content — never taken from the wire.
    pub oid: String,
    pub data: Vec<u8>,
}

/// Parse a packfile into objects, resolving deltas and checking the trailer.
pub fn parse_pack(pack: &[u8]) -> Result<Vec<PackedObject>, SourceError> {
    if pack.len() < 32 {
        return Err(malformed("pack is too short to be real"));
    }
    if &pack[0..4] != b"PACK" {
        return Err(malformed("bad pack magic"));
    }
    let version = u32::from_be_bytes(pack[4..8].try_into().unwrap());
    if version != 2 && version != 3 {
        return Err(malformed(&format!("unsupported pack version {version}")));
    }
    let count = u32::from_be_bytes(pack[8..12].try_into().unwrap()) as usize;

    // The trailer is SHA-1 over everything before it. Checking it first means a
    // truncated or corrupted transfer fails cleanly before object parsing.
    let body_end = pack.len() - 20;
    let mut hasher = Sha1::new();
    hasher.update(&pack[..body_end]);
    if hasher.finalize().as_slice() != &pack[body_end..] {
        return Err(malformed("pack trailer checksum mismatch"));
    }

    // Every object needs at least a header byte and a couple of zlib bytes, so
    // a count larger than the byte budget is hostile. Checking before the
    // `with_capacity` calls below keeps a lying header from becoming a
    // multi-gigabyte allocation.
    if count > body_end - 12 {
        return Err(malformed(&format!(
            "pack claims {count} objects but only carries {} bytes",
            body_end - 12
        )));
    }

    // First pass: inflate every entry, remembering offsets for delta bases.
    struct Entry {
        type_code: u8,
        /// For ofs-delta: distance back to the base's offset.
        base_offset: Option<usize>,
        /// For ref-delta: the base's object id.
        base_ref: Option<String>,
        data: Vec<u8>,
        offset: usize,
    }

    let mut entries: Vec<Entry> = Vec::with_capacity(count);
    let mut pos = 12;

    for _ in 0..count {
        let offset = pos;
        if pos >= body_end {
            return Err(malformed("pack ended before all objects were read"));
        }

        // Object header: type in bits 4-6 of the first byte, size as a
        // little-endian base-128 varint spread across the low bits.
        let mut byte = pack[pos];
        pos += 1;
        let type_code = (byte >> 4) & 0x7;
        let mut size = (byte & 0x0f) as u64;
        let mut shift = 4;
        while byte & 0x80 != 0 {
            if pos >= body_end {
                return Err(malformed("truncated object size varint"));
            }
            byte = pack[pos];
            pos += 1;
            size |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
        }

        let mut base_offset = None;
        let mut base_ref = None;
        match type_code {
            1..=4 => {}
            6 => {
                // Offset delta: distance to the base, in git's peculiar
                // "each continuation adds 1 to the accumulated value" varint.
                if pos >= body_end {
                    return Err(malformed("truncated ofs-delta header"));
                }
                let mut b = pack[pos];
                pos += 1;
                let mut dist = (b & 0x7f) as usize;
                while b & 0x80 != 0 {
                    if pos >= body_end {
                        return Err(malformed("truncated ofs-delta varint"));
                    }
                    b = pack[pos];
                    pos += 1;
                    dist = ((dist + 1) << 7) | (b & 0x7f) as usize;
                }
                if dist > offset {
                    return Err(malformed("ofs-delta points before the pack start"));
                }
                base_offset = Some(offset - dist);
            }
            7 => {
                if pos + 20 > body_end {
                    return Err(malformed("truncated ref-delta header"));
                }
                base_ref = Some(hex::encode(&pack[pos..pos + 20]));
                pos += 20;
            }
            other => return Err(malformed(&format!("unknown pack object type {other}"))),
        }

        let (data, consumed) = inflate(&pack[pos..body_end], size)?;
        pos += consumed;

        entries.push(Entry {
            type_code,
            base_offset,
            base_ref,
            data,
            offset,
        });
    }
    if pos != body_end {
        return Err(malformed("pack has trailing garbage after the last object"));
    }

    // Second pass: resolve deltas. Bases always precede their deltas in packs
    // git produces, so a single forward pass suffices; a delta whose base is
    // missing after that is an error, not something to loop over.
    let mut by_offset: HashMap<usize, (ObjectKind, Vec<u8>)> = HashMap::new();
    let mut by_oid: HashMap<String, (ObjectKind, Vec<u8>)> = HashMap::new();
    let mut out = Vec::with_capacity(count);

    for entry in &entries {
        let (kind, data) = match entry.type_code {
            1 => (ObjectKind::Commit, entry.data.clone()),
            2 => (ObjectKind::Tree, entry.data.clone()),
            3 => (ObjectKind::Blob, entry.data.clone()),
            4 => {
                // Annotated tags cannot appear on the path we request, and the
                // evidence chain has no use for them; skip rather than fail so
                // an unusual server response does not kill the fetch.
                continue;
            }
            6 => {
                let base_off = entry.base_offset.unwrap();
                let (base_kind, base_data) = by_offset.get(&base_off).ok_or_else(|| {
                    malformed("ofs-delta base not found at the referenced offset")
                })?;
                (*base_kind, apply_delta(base_data, &entry.data)?)
            }
            7 => {
                let base_id = entry.base_ref.as_ref().unwrap();
                let (base_kind, base_data) = by_oid.get(base_id).ok_or_else(|| {
                    // A thin pack references a base we were never sent. We do
                    // not request thin packs, so this is a protocol violation.
                    malformed(&format!("ref-delta base {base_id} not present in pack"))
                })?;
                (*base_kind, apply_delta(base_data, &entry.data)?)
            }
            _ => unreachable!("filtered in the first pass"),
        };

        let oid = amf_verify::git::object_id(kind, &data);
        by_offset.insert(entry.offset, (kind, data.clone()));
        by_oid.insert(oid.clone(), (kind, data.clone()));
        out.push(PackedObject { kind, oid, data });
    }

    Ok(out)
}

/// Inflate one zlib stream, returning the data and the compressed bytes consumed.
fn inflate(input: &[u8], expected_size: u64) -> Result<(Vec<u8>, usize), SourceError> {
    use flate2::{Decompress, FlushDecompress, Status};

    // Cap the allocation: a hostile size header must not become an OOM. Packs
    // we consume hold commits and trees, which are small; 64 MiB of headroom is
    // three orders of magnitude more than any real tree.
    const MAX_OBJECT: u64 = 64 * 1024 * 1024;
    if expected_size > MAX_OBJECT {
        return Err(malformed(&format!(
            "pack object claims {expected_size} bytes, over the {MAX_OBJECT} sanity limit"
        )));
    }

    let mut decomp = Decompress::new(true);
    let mut out = Vec::with_capacity(expected_size as usize);
    loop {
        let before_in = decomp.total_in();
        let status = decomp
            .decompress_vec(
                &input[decomp.total_in() as usize..],
                &mut out,
                FlushDecompress::None,
            )
            .map_err(|e| malformed(&format!("zlib error in pack object: {e}")))?;
        match status {
            Status::StreamEnd => break,
            Status::Ok | Status::BufError => {
                if out.len() as u64 > expected_size {
                    return Err(malformed("pack object inflated past its declared size"));
                }
                // Input exhausted without StreamEnd: truncated stream. This
                // must be checked before the reserve branch — a no-progress
                // BufError with nothing left to read means "need more input",
                // and reserving output space for it would loop forever.
                if decomp.total_in() as usize >= input.len() {
                    return Err(malformed("zlib stream ended prematurely"));
                }
                if decomp.total_in() == before_in {
                    if status == Status::BufError {
                        // Input remains, so progress is blocked on output space.
                        out.reserve(8192);
                        continue;
                    }
                    return Err(malformed("zlib made no progress"));
                }
            }
        }
    }
    if out.len() as u64 != expected_size {
        return Err(malformed(&format!(
            "pack object inflated to {} bytes but declared {expected_size}",
            out.len()
        )));
    }
    Ok((out, decomp.total_in() as usize))
}

/// Apply a git delta (copy/insert instruction stream) to a base object.
fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, SourceError> {
    let mut pos = 0;

    let base_size = read_delta_size(delta, &mut pos)?;
    if base_size as usize != base.len() {
        return Err(malformed(&format!(
            "delta expects a base of {base_size} bytes, have {}",
            base.len()
        )));
    }
    let result_size = read_delta_size(delta, &mut pos)?;

    let mut out = Vec::with_capacity(result_size as usize);
    while pos < delta.len() {
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            // Copy from base: offset and size fields are present only where
            // their bit is set in the opcode.
            let mut offset: usize = 0;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err(malformed("truncated delta copy offset"));
                    }
                    offset |= (delta[pos] as usize) << (8 * i);
                    pos += 1;
                }
            }
            let mut size: usize = 0;
            for i in 0..3 {
                if op & (1 << (4 + i)) != 0 {
                    if pos >= delta.len() {
                        return Err(malformed("truncated delta copy size"));
                    }
                    size |= (delta[pos] as usize) << (8 * i);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = offset
                .checked_add(size)
                .ok_or_else(|| malformed("delta copy range overflows"))?;
            if end > base.len() {
                return Err(malformed("delta copy reads past the base object"));
            }
            out.extend_from_slice(&base[offset..end]);
        } else if op != 0 {
            // Insert literal bytes.
            let size = op as usize;
            if pos + size > delta.len() {
                return Err(malformed("truncated delta insert"));
            }
            out.extend_from_slice(&delta[pos..pos + size]);
            pos += size;
        } else {
            return Err(malformed("delta opcode 0 is reserved"));
        }
    }

    if out.len() as u64 != result_size {
        return Err(malformed(&format!(
            "delta produced {} bytes but declared {result_size}",
            out.len()
        )));
    }
    Ok(out)
}

fn read_delta_size(delta: &[u8], pos: &mut usize) -> Result<u64, SourceError> {
    let mut size: u64 = 0;
    let mut shift = 0;
    loop {
        if *pos >= delta.len() {
            return Err(malformed("truncated delta size header"));
        }
        let b = delta[*pos];
        *pos += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(size);
        }
    }
}

fn malformed(msg: &str) -> SourceError {
    SourceError::Malformed(format!("packfile: {msg}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    /// Build a pack from (type_code, payload, extra_header) entries.
    fn build_pack(entries: &[(u8, &[u8], &[u8])]) -> Vec<u8> {
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&(entries.len() as u32).to_be_bytes());

        for (type_code, payload, extra) in entries {
            // Encode the size varint with the type in the first byte.
            let mut size = payload.len() as u64;
            let mut first = (type_code << 4) | (size & 0x0f) as u8;
            size >>= 4;
            if size > 0 {
                first |= 0x80;
            }
            pack.push(first);
            while size > 0 {
                let mut b = (size & 0x7f) as u8;
                size >>= 7;
                if size > 0 {
                    b |= 0x80;
                }
                pack.push(b);
            }
            pack.extend_from_slice(extra);
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(payload).unwrap();
            pack.extend_from_slice(&enc.finish().unwrap());
        }

        let mut hasher = Sha1::new();
        hasher.update(&pack);
        let trailer = hasher.finalize();
        pack.extend_from_slice(&trailer);
        pack
    }

    fn delta_size(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut b = (n & 0x7f) as u8;
            n >>= 7;
            if n > 0 {
                b |= 0x80;
            }
            out.push(b);
            if n == 0 {
                return out;
            }
        }
    }

    #[test]
    fn parses_a_simple_pack() {
        let pack = build_pack(&[(1, b"tree abc\n\nmsg\n", b""), (3, b"blob data", b"")]);
        let objects = parse_pack(&pack).unwrap();
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].kind, ObjectKind::Commit);
        assert_eq!(objects[1].kind, ObjectKind::Blob);
        assert_eq!(
            objects[1].oid,
            amf_verify::git::object_id(ObjectKind::Blob, b"blob data")
        );
    }

    #[test]
    fn rejects_a_corrupted_trailer() {
        let mut pack = build_pack(&[(3, b"data", b"")]);
        let last = pack.len() - 1;
        pack[last] ^= 1;
        let err = parse_pack(&pack).unwrap_err().to_string();
        assert!(err.contains("trailer"), "{err}");
    }

    #[test]
    fn rejects_a_truncated_pack() {
        let pack = build_pack(&[(3, b"data", b"")]);
        assert!(parse_pack(&pack[..pack.len() - 25]).is_err());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut pack = build_pack(&[(3, b"data", b"")]);
        pack[0] = b'K';
        // Fix the trailer so only the magic is wrong.
        let body_end = pack.len() - 20;
        let mut hasher = Sha1::new();
        hasher.update(&pack[..body_end]);
        let t = hasher.finalize();
        pack[body_end..].copy_from_slice(&t);
        assert!(parse_pack(&pack).unwrap_err().to_string().contains("magic"));
    }

    #[test]
    fn resolves_a_ref_delta() {
        let base = b"hello base object";
        let base_oid_hex = amf_verify::git::object_id(ObjectKind::Blob, base);
        let base_oid = hex::decode(&base_oid_hex).unwrap();

        // Delta: copy bytes 0..5 of the base, then insert " world".
        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_size(base.len() as u64));
        delta.extend_from_slice(&delta_size(11));
        delta.push(0x80 | 0x10); // copy, size1 field present
        delta.push(5); // size = 5, offset = 0
        delta.push(6); // insert 6 bytes
        delta.extend_from_slice(b" world");

        let pack = build_pack(&[(3, base, b""), (7, &delta, &base_oid)]);
        let objects = parse_pack(&pack).unwrap();
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[1].data, b"hello world");
        assert_eq!(
            objects[1].kind,
            ObjectKind::Blob,
            "delta inherits base type"
        );
        assert_eq!(
            objects[1].oid,
            amf_verify::git::object_id(ObjectKind::Blob, b"hello world")
        );
    }

    #[test]
    fn resolves_an_ofs_delta() {
        let base = b"hello base object";

        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_size(base.len() as u64));
        delta.extend_from_slice(&delta_size(5));
        delta.push(0x80 | 0x10);
        delta.push(5); // copy first 5 bytes

        // The ofs-delta's base-distance varint: base is at offset 12, delta
        // entry starts right after it. Build the pack manually to control
        // offsets.
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&2u32.to_be_bytes());

        // Base at offset 12.
        pack.push((3 << 4) | (base.len() as u8 & 0x0f) | 0x80);
        pack.push((base.len() >> 4) as u8);
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(base).unwrap();
        pack.extend_from_slice(&enc.finish().unwrap());

        let delta_offset = pack.len();
        let dist = delta_offset - 12;
        assert!(dist < 128, "test assumes a one-byte distance varint");
        pack.push((6 << 4) | (delta.len() as u8 & 0x0f) | if delta.len() > 15 { 0x80 } else { 0 });
        if delta.len() > 15 {
            pack.push((delta.len() >> 4) as u8);
        }
        pack.push(dist as u8);
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&delta).unwrap();
        pack.extend_from_slice(&enc.finish().unwrap());

        let mut hasher = Sha1::new();
        hasher.update(&pack);
        let t = hasher.finalize();
        pack.extend_from_slice(&t);

        let objects = parse_pack(&pack).unwrap();
        assert_eq!(objects[1].data, b"hello");
    }

    #[test]
    fn rejects_a_delta_whose_base_is_missing() {
        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_size(4));
        delta.extend_from_slice(&delta_size(4));
        delta.push(4);
        delta.extend_from_slice(b"abcd");
        let fake_base = [0u8; 20];
        let pack = build_pack(&[(7, &delta, &fake_base)]);
        let err = parse_pack(&pack).unwrap_err().to_string();
        assert!(err.contains("not present"), "{err}");
    }

    #[test]
    fn rejects_a_delta_copy_past_the_base() {
        let base = b"tiny";
        let base_oid = hex::decode(amf_verify::git::object_id(ObjectKind::Blob, base)).unwrap();
        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_size(4));
        delta.extend_from_slice(&delta_size(100));
        delta.push(0x80 | 0x10);
        delta.push(100); // copy 100 bytes from a 4-byte base
        let pack = build_pack(&[(3, base, b""), (7, &delta, &base_oid)]);
        assert!(parse_pack(&pack)
            .unwrap_err()
            .to_string()
            .contains("past the base"));
    }

    #[test]
    fn rejects_an_object_lying_about_its_size() {
        // Declared size 3, actual inflated content 4 bytes.
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());
        pack.push(3 << 4 | 3); // blob, size 3
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"abcd").unwrap();
        pack.extend_from_slice(&enc.finish().unwrap());
        let mut hasher = Sha1::new();
        hasher.update(&pack);
        let t = hasher.finalize();
        pack.extend_from_slice(&t);

        assert!(parse_pack(&pack).is_err());
    }

    #[test]
    fn rejects_a_truncated_zlib_stream_behind_a_valid_trailer() {
        // A hostile server controls the trailer, so a truncated object stream
        // can arrive with a checksum that verifies. This must error, not hang.
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());
        pack.push(3 << 4 | 10); // blob, size 10
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"0123456789").unwrap();
        let z = enc.finish().unwrap();
        pack.extend_from_slice(&z[..z.len() - 4]); // cut the stream short
        let mut hasher = Sha1::new();
        hasher.update(&pack);
        let t = hasher.finalize();
        pack.extend_from_slice(&t);

        let err = parse_pack(&pack).unwrap_err().to_string();
        assert!(err.contains("prematurely"), "{err}");
    }

    #[test]
    fn rejects_an_object_count_larger_than_the_pack() {
        // count is attacker-supplied; it must not size an allocation.
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut hasher = Sha1::new();
        hasher.update(&pack);
        let t = hasher.finalize();
        pack.extend_from_slice(&t);

        let err = parse_pack(&pack).unwrap_err().to_string();
        assert!(err.contains("claims"), "{err}");
    }

    #[test]
    fn rejects_an_absurd_declared_size() {
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());
        // Type blob, size varint encoding ~2^40.
        pack.push(3 << 4 | 0x0f | 0x80);
        pack.extend_from_slice(&[0xff; 4]);
        pack.push(0x7f);
        pack.extend_from_slice(&[0u8; 30]);
        let mut hasher = Sha1::new();
        hasher.update(&pack);
        let t = hasher.finalize();
        pack.extend_from_slice(&t);

        let err = parse_pack(&pack).unwrap_err().to_string();
        assert!(err.contains("sanity limit"), "{err}");
    }
}
