//! Small block decoders the disk-image readers call on each chunk: NTFS's LZNT1 (fs/ntfs.py),
//! Apple's ADC (vdisk.py) and an LZ4 block (squashfs.py). Each is the Python function, compiled.

use crate::{raise, Damage, Res};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;

fn lznt1(data: &[u8], size: usize) -> Res<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(size);
    let mut i = 0usize;
    while i + 2 <= data.len() && out.len() < size {
        let h = data[i] as usize | (data[i + 1] as usize) << 8;
        if h == 0 {
            break;
        }
        let n = (h & 0xFFF) + 1;
        let end = std::cmp::min(i + 2 + n, data.len());
        let chunk = &data[i + 2..end];
        i += 2 + n;
        if h & 0x8000 == 0 {
            out.extend_from_slice(chunk);
            continue;
        }
        let start = out.len();
        let mut j = 0usize;
        while j < chunk.len() {
            let flags = chunk[j];
            j += 1;
            for bit in 0..8 {
                if j >= chunk.len() {
                    break;
                }
                if (flags >> bit) & 1 == 0 {
                    out.push(chunk[j]);
                    j += 1;
                    continue;
                }
                if j + 2 > chunk.len() {
                    return Err(Damage::new("The NTFS compressed data is damaged"));
                }
                let token = chunk[j] as usize | (chunk[j + 1] as usize) << 8;
                j += 2;
                let (mut q, mut shift) = ((out.len() - start) as i64 - 1, 12u32);
                while q >= 16 {
                    q >>= 1;
                    shift -= 1;
                }
                let length = (token & ((1 << shift) - 1)) + 3;
                let dist = (token >> shift) + 1;
                if dist > out.len() || out.len() - dist < start {
                    return Err(Damage::new("The NTFS compressed data is damaged"));
                }
                let src = out.len() - dist;
                for k in 0..length {
                    let v = out[src + k];
                    out.push(v);
                }
            }
        }
    }
    out.truncate(size);
    Ok(out)
}

fn adc(data: &[u8], size: usize) -> Res<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(size);
    let mut i = 0usize;
    while i < data.len() && out.len() < size {
        let b = data[i];
        if b & 0x80 != 0 {
            let n = (b & 0x7F) as usize + 1;
            let end = std::cmp::min(i + 1 + n, data.len());
            out.extend_from_slice(&data[i + 1..end]);
            i += 1 + n;
            continue;
        }
        let (length, dist);
        if b & 0x40 != 0 {
            if i + 3 > data.len() {
                break;
            }
            length = (b & 0x3F) as usize + 4;
            dist = ((data[i + 1] as usize) << 8 | data[i + 2] as usize) + 1;
            i += 3;
        } else {
            if i + 2 > data.len() {
                break;
            }
            length = ((b >> 2) & 0x0F) as usize + 3;
            dist = (((b & 3) as usize) << 8 | data[i + 1] as usize) + 1;
            i += 2;
        }
        if dist > out.len() {
            return Err(Damage::new("The DMG is damaged (ADC data)"));
        }
        let start = out.len() - dist;
        for k in 0..length {
            let v = out[start + k];
            out.push(v);
        }
    }
    out.truncate(size);
    Ok(out)
}

fn lz4_block(data: &[u8], limit: usize) -> Res<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(limit.min(1 << 20));
    let (mut i, n) = (0usize, data.len());
    while i < n {
        let token = data[i];
        i += 1;
        let mut count = (token >> 4) as usize;
        if count == 15 {
            loop {
                if i >= n {
                    return Err(Damage::new("The LZ4 data is cut short"));
                }
                let b = data[i];
                i += 1;
                count += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        if i + count > n || out.len() + count > limit {
            return Err(Damage::new("The LZ4 data is damaged"));
        }
        out.extend_from_slice(&data[i..i + count]);
        i += count;
        if i >= n {
            break;
        }
        if i + 2 > n {
            return Err(Damage::new("The LZ4 data is cut short"));
        }
        let dist = data[i] as usize | (data[i + 1] as usize) << 8;
        i += 2;
        let mut length = (token & 15) as usize + 4;
        if token & 15 == 15 {
            loop {
                if i >= n {
                    return Err(Damage::new("The LZ4 data is cut short"));
                }
                let b = data[i];
                i += 1;
                length += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        if dist == 0 || dist > out.len() || out.len() + length > limit {
            return Err(Damage::new("The LZ4 data is damaged"));
        }
        let start = out.len() - dist;
        if dist >= length {
            out.extend_from_within(start..start + length);
        } else {
            for k in 0..length {
                let v = out[start + k];
                out.push(v);
            }
        }
    }
    Ok(out)
}

macro_rules! export {
    ($name:ident, $inner:ident, $doc:literal) => {
        #[doc = $doc]
        #[pyfunction]
        pub fn $name<'py>(py: Python<'py>, data: PyBackedBytes, size: usize) -> PyResult<Bound<'py, PyBytes>> {
            let out = py.detach(|| $inner(&data, size)).map_err(|e| raise(py, e))?;
            Ok(PyBytes::new(py, &out))
        }
    };
}

export!(lznt1_decompress, lznt1, "size bytes of NTFS LZNT1 data.");
export!(adc_decompress, adc, "size bytes of Apple Data Compression.");
export!(lz4_block_decompress, lz4_block, "An LZ4 block, limit bytes at most.");

#[cfg(test)]
mod tests {
    use super::{adc, lz4_block, lznt1};

    #[test]
    fn lz4_literals_then_a_match() {
        // 3 literals "abc", then a match 3 back, 4 + 2 long, then 1 literal
        let block = [0x32, b'a', b'b', b'c', 3, 0, 0x10, b'z'];
        assert_eq!(lz4_block(&block, 100).ok().unwrap(), b"abcabcabcz".to_vec());
        assert!(lz4_block(&[0x10, b'a', 9, 0], 100).is_err()); // a match before the start
    }

    #[test]
    fn adc_literals_and_a_short_match() {
        // 3 literals, then a 3-byte match 3 back
        let data = [0x82, b'x', b'y', b'z', 0x00, 0x02];
        assert_eq!(adc(&data, 6).ok().unwrap(), b"xyzxyz".to_vec());
    }

    #[test]
    fn lznt1_stored_chunk() {
        let mut data = vec![0x03, 0x30]; // 4 bytes, not compressed
        data.extend_from_slice(b"data");
        assert_eq!(lznt1(&data, 4).ok().unwrap(), b"data".to_vec());
    }
}
