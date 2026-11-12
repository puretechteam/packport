//! XPRESS Huffman ([MS-XCA] 2.2: WIM resources, NTFS's compressed files), as xpress.py decodes
//! it: 64 KB blocks, each with its 512 code lengths, codes read from 16-bit words most
//! significant bit first, extra length bytes from the byte stream where it stands.

use crate::huff::huffman;
use crate::{raise, Damage, Res};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;

const BLOCK: usize = 65536;

fn run(data: &[u8], size: usize) -> Res<Vec<u8>> {
    let n = data.len();
    let at = |i: usize| -> u32 { *data.get(i).unwrap_or(&0) as u32 };
    let mut out: Vec<u8> = Vec::new();
    // size comes from the archive's header: a failed allocation is damage, not an abort
    out.try_reserve_exact(size).map_err(|_| Damage::new("The data is damaged (an XPRESS size too big to hold)"))?;
    let mut pos = 0usize;
    while out.len() < size {
        if pos + 256 > n {
            return Err(Damage::new("The data is damaged (an XPRESS block is cut short)"));
        }
        let mut lengths = Vec::with_capacity(512);
        for &b in &data[pos..pos + 256] {
            lengths.push((b & 15) as u32);
            lengths.push((b >> 4) as u32);
        }
        let table = huffman(&lengths, 15)?;
        pos += 256;
        let mut bits: u32 = (at(pos) | at(pos + 1) << 8) << 16 | at(pos + 2) | at(pos + 3) << 8;
        pos += 4;
        let mut have: i32 = 32;
        let block_end = std::cmp::min(size, out.len() + BLOCK);
        while out.len() < block_end {
            let e = table[((bits >> 17) & 0x7FFF) as usize];
            if e < 0 {
                return Err(Damage::new("The data is damaged (a bad XPRESS Huffman code)"));
            }
            let k = (e & 15) as u32;
            bits = if k >= 32 { 0 } else { bits << k };
            have -= k as i32;
            if have < 16 {
                bits |= (at(pos) | at(pos + 1) << 8) << (16 - have);
                pos += 2;
                have += 16;
            }
            let sym = (e >> 4) as usize;
            if sym < 256 {
                out.push(sym as u8);
                continue;
            }
            let sym = sym - 256;
            let mut length = sym & 15;
            let log2 = (sym >> 4) as u32;
            if length == 15 {
                length = at(pos) as usize;
                pos += 1;
                if length == 255 {
                    length = (at(pos) | at(pos + 1) << 8) as usize;
                    pos += 2;
                    if length == 0 {
                        length = (at(pos) | at(pos + 1) << 8 | at(pos + 2) << 16 | at(pos + 3) << 24) as usize;
                        pos += 4;
                    }
                    if length < 15 {
                        return Err(Damage::new("The data is damaged (an XPRESS match length)"));
                    }
                    length -= 15;
                }
                length += 15;
            }
            length += 3;
            // a 32-bit length can say gigabytes: only what's left of size is ever copied
            length = length.min(size - out.len());
            let mut offset = 1usize << log2;
            if log2 > 0 {
                offset |= (bits >> (32 - log2)) as usize;
                bits = if log2 >= 32 { 0 } else { bits << log2 };
                have -= log2 as i32;
                if have < 16 {
                    bits |= (at(pos) | at(pos + 1) << 8) << (16 - have);
                    pos += 2;
                    have += 16;
                }
            }
            if offset > out.len() {
                return Err(Damage::new("The data is damaged (an XPRESS match reaches before the start)"));
            }
            let start = out.len() - offset;
            if offset >= length {
                out.extend_from_within(start..start + length);
            } else {
                for k in 0..length {
                    let b = out[start + k];
                    out.push(b);
                }
            }
            if pos > n + 4 {
                return Err(Damage::new("The data is damaged (XPRESS data ends early)"));
            }
        }
    }
    out.truncate(size);
    Ok(out)
}

/// size bytes of output from XPRESS Huffman data.
#[pyfunction]
pub fn xpress_decompress<'py>(py: Python<'py>, data: PyBackedBytes, size: usize) -> PyResult<Bound<'py, PyBytes>> {
    let out = py.detach(|| run(&data, size)).map_err(|e| raise(py, e))?;
    Ok(PyBytes::new(py, &out))
}
