//! RAR 5 decompression (rar5.py's Unpack5), a block at a time: the Python side reads each
//! block's header and hands its data here; take() gives the output decoded so far, filters
//! (Delta, E8, E8E9, ARM) undone, keeping the dictionary for later matches. Solid files carry
//! the state on.

use crate::huff::huffman;
use crate::{raise, Damage, Res};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;
use std::collections::VecDeque;

const NC: usize = 306;
const DC: usize = 64;
const LDC: usize = 16;
const RC: usize = 44;
const BC: usize = 20;
const MAX_FILTER: u64 = 0x40_0000;
const MAX_FILTERS: usize = 8192;
const FILTER_DELTA: u32 = 0;
const FILTER_E8: u32 = 1;
const FILTER_E8E9: u32 = 2;
const FILTER_ARM: u32 = 3;
const FLUSH: u64 = 4 << 20;

/// n (<= 57) bits from bit position pos, most significant first; past the data, zeros.
#[inline]
fn bits_at(d: &[u8], pos: usize, n: u32) -> u64 {
    let i = pos >> 3;
    let v = if i + 8 <= d.len() {
        u64::from_be_bytes(d[i..i + 8].try_into().unwrap())
    } else {
        let mut b = [0u8; 8];
        for (k, slot) in b.iter_mut().enumerate() {
            *slot = *d.get(i + k).unwrap_or(&0);
        }
        u64::from_be_bytes(b)
    };
    if n == 0 {
        return 0;
    }
    (v >> (64 - n as usize - (pos & 7))) & ((1u64 << n) - 1)
}

#[inline]
fn window(d: &[u8], pos: usize) -> (u64, u32) {
    let i = pos >> 3;
    let v = if i + 8 <= d.len() {
        u64::from_be_bytes(d[i..i + 8].try_into().unwrap())
    } else {
        let mut b = [0u8; 8];
        for (k, slot) in b.iter_mut().enumerate() {
            *slot = *d.get(i + k).unwrap_or(&0);
        }
        u64::from_be_bytes(b)
    };
    (v, 64 - (pos & 7) as u32)
}

struct Tables {
    ld: Vec<i32>,
    dd: Vec<i32>,
    ldd: Vec<i32>,
    rd: Vec<i32>,
}

#[pyclass(module = "packport_native")]
pub struct Rar5Decoder {
    #[pyo3(get, set)]
    dictionary: u64,
    hist: Vec<u8>,
    base: u64,
    written: u64,
    file_start: u64,
    old: [u64; 4],
    last_length: u64,
    tables: Option<Tables>,
    filters: VecDeque<(u64, u64, u32, u32)>,
}

impl Rar5Decoder {
    fn read_tables(&mut self, d: &[u8], mut pos: usize) -> Res<usize> {
        let mut lengths: Vec<u32> = Vec::with_capacity(BC);
        while lengths.len() < BC {
            let n = bits_at(d, pos, 4) as u32;
            pos += 4;
            if n == 15 {
                let zeros = bits_at(d, pos, 4) as usize;
                pos += 4;
                if zeros == 0 {
                    lengths.push(15);
                } else {
                    let k = std::cmp::min(zeros + 2, BC - lengths.len());
                    lengths.extend(std::iter::repeat_n(0, k));
                }
            } else {
                lengths.push(n);
            }
        }
        let bd = huffman(&lengths, 15)?;
        let size = NC + DC + LDC + RC;
        let mut table: Vec<u32> = Vec::with_capacity(size);
        while table.len() < size {
            let e = bd[bits_at(d, pos, 15) as usize];
            if e < 0 {
                return Err(Damage::new("The archive is damaged (a bad code in the Huffman tables)"));
            }
            pos += (e & 15) as usize;
            let n = (e >> 4) as u32;
            if n < 16 {
                table.push(n);
            } else if n < 18 {
                let k = if n == 16 { bits_at(d, pos, 3) + 3 } else { bits_at(d, pos, 7) + 11 } as usize;
                pos += if n == 16 { 3 } else { 7 };
                let Some(&last) = table.last() else {
                    return Err(Damage::new("The archive is damaged (a Huffman table repeats nothing)"));
                };
                let k = std::cmp::min(k, size - table.len());
                table.extend(std::iter::repeat_n(last, k));
            } else {
                let k = if n == 18 { bits_at(d, pos, 3) + 3 } else { bits_at(d, pos, 7) + 11 } as usize;
                pos += if n == 18 { 3 } else { 7 };
                let k = std::cmp::min(k, size - table.len());
                table.extend(std::iter::repeat_n(0, k));
            }
        }
        self.tables = Some(Tables {
            ld: huffman(&table[..NC], 15)?,
            dd: huffman(&table[NC..NC + DC], 15)?,
            ldd: huffman(&table[NC + DC..NC + DC + LDC], 15)?,
            rd: huffman(&table[NC + DC + LDC..], 15)?,
        });
        Ok(pos)
    }

    fn filter(&mut self, d: &[u8], mut pos: usize) -> Res<usize> {
        let data = |pos: &mut usize| -> u64 {
            let count = bits_at(d, *pos, 2) + 1;
            *pos += 2;
            let mut value = 0u64;
            for k in 0..count {
                value += bits_at(d, *pos, 8) << (8 * k);
                *pos += 8;
            }
            value
        };
        let start = data(&mut pos);
        let mut length = data(&mut pos);
        let kind = bits_at(d, pos, 3) as u32;
        pos += 3;
        let mut channels = 0u32;
        if kind == FILTER_DELTA {
            channels = bits_at(d, pos, 5) as u32 + 1;
            pos += 5;
        }
        if length > MAX_FILTER {
            length = 0;
        }
        if start >= self.dictionary {
            return Err(Damage::new("The archive is damaged (a filter that starts past the dictionary window)"));
        }
        if self.filters.len() >= MAX_FILTERS {
            return Err(Damage::new("The archive is damaged (too many filters)"));
        }
        if kind <= FILTER_ARM && length > 0 {
            self.filters.push_back((self.base + self.hist.len() as u64 + start, length, kind, channels));
        }
        Ok(pos)
    }

    fn decode_block(&mut self, d: &[u8], end: usize, new_tables: bool) -> Res<()> {
        let mut pos = 0usize;
        if new_tables {
            pos = self.read_tables(d, pos)?;
        }
        let Some(t) = self.tables.take() else {
            return Err(Damage::new("The archive is damaged (compressed data without Huffman tables)"));
        };
        let r = self.symbols(d, end, pos, &t);
        self.tables = Some(t);
        r
    }

    fn symbols(&mut self, d: &[u8], end: usize, mut pos: usize, t: &Tables) -> Res<()> {
        let dictionary = self.dictionary;
        let mut last_length = self.last_length;
        let mut old = self.old;
        let (mut v, mut s) = (0u64, 0u32);
        while pos < end {
            if s < 32 {
                (v, s) = window(d, pos);
            }
            let e = t.ld[((v >> (s - 15)) & 0x7FFF) as usize];
            if e < 0 {
                return Err(Damage::new("The archive is damaged (a bad Huffman code)"));
            }
            let n = (e & 15) as u32;
            pos += n as usize;
            s -= n;
            let slot = (e >> 4) as u32;
            if slot < 256 {
                self.hist.push(slot as u8);
                continue;
            }
            let (length, dist);
            if slot >= 262 {
                let slot = slot - 262;
                let mut len = if slot < 8 {
                    2 + slot as u64
                } else {
                    let lbits = (slot >> 2) - 1;
                    let l = 2 + (((4 | (slot & 3)) as u64) << lbits) + ((v >> (s - lbits)) & ((1u64 << lbits) - 1));
                    pos += lbits as usize;
                    s -= lbits;
                    l
                };
                if s < 32 {
                    (v, s) = window(d, pos);
                }
                let e = t.dd[((v >> (s - 15)) & 0x7FFF) as usize];
                if e < 0 {
                    return Err(Damage::new("The archive is damaged (a bad Huffman code)"));
                }
                pos += (e & 15) as usize;
                s -= (e & 15) as u32;
                let dslot = (e >> 4) as u32;
                let dd = if dslot < 4 {
                    1 + dslot as u64
                } else {
                    let dbits = (dslot >> 1) - 1;
                    let mut x = 1 + (((2 | (dslot & 1)) as u64) << dbits);
                    if dbits >= 4 {
                        if dbits > 4 {
                            x += bits_at(d, pos, dbits - 4) << 4;
                            pos += (dbits - 4) as usize;
                        }
                        let e = t.ldd[bits_at(d, pos, 15) as usize];
                        if e < 0 {
                            return Err(Damage::new("The archive is damaged (a bad Huffman code)"));
                        }
                        pos += (e & 15) as usize;
                        x += (e >> 4) as u64;
                    } else {
                        x += (v >> (s - dbits)) & ((1u64 << dbits) - 1);
                        pos += dbits as usize;
                    }
                    x
                };
                if dd > 0x100 {
                    len += 1;
                    if dd > 0x2000 {
                        len += 1;
                        if dd > 0x40000 {
                            len += 1;
                        }
                    }
                }
                old = [dd, old[0], old[1], old[2]];
                last_length = len;
                s = 0;
                length = len;
                dist = dd;
            } else if slot == 256 {
                self.last_length = last_length;
                pos = self.filter(d, pos)?;
                s = 0;
                continue;
            } else if slot == 257 {
                if last_length == 0 {
                    continue;
                }
                length = last_length;
                dist = old[0];
            } else {
                let k = (slot - 258) as usize;
                let dk = old[k];
                for j in (1..=k).rev() {
                    old[j] = old[j - 1];
                }
                old[0] = dk;
                let e = t.rd[((v >> (s - 15)) & 0x7FFF) as usize];
                if e < 0 {
                    return Err(Damage::new("The archive is damaged (a bad Huffman code)"));
                }
                pos += (e & 15) as usize;
                s -= (e & 15) as u32;
                let lslot = (e >> 4) as u32;
                length = if lslot < 8 {
                    2 + lslot as u64
                } else {
                    let lbits = (lslot >> 2) - 1;
                    let l = 2 + (((4 | (lslot & 3)) as u64) << lbits) + bits_at(d, pos, lbits);
                    pos += lbits as usize;
                    s = 0;
                    l
                };
                last_length = length;
                dist = dk;
            }
            let have = self.hist.len() as u64;
            if dist == 0 || dist > have || dist > dictionary {
                self.old = old;
                self.last_length = last_length;
                return Err(Damage::new("The archive is damaged (a match reaches back before the data)"));
            }
            let start = (have - dist) as usize;
            let length = length as usize;
            if dist as usize >= length {
                self.hist.extend_from_within(start..start + length);
            } else {
                self.hist.reserve(length);
                for k in 0..length {
                    let b = self.hist[start + k];
                    self.hist.push(b);
                }
            }
        }
        self.old = old;
        self.last_length = last_length;
        if pos > end + 8 {
            return Err(Damage::new("The archive is damaged (a block's data runs past its end)"));
        }
        Ok(())
    }

    fn flush(&mut self, out: &mut Vec<u8>, final_: bool) {
        let top = self.base + self.hist.len() as u64;
        loop {
            let mut limit = top;
            let mut pending = None;
            while let Some(&f) = self.filters.front() {
                if f.0 + f.1 <= self.written {
                    self.filters.pop_front();
                    continue;
                }
                pending = Some(f);
                break;
            }
            if let Some(p) = pending {
                limit = limit.min(p.0);
            }
            if limit > self.written {
                let a = (self.written - self.base) as usize;
                let b = (limit - self.base) as usize;
                out.extend_from_slice(&self.hist[a..b]);
                self.written = limit;
            }
            let Some(p) = pending else { break };
            if top < p.0 + p.1 {
                break;
            }
            let (start, length, kind, channels) = self.filters.pop_front().unwrap();
            if start < self.written {
                continue;
            }
            let a = (start - self.base) as usize;
            let mut block = self.hist[a..a + length as usize].to_vec();
            apply(&mut block, kind, channels, start - self.file_start);
            out.extend_from_slice(&block);
            self.written = start + length;
        }
        if final_ && !self.filters.is_empty() && self.written < top {
            let a = (self.written - self.base) as usize;
            out.extend_from_slice(&self.hist[a..]);
            self.written = top;
        }
        let drop = (self.written - self.base).saturating_sub(self.dictionary);
        if drop > FLUSH {
            self.hist.drain(..drop as usize);
            self.base += drop;
        }
    }
}

/// A filter undone on data, which starts offset bytes into the file.
fn apply(data: &mut Vec<u8>, kind: u32, channels: u32, offset: u64) {
    let n = data.len();
    if kind == FILTER_DELTA {
        let mut out = vec![0u8; n];
        let mut src = 0usize;
        let ch = channels.max(1) as usize;
        for c in 0..ch {
            let mut prev = 0u8;
            let mut at = c;
            while at < n {
                prev = prev.wrapping_sub(data[src]);
                out[at] = prev;
                src += 1;
                at += ch;
            }
        }
        *data = out;
    } else if kind == FILTER_E8 || kind == FILTER_E8E9 {
        let size: u64 = 0x100_0000;
        let mut pos = 0usize;
        let (m0, m1) = if kind == FILTER_E8E9 { (0xE8u8, 0xE9u8) } else { (0xE8, 0xE8) };
        while pos + 4 < n {
            let b = data[pos];
            pos += 1;
            if b == m0 || b == m1 {
                let at = (pos as u64 + offset) % size;
                let addr = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as u64;
                if addr & 0x8000_0000 != 0 {
                    if (addr + at) & 0x8000_0000 == 0 {
                        let v = ((addr + size) & 0xFFFF_FFFF) as u32;
                        data[pos..pos + 4].copy_from_slice(&v.to_le_bytes());
                    }
                } else if (addr.wrapping_sub(size)) & 0x8000_0000 != 0 {
                    let v = (addr.wrapping_sub(at) & 0xFFFF_FFFF) as u32;
                    data[pos..pos + 4].copy_from_slice(&v.to_le_bytes());
                }
                pos += 4;
            }
        }
    } else if kind == FILTER_ARM {
        let mut pos = 0usize;
        while pos + 3 < n {
            if data[pos + 3] == 0xEB {
                let v = (data[pos] as i64 | (data[pos + 1] as i64) << 8 | (data[pos + 2] as i64) << 16)
                    - ((offset + pos as u64) / 4) as i64;
                data[pos] = (v & 0xFF) as u8;
                data[pos + 1] = ((v >> 8) & 0xFF) as u8;
                data[pos + 2] = ((v >> 16) & 0xFF) as u8;
            }
            pos += 4;
        }
    }
}

#[pymethods]
impl Rar5Decoder {
    #[new]
    fn new(dictionary: u64) -> Self {
        Rar5Decoder { dictionary, hist: Vec::new(), base: 0, written: 0, file_start: 0, old: [0; 4], last_length: 0,
                      tables: None, filters: VecDeque::new() }
    }

    fn reset(&mut self) {
        let d = self.dictionary;
        *self = Rar5Decoder::new(d);
    }

    /// A new file starts here (in a solid archive, after the last one's data).
    fn begin_file(&mut self) {
        self.file_start = self.base + self.hist.len() as u64;
        self.written = self.file_start;
    }

    /// Decode one block's data (end: its length in bits).
    fn block(&mut self, py: Python<'_>, data: PyBackedBytes, end: usize, new_tables: bool) -> PyResult<()> {
        py.detach(|| self.decode_block(&data, end, new_tables)).map_err(|e| raise(py, e))
    }

    /// The output decoded since the last take, filters undone (final: the file's end).
    fn take<'py>(&mut self, py: Python<'py>, final_: bool) -> Bound<'py, PyBytes> {
        let mut out = Vec::new();
        py.detach(|| self.flush(&mut out, final_));
        PyBytes::new(py, &out)
    }

    #[getter]
    fn written(&self) -> u64 {
        self.written - self.file_start
    }
}
