//! LZH -lh4- to -lh7- (ar002's static Huffman; lzh.py's decode_iter, which ARJ's methods 1-3
//! use too), ARJ's method 4 (arj.py's fastest_iter), and LZH's CRC-16. Fed a piece at a time
//! (feed, finish, read, eof); each decodes only while it holds MARGIN bytes past where it is, or
//! all of its input.

use crate::huff::huffman;
use crate::{raise, Damage, Res};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;

const NT: usize = 19;
const NC: usize = 510;
const MARGIN: usize = 1 << 14; // more than a block's tables

/// Bits most significant first; past the end of the data, zeros (an overrun is damage).
struct Bits {
    d: Vec<u8>,
    at: usize,
    acc: u64,
    n: u32,
    past: i64,
}

impl Bits {
    #[inline]
    fn peek(&mut self, k: u32) -> u64 {
        while self.n < k {
            let b = match self.d.get(self.at) {
                Some(&b) => b as u64,
                None => {
                    self.past += 1;
                    0
                }
            };
            self.at += 1;
            self.acc = (self.acc << 8) | b;
            self.n += 8;
        }
        (self.acc >> (self.n - k)) & ((1u64 << k) - 1)
    }

    #[inline]
    fn drop_bits(&mut self, k: u32) -> Res<()> {
        self.n -= k;
        if self.past - (self.n / 8) as i64 > 2 {
            return Err(Damage::new("The archive is damaged (a member's data runs short)"));
        }
        Ok(())
    }

    #[inline]
    fn get(&mut self, k: u32) -> Res<u64> {
        if k == 0 {
            return Ok(0);
        }
        let v = self.peek(k);
        self.drop_bits(k)?;
        Ok(v)
    }

    fn left(&self) -> usize {
        self.d.len().saturating_sub(self.at)
    }

    fn compact(&mut self) {
        if self.at > (1 << 20) && self.at <= self.d.len() {
            self.d.drain(..self.at);
            self.at = 0;
        }
    }
}

/// A Huffman code: a lookup table, or one symbol that takes no bits.
enum Code {
    Only(u32),
    Table(Vec<i32>, u32),
}

impl Code {
    fn new(lengths: &[u32]) -> Res<Code> {
        let bits = lengths.iter().copied().max().unwrap_or(0);
        Ok(Code::Table(huffman(lengths, bits)?, bits))
    }

    #[inline]
    fn read(&self, b: &mut Bits) -> Res<u32> {
        match self {
            Code::Only(c) => Ok(*c),
            Code::Table(t, bits) => {
                let e = t[b.peek(*bits) as usize];
                if e < 0 {
                    return Err(Damage::new("The archive is damaged (a bad Huffman code)"));
                }
                b.drop_bits((e & 15) as u32)?;
                Ok((e >> 4) as u32)
            }
        }
    }
}

fn lengths_code(b: &mut Bits, nbits: u32, count: usize, special: bool) -> Res<Code> {
    let n = b.get(nbits)? as usize;
    if n == 0 {
        let c = b.get(nbits)? as u32;
        if c as usize >= count {
            return Err(Damage::new("The archive is damaged (a Huffman table)"));
        }
        return Ok(Code::Only(c));
    }
    if n > count {
        return Err(Damage::new("The archive is damaged (a Huffman table)"));
    }
    let mut lengths = vec![0u32; count];
    let mut i = 0usize;
    while i < n {
        let mut c = b.get(3)? as u32;
        if c == 7 {
            while b.get(1)? != 0 {
                c += 1;
                if c > 16 {
                    return Err(Damage::new("The archive is damaged (a Huffman code length)"));
                }
            }
        }
        lengths[i] = c;
        i += 1;
        if special && i == 3 {
            let zeros = b.get(2)? as usize;
            if i + zeros > n {
                return Err(Damage::new("The archive is damaged (a Huffman table)"));
            }
            i += zeros;
        }
    }
    if lengths.iter().all(|&l| l == 0) {
        return Err(Damage::new("The archive is damaged (an empty Huffman table)"));
    }
    Code::new(&lengths)
}

fn literal_code(b: &mut Bits, pt: &Code) -> Res<Code> {
    let n = b.get(9)? as usize;
    if n == 0 {
        let c = b.get(9)? as u32;
        if c as usize >= NC {
            return Err(Damage::new("The archive is damaged (a Huffman table)"));
        }
        return Ok(Code::Only(c));
    }
    if n > NC {
        return Err(Damage::new("The archive is damaged (a Huffman table)"));
    }
    let mut lengths = vec![0u32; NC];
    let mut i = 0usize;
    while i < n {
        let c = pt.read(b)?;
        if c > 2 {
            lengths[i] = c - 2;
            i += 1;
        } else if c == 0 {
            i += 1;
        } else {
            i += if c == 1 { b.get(4)? as usize + 3 } else { b.get(9)? as usize + 20 };
            if i > n {
                return Err(Damage::new("The archive is damaged (a Huffman table)"));
            }
        }
    }
    if lengths.iter().all(|&l| l == 0) {
        return Err(Damage::new("The archive is damaged (an empty Huffman table)"));
    }
    Code::new(&lengths)
}

struct Block {
    left: u32,
    lt: Code,
    dt: Code,
}

/// -lh4- to -lh7- (and ARJ methods 1-3).
#[pyclass(module = "packport_native")]
pub struct LzhDecoder {
    b: Bits,
    finished: bool,
    window_bits: u32,
    window: usize,
    out: Vec<u8>, // the window (starting as spaces), then new output
    given: usize,
    size: u64,
    total: u64,
    block: Option<Block>,
    fast: bool, // ARJ method 4
}

impl LzhDecoder {
    fn ready(&self) -> bool {
        self.finished || self.b.left() >= MARGIN
    }

    fn produced(&self) -> u64 {
        self.total + (self.out.len() - self.given) as u64
    }

    fn step_lzh(&mut self, want: usize) -> Res<()> {
        let pbits = if self.window_bits >= 15 { 5 } else { 4 };
        while self.out.len() - self.given < want && self.produced() < self.size {
            if !self.ready() {
                return Ok(());
            }
            if self.block.is_none() {
                let count = self.b.get(16)? as u32;
                if count == 0 {
                    return Err(Damage::new("The archive is damaged (an empty LZH block)"));
                }
                let pt = lengths_code(&mut self.b, 5, NT, true)?;
                let lt = literal_code(&mut self.b, &pt)?;
                let dt = lengths_code(&mut self.b, pbits, self.window_bits as usize + 1, false)?;
                self.block = Some(Block { left: count, lt, dt });
            }
            let mut blk = self.block.take().unwrap();
            let r = self.symbols(&mut blk, want);
            if blk.left > 0 {
                self.block = Some(blk);
            }
            r?;
        }
        Ok(())
    }

    fn symbols(&mut self, blk: &mut Block, want: usize) -> Res<()> {
        while blk.left > 0 && self.out.len() - self.given < want && self.produced() < self.size {
            if !self.finished && self.b.left() < MARGIN {
                return Ok(());
            }
            blk.left -= 1;
            let c = blk.lt.read(&mut self.b)?;
            if c < 256 {
                self.out.push(c as u8);
                continue;
            }
            let length = (c - 253) as usize;
            let mut p = blk.dt.read(&mut self.b)? as u64;
            if p > 1 {
                p = (1u64 << (p - 1)) + self.b.get((p - 1) as u32)?;
            }
            let have = self.out.len();
            if (p + 1) as usize > have {
                return Err(Damage::new("The archive is damaged (a match before the start of the window)"));
            }
            let start = have - p as usize - 1;
            if start + length <= have {
                self.out.extend_from_within(start..start + length);
            } else {
                for k in 0..length {
                    let v = self.out[start + k];
                    self.out.push(v);
                }
            }
        }
        Ok(())
    }

    fn step_fast(&mut self, want: usize) -> Res<()> {
        while self.out.len() - self.given < want && self.produced() < self.size {
            if !self.ready() {
                return Ok(());
            }
            let c = groups(&mut self.b, 0, 7)?;
            if c == 0 {
                let v = self.b.get(8)? as u8;
                self.out.push(v);
                continue;
            }
            let length = (c + 2) as usize;
            let back = groups(&mut self.b, 9, 13)? as usize + 1;
            if back > self.out.len() {
                return Err(Damage::new("The archive is damaged (a match before the start of the data)"));
            }
            let start = self.out.len() - back;
            if start + length <= self.out.len() {
                self.out.extend_from_within(start..start + length);
            } else {
                for k in 0..length {
                    let v = self.out[start + k];
                    self.out.push(v);
                }
            }
        }
        Ok(())
    }

    /// The range of out to hand over next (want bytes at most).
    fn take(&mut self, want: usize) -> (usize, usize) {
        let left = (self.size - self.total) as usize;
        let n = want.min(self.out.len() - self.given).min(left);
        self.given += n;
        self.total += n as u64;
        (self.given - n, self.given)
    }

    fn trim(&mut self) {
        if self.given > self.window + (4 << 20) {
            let drop = self.given - self.window;
            self.out.drain(..drop);
            self.given -= drop;
        }
    }
}

fn groups(b: &mut Bits, mut width: u32, top: u32) -> Res<u64> {
    let mut plus = 0u64;
    while width < top {
        if b.get(1)? == 0 {
            break;
        }
        plus += 1 << width;
        width += 1;
    }
    Ok(plus + b.get(width)?)
}

#[pymethods]
impl LzhDecoder {
    /// window_bits for -lh4- to -lh7- (16 for ARJ 1-3); fast=True for ARJ method 4.
    #[new]
    #[pyo3(signature = (window_bits, size, fast = false))]
    fn new(window_bits: u32, size: u64, fast: bool) -> Self {
        let window = if fast { 1 << 15 } else { 1usize << window_bits.min(16) };
        let out = if fast { Vec::new() } else { vec![b' '; window] };
        let given = out.len();
        LzhDecoder { b: Bits { d: Vec::new(), at: 0, acc: 0, n: 0, past: 0 }, finished: false, window_bits,
                     window, out, given, size, total: 0, block: None, fast }
    }

    fn feed(&mut self, py: Python<'_>, data: PyBackedBytes) {
        py.detach(|| {
            self.b.compact();
            self.b.d.extend_from_slice(&data);
        });
    }

    fn finish(&mut self) {
        self.finished = true;
    }

    #[getter]
    fn finished(&self) -> bool {
        self.finished
    }

    #[getter]
    fn eof(&self) -> bool {
        self.total >= self.size
    }

    fn read<'py>(&mut self, py: Python<'py>, max_len: usize) -> PyResult<Bound<'py, PyBytes>> {
        let (a, b) = py.detach(|| -> Res<(usize, usize)> {
            self.trim();
            if self.fast { self.step_fast(max_len)? } else { self.step_lzh(max_len)? }
            Ok(self.take(max_len))
        }).map_err(|e| raise(py, e))?;
        Ok(PyBytes::new(py, &self.out[a..b]))
    }
}

/// LZH's CRC-16 (polynomial 0xA001) of data, carrying on from crc.
#[pyfunction]
#[pyo3(signature = (data, crc = 0))]
pub fn crc16(py: Python<'_>, data: PyBackedBytes, crc: u32) -> u32 {
    py.detach(|| {
        let mut table = [0u16; 256];
        for (n, slot) in table.iter_mut().enumerate() {
            let mut c = n as u16;
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ 0xA001 } else { c >> 1 };
            }
            *slot = c;
        }
        let mut c = crc as u16;
        for &b in data.iter() {
            c = (c >> 8) ^ table[((c ^ b as u16) & 0xFF) as usize];
        }
        c as u32
    })
}
