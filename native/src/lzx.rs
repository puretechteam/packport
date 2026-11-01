//! LZX (CAB, WIM, CHM and NTFS's WOF): a port of packport's lzx.py, decoding the same bits the
//! same way (verbatim, aligned and uncompressed blocks, 32 KB frames realigned to 16 bits, the
//! three repeated offsets, E8 call translation over the first 32768 frames). Like LzxDecoder
//! in Python, one decoder carries on from call to call, so a reset span can come in pieces that
//! end on frames.

use crate::{raise, Damage, Res};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;

const FRAME: usize = 32768;
const MIN_MATCH: usize = 2;
const NUM_CHARS: usize = 256;
const PRETREE_SIZE: usize = 20;
const LENGTH_SIZE: usize = 249;
const ALIGNED_SIZE: usize = 8;

fn position_slots(window_bits: u32) -> Option<usize> {
    Some(match window_bits {
        15 => 30,
        16 => 32,
        17 => 34,
        18 => 36,
        19 => 38,
        20 => 42,
        21 => 50,
        _ => return None,
    })
}

const fn tables() -> ([u32; 51], [u32; 51]) {
    let mut extra = [0u32; 51];
    let mut base = [0u32; 51];
    let mut b = 0u32;
    let mut i = 0;
    while i < 51 {
        let e = if i < 4 { 0 } else { let v = (i as u32 - 2) >> 1; if v < 17 { v } else { 17 } };
        extra[i] = e;
        base[i] = b;
        b += 1 << e;
        i += 1;
    }
    (extra, base)
}

const TABLES: ([u32; 51], [u32; 51]) = tables();
const EXTRA_BITS: [u32; 51] = TABLES.0;
const POSITION_BASE: [u32; 51] = TABLES.1;

/// LZX bit input: 16-bit little-endian words, bits taken from the most significant end of a
/// 32-bit window. Past the data, zeros.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u32,
    left: u32,
}

impl<'a> Bits<'a> {
    #[inline]
    fn byte(&self, i: usize) -> u32 {
        *self.data.get(i).unwrap_or(&0) as u32
    }

    #[inline]
    fn word(&self) -> u32 {
        self.byte(self.pos) | self.byte(self.pos + 1) << 8
    }

    #[inline]
    fn ensure(&mut self, n: u32) {
        while self.left < n {
            let w = self.word();
            self.pos += 2;
            self.buf |= w << (16 - self.left);
            self.left += 16;
        }
    }

    #[inline]
    fn peek(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        self.ensure(n);
        (self.buf >> (32 - n)) & ((1u32 << n) - 1)
    }

    #[inline]
    fn drop_bits(&mut self, n: u32) {
        self.buf = if n >= 32 { 0 } else { self.buf << n };
        self.left -= n;
    }

    fn read(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        if n > 16 {
            let hi = self.read(n - 16);
            return (hi << 16) | self.read(16);
        }
        let v = self.peek(n);
        self.drop_bits(n);
        v
    }

    fn align(&mut self) {
        if !self.left.is_multiple_of(16) {
            self.drop_bits(self.left % 16);
        }
    }

    /// n bytes straight from the input (whole words still in the bit buffer go back first).
    fn raw_bytes(&mut self, n: usize) -> &'a [u8] {
        let back = (self.left / 16 * 2) as usize;
        self.pos = self.pos.saturating_sub(back);
        self.buf = 0;
        self.left = 0;
        let start = self.pos.min(self.data.len());
        let end = self.pos.saturating_add(n).min(self.data.len());
        self.pos = self.pos.saturating_add(n);
        &self.data[start..end]
    }
}

/// A canonical Huffman decoding table from code lengths: a flat table of `bits`-bit prefixes
/// (symbol << 5 | length, or -1); a longer code is found from its length's first code and the
/// symbols in (length, symbol) order, as canonical codes are numbered.
#[derive(Clone)]
struct Tree {
    bits: u32,
    max_len: u32,
    flat: Vec<i32>,
    first: [u64; 17],     // the first code of each length
    count: [u32; 17],     // how many codes have each length
    start: [usize; 17],   // where each length's symbols start in `order`
    order: Vec<u32>,      // the symbols, by (length, symbol)
    // the 12-bit (main, length) and 7-bit (aligned) tables as fixed arrays, so a lookup by the
    // top bits of the 32-bit buffer needs no bounds check
    f12: Option<Box<[i32; 4096]>>,
    f7: Option<Box<[i32; 128]>>,
}

impl Tree {
    fn new(lengths: &[u32], bits: u32) -> Tree {
        let size = 1usize << bits;
        let mut count = [0u32; 17];
        for &l in lengths {
            count[(l as usize).min(16)] += 1;
        }
        count[0] = 0;
        let max_len = (1..17).rev().find(|&l| count[l] > 0).unwrap_or(0) as u32;
        let mut start = [0usize; 17];
        for l in 1..17 {
            start[l] = start[l - 1] + if l > 1 { count[l - 1] as usize } else { 0 };
        }
        let mut order = vec![0u32; start[16] + count[16] as usize];
        let mut next = start;
        for (sym, &l) in lengths.iter().enumerate() {
            let l = (l as usize).min(16);
            if l > 0 {
                order[next[l]] = sym as u32;
                next[l] += 1;
            }
        }
        // canonical codes: shorter first, then by symbol (lzx.py's order)
        let mut first = [0u64; 17];
        let mut code = 0u64;
        for l in 1..17 {
            code = (code + if l > 1 { count[l - 1] as u64 } else { 0 }) << 1;
            first[l] = code;
        }
        let mut flat = vec![-1i32; size];
        for l in 1..=(bits as usize).min(16) {
            for k in 0..count[l] as usize {
                let c = first[l] + k as u64;
                let lo = (c << (bits as usize - l)) as usize;
                if lo < size {
                    let span = std::cmp::min(1usize << (bits as usize - l), size - lo);
                    let e = ((order[start[l] + k] as i32) << 5) | l as i32;
                    for slot in &mut flat[lo..lo + span] {
                        *slot = e;
                    }
                }
            }
        }
        let f12 = if bits == 12 { flat.as_slice().try_into().ok().map(|a: &[i32; 4096]| Box::new(*a)) } else { None };
        let f7 = if bits == 7 { flat.as_slice().try_into().ok().map(|a: &[i32; 128]| Box::new(*a)) } else { None };
        Tree { bits, max_len, flat, first, count, start, order, f12, f7 }
    }

    fn decode(&self, b: &mut Bits) -> Res<u32> {
        if self.max_len > 0 {
            let e = self.flat[b.peek(self.bits) as usize];
            if e >= 0 {
                b.drop_bits((e & 31) as u32);
                return Ok((e >> 5) as u32);
            }
        }
        for length in self.bits + 1..=self.max_len {
            let l = length as usize;
            let v = b.peek(length) as u64;
            if self.count[l] > 0 && v >= self.first[l] && v - self.first[l] < self.count[l] as u64 {
                b.drop_bits(length);
                return Ok(self.order[self.start[l] + (v - self.first[l]) as usize]);
            }
        }
        Err(Damage::new("Damaged LZX data: bad Huffman code"))
    }
}

#[pyclass(module = "packport_native")]
pub struct LzxDecoder {
    window_size: usize,
    window_bits: u32,
    wim: bool,
    main_size: usize,
    hist: Vec<u8>,
    carry: usize,
    r: [u32; 3],
    main_lengths: Vec<u32>,
    length_lengths: Vec<u32>,
    header_read: bool,
    e8_size: u32,
    frames: u64,
    block_left: i64,
    block_type: u32,
    uncompressed_odd: bool,
    trees: (Option<Tree>, Option<Tree>, Option<Tree>),
    position: u64,
}

impl LzxDecoder {
    fn reset_state(&mut self) {
        self.r = [1, 1, 1];
        self.main_lengths = vec![0; self.main_size];
        self.length_lengths = vec![0; LENGTH_SIZE];
        self.header_read = false;
        self.e8_size = 0;
        self.frames = 0;
        self.block_left = 0;
        self.block_type = 0;
        self.uncompressed_odd = false;
        self.trees = (None, None, None);
        self.position = 0;
    }

    fn read_lengths(b: &mut Bits, lengths: &mut [u32], first: usize, last: usize) -> Res<()> {
        let pre_lengths: Vec<u32> = (0..PRETREE_SIZE).map(|_| b.read(4)).collect();
        let pre = Tree::new(&pre_lengths, 6);
        let mut i = first;
        while i < last {
            let code = pre.decode(b)?;
            if code == 17 {
                let n = 4 + b.read(4) as usize;
                for _ in 0..n {
                    if i < last {
                        lengths[i] = 0;
                        i += 1;
                    }
                }
            } else if code == 18 {
                let n = 20 + b.read(5) as usize;
                for _ in 0..n {
                    if i < last {
                        lengths[i] = 0;
                        i += 1;
                    }
                }
            } else if code == 19 {
                let n = 4 + b.read(1) as usize;
                let code = pre.decode(b)?;
                let v = if i < last { (lengths[i] as i64 - code as i64).rem_euclid(17) as u32 } else { 0 };
                for _ in 0..n {
                    if i < last {
                        lengths[i] = v;
                        i += 1;
                    }
                }
            } else {
                lengths[i] = (lengths[i] as i64 - code as i64).rem_euclid(17) as u32;
                i += 1;
            }
        }
        Ok(())
    }

    /// Literals and matches into hist until take bytes are made (a match may run past).
    #[allow(clippy::too_many_arguments)]
    fn symbols(hist: &mut Vec<u8>, r: &mut [u32; 3], window_size: usize, b: &mut Bits, end: usize, take: usize,
               main: &Tree, length_tree: &Tree, aligned: Option<&Tree>) -> Res<usize> {
        let (extra_bits, base) = (&EXTRA_BITS, &POSITION_BASE);
        let wsize = window_size as u64;
        let [mut r0, mut r1, mut r2] = *r;
        let (Some(mf), Some(lf)) = (main.f12.as_deref(), length_tree.f12.as_deref()) else {
            return Err(Damage::new("Damaged LZX data: bad Huffman code"));
        };
        let af = aligned.and_then(|t| t.f7.as_deref());
        hist.reserve(take + 300);
        let mut produced = 0usize;
        while produced < take && b.pos <= end {
            if b.left < 12 {
                let w = b.word();
                b.pos += 2;
                b.buf |= w << (16 - b.left);
                b.left += 16;
            }
            let e = mf[(b.buf >> 20) as usize];
            let sym = if e >= 0 {
                b.drop_bits((e & 31) as u32);
                (e >> 5) as u32
            } else {
                main.decode(b)?
            };
            if (sym as usize) < NUM_CHARS {
                hist.push(sym as u8);
                produced += 1;
                continue;
            }
            let sym = sym as usize - NUM_CHARS;
            let mut length = sym & 7;
            if length == 7 {
                if b.left < 12 {
                    let w = b.word();
                    b.pos += 2;
                    b.buf |= w << (16 - b.left);
                    b.left += 16;
                }
                let e = lf[(b.buf >> 20) as usize];
                if e >= 0 {
                    b.drop_bits((e & 31) as u32);
                    length += (e >> 5) as usize;
                } else {
                    length += length_tree.decode(b)? as usize;
                }
            }
            length += MIN_MATCH;
            let slot = sym >> 3;
            let offset: u64;
            if slot > 2 {
                if slot >= 51 {
                    return Err(Damage::new("Damaged LZX data: bad Huffman code"));
                }
                let extra = extra_bits[slot];
                let use_aligned = aligned.is_some() && extra >= 3;
                let mut n = if use_aligned { extra - 3 } else { extra };
                let mut value: u64 = 0;
                if n > 16 {
                    if b.left < 1 {
                        let w = b.word();
                        b.pos += 2;
                        b.buf |= w << (16 - b.left);
                        b.left += 16;
                    }
                    value = (b.buf >> 31) as u64;
                    b.drop_bits(1);
                    n = 16;
                }
                if n > 0 {
                    if b.left < n {
                        let w = b.word();
                        b.pos += 2;
                        b.buf |= w << (16 - b.left);
                        b.left += 16;
                    }
                    value = (value << n) | (b.buf >> (32 - n)) as u64;
                    b.drop_bits(n);
                }
                if use_aligned {
                    let at = aligned.unwrap();
                    if b.left < 7 {
                        let w = b.word();
                        b.pos += 2;
                        b.buf |= w << (16 - b.left);
                        b.left += 16;
                    }
                    let e = match af {
                        Some(t) => t[(b.buf >> 25) as usize],
                        None => -1,
                    };
                    let a = if e >= 0 {
                        b.drop_bits((e & 31) as u32);
                        (e >> 5) as u64
                    } else {
                        at.decode(b)? as u64
                    };
                    offset = (base[slot] as u64 + (value << 3) + a).wrapping_sub(2);
                } else {
                    offset = (base[slot] as u64 + value).wrapping_sub(2);
                }
                r2 = r1;
                r1 = r0;
                r0 = offset as u32;
            } else if slot == 0 {
                offset = r0 as u64;
            } else if slot == 1 {
                offset = r1 as u64;
                r1 = r0;
                r0 = offset as u32;
            } else {
                offset = r2 as u64;
                r2 = r0;
                r0 = offset as u32;
            }
            // the window is a ring of wsize bytes: an offset of 0 or past it wraps around
            let offset = offset as u32 as i64;
            let dist = if offset > 0 && offset as u64 <= wsize { offset as u64 } else { ((offset - 1).rem_euclid(wsize as i64) + 1) as u64 } as usize;
            let src = hist.len() - dist; // hist always holds at least the window
            if dist >= length {
                hist.extend_from_within(src..src + length);
            } else {
                for k in 0..length {
                    let v = hist[src + k];
                    hist.push(v);
                }
            }
            produced += length;
        }
        *r = [r0, r1, r2];
        Ok(produced)
    }

    fn undo_e8(&self, data: &mut [u8], offset: u64) -> Res<()> {
        let size = self.e8_size as i64;
        let n = data.len();
        let mut start = 0usize;
        while start < n {
            if (offset + start as u64) / FRAME as u64 >= 32768 {
                break;
            }
            let end = std::cmp::min(n, start + FRAME);
            if end - start > 10 {
                let mut i = start;
                let limit = end - 10;
                while i < limit {
                    match memchr::memchr(0xE8, &data[i..limit]) {
                        Some(k) => i += k,
                        None => break,
                    }
                    {
                        let cur = offset as i64 + i as i64;
                        let abs_off = i32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]) as i64;
                        if -cur <= abs_off && abs_off < size {
                            let rel = if abs_off >= 0 { abs_off - cur } else { abs_off + size };
                            if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
                                return Err(Damage::new("Damaged LZX data: an E8 translation out of range"));
                            }
                            data[i + 1..i + 5].copy_from_slice(&(rel as i32).to_le_bytes());
                        }
                        i += 5;
                    }
                }
            }
            start += FRAME;
        }
        Ok(())
    }

    fn run(&mut self, data: &[u8], out_len: usize) -> Res<Vec<u8>> {
        let mut b = Bits { data, pos: 0, buf: 0, left: 0 };
        let end = data.len() + 4; // the bit buffer reads up to two words ahead
        let base = self.hist.len() - self.carry;
        if !self.header_read && self.wim {
            self.e8_size = 12_000_000;
            self.header_read = true;
        }
        if !self.header_read {
            if b.read(1) != 0 {
                let hi = b.read(16);
                let lo = b.read(16);
                self.e8_size = (hi << 16) | lo;
            } else {
                self.e8_size = 0;
            }
            self.header_read = true;
        }
        let (mut main_tree, mut length_tree, mut aligned_tree) = std::mem::take(&mut self.trees);
        while self.hist.len() - base < out_len && b.pos <= end {
            let frame_size = std::cmp::min(FRAME, out_len - (self.hist.len() - base));
            let frame_start = self.hist.len();
            while self.hist.len() - frame_start < frame_size && b.pos <= end {
                if self.block_left == 0 {
                    if self.block_type == 3 && self.uncompressed_odd {
                        b.pos += 1; // an odd-sized uncompressed block is padded to 16 bits
                        self.uncompressed_odd = false;
                    }
                    self.block_type = b.read(3);
                    if self.wim {
                        if b.read(1) != 0 {
                            self.block_left = FRAME as i64;
                        } else {
                            self.block_left = b.read(16) as i64;
                            if self.window_bits >= 16 {
                                self.block_left = (self.block_left << 8) | b.read(8) as i64;
                            }
                        }
                    } else {
                        let hi = b.read(8) as i64;
                        let mid = b.read(8) as i64;
                        let lo = b.read(8) as i64;
                        self.block_left = (hi << 16) | (mid << 8) | lo;
                    }
                    if self.block_type == 2 {
                        let lengths: Vec<u32> = (0..ALIGNED_SIZE).map(|_| b.read(3)).collect();
                        aligned_tree = Some(Tree::new(&lengths, 7));
                    }
                    if self.block_type == 1 || self.block_type == 2 {
                        let mut ml = std::mem::take(&mut self.main_lengths);
                        Self::read_lengths(&mut b, &mut ml, 0, NUM_CHARS)?;
                        Self::read_lengths(&mut b, &mut ml, NUM_CHARS, self.main_size)?;
                        main_tree = Some(Tree::new(&ml, 12));
                        self.main_lengths = ml;
                        let mut ll = std::mem::take(&mut self.length_lengths);
                        Self::read_lengths(&mut b, &mut ll, 0, LENGTH_SIZE)?;
                        length_tree = Some(Tree::new(&ll, 12));
                        self.length_lengths = ll;
                    } else if self.block_type == 3 {
                        // 1 to 16 bits of padding (never 0) bring the input to a 16-bit boundary
                        b.ensure(16);
                        if b.left > 16 {
                            b.pos -= 2;
                        }
                        b.buf = 0;
                        b.left = 0;
                        let hdr = b.raw_bytes(12);
                        let mut h = [0u8; 12];
                        h[..hdr.len()].copy_from_slice(hdr);
                        self.r = [u32::from_le_bytes([h[0], h[1], h[2], h[3]]), u32::from_le_bytes([h[4], h[5], h[6], h[7]]),
                                  u32::from_le_bytes([h[8], h[9], h[10], h[11]])];
                        self.uncompressed_odd = self.block_left & 1 == 1;
                    } else {
                        self.trees = (main_tree, length_tree, aligned_tree);
                        return Err(Damage::new(format!("Damaged LZX data: block type {}", self.block_type)));
                    }
                }
                let take = std::cmp::min(self.block_left.max(0) as usize, frame_size - (self.hist.len() - frame_start));
                if self.block_type == 3 {
                    let raw = b.raw_bytes(take);
                    if raw.len() < take {
                        b.pos = end + 1;
                    }
                    self.hist.extend_from_slice(raw);
                    self.block_left -= take as i64;
                    continue;
                }
                let (Some(mt), Some(lt)) = (main_tree.as_ref(), length_tree.as_ref()) else {
                    self.trees = (main_tree, length_tree, aligned_tree);
                    return Err(Damage::new("Damaged LZX data: bad Huffman code"));
                };
                let at = if self.block_type == 2 { aligned_tree.as_ref() } else { None };
                let produced = match Self::symbols(&mut self.hist, &mut self.r, self.window_size, &mut b, end, take, mt, lt, at) {
                    Ok(p) => p,
                    Err(e) => {
                        self.trees = (main_tree, length_tree, aligned_tree);
                        return Err(e);
                    }
                };
                self.block_left -= produced as i64;
                if produced > take {
                    self.block_left = self.block_left.max(0);
                }
            }
            if self.block_type != 3 {
                b.align();
            }
            self.frames += 1;
        }
        self.trees = (main_tree, length_tree, aligned_tree);
        let have = self.hist.len() - base;
        let n = std::cmp::min(out_len, have);
        let mut out = self.hist[base..base + n].to_vec();
        self.carry = have - n;
        if self.e8_size != 0 {
            self.undo_e8(&mut out, self.position)?;
        }
        self.position += out.len() as u64;
        if self.hist.len() > 2 * self.window_size {
            let drop = self.hist.len() - self.window_size - self.carry;
            self.hist.drain(..drop);
        }
        Ok(out)
    }
}

#[pymethods]
impl LzxDecoder {
    #[new]
    #[pyo3(signature = (window_bits, wim = false))]
    fn new(py: Python<'_>, window_bits: u32, wim: bool) -> PyResult<Self> {
        let slots = position_slots(window_bits)
            .ok_or_else(|| crate::damaged(py, &format!("Unsupported LZX window size 2^{window_bits}")))?;
        let main_size = NUM_CHARS + slots * 8;
        let mut d = LzxDecoder {
            window_size: 1 << window_bits,
            window_bits,
            wim,
            main_size,
            hist: vec![0; 1 << window_bits],
            carry: 0,
            r: [1, 1, 1],
            main_lengths: vec![],
            length_lengths: vec![],
            header_read: false,
            e8_size: 0,
            frames: 0,
            block_left: 0,
            block_type: 0,
            uncompressed_odd: false,
            trees: (None, None, None),
            position: 0,
        };
        d.reset_state();
        Ok(d)
    }

    fn reset(&mut self) {
        self.reset_state();
    }

    #[getter]
    fn window_size(&self) -> usize {
        self.window_size
    }

    /// Decode out_len bytes of compressed data (fewer when the data runs out first).
    fn decompress<'py>(&mut self, py: Python<'py>, data: PyBackedBytes, out_len: usize) -> PyResult<Bound<'py, PyBytes>> {
        let out = py.detach(|| self.run(&data, out_len)).map_err(|e| raise(py, e))?;
        Ok(PyBytes::new(py, &out))
    }
}
