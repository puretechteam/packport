//! Deflate64 (ZIP method 9, 7z's Deflate64): Deflate with a 64 KB window, length code 285 as 3 +
//! 16 bits, and distance codes 30 and 31. The same decoding as deflate64.py, fed a piece at a time:
//! feed() data, finish() at the end, read() what's ready. It decodes only while it holds MARGIN
//! bytes of input past where it is (more than a stored block and a block header), or all of it.

use crate::{raise, Damage, Res};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;

const LENGTH_BASE: [u32; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163,
                                195, 227, 3];
const LENGTH_EXTRA: [u32; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16];
const DIST_BASE: [u32; 32] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049,
                              3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153];
const DIST_EXTRA: [u32; 32] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
                               14, 14];
const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
const WINDOW: usize = 1 << 16;
const MARGIN: usize = 1 << 17;

/// A lookup table indexed by the next `bits` bits (least significant first): symbol << 4 | length.
#[derive(Clone)]
struct Table {
    t: Vec<i32>,
    bits: u32,
}

fn table(lengths: &[u32]) -> Res<Table> {
    let bits = lengths.iter().copied().max().unwrap_or(0).max(1);
    let mut counts = [0u32; 16];
    for &n in lengths {
        counts[n as usize & 15] += 1;
    }
    counts[0] = 0;
    let mut first = [0u32; 17];
    let mut code = 0u32;
    for n in 1..16 {
        code = (code + counts[n - 1]) << 1;
        first[n] = code;
    }
    let mut t = vec![-1i32; 1 << bits];
    for (sym, &n) in lengths.iter().enumerate() {
        if n == 0 {
            continue;
        }
        let c = first[n as usize];
        first[n as usize] += 1;
        if c >= 1 << n {
            return Err(Damage::new("The data is damaged (an over-full Deflate64 code)"));
        }
        let rev = c.reverse_bits() >> (32 - n);
        let mut fill = rev as usize;
        while fill < 1 << bits {
            t[fill] = (sym as i32) << 4 | n as i32;
            fill += 1 << n;
        }
    }
    Ok(Table { t, bits })
}

enum State {
    Header,
    Stored(usize),
    Huffman(Table, Table),
    Done,
}

#[pyclass(module = "packport_native")]
pub struct Deflate64Decoder {
    inp: Vec<u8>,
    pos: usize, // bit position in inp
    finished: bool,
    out: Vec<u8>,
    given: usize,
    state: State,
    last: bool,
    fixed: Option<(Table, Table)>,
}

impl Deflate64Decoder {
    #[inline]
    fn byte(&self, i: usize) -> u64 {
        *self.inp.get(i).unwrap_or(&0) as u64
    }

    #[inline]
    fn peek(&self, n: u32) -> u64 {
        let i = self.pos >> 3;
        let mut v = 0u64;
        if i + 8 <= self.inp.len() {
            v = u64::from_le_bytes(self.inp[i..i + 8].try_into().unwrap());
        } else {
            for k in 0..8 {
                v |= self.byte(i + k) << (8 * k);
            }
        }
        (v >> (self.pos & 7)) & ((1u64 << n) - 1)
    }

    #[inline]
    fn bits(&mut self, n: u32) -> u32 {
        let v = self.peek(n) as u32;
        self.pos += n as usize;
        v
    }

    fn end_bits(&self) -> usize {
        self.inp.len() * 8
    }

    /// Whether there's enough input to go on (or all of it has come).
    fn ready(&self) -> bool {
        self.finished || self.inp.len().saturating_sub(self.pos >> 3) >= MARGIN
    }

    fn fixed(&mut self) -> Res<(Table, Table)> {
        if self.fixed.is_none() {
            let mut lit = vec![8u32; 144];
            lit.extend(std::iter::repeat_n(9, 112));
            lit.extend(std::iter::repeat_n(7, 24));
            lit.extend(std::iter::repeat_n(8, 8));
            self.fixed = Some((table(&lit)?, table(&[5; 32])?));
        }
        Ok(self.fixed.clone().unwrap())
    }

    fn header(&mut self) -> Res<()> {
        if self.pos > self.end_bits() {
            return Err(Damage::new("The data is damaged or cut short (Deflate64 data ended early)"));
        }
        self.last = self.bits(1) == 1;
        let kind = self.bits(2);
        if kind == 0 {
            self.pos = (self.pos + 7) & !7;
            let i = self.pos >> 3;
            let n = self.byte(i) | self.byte(i + 1) << 8;
            let nn = self.byte(i + 2) | self.byte(i + 3) << 8;
            if n ^ nn != 0xFFFF {
                return Err(Damage::new("The data is damaged (a stored Deflate64 block's length)"));
            }
            self.pos += 32;
            self.state = State::Stored(n as usize);
            return Ok(());
        }
        let (lit, dist) = if kind == 1 {
            self.fixed()?
        } else if kind == 2 {
            let hlit = self.bits(5) as usize + 257;
            let hdist = self.bits(5) as usize + 1;
            let hclen = self.bits(4) as usize + 4;
            let mut cl = [0u32; 19];
            for &o in ORDER.iter().take(hclen) {
                cl[o] = self.bits(3);
            }
            let ctab = table(&cl)?;
            let mut lengths: Vec<u32> = Vec::with_capacity(hlit + hdist);
            while lengths.len() < hlit + hdist {
                let e = ctab.t[self.peek(ctab.bits) as usize];
                if e < 0 {
                    return Err(Damage::new("The data is damaged (a bad Deflate64 code)"));
                }
                self.pos += (e & 15) as usize;
                let sym = (e >> 4) as u32;
                if sym < 16 {
                    lengths.push(sym);
                } else if sym == 16 {
                    let Some(&prev) = lengths.last() else {
                        return Err(Damage::new("The data is damaged (a Deflate64 code repeats nothing)"));
                    };
                    let n = 3 + self.bits(2) as usize;
                    lengths.extend(std::iter::repeat_n(prev, n));
                } else if sym == 17 {
                    let n = 3 + self.bits(3) as usize;
                    lengths.extend(std::iter::repeat_n(0, n));
                } else {
                    let n = 11 + self.bits(7) as usize;
                    lengths.extend(std::iter::repeat_n(0, n));
                }
            }
            if lengths.len() > hlit + hdist {
                return Err(Damage::new("The data is damaged (Deflate64 code lengths overflow)"));
            }
            (table(&lengths[..hlit])?, table(&lengths[hlit..])?)
        } else {
            return Err(Damage::new("The data is damaged (Deflate64 block type 3)"));
        };
        self.state = State::Huffman(lit, dist);
        Ok(())
    }

    /// Decode until want bytes are waiting, the stream ends, or more input is needed.
    fn run(&mut self, want: usize) -> Res<()> {
        loop {
            if self.out.len() - self.given >= want {
                return Ok(());
            }
            match &self.state {
                State::Done => return Ok(()),
                State::Header => {
                    if !self.ready() {
                        return Ok(());
                    }
                    if self.pos > self.end_bits() && self.finished {
                        return Err(Damage::new("The data is damaged or cut short (Deflate64 data ended early)"));
                    }
                    self.header()?;
                }
                State::Stored(n) => {
                    let n = *n;
                    let i = self.pos >> 3;
                    if !self.finished && i + n > self.inp.len() {
                        return Ok(());
                    }
                    let end = std::cmp::min(i + n, self.inp.len());
                    let start = std::cmp::min(i, end);
                    let chunk = self.inp[start..end].to_vec();
                    self.out.extend_from_slice(&chunk);
                    self.pos += n * 8;
                    self.state = if self.last { State::Done } else { State::Header };
                }
                State::Huffman(_, _) => {
                    let State::Huffman(lit, dist) = std::mem::replace(&mut self.state, State::Header) else { unreachable!() };
                    let done = self.symbols(&lit, &dist, want)?;
                    self.state = if done { if self.last { State::Done } else { State::Header } } else { State::Huffman(lit, dist) };
                    if !done {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Symbols of one block; true at its end, false when out holds want bytes or input is short.
    fn symbols(&mut self, lit: &Table, dist: &Table, want: usize) -> Res<bool> {
        let lmask = (1u64 << lit.bits) - 1;
        let dmask = (1u64 << dist.bits) - 1;
        let limit_bytes = if self.finished { usize::MAX } else { self.inp.len().saturating_sub(MARGIN) };
        let end = self.end_bits();
        loop {
            if self.out.len() - self.given >= want {
                return Ok(false);
            }
            if (self.pos >> 3) > limit_bytes {
                return Ok(false);
            }
            if self.pos > end + 64 {
                return Err(Damage::new("The data is damaged or cut short (Deflate64 data ended early)"));
            }
            let mut v = self.peek(57);
            let e = lit.t[(v & lmask) as usize];
            if e < 0 {
                return Err(Damage::new("The data is damaged (a bad Deflate64 code)"));
            }
            let n = (e & 15) as u32;
            self.pos += n as usize;
            v >>= n;
            let sym = (e >> 4) as usize;
            if sym < 256 {
                self.out.push(sym as u8);
                continue;
            }
            if sym == 256 {
                return Ok(true);
            }
            let s = sym - 257;
            if s > 28 {
                return Err(Damage::new("The data is damaged (a Deflate64 length code)"));
            }
            let extra = LENGTH_EXTRA[s];
            let length = (LENGTH_BASE[s] as u64 + (v & ((1u64 << extra) - 1))) as usize;
            self.pos += extra as usize;
            v = if extra > 13 { self.peek(57) } else { v >> extra };
            let e = dist.t[(v & dmask) as usize];
            if e < 0 {
                return Err(Damage::new("The data is damaged (a bad Deflate64 code)"));
            }
            self.pos += (e & 15) as usize;
            let ds = (e >> 4) as usize;
            if ds > 31 {
                return Err(Damage::new("The data is damaged (a Deflate64 distance code)"));
            }
            let extra = DIST_EXTRA[ds];
            let distance = DIST_BASE[ds] as usize + if extra > 0 { self.peek(extra) as usize } else { 0 };
            self.pos += extra as usize;
            if distance > self.out.len() {
                return Err(Damage::new("The data is damaged (a Deflate64 match reaches before the start)"));
            }
            let start = self.out.len() - distance;
            if distance >= length {
                self.out.extend_from_within(start..start + length);
            } else {
                for k in 0..length {
                    let b = self.out[start + k];
                    self.out.push(b);
                }
            }
        }
    }

    fn compact(&mut self) {
        // drop the input already read, and the output history past the window
        let used = self.pos >> 3;
        if used > (4 << 20) {
            self.inp.drain(..used);
            self.pos -= used * 8;
        }
        if self.given > 2 * WINDOW + (4 << 20) {
            let drop = self.given - WINDOW;
            self.out.drain(..drop);
            self.given -= drop;
        }
    }
}

#[pymethods]
impl Deflate64Decoder {
    #[new]
    fn new() -> Self {
        Deflate64Decoder { inp: Vec::new(), pos: 0, finished: false, out: Vec::new(), given: 0, state: State::Header,
                           last: false, fixed: None }
    }

    fn feed(&mut self, py: Python<'_>, data: PyBackedBytes) {
        py.detach(|| {
            self.compact();
            self.inp.extend_from_slice(&data);
        });
    }

    fn finish(&mut self) {
        self.finished = true;
    }

    #[getter]
    fn eof(&self) -> bool {
        matches!(self.state, State::Done) && self.given >= self.out.len()
    }

    #[getter]
    fn finished(&self) -> bool {
        self.finished
    }

    /// Up to max_len bytes of output: b"" when more input is needed (or the stream has ended).
    fn read<'py>(&mut self, py: Python<'py>, max_len: usize) -> PyResult<Bound<'py, PyBytes>> {
        let (a, b) = py.detach(|| -> Res<(usize, usize)> {
            self.run(max_len)?;
            let n = std::cmp::min(max_len, self.out.len() - self.given);
            self.given += n;
            Ok((self.given - n, self.given))
        }).map_err(|e| raise(py, e))?;
        Ok(PyBytes::new(py, &self.out[a..b]))
    }
}
