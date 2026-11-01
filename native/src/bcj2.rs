//! BCJ2 (7z): x86 code with its call and jump targets split into two streams of absolute
//! big-endian addresses, and a range-coded stream saying which E8/E9/Jcc bytes were converted
//! (the LZMA SDK's Bcj2, as sevenzip.py's _bcj2 decodes it). Four inputs, fed separately: read()
//! gives what it can and `needs` says which input it's waiting for (0 main, 1 call, 2 jump,
//! 3 range coder), or -1.

use crate::{raise, Damage, Res};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;

struct Input {
    d: Vec<u8>,
    p: usize,
    fin: bool,
}

impl Input {
    fn left(&self) -> usize {
        self.d.len() - self.p
    }

    fn compact(&mut self) {
        if self.p > (1 << 20) {
            self.d.drain(..self.p);
            self.p = 0;
        }
    }
}

#[pyclass(module = "packport_native")]
pub struct Bcj2Decoder {
    ins: [Input; 4],
    probs: [u32; 258],
    code: u32,
    range: u32,
    started: bool,
    prev: u8,
    done: u64,
    size: u64,
    #[pyo3(get)]
    needs: i32,
    ended: bool,
}

impl Bcj2Decoder {
    fn rc_byte(&mut self) -> u32 {
        let r = &mut self.ins[3];
        let b = *r.d.get(r.p).unwrap_or(&0) as u32;
        r.p += 1;
        b
    }

    fn run(&mut self, max: usize) -> Res<Vec<u8>> {
        let mut out: Vec<u8> = Vec::with_capacity(max.min(1 << 20));
        self.needs = -1;
        if !self.started {
            if self.ins[3].left() < 5 && !self.ins[3].fin {
                self.needs = 3;
                return Ok(out);
            }
            for _ in 0..5 {
                self.code = (self.code << 8) | self.rc_byte();
            }
            self.started = true;
        }
        while out.len() < max && self.done + (out.len() as u64) < self.size {
            // plain bytes up to the next E8, E9 or Jcc
            {
                let m = &mut self.ins[0];
                let limit = std::cmp::min(m.d.len(), m.p + (max - out.len()).min((self.size - self.done) as usize - out.len()));
                let start = m.p;
                let mut prev = self.prev;
                while m.p < limit {
                    let b = m.d[m.p];
                    if (b & 0xFE) == 0xE8 || (prev == 0x0F && (b & 0xF0) == 0x80) {
                        break;
                    }
                    prev = b;
                    m.p += 1;
                }
                out.extend_from_slice(&m.d[start..m.p]);
                self.prev = prev;
            }
            if out.len() >= max || self.done + out.len() as u64 >= self.size {
                break;
            }
            if self.ins[0].left() == 0 {
                if self.ins[0].fin {
                    self.ended = true;
                    break;
                }
                self.needs = 0;
                break;
            }
            // a marker byte: make sure what deciding it can take is there
            for (k, want) in [(3usize, 1usize), (1, 4), (2, 4)] {
                if self.ins[k].left() < want && !self.ins[k].fin {
                    self.needs = k as i32;
                    self.done += out.len() as u64;
                    return Ok(out);
                }
            }
            let b = self.ins[0].d[self.ins[0].p];
            self.ins[0].p += 1;
            out.push(b);
            if self.done + out.len() as u64 >= self.size {
                break;
            }
            let k = if b == 0xE8 { self.prev as usize } else if b == 0xE9 { 256 } else { 257 };
            let p = self.probs[k];
            let bound = (self.range >> 11).wrapping_mul(p);
            if self.code < bound {
                self.range = bound;
                self.probs[k] = p + ((2048 - p) >> 5);
                self.prev = b;
            } else {
                self.range = self.range.wrapping_sub(bound);
                self.code = self.code.wrapping_sub(bound);
                self.probs[k] = p - (p >> 5);
                let s = &mut self.ins[if b == 0xE8 { 1 } else { 2 }];
                if s.left() < 4 {
                    return Err(Damage::new("The 7z archive is damaged (BCJ2 runs out of addresses)"));
                }
                let src = u32::from_be_bytes([s.d[s.p], s.d[s.p + 1], s.d[s.p + 2], s.d[s.p + 3]]);
                s.p += 4;
                let here = self.done + out.len() as u64 + 4;
                let dest = src.wrapping_sub(here as u32);
                out.extend_from_slice(&dest.to_le_bytes());
                self.prev = (dest >> 24) as u8;
            }
            if self.range < 1 << 24 {
                self.range <<= 8;
                self.code = (self.code << 8) | self.rc_byte();
            }
        }
        let n = std::cmp::min(out.len() as u64, self.size - self.done) as usize;
        out.truncate(n);
        self.done += out.len() as u64;
        Ok(out)
    }
}

#[pymethods]
impl Bcj2Decoder {
    #[new]
    fn new(size: u64) -> Self {
        let mk = || Input { d: Vec::new(), p: 0, fin: false };
        Bcj2Decoder { ins: [mk(), mk(), mk(), mk()], probs: [1 << 10; 258], code: 0, range: 0xFFFF_FFFF,
                      started: false, prev: 0, done: 0, size, needs: -1, ended: false }
    }

    /// More of input k (0 main, 1 call, 2 jump, 3 range coder); b"" marks its end.
    fn feed(&mut self, k: usize, data: PyBackedBytes) {
        if let Some(i) = self.ins.get_mut(k) {
            if data.is_empty() {
                i.fin = true;
            } else {
                i.compact();
                i.d.extend_from_slice(&data);
            }
        }
    }

    #[getter]
    fn eof(&self) -> bool {
        self.ended || self.done >= self.size
    }

    fn read<'py>(&mut self, py: Python<'py>, max_len: usize) -> PyResult<Bound<'py, PyBytes>> {
        let out = py.detach(|| self.run(max_len)).map_err(|e| raise(py, e))?;
        Ok(PyBytes::new(py, &out))
    }
}
