//! RAR 2.9 / 3.x compression (rar3.py's Unpack29, with ppmd.py's RarPpmd): LZ with its
//! Huffman tables, PPMd blocks (variant H with RAR's range coder), and RAR's six standard filters
//! (recognised by their program's size and CRC, run as what they do). One decoder per solid
//! stream: begin_file() for each file, then feed(), finish() and read() like the other streaming
//! decoders. It decodes only while it holds MARGIN bytes past where it is, or all of the file.

use crate::huff::huffman;
use crate::ppmd7::{ByteSource, Model, RangeRar, RarCoder};
use crate::{raise, Damage, Res};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;

const NC: usize = 299;
const DC: usize = 60;
const LDC: usize = 17;
const RC: usize = 28;
const BC: usize = 20;
const LOW_DIST_REP: u32 = 16;
const MAX_FILTERS: usize = 1024;
const VM_MEMSIZE: usize = 0x40000;
const FLUSH: u64 = 4 << 20;
const MARGIN: usize = 1 << 18;
const RUN: usize = 1_000_000; // output decoded before coming back

const LDECODE: [u32; 28] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224];
const LBITS: [u32; 28] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5];
const SDDECODE: [u32; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SDBITS: [u32; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

fn dist_tables() -> ([u32; DC], [u32; DC]) {
    let mut decode = [0u32; DC];
    let mut bits = [0u32; DC];
    let counts = [4u32, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 14, 0, 12];
    let (mut d, mut k) = (0u32, 0usize);
    for (b, &c) in counts.iter().enumerate() {
        for _ in 0..c {
            decode[k] = d;
            bits[k] = b as u32;
            d += 1 << b;
            k += 1;
        }
    }
    (decode, bits)
}

fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    E8,
    E8E9,
    Itanium,
    Delta,
    Rgb,
    Audio,
}

fn standard(size: usize, crc: u32) -> Option<Kind> {
    Some(match (size, crc) {
        (53, 0xAD57_6887) => Kind::E8,
        (57, 0x3CD7_E57E) => Kind::E8E9,
        (120, 0x3769_893F) => Kind::Itanium,
        (29, 0x0E06_077D) => Kind::Delta,
        (149, 0x1C2C_5DC8) => Kind::Rgb,
        (216, 0xBC85_E701) => Kind::Audio,
        _ => return None,
    })
}

/// n (<= 57) bits from bit position pos, most significant first; past the data, zeros.
#[inline]
fn bits_at(d: &[u8], pos: usize, n: u32) -> u64 {
    if n == 0 {
        return 0;
    }
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
    (v >> (64 - n as usize - (pos & 7))) & ((1u64 << n) - 1)
}

/// A filter program's parameters, read as bits (RarVM::ReadData).
struct Code<'a> {
    d: &'a [u8],
    pos: usize,
}

impl Code<'_> {
    fn bits(&mut self, n: u32) -> u64 {
        let v = bits_at(self.d, self.pos, n);
        self.pos += n as usize;
        v
    }

    fn number(&mut self) -> u64 {
        let v = bits_at(self.d, self.pos, 16);
        let top = v & 0xC000;
        if top == 0 {
            self.pos += 6;
            return (v >> 10) & 0xF;
        }
        if top == 0x4000 {
            if v & 0x3C00 == 0 {
                self.pos += 14;
                return 0xFFFF_FF00 | ((v >> 2) & 0xFF);
            }
            self.pos += 10;
            return (v >> 6) & 0xFF;
        }
        if top == 0x8000 {
            self.pos += 2;
            return self.bits(16);
        }
        self.pos += 2;
        let hi = self.bits(16);
        (hi << 16) | self.bits(16)
    }
}

struct FilterDef {
    kind: Option<Kind>,
    length: u64,
}

struct Pending {
    start: u64,
    length: u64,
    kind: Kind,
    regs: [u64; 7],
}

struct Tables {
    ld: Vec<i32>,
    dd: Vec<i32>,
    ldd: Vec<i32>,
    rd: Vec<i32>,
}

struct Ppm {
    model: Model,
    rc: Option<RangeRar>,
    esc: u32,
    at: usize, // the next input byte it reads
}

/// The PPMd coder's bytes: the decoder's input from `at`, 0 past it.
struct Src<'a> {
    d: &'a [u8],
    at: &'a mut usize,
}

impl ByteSource for Src<'_> {
    #[inline]
    fn next(&mut self) -> u64 {
        let p = *self.at;
        *self.at += 1;
        *self.d.get(p).unwrap_or(&0) as u64
    }
}

#[pyclass(module = "packport_native")]
pub struct Rar29Decoder {
    dictionary: u64,
    hist: Vec<u8>,
    base: u64,
    written: u64,
    old: [u64; 4],
    last_length: u64,
    old_table: Vec<u32>,
    tables: Option<Tables>,
    prev_low: u64,
    low_reps: u32,
    filters: Vec<FilterDef>,
    pending: Vec<Pending>,
    last_filter: usize,
    ppm: Option<Ppm>,
    ppm_esc: u32,
    block_ppm: bool,
    // the file being decoded
    d: Vec<u8>,
    pos: usize, // bit position in d
    finished: bool,
    file_start: u64,
    size: u64,
    started: bool,
    done: bool,
    out: Vec<u8>,
    given: usize,
    ddecode: [u32; DC],
    dbits: [u32; DC],
    drop_tables: bool,
}

impl Rar29Decoder {
    fn end(&self) -> usize {
        self.d.len() * 8
    }

    /// Where decoding stops to wait for more input (or, at the end, where running past means
    /// the data was cut short).
    fn lim(&self) -> usize {
        if self.finished { self.end() + 32 } else { self.end().saturating_sub(8 * MARGIN) }
    }

    fn ready(&self) -> bool {
        self.finished || self.d.len().saturating_sub(self.pos >> 3) >= 2 * MARGIN
    }

    fn produced(&self) -> u64 {
        self.base + self.hist.len() as u64 - self.file_start
    }

    fn bits(&mut self, n: u32) -> u64 {
        let v = bits_at(&self.d, self.pos, n);
        self.pos += n as usize;
        v
    }

    fn read_tables(&mut self) -> Res<()> {
        self.pos = (self.pos + 7) & !7;
        let flags = bits_at(&self.d, self.pos, 16);
        if flags & 0x8000 != 0 {
            self.block_ppm = true;
            return self.ppm_init();
        }
        self.block_ppm = false;
        self.prev_low = 0;
        self.low_reps = 0;
        if flags & 0x4000 == 0 {
            self.old_table = vec![0; NC + DC + LDC + RC];
        }
        self.pos += 2;
        let mut lengths: Vec<u32> = Vec::with_capacity(BC);
        while lengths.len() < BC {
            let n = self.bits(4) as u32;
            if n == 15 {
                let zeros = self.bits(4) as usize;
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
            let e = bd[bits_at(&self.d, self.pos, 15) as usize];
            if e < 0 {
                return Err(Damage::new("The archive is damaged (a bad code in the Huffman tables)"));
            }
            self.pos += (e & 15) as usize;
            let n = (e >> 4) as u32;
            if n < 16 {
                let i = table.len();
                table.push((n + self.old_table[i]) & 15);
            } else if n < 18 {
                let k = if n == 16 { self.bits(3) + 3 } else { self.bits(7) + 11 } as usize;
                let Some(&last) = table.last() else {
                    return Err(Damage::new("The archive is damaged (a Huffman table repeats nothing)"));
                };
                let k = std::cmp::min(k, size - table.len());
                table.extend(std::iter::repeat_n(last, k));
            } else {
                let k = if n == 18 { self.bits(3) + 3 } else { self.bits(7) + 11 } as usize;
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
        self.old_table = table;
        Ok(())
    }

    fn ppm_init(&mut self) -> Res<()> {
        let mut at = self.pos >> 3;
        let byte = |at: &mut usize| -> u32 {
            let p = *at;
            *at += 1;
            *self.d.get(p).unwrap_or(&0) as u32
        };
        let order = byte(&mut at);
        let reset = order & 0x20 != 0;
        let mb = if reset { byte(&mut at) } else { 0 };
        let mut esc = self.ppm_esc;
        if order & 0x40 != 0 {
            esc = byte(&mut at);
        }
        if !reset && self.ppm.is_none() {
            return Err(Damage::new("The archive is damaged (PPMd data without its model)"));
        }
        let mut src = Src { d: &self.d, at: &mut at };
        let rc = RangeRar::new(&mut src);
        if reset {
            let mut order = (order & 0x1F) + 1;
            if order > 16 {
                order = 16 + (order - 16) * 3;
            }
            if order == 1 {
                return Err(Damage::new("The archive is damaged (a PPMd order of 1)"));
            }
            let size = ((mb as u64) + 1) << 20;
            let same = self.ppm.as_ref().map(|p| p.model.size as u64 == size).unwrap_or(false);
            if !same {
                self.ppm = None; // the old model goes before the new one is made
                let model = Model::new(size).map_err(Damage::new)?;
                self.ppm = Some(Ppm { model, rc: None, esc, at });
            }
            self.ppm.as_mut().unwrap().model.init(order);
        }
        let ppm = self.ppm.as_mut().unwrap();
        ppm.rc = Some(rc);
        ppm.esc = esc;
        ppm.at = at;
        self.ppm_esc = esc;
        self.pos = at * 8;
        Ok(())
    }

    /// LZ symbols until the file's output is complete, RUN bytes are made, the input runs low,
    /// or a block ends the file (true).
    fn lz_run(&mut self) -> Res<bool> {
        let Some(t) = self.tables.take() else {
            return Err(Damage::new("The archive is damaged (compressed data without Huffman tables)"));
        };
        let r = self.lz_symbols(&t);
        if self.drop_tables {
            self.drop_tables = false; // the next file starts with new tables
        } else if self.tables.is_none() {
            self.tables = Some(t);
        }
        r
    }

    fn lz_symbols(&mut self, t: &Tables) -> Res<bool> {
        let target = self.file_start.saturating_add(self.size).saturating_sub(self.base) as usize;
        let stop = self.hist.len() + RUN;
        let lim = self.lim();
        let mut pos = self.pos;
        let mut old = self.old;
        let mut last_length = self.last_length;
        let (mut v, mut s) = (0u64, 0u32);
        macro_rules! window {
            () => {{
                let i = pos >> 3;
                v = if i + 8 <= self.d.len() {
                    u64::from_be_bytes(self.d[i..i + 8].try_into().unwrap())
                } else {
                    let mut b = [0u8; 8];
                    for (k, slot) in b.iter_mut().enumerate() {
                        *slot = *self.d.get(i + k).unwrap_or(&0);
                    }
                    u64::from_be_bytes(b)
                };
                s = 64 - (pos & 7) as u32;
            }};
        }
        while self.hist.len() < target && self.hist.len() < stop {
            if s < 32 {
                if pos > lim {
                    if !self.finished {
                        break;
                    }
                    self.pos = pos;
                    return Err(Damage::new("The archive is damaged or cut short (compressed data ended early)"));
                }
                window!();
            }
            let e = t.ld[((v >> (s - 15)) & 0x7FFF) as usize];
            if e < 0 {
                return Err(Damage::new("The archive is damaged (a bad Huffman code)"));
            }
            let n = (e & 15) as u32;
            pos += n as usize;
            s -= n;
            let slot = (e >> 4) as usize;
            if slot < 256 {
                self.hist.push(slot as u8);
                continue;
            }
            let (length, dist): (u64, u64);
            if slot >= 271 {
                let slot = slot - 271;
                if slot >= 28 {
                    return Err(Damage::new("The archive is damaged (a bad Huffman code)"));
                }
                let mut len = LDECODE[slot] as u64 + 3;
                let b = LBITS[slot];
                if b > 0 {
                    len += (v >> (s - b)) & ((1u64 << b) - 1);
                    pos += b as usize;
                    s -= b;
                }
                if s < 32 {
                    window!();
                }
                let e = t.dd[((v >> (s - 15)) & 0x7FFF) as usize];
                if e < 0 {
                    return Err(Damage::new("The archive is damaged (a bad Huffman code)"));
                }
                pos += (e & 15) as usize;
                s -= (e & 15) as u32;
                let dn = (e >> 4) as usize;
                if dn >= DC {
                    return Err(Damage::new("The archive is damaged (a bad Huffman code)"));
                }
                let mut dd = self.ddecode[dn] as u64 + 1;
                let b = self.dbits[dn];
                if b > 0 {
                    if dn > 9 {
                        if b > 4 {
                            dd += bits_at(&self.d, pos, b - 4) << 4;
                            pos += (b - 4) as usize;
                        }
                        if self.low_reps > 0 {
                            self.low_reps -= 1;
                            dd += self.prev_low;
                        } else {
                            let e = t.ldd[bits_at(&self.d, pos, 15) as usize];
                            if e < 0 {
                                return Err(Damage::new("The archive is damaged (a bad Huffman code)"));
                            }
                            pos += (e & 15) as usize;
                            let low = (e >> 4) as u64;
                            if low == 16 {
                                self.low_reps = LOW_DIST_REP - 1;
                                dd += self.prev_low;
                            } else {
                                dd += low;
                                self.prev_low = low;
                            }
                        }
                    } else {
                        dd += (v >> (s - b)) & ((1u64 << b) - 1);
                        pos += b as usize;
                    }
                }
                if dd >= 0x2000 {
                    len += 1;
                    if dd >= 0x40000 {
                        len += 1;
                    }
                }
                old = [dd, old[0], old[1], old[2]];
                last_length = len;
                s = 0;
                length = len;
                dist = dd;
            } else if slot == 256 {
                self.pos = pos;
                self.last_length = last_length;
                self.old = old;
                let flags = bits_at(&self.d, pos, 2);
                if flags & 2 != 0 {
                    self.pos += 1;
                    self.read_tables()?;
                    return Ok(false); // on with the new tables (or a PPMd block)
                }
                self.pos += 2;
                if flags & 1 != 0 {
                    self.drop_tables = true;
                }
                return Ok(true);
            } else if slot == 257 {
                self.pos = pos;
                self.last_length = last_length;
                self.old = old;
                self.vm_code_lz()?;
                pos = self.pos;
                s = 0;
                continue;
            } else if slot == 258 {
                if last_length == 0 {
                    continue;
                }
                length = last_length;
                dist = old[0];
            } else if slot < 263 {
                let k = slot - 259;
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
                let ln = (e >> 4) as usize;
                if ln >= 28 {
                    return Err(Damage::new("The archive is damaged (a bad Huffman code)"));
                }
                let mut len = LDECODE[ln] as u64 + 2;
                let b = LBITS[ln];
                if b > 0 {
                    len += bits_at(&self.d, pos, b);
                    pos += b as usize;
                    s = 0;
                }
                last_length = len;
                length = len;
                dist = dk;
            } else {
                let sl = slot - 263;
                let mut dd = SDDECODE[sl] as u64 + 1;
                let b = SDBITS[sl];
                dd += (v >> (s - b)) & ((1u64 << b) - 1);
                pos += b as usize;
                s -= b;
                old = [dd, old[0], old[1], old[2]];
                last_length = 2;
                length = 2;
                dist = dd;
            }
            let have = self.hist.len() as u64;
            if dist == 0 || dist > have || dist > self.dictionary {
                self.pos = pos;
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
        self.pos = pos;
        self.old = old;
        self.last_length = last_length;
        Ok(false)
    }

    fn vm_code_lz(&mut self) -> Res<()> {
        let first = self.bits(8);
        let mut length = (first & 7) as usize + 1;
        if length == 7 {
            length = self.bits(8) as usize + 7;
        } else if length == 8 {
            length = self.bits(16) as usize;
        }
        let code: Vec<u8> = (0..length).map(|k| bits_at(&self.d, self.pos + 8 * k, 8) as u8).collect();
        self.pos += 8 * length;
        self.add_filter(first as u32, &code)
    }

    fn add_filter(&mut self, first: u32, code: &[u8]) -> Res<()> {
        let mut padded = code.to_vec();
        padded.extend_from_slice(&[0; 8]);
        let mut inp = Code { d: &padded, pos: 0 };
        let mut index;
        if first & 0x80 != 0 {
            index = inp.number() as usize;
            if index == 0 {
                self.filters.clear();
                self.pending.clear();
            } else {
                index -= 1;
            }
        } else {
            index = self.last_filter;
        }
        if index > self.filters.len() || index > MAX_FILTERS {
            return Err(Damage::new("The archive is damaged (a filter that isn't there)"));
        }
        self.last_filter = index;
        let new = index == self.filters.len();
        if new {
            self.filters.push(FilterDef { kind: None, length: 0 });
        }
        let mut start = inp.number();
        if first & 0x40 != 0 {
            start += 258;
        }
        if start >= self.dictionary {
            return Err(Damage::new("The archive is damaged (a filter that starts past the dictionary window)"));
        }
        if first & 0x20 != 0 {
            self.filters[index].length = inp.number();
        }
        let length = self.filters[index].length;
        if length > VM_MEMSIZE as u64 {
            return Err(Damage::new("The archive is damaged (a filter longer than RAR's VM memory)"));
        }
        let mut regs = [0u64; 7];
        regs[4] = length;
        if first & 0x10 != 0 {
            let mask = inp.bits(7);
            for (k, r) in regs.iter_mut().enumerate() {
                if mask & (1 << k) != 0 {
                    *r = inp.number();
                }
            }
        }
        if new {
            let size = inp.number() as usize;
            if size == 0 || size >= 0x10000 || inp.pos / 8 + size > code.len() {
                return Err(Damage::new("The archive is damaged (a broken filter program)"));
            }
            let prog: Vec<u8> = (0..size).map(|_| inp.bits(8) as u8).collect();
            self.filters[index].kind = standard(size, crc32(&prog));
            if self.filters[index].kind.is_none() {
                return Err(Damage::new("This RAR archive uses a filter program packport doesn't run \
                                        (only RAR's own six standard filters are supported)"));
            }
        }
        if self.pending.len() >= MAX_FILTERS {
            return Err(Damage::new("The archive is damaged (too many filters)"));
        }
        let Some(kind) = self.filters[index].kind else {
            return Err(Damage::new("The archive is damaged (a filter that isn't there)"));
        };
        self.pending.push(Pending { start: self.base + self.hist.len() as u64 + start, length, kind, regs });
        Ok(())
    }

    fn copy(&mut self, length: usize, dist: u64) -> Res<()> {
        let have = self.hist.len() as u64;
        if dist == 0 || dist > have {
            return Err(Damage::new("The archive is damaged (a match reaches back before the data)"));
        }
        let start = (have - dist) as usize;
        if dist as usize >= length {
            self.hist.extend_from_within(start..start + length);
        } else {
            for k in 0..length {
                let b = self.hist[start + k];
                self.hist.push(b);
            }
        }
        Ok(())
    }

    fn ppm_char(&mut self) -> Res<u32> {
        let ppm = self.ppm.as_mut().unwrap();
        let Some(rc) = ppm.rc.as_mut() else {
            return Err(Damage::new("The archive is damaged (PPMd data without its model)"));
        };
        let mut src = Src { d: &self.d, at: &mut ppm.at };
        let mut coder = RarCoder { rc, src: &mut src };
        let c = ppm.model.decode_symbol(&mut coder);
        if c < 0 {
            return Err(Damage::new("The archive is damaged (bad PPMd data)"));
        }
        Ok(c as u32)
    }

    /// PPMd until the file's output is complete, RUN bytes, the input runs low, the block goes
    /// back to LZ (false), or the file ends (true).
    fn ppm_run(&mut self) -> Res<bool> {
        let target = self.file_start.saturating_add(self.size).saturating_sub(self.base) as usize;
        let stop = self.hist.len() + RUN;
        let lim = if self.finished { None } else { Some(self.lim() >> 3) };
        while self.hist.len() < target && self.hist.len() < stop {
            if let Some(l) = lim {
                if self.ppm.as_ref().unwrap().at > l {
                    break;
                }
            }
            let c = self.ppm_char()?;
            let esc = self.ppm.as_ref().unwrap().esc;
            if c == esc {
                let nxt = self.ppm_char()?;
                if nxt == 0 {
                    self.pos = self.ppm.as_ref().unwrap().at * 8;
                    self.read_tables()?;
                    if self.block_ppm {
                        continue;
                    }
                    return Ok(false);
                }
                if nxt == 2 {
                    self.pos = self.ppm.as_ref().unwrap().at * 8;
                    return Ok(true);
                }
                if nxt == 3 {
                    let first = self.ppm_char()?;
                    let mut length = (first & 7) as usize + 1;
                    if length == 7 {
                        length = self.ppm_char()? as usize + 7;
                    } else if length == 8 {
                        let hi = self.ppm_char()? as usize;
                        length = hi << 8 | self.ppm_char()? as usize;
                    }
                    let mut code = Vec::with_capacity(length);
                    for _ in 0..length {
                        code.push(self.ppm_char()? as u8);
                    }
                    self.add_filter(first, &code)?;
                    continue;
                }
                if nxt == 4 {
                    let a = self.ppm_char()? as u64;
                    let b = self.ppm_char()? as u64;
                    let c3 = self.ppm_char()? as u64;
                    let dist = a << 16 | b << 8 | c3;
                    let length = self.ppm_char()? as usize;
                    self.copy(length + 32, dist + 2)?;
                    continue;
                }
                if nxt == 5 {
                    let n = self.ppm_char()? as usize;
                    self.copy(n + 4, 1)?;
                    continue;
                }
            }
            self.hist.push(c as u8);
        }
        self.pos = self.ppm.as_ref().unwrap().at * 8;
        Ok(false)
    }

    fn flush(&mut self, final_: bool) -> Res<()> {
        let top = self.base + self.hist.len() as u64;
        let stop = self.file_start.saturating_add(self.size);
        loop {
            let written = self.written;
            self.pending.retain(|f| f.start >= written);
            let nxt = self.pending.iter().enumerate().min_by_key(|(_, f)| f.start).map(|(i, f)| (i, f.start, f.length));
            let limit = match nxt {
                None => top.min(stop),
                Some((_, s, _)) => top.min(stop).min(s),
            };
            if limit > self.written {
                let a = (self.written - self.base) as usize;
                let b = (limit - self.base) as usize;
                self.out.extend_from_slice(&self.hist[a..b]);
                self.written = limit;
            }
            let Some((i, fstart, flen)) = nxt else { break };
            if fstart > self.written || top < fstart + flen {
                break;
            }
            let f = self.pending.remove(i);
            let a = (f.start - self.base) as usize;
            let mut data = self.hist[a..a + f.length as usize].to_vec();
            data = run_filter(f.kind, data, &f.regs, f.start - self.file_start)?;
            // more filters on the same block, one after the other
            while i < self.pending.len() && self.pending[i].start == f.start && self.pending[i].length as usize == data.len() {
                let g = self.pending.remove(i);
                data = run_filter(g.kind, data, &g.regs, g.start - self.file_start)?;
            }
            let room = (stop.saturating_sub(self.written)) as usize;
            self.out.extend_from_slice(&data[..data.len().min(room)]);
            self.written = f.start + f.length;
        }
        if final_ && self.written < top.min(stop) {
            let a = (self.written - self.base) as usize;
            let b = (top.min(stop) - self.base) as usize;
            self.out.extend_from_slice(&self.hist[a..b]);
            self.written = top.min(stop);
        }
        let drop = (self.written - self.base).saturating_sub(self.dictionary);
        if drop > FLUSH {
            self.hist.drain(..drop as usize);
            self.base += drop;
        }
        Ok(())
    }

    fn compact_input(&mut self) {
        let used = self.pos >> 3;
        let used = match &self.ppm {
            Some(p) if self.block_ppm => used.min(p.at),
            _ => used,
        };
        if used > (4 << 20) && used <= self.d.len() {
            self.d.drain(..used);
            self.pos -= used * 8;
            if let Some(p) = self.ppm.as_mut() {
                p.at = p.at.saturating_sub(used);
            }
        }
    }

    fn run(&mut self, want: usize) -> Res<()> {
        loop {
            if self.out.len() - self.given >= want || self.done {
                return Ok(());
            }
            if !self.ready() {
                return Ok(());
            }
            if !self.started {
                if self.block_ppm {
                    if let Some(p) = self.ppm.as_mut() {
                        p.at = 0; // a solid archive's next file: the coder reads its data from the start
                    }
                } else if self.tables.is_none() {
                    self.read_tables()?;
                }
                self.started = true;
            }
            if self.produced() >= self.size {
                self.flush(true)?;
                self.done = true;
                return Ok(());
            }
            if self.pos > self.end() + 64 {
                return Err(Damage::new("The archive is damaged or cut short (compressed data ended early)"));
            }
            let before = (self.hist.len(), self.pos);
            let ended = if self.block_ppm { self.ppm_run()? } else { self.lz_run()? };
            self.flush(false)?;
            if ended {
                self.flush(true)?;
                self.done = true;
                return Ok(());
            }
            if (self.hist.len(), self.pos) == before && !self.finished {
                return Ok(()); // nothing more until more input comes
            }
            if (self.hist.len(), self.pos) == before && self.finished && self.produced() < self.size {
                return Err(Damage::new("The archive is damaged or cut short (compressed data ended early)"));
            }
        }
    }
}

fn run_filter(kind: Kind, data: Vec<u8>, regs: &[u64; 7], offset: u64) -> Res<Vec<u8>> {
    let n = data.len();
    if n > VM_MEMSIZE {
        return Err(Damage::new("The archive is damaged (a filter block over 256 KB)"));
    }
    match kind {
        Kind::E8 | Kind::E8E9 => {
            let mut out = data;
            let size: u64 = 0x100_0000;
            let second = if kind == Kind::E8E9 { 0xE9 } else { 0xE8 };
            let mut pos = 0usize;
            while pos + 4 < n {
                let b = out[pos];
                pos += 1;
                if b == 0xE8 || b == second {
                    let at = (pos as u64 + offset) & 0xFFFF_FFFF;
                    let addr = u32::from_le_bytes([out[pos], out[pos + 1], out[pos + 2], out[pos + 3]]) as u64;
                    if addr & 0x8000_0000 != 0 {
                        if (addr + at) & 0x8000_0000 == 0 {
                            out[pos..pos + 4].copy_from_slice(&(((addr + size) & 0xFFFF_FFFF) as u32).to_le_bytes());
                        }
                    } else if addr.wrapping_sub(size) & 0x8000_0000 != 0 {
                        out[pos..pos + 4].copy_from_slice(&((addr.wrapping_sub(at) & 0xFFFF_FFFF) as u32).to_le_bytes());
                    }
                    pos += 4;
                }
            }
            Ok(out)
        }
        Kind::Itanium => {
            let mut out = data;
            out.extend_from_slice(&[0; 4]);
            let masks = [4u32, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0];
            let mut file_offset = offset >> 4;
            let mut pos = 0usize;
            while pos + 21 < n {
                let b = (out[pos] & 0x1F) as i32 - 0x10;
                if b >= 0 {
                    let mask = masks[b as usize];
                    for k in 0..3 {
                        if mask & (1 << k) != 0 {
                            let start = k * 41 + 5;
                            if ia_get(&out, pos, start + 37, 4) == 5 {
                                let target = ia_get(&out, pos, start + 13, 20);
                                ia_set(&mut out, pos, (target.wrapping_sub(file_offset)) & 0xFFFFF, start + 13, 20);
                            }
                        }
                    }
                }
                pos += 16;
                file_offset += 1;
            }
            out.truncate(n);
            Ok(out)
        }
        Kind::Delta => {
            let channels = regs[0] as usize;
            if channels == 0 || channels > 1024 {
                return Err(Damage::new("The archive is damaged (a Delta filter with no channels)"));
            }
            let mut out = vec![0u8; n];
            let mut src = 0usize;
            for c in 0..channels {
                let mut prev = 0u8;
                let mut at = c;
                while at < n {
                    prev = prev.wrapping_sub(data[src]);
                    out[at] = prev;
                    src += 1;
                    at += channels;
                }
            }
            Ok(out)
        }
        Kind::Rgb => {
            let width = regs[0] as i64 - 3;
            let pos_r = regs[1] as usize;
            if n < 3 || width > n as i64 || pos_r > 2 || width < 0 {
                return Err(Damage::new("The archive is damaged (a broken RGB filter)"));
            }
            let width = width as usize;
            let mut out = vec![0u8; n];
            let mut src = 0usize;
            for c in 0..3 {
                let mut prev: i64 = 0;
                let mut i = c;
                while i < n {
                    let predicted = if i >= width + 3 {
                        let up = out[i - width] as i64;
                        let up_left = out[i - width - 3] as i64;
                        let p = prev + up - up_left;
                        let (pa, pb, pc) = ((p - prev).abs(), (p - up).abs(), (p - up_left).abs());
                        if pa <= pb && pa <= pc {
                            prev
                        } else if pb <= pc {
                            up
                        } else {
                            up_left
                        }
                    } else {
                        prev
                    };
                    prev = (predicted - data[src] as i64) & 0xFF;
                    out[i] = prev as u8;
                    src += 1;
                    i += 3;
                }
            }
            let mut i = pos_r;
            while i + 2 < n {
                let g = out[i + 1];
                out[i] = out[i].wrapping_add(g);
                out[i + 2] = out[i + 2].wrapping_add(g);
                i += 3;
            }
            Ok(out)
        }
        Kind::Audio => {
            let channels = regs[0] as usize;
            if channels == 0 || channels > 128 {
                return Err(Damage::new("The archive is damaged (an audio filter with no channels)"));
            }
            let mut out = vec![0u8; n];
            let mut src = 0usize;
            for c in 0..channels {
                let (mut prev, mut prev_delta) = (0i64, 0i64);
                let (mut d1, mut d2) = (0i64, 0i64);
                let (mut k1, mut k2, mut k3) = (0i64, 0i64, 0i64);
                let mut dif = [0i64; 7];
                let mut count = 0usize;
                let mut i = c;
                while i < n {
                    let d3 = d2;
                    d2 = prev_delta - d1;
                    d1 = prev_delta;
                    let mut predicted = ((8 * prev + k1 * d1 + k2 * d2 + k3 * d3) >> 3) & 0xFF;
                    let cur = data[src] as i64;
                    src += 1;
                    predicted = (predicted - cur) & 0xFF;
                    out[i] = predicted as u8;
                    let delta = (predicted - prev) & 0xFF;
                    prev_delta = if delta > 127 { delta - 256 } else { delta };
                    prev = predicted;
                    let dv = (if cur > 127 { cur - 256 } else { cur }) * 8;
                    dif[0] += dv.abs();
                    dif[1] += (dv - d1).abs();
                    dif[2] += (dv + d1).abs();
                    dif[3] += (dv - d2).abs();
                    dif[4] += (dv + d2).abs();
                    dif[5] += (dv - d3).abs();
                    dif[6] += (dv + d3).abs();
                    if count & 0x1F == 0 {
                        let (mut best, mut which) = (dif[0], 0usize);
                        dif[0] = 0;
                        for (j, slot) in dif.iter_mut().enumerate().skip(1) {
                            if *slot < best {
                                best = *slot;
                                which = j;
                            }
                            *slot = 0;
                        }
                        match which {
                            1 if k1 >= -16 => k1 -= 1,
                            2 if k1 < 16 => k1 += 1,
                            3 if k2 >= -16 => k2 -= 1,
                            4 if k2 < 16 => k2 += 1,
                            5 if k3 >= -16 => k3 -= 1,
                            6 if k3 < 16 => k3 += 1,
                            _ => {}
                        }
                    }
                    count += 1;
                    i += channels;
                }
            }
            Ok(out)
        }
    }
}

fn ia_get(data: &[u8], base: usize, bit: usize, count: u32) -> u64 {
    let at = base + bit / 8;
    let mut b = [0u8; 4];
    for (k, slot) in b.iter_mut().enumerate() {
        *slot = *data.get(at + k).unwrap_or(&0);
    }
    let v = u32::from_le_bytes(b) as u64 >> (bit & 7);
    v & ((1u64 << count) - 1)
}

fn ia_set(data: &mut [u8], base: usize, value: u64, bit: usize, count: u32) {
    let at = base + bit / 8;
    let shift = bit & 7;
    let mask = !((((1u64 << count) - 1) << shift) as u32);
    let mut b = [0u8; 4];
    for (k, slot) in b.iter_mut().enumerate() {
        *slot = *data.get(at + k).unwrap_or(&0);
    }
    let v = (u32::from_le_bytes(b) & mask) | (((value << shift) & 0xFFFF_FFFF) as u32);
    for (k, byte) in v.to_le_bytes().iter().enumerate() {
        if let Some(slot) = data.get_mut(at + k) {
            *slot = *byte;
        }
    }
}

#[pymethods]
impl Rar29Decoder {
    #[new]
    fn new(dictionary: u64) -> Self {
        let (ddecode, dbits) = dist_tables();
        Rar29Decoder {
            dictionary, hist: Vec::new(), base: 0, written: 0, old: [0; 4], last_length: 0,
            old_table: vec![0; NC + DC + LDC + RC], tables: None, prev_low: 0, low_reps: 0, filters: Vec::new(),
            pending: Vec::new(), last_filter: 0, ppm: None, ppm_esc: 2, block_ppm: false, d: Vec::new(), pos: 0,
            finished: false, file_start: 0, size: 0, started: false, done: false, out: Vec::new(), given: 0,
            ddecode, dbits, drop_tables: false,
        }
    }

    /// The next file (in a solid archive, carrying the state on): size bytes of output.
    fn begin_file(&mut self, size: u64) {
        self.d.clear();
        self.pos = 0;
        self.finished = false;
        self.file_start = self.base + self.hist.len() as u64;
        self.written = self.file_start;
        self.size = size;
        self.started = false;
        self.done = false;
        self.out.clear();
        self.given = 0;
    }

    fn feed(&mut self, py: Python<'_>, data: PyBackedBytes) {
        py.detach(|| {
            self.compact_input();
            self.d.extend_from_slice(&data);
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
        self.done && self.given >= self.out.len()
    }

    fn read<'py>(&mut self, py: Python<'py>, max_len: usize) -> PyResult<Bound<'py, PyBytes>> {
        let (a, b) = py.detach(|| -> Res<(usize, usize)> {
            if self.given > (8 << 20) {
                self.out.drain(..self.given);
                self.given = 0;
            }
            self.run(max_len)?;
            let n = std::cmp::min(max_len, self.out.len() - self.given);
            self.given += n;
            Ok((self.given - n, self.given))
        }).map_err(|e| raise(py, e))?;
        Ok(PyBytes::new(py, &self.out[a..b]))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn crc32_matches_zlib() {
        assert_eq!(super::crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn delta_filter_undoes_differences() {
        let regs = [1u64, 0, 0, 0, 4, 0, 0];
        let out = super::run_filter(super::Kind::Delta, vec![0xFF, 0xFF, 0xFF, 0xFF], &regs, 0).ok().unwrap();
        assert_eq!(out, vec![1, 2, 3, 4]);
    }
}
