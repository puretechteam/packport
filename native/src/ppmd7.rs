//! PPMd variant H (PPMII), the model of 7z's PPMd and of RAR 2.9-4.x, with both range decoders:
//! a port of packport's ppmd.py (itself written from Igor Pavlov's public-domain Ppmd7). The model
//! lives in one block of memory laid out as the reference lays it out, because a decoder has to
//! run out of memory exactly where the encoder did; 16-bit fields are read as ppmd.py's 16-bit
//! view reads them (at the even address at or below). Reads outside the memory give 0 and writes
//! that don't fit their field are dropped, both marking the model damaged (ppmd.py would raise
//! there): the symbol being decoded then reports damage.

use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

pub const UNIT_SIZE: u32 = 12;
pub const MAX_FREQ: u32 = 124;
const INT_BITS: u32 = 7;
pub const PERIOD_BITS: u32 = 7;
pub const BIN_SCALE: u32 = 1 << (INT_BITS + PERIOD_BITS);
pub const NUM_INDEXES: usize = 38;
pub const INIT_BIN_ESC: [u32; 8] = [0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051];
pub const EXP_ESCAPE: [u32; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];
pub const TOP: u64 = 1 << 24;

pub const BOT: u64 = 1 << 15;
const M32: u64 = 0xFFFF_FFFF;
pub const MAX_MEMORY: u64 = 1 << 31;

pub struct Tables {
    pub indx2units: [u32; NUM_INDEXES],
    pub units2indx: [u32; 128],
    pub ns2bsindx: [u32; 256],
    ns2indx: [u32; 256],
    hb2flag: [u32; 256],
}

pub fn tables() -> Tables {
    let mut indx2units = [0u32; NUM_INDEXES];
    let mut units2indx = [0u32; 128];
    let mut n = 0usize;
    for (i, slot) in indx2units.iter_mut().enumerate() {
        let step = if i >= 12 { 4 } else { (i >> 2) + 1 };
        for _ in 0..step {
            if n < 128 {
                units2indx[n] = i as u32;
            }
            n += 1;
        }
        *slot = n as u32;
    }
    let mut ns2bsindx = [6u32; 256];
    ns2bsindx[0] = 0;
    ns2bsindx[1] = 2;
    for v in &mut ns2bsindx[2..11] {
        *v = 4;
    }
    let mut ns2indx = [0u32; 256];
    ns2indx[1] = 1;
    ns2indx[2] = 2;
    let (mut m, mut k) = (3u32, 1u32);
    for v in &mut ns2indx[3..256] {
        *v = m;
        k -= 1;
        if k == 0 {
            m += 1;
            k = m - 2;
        }
    }
    let mut hb2flag = [0u32; 256];
    for v in &mut hb2flag[0x40..] {
        *v = 8;
    }
    Tables { indx2units, units2indx, ns2bsindx, ns2indx, hb2flag }
}

/// A range decoder the model can use (7z's or RAR's).
pub trait Range {
    fn threshold(&mut self, total: u32) -> Option<u32>;
    fn decode(&mut self, start: u32, size: u32);
    fn bit(&mut self, size0: u32, total: u32) -> u32;
}

/// Bytes for a range decoder: the data fed so far, 0 past it.
pub struct Input {
    pub data: Vec<u8>,
    pub pos: usize,
}

impl Input {
    #[inline]
    pub fn byte(&mut self) -> u64 {
        let p = self.pos;
        self.pos += 1;
        *self.data.get(p).unwrap_or(&0) as u64
    }

    pub fn left(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn compact(&mut self) {
        if self.pos > (4 << 20) {
            let k = self.pos.min(self.data.len());
            self.data.drain(..k);
            self.pos -= k;
        }
    }
}

/// 7z's range decoder (ppmd.py's Range7z).
pub struct Range7z {
    pub inp: Input,
    code: u32,
    range: u32,
    pub bad: bool,
}

impl Range7z {
    /// Started from the first five bytes of inp (the first must be 0); None if it isn't.
    pub fn new(mut inp: Input) -> Option<Range7z> {
        if inp.byte() != 0 {
            return None;
        }
        let mut code = 0u32;
        for _ in 0..4 {
            code = (code << 8) | inp.byte() as u32;
        }
        Some(Range7z { inp, code, range: M32 as u32, bad: false })
    }

    #[inline(always)]
    fn normalize(&mut self) {
        while (self.range as u64) < TOP {
            if self.range == 0 {
                self.bad = true;
                return;
            }
            self.code = (self.code << 8) | self.inp.byte() as u32;
            self.range <<= 8;
        }
    }
}

impl Range for Range7z {
    #[inline(always)]
    fn threshold(&mut self, total: u32) -> Option<u32> {
        if total == 0 {
            return None;
        }
        self.range /= total;
        if self.range == 0 {
            return None;
        }
        Some(self.code / self.range)
    }

    #[inline(always)]
    fn decode(&mut self, start: u32, size: u32) {
        self.code = self.code.wrapping_sub(start.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(size);
        self.normalize();
    }

    #[inline(always)]
    fn bit(&mut self, size0: u32, total: u32) -> u32 {
        let bound = (self.range / total).wrapping_mul(size0);
        let bit = if self.code < bound {
            self.range = bound;
            0
        } else {
            self.code -= bound;
            self.range -= bound;
            1
        };
        self.normalize();
        bit
    }
}

/// RAR's carry-less range decoder (Subbotin's; ppmd.py's RangeRar), over a byte source.
pub struct RangeRar {
    low: u64,
    code: u64,
    range: u64,
}

pub trait ByteSource {
    fn next(&mut self) -> u64;
}

impl RangeRar {
    pub fn new(src: &mut dyn ByteSource) -> RangeRar {
        let mut code = 0u64;
        for _ in 0..4 {
            code = (code << 8) | src.next();
        }
        RangeRar { low: 0, code, range: M32 }
    }
}

/// A RangeRar with the source it reads from, for the model.
pub struct RarCoder<'a> {
    pub rc: &'a mut RangeRar,
    pub src: &'a mut dyn ByteSource,
}

impl RarCoder<'_> {
    fn normalize(&mut self) {
        let rc = &mut *self.rc;
        loop {
            if (rc.low ^ ((rc.low + rc.range) & M32)) >= TOP {
                if rc.range >= BOT {
                    return;
                }
                rc.range = (rc.low.wrapping_neg()) & (BOT - 1);
            }
            rc.code = ((rc.code << 8) | self.src.next()) & M32;
            rc.range = (rc.range << 8) & M32;
            rc.low = (rc.low << 8) & M32;
            if rc.range == 0 && rc.low == 0 {
                rc.range = 1; // damaged: never loop for ever
            }
        }
    }
}

impl Range for RarCoder<'_> {
    fn threshold(&mut self, total: u32) -> Option<u32> {
        if total == 0 {
            return None;
        }
        self.rc.range /= total as u64;
        if self.rc.range == 0 {
            return None;
        }
        Some((((self.rc.code.wrapping_sub(self.rc.low)) & M32) / self.rc.range).min(u32::MAX as u64) as u32)
    }

    fn decode(&mut self, start: u32, size: u32) {
        self.rc.low = (self.rc.low + start as u64 * self.rc.range) & M32;
        self.rc.range = (self.rc.range * size as u64) & M32;
        self.normalize();
    }

    fn bit(&mut self, size0: u32, total: u32) -> u32 {
        match self.threshold(total) {
            Some(t) if t < size0 => {
                self.decode(0, size0);
                0
            }
            Some(_) => {
                self.decode(size0, total - size0);
                1
            }
            None => 1,
        }
    }
}

#[derive(Clone, Copy)]
struct See {
    summ: u32,
    shift: u32,
    count: u32,
}

pub struct Model {
    mem: Vec<u8>,
    pub size: u32,
    align: u32,
    see: Vec<[See; 16]>,
    dummy_see: See,
    bin_summ: Vec<[u32; 64]>,
    init_esc: u32,
    hi_bits_flag: u32,
    free: [u32; NUM_INDEXES],
    text: u32,
    hi_unit: u32,
    lo_unit: u32,
    units_start: u32,
    glue_count: u32,
    order_fall: i64,
    run_length: i64,
    init_rl: i64,
    prev_success: u32,
    min_context: u32,
    max_context: u32,
    found: u32,
    max_order: u32,
    bad: AtomicBool,
    t: Tables,
    ps: Vec<u32>,   // scratch for decode_symbol's escapes
    cs: Vec<u32>,   // scratch for create_successors (kept, so it allocates once)
    mask: [bool; 256],
}

enum SeeRef {
    Dummy,
    At(usize, usize),
}

impl Model {
    /// A model of size bytes; Err(message) for sizes ppmd.py refuses.
    pub fn new(size: u64) -> Result<Model, &'static str> {
        if !((1 << 11)..=0xFFFF_FFFF - 12 * 3).contains(&size) {
            return Err("The archive is damaged (a PPMd memory size out of range)");
        }
        if size > MAX_MEMORY {
            return Err("This archive's PPMd model needs more than 2 GB, more than 7-Zip ever writes \
                        (the archive is probably damaged)");
        }
        let size = size as u32;
        let align = 4 - (size & 3);
        let total = (align + size + UNIT_SIZE + 8) as usize;
        Ok(Model {
            mem: vec![0; total],
            size,
            align,
            see: vec![[See { summ: 0, shift: 0, count: 0 }; 16]; 25],
            dummy_see: See { summ: 0, shift: PERIOD_BITS, count: 64 },
            bin_summ: vec![[0; 64]; 128],
            init_esc: 0,
            hi_bits_flag: 0,
            free: [0; NUM_INDEXES],
            text: 0,
            hi_unit: 0,
            lo_unit: 0,
            units_start: 0,
            glue_count: 0,
            order_fall: 0,
            run_length: 0,
            init_rl: 0,
            prev_success: 0,
            min_context: 0,
            max_context: 0,
            found: 0,
            max_order: 0,
            bad: AtomicBool::new(false),
            t: tables(),
            ps: Vec::with_capacity(256),
            cs: Vec::with_capacity(64),
            mask: [true; 256],
        })
    }

    // -- memory

    #[inline(always)]
    fn r8(&self, a: u32) -> u32 {
        match self.mem.get(a as usize) {
            Some(&v) => v as u32,
            None => {
                self.bad.store(true, Relaxed);
                0
            }
        }
    }

    #[inline]
    fn w8(&mut self, a: u32, v: i64) {
        if !(0..=255).contains(&v) {
            self.bad.store(true, Relaxed);
            return;
        }
        match self.mem.get_mut(a as usize) {
            Some(slot) => *slot = v as u8,
            None => self.bad.store(true, Relaxed),
        }
    }

    #[inline(always)]
    fn r16(&self, a: u32) -> u32 {
        let i = (a & !1) as usize;
        match self.mem.get(i..i + 2) {
            Some(b) => u16::from_le_bytes([b[0], b[1]]) as u32,
            None => {
                self.bad.store(true, Relaxed);
                0
            }
        }
    }

    #[inline]
    fn w16(&mut self, a: u32, v: i64) {
        if !(0..=0xFFFF).contains(&v) {
            self.bad.store(true, Relaxed);
            return;
        }
        let i = (a & !1) as usize;
        match self.mem.get_mut(i..i + 2) {
            Some(b) => b.copy_from_slice(&(v as u16).to_le_bytes()),
            None => self.bad.store(true, Relaxed),
        }
    }

    #[inline(always)]
    fn g32(&self, a: u32) -> u32 {
        let i = (a & !1) as usize;
        match self.mem.get(i..i + 4) {
            Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            None => {
                self.bad.store(true, Relaxed);
                0
            }
        }
    }

    #[inline]
    fn s32(&mut self, a: u32, v: u32) {
        self.w16(a, (v & 0xFFFF) as i64);
        self.w16((a & !1).wrapping_add(2), (v >> 16) as i64);
    }

    fn copy_units(&mut self, dst: u32, src: u32, nu: u32) {
        let n = (nu * UNIT_SIZE) as usize;
        let (d, s) = (dst as usize, src as usize);
        if d + n > self.mem.len() || s + n > self.mem.len() {
            self.bad.store(true, Relaxed);
            return;
        }
        self.mem.copy_within(s..s + n, d);
    }

    fn copy6(&mut self, dst: u32, src: u32) {
        let (d, s) = (dst as usize, src as usize);
        if d + 6 > self.mem.len() || s + 6 > self.mem.len() {
            self.bad.store(true, Relaxed);
            return;
        }
        self.mem.copy_within(s..s + 6, d);
    }

    fn get6(&self, a: u32) -> [u8; 6] {
        let i = a as usize;
        match self.mem.get(i..i + 6) {
            Some(b) => [b[0], b[1], b[2], b[3], b[4], b[5]],
            None => {
                self.bad.store(true, Relaxed);
                [0; 6]
            }
        }
    }

    fn put6(&mut self, a: u32, v: [u8; 6]) {
        let i = a as usize;
        match self.mem.get_mut(i..i + 6) {
            Some(b) => b.copy_from_slice(&v),
            None => self.bad.store(true, Relaxed),
        }
    }

    fn swap(&mut self, a: u32, b: u32) {
        let x = self.get6(a);
        let y = self.get6(b);
        self.put6(a, y);
        self.put6(b, x);
    }

    // -- allocator (units of 12 bytes)

    fn insert(&mut self, node: u32, indx: usize) {
        if indx >= NUM_INDEXES {
            self.bad.store(true, Relaxed);
            return;
        }
        self.s32(node, self.free[indx]);
        self.free[indx] = node;
    }

    fn remove(&mut self, indx: usize) -> u32 {
        let node = self.free[indx];
        self.free[indx] = self.g32(node);
        node
    }

    fn u2i(&self, nu: u32) -> usize {
        match self.t.units2indx.get((nu as usize).wrapping_sub(1)) {
            Some(&v) => v as usize,
            None => {
                self.bad.store(true, Relaxed);
                0
            }
        }
    }

    fn split(&mut self, ptr: u32, old: usize, new: usize) {
        let nu = self.t.indx2units[old] as i64 - self.t.indx2units[new] as i64;
        if nu <= 0 {
            self.bad.store(true, Relaxed);
            return;
        }
        let ptr = ptr + self.t.indx2units[new] * UNIT_SIZE;
        let mut i = self.u2i(nu as u32);
        if self.t.indx2units[i] as i64 != nu {
            i -= 1;
            let k = self.t.indx2units[i];
            self.insert(ptr + k * UNIT_SIZE, (nu as u32 - k - 1) as usize);
        }
        self.insert(ptr, i);
    }

    fn glue(&mut self) {
        let head = self.align + self.size;
        let mut n = head;
        self.glue_count = 255;
        for i in 0..NUM_INDEXES {
            let nu = self.t.indx2units[i];
            let mut nxt = self.free[i];
            self.free[i] = 0;
            let mut guard = 0u64;
            while nxt != 0 {
                let node = nxt;
                nxt = self.g32(node);
                self.s32(node + 4, n);
                self.s32(n + 8, node);
                n = node;
                self.w16(node, 0);
                self.w16(node + 2, nu as i64);
                guard += 1;
                if guard > self.mem.len() as u64 || self.bad.load(Relaxed) {
                    self.bad.store(true, Relaxed);
                    return;
                }
            }
        }
        self.w16(head, 1);
        self.s32(head + 4, n);
        self.s32(n + 8, head);
        if self.lo_unit != self.hi_unit {
            self.w16(self.lo_unit, 1);
        }
        let mut guard = 0u64;
        while n != head {
            let node = n;
            let mut nu = self.r16(node + 2);
            loop {
                let node2 = node.wrapping_add(nu * UNIT_SIZE);
                nu += self.r16(node2 + 2);
                if self.r16(node2) != 0 || nu >= 0x10000 {
                    break;
                }
                let prev = self.g32(node2 + 8);
                let nx = self.g32(node2 + 4);
                self.s32(prev + 4, nx);
                self.s32(nx + 8, prev);
                self.w16(node + 2, nu as i64);
                if self.bad.load(Relaxed) {
                    return;
                }
            }
            n = self.g32(node + 4);
            guard += 1;
            if guard > self.mem.len() as u64 || self.bad.load(Relaxed) {
                self.bad.store(true, Relaxed);
                return;
            }
        }
        n = self.g32(head + 4);
        let mut guard = 0u64;
        while n != head {
            let mut node = n;
            let nxt = self.g32(node + 4);
            let mut nu = self.r16(node + 2);
            while nu > 128 {
                self.insert(node, NUM_INDEXES - 1);
                nu -= 128;
                node += 128 * UNIT_SIZE;
            }
            if nu == 0 {
                self.bad.store(true, Relaxed);
                return;
            }
            let mut i = self.u2i(nu);
            if self.t.indx2units[i] != nu {
                i -= 1;
                let k = self.t.indx2units[i];
                self.insert(node + k * UNIT_SIZE, (nu - k - 1) as usize);
            }
            self.insert(node, i);
            n = nxt;
            guard += 1;
            if guard > self.mem.len() as u64 || self.bad.load(Relaxed) {
                self.bad.store(true, Relaxed);
                return;
            }
        }
    }

    fn alloc_rare(&mut self, indx: usize) -> u32 {
        if self.glue_count == 0 {
            self.glue();
            if self.free[indx] != 0 {
                return self.remove(indx);
            }
        }
        let mut i = indx;
        loop {
            i += 1;
            if i == NUM_INDEXES {
                let num = self.t.indx2units[indx] * UNIT_SIZE;
                self.glue_count = self.glue_count.wrapping_sub(1);
                if self.units_start as i64 - self.text as i64 > num as i64 {
                    self.units_start -= num;
                    return self.units_start;
                }
                return 0;
            }
            if self.free[i] != 0 {
                break;
            }
        }
        let ptr = self.remove(i);
        self.split(ptr, i, indx);
        ptr
    }

    fn alloc(&mut self, indx: usize) -> u32 {
        if self.free[indx] != 0 {
            return self.remove(indx);
        }
        let num = self.t.indx2units[indx] * UNIT_SIZE;
        if num as i64 <= self.hi_unit as i64 - self.lo_unit as i64 {
            let ptr = self.lo_unit;
            self.lo_unit += num;
            return ptr;
        }
        self.alloc_rare(indx)
    }

    fn shrink(&mut self, old: u32, old_nu: u32, new_nu: u32) -> u32 {
        let (i0, i1) = (self.u2i(old_nu), self.u2i(new_nu));
        if i0 == i1 {
            return old;
        }
        if self.free[i1] != 0 {
            let ptr = self.remove(i1);
            self.copy_units(ptr, old, new_nu);
            self.insert(old, i0);
            return ptr;
        }
        self.split(old, i0, i1);
        old
    }

    // -- the model

    pub fn init(&mut self, max_order: u32) {
        self.max_order = max_order;
        self.restart();
        self.dummy_see = See { summ: 0, shift: PERIOD_BITS, count: 64 };
    }

    fn restart(&mut self) {
        self.free = [0; NUM_INDEXES];
        self.text = self.align;
        self.hi_unit = self.text + self.size;
        self.lo_unit = self.hi_unit - self.size / 8 / UNIT_SIZE * 7 * UNIT_SIZE;
        self.units_start = self.lo_unit;
        self.glue_count = 0;
        self.order_fall = self.max_order as i64;
        self.init_rl = -(std::cmp::min(12, self.max_order) as i64) - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;
        self.hi_unit -= UNIT_SIZE;
        let ctx = self.hi_unit;
        self.min_context = ctx;
        self.max_context = ctx;
        self.s32(ctx + 8, 0);
        self.w16(ctx, 256);
        self.w16(ctx + 2, 257);
        let stats = self.lo_unit;
        self.found = stats;
        self.lo_unit += (256 / 2) * UNIT_SIZE;
        self.s32(ctx + 4, stats);
        for i in 0..256u32 {
            let s = stats + 6 * i;
            self.w16(s, (i | 1 << 8) as i64);
            self.w16(s + 2, 0);
            self.w16(s + 4, 0);
        }
        for i in 0..128usize {
            for (k, &esc) in INIT_BIN_ESC.iter().enumerate() {
                let val = BIN_SCALE - esc / (i as u32 + 2);
                let mut j = k;
                while j < 64 {
                    self.bin_summ[i][j] = val;
                    j += 8;
                }
            }
        }
        for i in 0..25usize {
            for k in 0..16usize {
                let shift = PERIOD_BITS - 4;
                self.see[i][k] = See { summ: ((5 * i as u32 + 10) << shift) & 0xFFFF, shift, count: 4 };
            }
        }
    }

    fn create_successors(&mut self, skip: bool) -> u32 {
        let mut ps = std::mem::take(&mut self.cs);
        ps.clear();
        let r = self.create_successors_in(skip, &mut ps);
        self.cs = ps;
        r
    }

    fn create_successors_in(&mut self, skip: bool, ps: &mut Vec<u32>) -> u32 {
        let mut c = self.min_context;
        let fs = self.found;
        let up_branch = self.g32(fs + 2);
        let fsym = self.r8(fs);
        if !skip {
            ps.push(fs);
        }
        let mut guard = 0u32;
        while self.g32(c + 8) != 0 {
            c = self.g32(c + 8);
            let s = if self.r16(c) != 1 {
                let mut x = self.g32(c + 4);
                let mut steps = 0u32;
                while self.r8(x) != fsym {
                    x = x.wrapping_add(6);
                    steps += 1;
                    if steps > 256 || self.bad.load(Relaxed) {
                        self.bad.store(true, Relaxed);
                        return 0;
                    }
                }
                x
            } else {
                c + 2
            };
            let succ = self.g32(s + 2);
            if succ != up_branch {
                c = succ;
                if ps.is_empty() {
                    return c;
                }
                break;
            }
            ps.push(s);
            guard += 1;
            if guard > 1 << 16 || self.bad.load(Relaxed) {
                self.bad.store(true, Relaxed);
                return 0;
            }
        }
        let up_sym = self.r8(up_branch);
        let up_succ = up_branch.wrapping_add(1);
        let up_freq: i64 = if self.r16(c) == 1 {
            self.r8(c + 3) as i64
        } else {
            let mut s = self.g32(c + 4);
            let mut steps = 0u32;
            while self.r8(s) != up_sym {
                s = s.wrapping_add(6);
                steps += 1;
                if steps > 256 || self.bad.load(Relaxed) {
                    self.bad.store(true, Relaxed);
                    return 0;
                }
            }
            let cf = self.r8(s + 1) as i64 - 1;
            let s0 = self.r16(c + 2) as i64 - self.r16(c) as i64 - cf;
            if 2 * cf <= s0 {
                1 + if 5 * cf > s0 { 1 } else { 0 }
            } else {
                if s0 <= 0 {
                    self.bad.store(true, Relaxed);
                    return 0;
                }
                1 + (2 * cf + 3 * s0 - 1).div_euclid(2 * s0)
            }
        };
        while let Some(p) = ps.pop() {
            let c1 = if self.hi_unit != self.lo_unit {
                self.hi_unit -= UNIT_SIZE;
                self.hi_unit
            } else if self.free[0] != 0 {
                self.remove(0)
            } else {
                let c1 = self.alloc_rare(0);
                if c1 == 0 {
                    return 0;
                }
                c1
            };
            self.w16(c1, 1);
            self.w8(c1 + 2, up_sym as i64);
            self.w8(c1 + 3, up_freq);
            self.s32(c1 + 4, up_succ);
            self.s32(c1 + 8, c);
            self.s32(p + 2, c1);
            c = c1;
        }
        c
    }

    fn update_model(&mut self) {
        let fs = self.found;
        let fsym = self.r8(fs);
        let ffreq = self.r8(fs + 1);
        let mut f_succ = self.g32(fs + 2);
        let minc = self.min_context;
        if ffreq < MAX_FREQ / 4 && self.g32(minc + 8) != 0 {
            let c = self.g32(minc + 8);
            if self.r16(c) == 1 {
                if self.r8(c + 3) < 32 {
                    let v = self.r8(c + 3) as i64 + 1;
                    self.w8(c + 3, v);
                }
            } else {
                let mut s = self.g32(c + 4);
                if self.r8(s) != fsym {
                    s = s.wrapping_add(6);
                    let mut steps = 0u32;
                    while self.r8(s) != fsym {
                        s = s.wrapping_add(6);
                        steps += 1;
                        if steps > 256 || self.bad.load(Relaxed) {
                            self.bad.store(true, Relaxed);
                            return;
                        }
                    }
                    if self.r8(s + 1) >= self.r8(s.wrapping_sub(5)) {
                        self.swap(s, s.wrapping_sub(6));
                        s = s.wrapping_sub(6);
                    }
                }
                if self.r8(s + 1) < MAX_FREQ - 9 {
                    let v = self.r8(s + 1) as i64 + 2;
                    self.w8(s + 1, v);
                    let v = self.r16(c + 2) as i64 + 2;
                    self.w16(c + 2, v);
                }
            }
        }
        if self.order_fall == 0 {
            let c = self.create_successors(true);
            self.min_context = c;
            self.max_context = c;
            if c == 0 {
                self.restart();
                return;
            }
            self.s32(self.found + 2, c);
            return;
        }
        self.w8(self.text, fsym as i64);
        self.text += 1;
        let mut successor = self.text;
        if self.text >= self.units_start {
            self.restart();
            return;
        }
        if f_succ != 0 {
            if f_succ <= successor {
                let cs = self.create_successors(false);
                if cs == 0 {
                    self.restart();
                    return;
                }
                f_succ = cs;
            }
            self.order_fall -= 1;
            if self.order_fall == 0 {
                successor = f_succ;
                if self.max_context != self.min_context {
                    self.text -= 1;
                }
            }
        } else {
            self.s32(self.found + 2, successor);
            f_succ = self.min_context;
        }
        let ns = self.r16(minc) as i64;
        let s0 = self.r16(minc + 2) as i64 - ns - (self.r8(self.found + 1) as i64 - 1);
        let mut c = self.max_context;
        let mut guard = 0u32;
        while c != minc {
            let ns1 = self.r16(c) as i64;
            if ns1 != 1 {
                if ns1 & 1 == 0 {
                    let old_nu = (ns1 >> 1) as u32;
                    let i = self.u2i(old_nu);
                    let Some(&next) = self.t.units2indx.get(old_nu as usize) else {
                        self.bad.store(true, Relaxed); // ppmd.py's UNITS2INDX[old_nu] would raise IndexError
                        return;
                    };
                    if i as u32 != next {
                        let ptr = self.alloc(i + 1);
                        if ptr == 0 {
                            self.restart();
                            return;
                        }
                        let old = self.g32(c + 4);
                        self.copy_units(ptr, old, old_nu);
                        self.insert(old, i);
                        self.s32(c + 4, ptr);
                    }
                }
                let mut sf_c = self.r16(c + 2) as i64;
                sf_c += (if 2 * ns1 < ns { 1 } else { 0 })
                    + 2 * ((if 4 * ns1 <= ns { 1 } else { 0 }) & (if sf_c <= 8 * ns1 { 1 } else { 0 }));
                self.w16(c + 2, sf_c & 0xFFFF);
            } else {
                let s = self.alloc(0);
                if s == 0 {
                    self.restart();
                    return;
                }
                self.copy6(s, c + 2);
                self.s32(c + 4, s);
                let freq = self.r8(s + 1);
                let freq = if freq < MAX_FREQ / 4 - 1 { freq << 1 } else { MAX_FREQ - 4 };
                self.w8(s + 1, freq as i64);
                self.w16(c + 2, freq as i64 + self.init_esc as i64 + if ns > 3 { 1 } else { 0 });
            }
            let sfc = self.r16(c + 2) as i64;
            let mut cf = 2 * self.r8(self.found + 1) as i64 * (sfc + 6);
            let sf = s0 + sfc;
            if cf < 6 * sf {
                cf = 1 + (if cf > sf { 1 } else { 0 }) + (if cf >= 4 * sf { 1 } else { 0 });
                self.w16(c + 2, (sfc + 3) & 0xFFFF);
            } else {
                cf = 4 + (if cf >= 9 * sf { 1 } else { 0 }) + (if cf >= 12 * sf { 1 } else { 0 })
                    + (if cf >= 15 * sf { 1 } else { 0 });
                self.w16(c + 2, (sfc + cf) & 0xFFFF);
            }
            let s = self.g32(c + 4).wrapping_add(6 * ns1 as u32);
            self.s32(s + 2, successor);
            self.w8(s, fsym as i64);
            self.w8(s + 1, cf);
            self.w16(c, ns1 + 1);
            c = self.g32(c + 8);
            guard += 1;
            if guard > 1 << 16 || self.bad.load(Relaxed) {
                self.bad.store(true, Relaxed);
                return;
            }
        }
        self.max_context = f_succ;
        self.min_context = f_succ;
    }

    fn rescale(&mut self) {
        let minc = self.min_context;
        let stats = self.g32(minc + 4);
        let mut s = self.found;
        let tmp = self.get6(s);
        let mut guard = 0u32;
        while s != stats {
            self.copy6(s, s.wrapping_sub(6));
            s = s.wrapping_sub(6);
            guard += 1;
            if guard > 256 || self.bad.load(Relaxed) {
                self.bad.store(true, Relaxed);
                return;
            }
        }
        self.put6(s, tmp);
        let mut esc = self.r16(minc + 2) as i64 - self.r8(s + 1) as i64;
        let mut f = self.r8(s + 1) as i64 + 4;
        let adder = if self.order_fall != 0 { 1 } else { 0 };
        f = (f + adder) >> 1;
        self.w8(s + 1, f);
        let mut total = f;
        let mut i = self.r16(minc) as i64 - 1;
        loop {
            s = s.wrapping_add(6);
            esc -= self.r8(s + 1) as i64;
            let f = (self.r8(s + 1) as i64 + adder) >> 1;
            self.w8(s + 1, f);
            total += f;
            if f > self.r8(s.wrapping_sub(5)) as i64 {
                let mut s1 = s;
                let tmp = self.get6(s1);
                let mut steps = 0u32;
                loop {
                    self.copy6(s1, s1.wrapping_sub(6));
                    s1 = s1.wrapping_sub(6);
                    if s1 == stats || tmp[1] as u32 <= self.r8(s1.wrapping_sub(5)) {
                        break;
                    }
                    steps += 1;
                    if steps > 256 || self.bad.load(Relaxed) {
                        self.bad.store(true, Relaxed);
                        return;
                    }
                }
                self.put6(s1, tmp);
            }
            i -= 1;
            if i == 0 {
                break;
            }
            if i < 0 || self.bad.load(Relaxed) {
                self.bad.store(true, Relaxed);
                return;
            }
        }
        if self.r8(s + 1) == 0 {
            let num = self.r16(minc) as i64;
            let mut i = 0i64;
            loop {
                i += 1;
                s = s.wrapping_sub(6);
                if self.r8(s + 1) != 0 {
                    break;
                }
                if i > 256 || self.bad.load(Relaxed) {
                    self.bad.store(true, Relaxed);
                    return;
                }
            }
            esc += i;
            self.w16(minc, num - i);
            if num - i == 1 {
                let mut tmp = self.get6(stats);
                loop {
                    tmp[1] -= tmp[1] >> 1;
                    esc >>= 1;
                    if esc <= 1 {
                        break;
                    }
                }
                let idx = self.u2i(((num + 1) >> 1) as u32);
                self.insert(stats, idx);
                self.found = minc + 2;
                self.put6(minc + 2, tmp);
                return;
            }
            let (n0, n1) = (((num + 1) >> 1) as u32, ((num - i + 1) >> 1) as u32);
            if n0 != n1 {
                let p = self.shrink(stats, n0, n1);
                self.s32(minc + 4, p);
            }
        }
        self.w16(minc + 2, (total + esc - (esc >> 1)) & 0xFFFF);
        self.found = self.g32(minc + 4);
    }

    fn make_esc_freq(&mut self, num_masked: u32) -> (SeeRef, u32) {
        let minc = self.min_context;
        let ns = self.r16(minc);
        let non_masked = ns as i64 - num_masked as i64;
        if ns != 256 {
            let suffix_ns = self.r16(self.g32(minc + 8)) as i64;
            let row = match self.t.ns2indx.get((non_masked - 1).clamp(0, 255) as usize) {
                Some(&v) if non_masked >= 1 => v as usize,
                _ => {
                    self.bad.store(true, Relaxed);
                    return (SeeRef::Dummy, 1);
                }
            };
            let col = (if non_masked < suffix_ns - ns as i64 { 1 } else { 0 })
                + 2 * (if (self.r16(minc + 2) as i64) < 11 * ns as i64 { 1 } else { 0 })
                + 4 * (if num_masked as i64 > non_masked { 1 } else { 0 })
                + self.hi_bits_flag as usize;
            if row >= 25 || col >= 16 {
                self.bad.store(true, Relaxed);
                return (SeeRef::Dummy, 1);
            }
            let see = &mut self.see[row][col];
            let r = see.summ >> see.shift;
            see.summ = see.summ.wrapping_sub(r) & 0xFFFF;
            return (SeeRef::At(row, col), r + if r == 0 { 1 } else { 0 });
        }
        (SeeRef::Dummy, 1)
    }

    fn next_context(&mut self) {
        let c = self.g32(self.found + 2);
        if self.order_fall == 0 && c > self.text {
            self.min_context = c;
            self.max_context = c;
        } else {
            self.update_model();
        }
    }

    fn update1(&mut self) {
        let mut s = self.found;
        let v = self.r8(s + 1) as i64 + 4;
        self.w8(s + 1, v);
        let v = self.r16(self.min_context + 2) as i64 + 4;
        self.w16(self.min_context + 2, v);
        if self.r8(s + 1) > self.r8(s.wrapping_sub(5)) {
            self.swap(s, s.wrapping_sub(6));
            s = s.wrapping_sub(6);
            self.found = s;
            if self.r8(s + 1) > MAX_FREQ {
                self.rescale();
            }
        }
        self.next_context();
    }

    fn update1_0(&mut self) {
        let minc = self.min_context;
        self.prev_success = if 2 * self.r8(self.found + 1) > self.r16(minc + 2) { 1 } else { 0 };
        self.run_length += self.prev_success as i64;
        let v = self.r16(minc + 2) as i64 + 4;
        self.w16(minc + 2, v);
        let f = self.r8(self.found + 1) + 4;
        self.w8(self.found + 1, (f & 0xFF) as i64);
        if f > MAX_FREQ {
            self.rescale();
        }
        self.next_context();
    }

    fn update_bin(&mut self) {
        let f = self.r8(self.found + 1);
        self.w8(self.found + 1, (f + if f < 128 { 1 } else { 0 }) as i64);
        self.prev_success = 1;
        self.run_length += 1;
        self.next_context();
    }

    fn update2(&mut self) {
        let s = self.found;
        let f = self.r8(s + 1) + 4;
        self.w8(s + 1, (f & 0xFF) as i64);
        let v = self.r16(self.min_context + 2) as i64 + 4;
        self.w16(self.min_context + 2, v);
        if f > MAX_FREQ {
            self.rescale();
        }
        self.run_length = self.init_rl;
        self.update_model();
    }

    /// The next byte, -1 at the end mark, -2 for damaged data.
    pub fn decode_symbol<R: Range>(&mut self, rc: &mut R) -> i32 {
        let r = self.decode_inner(rc);
        if self.bad.load(Relaxed) {
            return -2;
        }
        r
    }

    fn decode_inner<R: Range>(&mut self, rc: &mut R) -> i32 {
        let minc = self.min_context;
        let ns = self.r16(minc);
        if ns != 1 {
            let s = self.g32(minc + 4);
            let summ = self.r16(minc + 2);
            let Some(count) = rc.threshold(summ) else { return -2 };
            // the context's states, read as one block: (symbol, freq, successor) in 6 bytes each
            let (base, n) = (s as usize, ns as usize);
            let Some(block) = self.mem.get(base..base + 6 * n) else { return -2 };
            let mut hi = block[1] as u32;
            if count < hi {
                rc.decode(0, hi);
                self.found = s;
                let sym = block[0] as i32;
                self.update1_0();
                return sym;
            }
            self.prev_success = 0;
            let mut hit = None;
            for k in 1..n {
                let f = block[6 * k + 1] as u32;
                hi += f;
                if hi > count {
                    hit = Some((k, f, block[6 * k] as i32));
                    break;
                }
            }
            if let Some((k, f, sym)) = hit {
                rc.decode(hi - f, f);
                self.found = s + 6 * k as u32;
                self.update1();
                return sym;
            }
            if count >= summ {
                return -2;
            }
            self.hi_bits_flag = self.t.hb2flag[self.r8(self.found) as usize & 0xFF];
            rc.decode(hi, summ - hi);
            let mut mask = [true; 256]; // true: not masked
            for st in block.as_chunks::<6>().0 {
                mask[st[0] as usize] = false;
            }
            self.mask = mask;
        } else {
            let suffix = self.g32(minc + 8);
            self.hi_bits_flag = self.t.hb2flag[self.r8(self.found) as usize & 0xFF];
            let row = (self.r8(minc + 3) as usize).wrapping_sub(1);
            let ns_suffix = self.r16(suffix) as usize;
            let col = self.prev_success as i64
                + self.t.ns2bsindx.get(ns_suffix.wrapping_sub(1)).copied().unwrap_or(0) as i64
                + self.hi_bits_flag as i64
                + 2 * self.t.hb2flag[self.r8(minc + 2) as usize & 0xFF] as i64
                + ((self.run_length >> 26) & 0x20);
            if row >= 128 || !(0..64).contains(&col) || ns_suffix == 0 || ns_suffix > 256 {
                return -2;
            }
            let col = col as usize;
            let prob = self.bin_summ[row][col];
            if rc.bit(prob, BIN_SCALE) == 0 {
                self.bin_summ[row][col] = (prob + (1 << INT_BITS) - ((prob + 32) >> 7)) & 0xFFFF;
                self.found = minc + 2;
                let sym = self.r8(minc + 2) as i32;
                self.update_bin();
                return sym;
            }
            let prob = (prob.wrapping_sub((prob + 32) >> 7)) & 0xFFFF;
            self.bin_summ[row][col] = prob;
            self.init_esc = EXP_ESCAPE[(prob >> 10) as usize & 15];
            self.mask = [true; 256];
            let sym = self.r8(minc + 2) as usize & 0xFF;
            self.mask[sym] = false;
            self.prev_success = 0;
        }
        let mut ps = std::mem::take(&mut self.ps);
        let r = self.escapes(rc, &mut ps);
        self.ps = ps;
        r
    }

    fn escapes<R: Range>(&mut self, rc: &mut R, ps: &mut Vec<u32>) -> i32 {
        let mut minc;
        loop {
            let num_masked = self.r16(self.min_context);
            let mut guard = 0u32;
            loop {
                self.order_fall += 1;
                let suffix = self.g32(self.min_context + 8);
                if suffix == 0 {
                    return -1;
                }
                self.min_context = suffix;
                if self.r16(suffix) != num_masked {
                    break;
                }
                guard += 1;
                if guard > 1 << 16 || self.bad.load(Relaxed) {
                    return -2;
                }
            }
            minc = self.min_context;
            let ns = self.r16(minc);
            let s = self.g32(minc + 4);
            ps.clear();
            let mut hi = 0u32;
            let want = ns as i64 - num_masked as i64;
            if want <= 0 {
                return -2;
            }
            {
                let (base, n) = (s as usize, ns as usize);
                let Some(block) = self.mem.get(base..base + 6 * n) else { return -2 };
                let mask = &self.mask;
                for (k, st) in block.as_chunks::<6>().0.iter().enumerate() {
                    if mask[st[0] as usize] {
                        hi += st[1] as u32;
                        ps.push(s + 6 * k as u32);
                        if ps.len() as i64 == want {
                            break;
                        }
                    }
                }
            }
            if ps.len() as i64 != want {
                return -2;
            }
            let (see, mut freq_sum) = self.make_esc_freq(num_masked);
            freq_sum += hi;
            let Some(count) = rc.threshold(freq_sum) else { return -2 };
            if count < hi {
                let mut acc = 0u32;
                let mut chosen = ps[0];
                for &p in ps.iter() {
                    chosen = p;
                    acc += self.r8(p + 1);
                    if acc > count {
                        break;
                    }
                }
                let f = self.r8(chosen + 1);
                rc.decode(acc - f, f);
                if let SeeRef::At(r, c) = see {
                    let e = &mut self.see[r][c];
                    if e.shift < PERIOD_BITS {
                        e.count = e.count.wrapping_sub(1);
                        if e.count == 0 {
                            e.summ = (e.summ << 1) & 0xFFFF;
                            e.count = 3 << e.shift;
                            e.shift += 1;
                        }
                    }
                } else {
                    let e = &mut self.dummy_see;
                    if e.shift < PERIOD_BITS {
                        e.count = e.count.wrapping_sub(1);
                        if e.count == 0 {
                            e.summ = (e.summ << 1) & 0xFFFF;
                            e.count = 3 << e.shift;
                            e.shift += 1;
                        }
                    }
                }
                self.found = chosen;
                let sym = self.r8(chosen) as i32;
                self.update2();
                return sym;
            }
            if count >= freq_sum {
                return -2;
            }
            rc.decode(hi, freq_sum - hi);
            match see {
                SeeRef::At(r, c) => {
                    let e = &mut self.see[r][c];
                    e.summ = (e.summ + freq_sum) & 0xFFFF;
                }
                SeeRef::Dummy => {
                    self.dummy_see.summ = (self.dummy_see.summ + freq_sum) & 0xFFFF;
                }
            }
            for &p in ps.iter() {
                let sym = self.r8(p) as usize & 0xFF;
                self.mask[sym] = false;
            }
        }
    }
}
