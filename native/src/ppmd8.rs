//! PPMd variant I, revision 1 (ZIP method 98): a port of packport's ppmd8.py (itself written from
//! Igor Pavlov's public-domain Ppmd8), with RAR's carry-less range decoder, fed a piece at a time
//! like the other streaming decoders (feed, finish, read, eof). The model lives in one block of
//! memory laid out as ppmd8.py lays it out. As in ppmd7.rs, reads outside it give 0 and writes
//! that don't fit their field are dropped, both marking the model damaged (ppmd8.py would raise
//! there), and every loop that damaged links could keep going is bounded by the memory's size.
//! Lists ppmd8.py indexes with a computed number are indexed as Python does (-1: the last).

use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

use crate::ppmd7::{
    tables, Input, Range, Tables, BIN_SCALE, BOT, EXP_ESCAPE, INIT_BIN_ESC, MAX_FREQ, NUM_INDEXES, PERIOD_BITS, TOP,
    UNIT_SIZE,
};
use crate::{raise, Damage, Res};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;

const EMPTY: u32 = 0xFFFF_FFFF;
const RESTART: u32 = 0;
const M32: i64 = 0xFFFF_FFFF;
const MARGIN: usize = 4096; // more input than one symbol can take, escapes and all

/// Python's list indexing: i from the end when negative; None where Python raises IndexError.
#[inline]
fn pyidx(i: i64, len: usize) -> Option<usize> {
    let n = len as i64;
    let j = if i < 0 { i + n } else { i };
    if (0..n).contains(&j) {
        Some(j as usize)
    } else {
        None
    }
}

#[inline]
fn hi_flag(sym: u32) -> u32 {
    if sym >= 0x40 {
        0x08
    } else {
        0
    }
}

/// RAR's range decoder (ppmd.py's RangeRar) over the bytes fed so far, 0 past them. 32-bit
/// arithmetic that wraps, as 7-Zip's Ppmd8 decoder has it (ppmd.py masks to 32 bits instead).
struct ZipCoder {
    inp: Input,
    low: u32,
    code: u32,
    range: u32,
}

impl ZipCoder {
    fn new(mut inp: Input) -> ZipCoder {
        let mut code = 0u32;
        for _ in 0..4 {
            code = (code << 8) | inp.byte() as u32;
        }
        ZipCoder { inp, low: 0, code, range: M32 as u32 }
    }

    #[inline]
    fn normalize(&mut self) {
        const TOP32: u32 = TOP as u32;
        const BOT32: u32 = BOT as u32;
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= TOP32 {
                if self.range >= BOT32 {
                    return;
                }
                self.range = self.low.wrapping_neg() & (BOT32 - 1);
            }
            self.code = (self.code << 8) | self.inp.byte() as u32;
            self.range <<= 8;
            self.low <<= 8;
            if self.range == 0 && self.low == 0 {
                self.range = 1; // damaged: never loop for ever
            }
        }
    }
}

impl Range for ZipCoder {
    #[inline]
    fn threshold(&mut self, total: u32) -> Option<u32> {
        if total == 0 {
            return None;
        }
        self.range /= total;
        if self.range == 0 {
            return None;
        }
        Some(self.code.wrapping_sub(self.low) / self.range)
    }

    #[inline]
    fn decode(&mut self, start: u32, size: u32) {
        self.low = self.low.wrapping_add(start.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(size);
        self.normalize();
    }

    fn bit(&mut self, size0: u32, total: u32) -> u32 {
        match self.threshold(total) {
            Some(t) if t < size0 => {
                self.decode(0, size0);
                0
            }
            _ => {
                self.decode(size0, total.wrapping_sub(size0));
                1
            }
        }
    }
}

#[derive(Clone, Copy)]
struct See {
    summ: u32,
    shift: u32,
    count: u32,
}

#[derive(Clone, Copy)]
enum SeeRef {
    Dummy,
    At(usize, usize),
}

pub struct Model8 {
    mem: Vec<u8>,
    size: u32,
    align: u32,
    free: [u32; NUM_INDEXES],
    stamps: [i64; NUM_INDEXES],
    see: Vec<[See; 32]>,
    dummy_see: See,
    bin_summ: Vec<[u32; 64]>,
    init_esc: u32,
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
    restore: u32,
    bad: AtomicBool,
    t: Tables,
    ns2indx8: [u32; 260],
    ps: Vec<u32>, // scratch for decode_symbol's escapes
    cs: Vec<u32>, // scratch for create_successors (its own: it runs inside the escapes)
    mask: [bool; 256],
}

impl Model8 {
    /// A model of size bytes; Err(message) for sizes ppmd8.py refuses.
    pub fn new(size: u64, max_order: u32, restore: u32) -> Result<Model8, &'static str> {
        if !((1 << 11)..=0xFFFF_FFFF - 12 * 3).contains(&size) {
            return Err("The archive is damaged (a PPMd memory size out of range)");
        }
        let size = size as u32;
        let align = 4 - (size & 3);
        let mut ns2indx8 = [0u32; 260];
        let (mut m, mut k) = (5u32, 1u32);
        for (i, v) in ns2indx8.iter_mut().enumerate() {
            if i < 5 {
                *v = i as u32;
                continue;
            }
            *v = m;
            k -= 1;
            if k == 0 {
                m += 1;
                k = m - 4;
            }
        }
        let mut model = Model8 {
            mem: vec![0; (align + size + UNIT_SIZE * 2) as usize],
            size,
            align,
            free: [0; NUM_INDEXES],
            stamps: [0; NUM_INDEXES],
            see: vec![[See { summ: 0, shift: 0, count: 0 }; 32]; 24],
            dummy_see: See { summ: 0, shift: PERIOD_BITS, count: 64 },
            bin_summ: vec![[0; 64]; 25],
            init_esc: 0,
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
            max_order,
            restore,
            bad: AtomicBool::new(false),
            t: tables(),
            ns2indx8,
            ps: Vec::with_capacity(256),
            cs: Vec::with_capacity(64),
            mask: [true; 256],
        };
        model.restart();
        Ok(model)
    }

    // -- memory: bytes, 16-bit fields, and 32-bit references made of two of them

    #[inline(always)]
    fn flag(&self) {
        self.bad.store(true, Relaxed);
    }

    #[inline(always)]
    fn is_bad(&self) -> bool {
        self.bad.load(Relaxed)
    }

    /// Counts a step of a loop that damaged links could keep going: true once it's gone on longer
    /// than any real model can (or the model is damaged), to stop.
    #[inline]
    fn stuck(&self, n: &mut u64) -> bool {
        *n += 1;
        if *n > self.mem.len() as u64 {
            self.flag();
        }
        self.is_bad()
    }

    #[inline(always)]
    fn r8(&self, a: u32) -> u32 {
        match self.mem.get(a as usize) {
            Some(&v) => v as u32,
            None => {
                self.flag();
                0
            }
        }
    }

    #[inline]
    fn w8(&mut self, a: u32, v: i64) {
        if !(0..=255).contains(&v) {
            self.flag();
            return;
        }
        match self.mem.get_mut(a as usize) {
            Some(slot) => *slot = v as u8,
            None => self.flag(),
        }
    }

    #[inline(always)]
    fn r16(&self, a: u32) -> u32 {
        let i = (a & !1) as usize;
        match self.mem.get(i..i + 2) {
            Some(b) => u16::from_le_bytes([b[0], b[1]]) as u32,
            None => {
                self.flag();
                0
            }
        }
    }

    #[inline]
    fn w16(&mut self, a: u32, v: i64) {
        if !(0..=0xFFFF).contains(&v) {
            self.flag();
            return;
        }
        let i = (a & !1) as usize;
        match self.mem.get_mut(i..i + 2) {
            Some(b) => b.copy_from_slice(&(v as u16).to_le_bytes()),
            None => self.flag(),
        }
    }

    #[inline(always)]
    fn g32(&self, a: u32) -> u32 {
        let i = (a & !1) as usize;
        match self.mem.get(i..i + 4) {
            Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            None => {
                self.flag();
                0
            }
        }
    }

    #[inline]
    fn s32(&mut self, a: u32, v: i64) {
        if !(0..=M32).contains(&v) {
            self.flag();
            return;
        }
        self.w16(a, v & 0xFFFF);
        self.w16((a & !1).saturating_add(2), v >> 16);
    }

    #[inline(always)]
    fn summ(&self, c: u32) -> u32 {
        self.r16(c.saturating_add(2))
    }

    #[inline]
    fn set_summ(&mut self, c: u32, v: i64) {
        self.w16(c.saturating_add(2), v & 0xFFFF);
    }

    fn copy_units(&mut self, dst: u32, src: u32, nu: i64) {
        if nu < 0 {
            self.flag();
            return;
        }
        let n = nu as usize * UNIT_SIZE as usize;
        let (d, s) = (dst as usize, src as usize);
        if d + n > self.mem.len() || s + n > self.mem.len() {
            self.flag();
            return;
        }
        self.mem.copy_within(s..s + n, d);
    }

    fn get6(&self, a: u32) -> [u8; 6] {
        let i = a as usize;
        match self.mem.get(i..i + 6) {
            Some(b) => [b[0], b[1], b[2], b[3], b[4], b[5]],
            None => {
                self.flag();
                [0; 6]
            }
        }
    }

    fn put6(&mut self, a: u32, v: [u8; 6]) {
        let i = a as usize;
        match self.mem.get_mut(i..i + 6) {
            Some(b) => b.copy_from_slice(&v),
            None => self.flag(),
        }
    }

    fn copy6(&mut self, dst: u32, src: u32) {
        let v = self.get6(src);
        self.put6(dst, v);
    }

    fn swap(&mut self, a: u32, b: u32) {
        let x = self.get6(a);
        let y = self.get6(b);
        self.put6(a, y);
        self.put6(b, x);
    }

    /// The first state at or after s (stepping 6 bytes) whose symbol is sym.
    fn seek(&self, mut s: u32, sym: u32) -> u32 {
        loop {
            match self.mem.get(s as usize) {
                Some(&b) if b as u32 == sym => return s,
                Some(_) => s = s.saturating_add(6),
                None => {
                    self.flag();
                    return s;
                }
            }
        }
    }

    // -- allocator (units of 12 bytes)

    #[inline]
    fn i2u(&self, i: i64) -> u32 {
        match pyidx(i, NUM_INDEXES) {
            Some(j) => self.t.indx2units[j],
            None => {
                self.flag();
                0
            }
        }
    }

    #[inline]
    fn u2i(&self, nu: i64) -> usize {
        match pyidx(nu - 1, 128) {
            Some(j) => self.t.units2indx[j] as usize,
            None => {
                self.flag();
                0
            }
        }
    }

    fn insert(&mut self, node: u32, indx: i64) {
        let Some(i) = pyidx(indx, NUM_INDEXES) else {
            self.flag();
            return;
        };
        self.s32(node, EMPTY as i64);
        self.s32(node.saturating_add(4), self.free[i] as i64);
        self.s32(node.saturating_add(8), self.t.indx2units[i] as i64);
        self.free[i] = node;
        self.stamps[i] += 1;
    }

    fn remove(&mut self, indx: usize) -> u32 {
        let node = self.free[indx];
        self.free[indx] = self.g32(node.saturating_add(4));
        self.stamps[indx] -= 1;
        node
    }

    fn split(&mut self, ptr: u32, old: usize, new: usize) {
        let nu = self.t.indx2units[old] as i64 - self.t.indx2units[new] as i64;
        let ptr = ptr.saturating_add(UNIT_SIZE * self.t.indx2units[new]);
        let mut i = self.u2i(nu) as i64;
        if self.i2u(i) as i64 != nu {
            i -= 1;
            let k = self.i2u(i);
            self.insert(ptr.saturating_add(UNIT_SIZE.saturating_mul(k)), nu - k as i64 - 1);
        }
        self.insert(ptr, i);
    }

    fn glue(&mut self) {
        self.glue_count = 1 << 13;
        self.stamps = [0; NUM_INDEXES];
        if self.lo_unit != self.hi_unit {
            self.s32(self.lo_unit, 0);
        }
        let mut n = 0u64;
        let mut head = 0u32;
        let mut prev: Option<u32> = None; // where the last kept block's "next" lives (None: head)
        for i in 0..NUM_INDEXES {
            let mut nxt = self.free[i];
            self.free[i] = 0;
            while nxt != 0 {
                let node = nxt;
                if self.g32(node.saturating_add(8)) != 0 {
                    match prev {
                        None => head = nxt,
                        Some(p) => self.s32(p, nxt as i64),
                    }
                    prev = Some(node.saturating_add(4));
                    loop {
                        let node2 = node.saturating_add(UNIT_SIZE.saturating_mul(self.g32(node.saturating_add(8))));
                        if self.g32(node2) != EMPTY {
                            break;
                        }
                        let v = self.g32(node.saturating_add(8)) as i64 + self.g32(node2.saturating_add(8)) as i64;
                        self.s32(node.saturating_add(8), v);
                        self.s32(node2.saturating_add(8), 0);
                        if self.stuck(&mut n) {
                            return;
                        }
                    }
                }
                nxt = self.g32(node.saturating_add(4));
                if self.stuck(&mut n) {
                    return;
                }
            }
        }
        match prev {
            None => head = 0,
            Some(p) => self.s32(p, 0),
        }
        while head != 0 {
            let mut node = head;
            head = self.g32(node.saturating_add(4));
            let mut nu = self.g32(node.saturating_add(8)) as i64;
            if self.stuck(&mut n) {
                return;
            }
            if nu == 0 {
                continue;
            }
            while nu > 128 {
                self.insert(node, NUM_INDEXES as i64 - 1);
                nu -= 128;
                node = node.saturating_add(UNIT_SIZE * 128);
            }
            let mut i = self.u2i(nu) as i64;
            if self.i2u(i) as i64 != nu {
                i -= 1;
                let k = self.i2u(i);
                self.insert(node.saturating_add(UNIT_SIZE.saturating_mul(k)), nu - k as i64 - 1);
            }
            self.insert(node, i);
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
                let num = UNIT_SIZE * self.t.indx2units[indx];
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
        let ret = self.remove(i);
        self.split(ret, i, indx);
        ret
    }

    fn alloc(&mut self, indx: usize) -> u32 {
        if indx >= NUM_INDEXES {
            self.flag();
            return 0;
        }
        if self.free[indx] != 0 {
            return self.remove(indx);
        }
        let num = UNIT_SIZE * self.t.indx2units[indx];
        if num as i64 <= self.hi_unit as i64 - self.lo_unit as i64 {
            let ret = self.lo_unit;
            self.lo_unit += num;
            return ret;
        }
        self.alloc_rare(indx)
    }

    fn shrink(&mut self, old: u32, old_nu: i64, new_nu: i64) -> u32 {
        let (i0, i1) = (self.u2i(old_nu), self.u2i(new_nu));
        if i0 == i1 {
            return old;
        }
        if self.free[i1] != 0 {
            let ptr = self.remove(i1);
            self.copy_units(ptr, old, new_nu);
            self.insert(old, i0 as i64);
            return ptr;
        }
        self.split(old, i0, i1);
        old
    }

    fn free_units(&mut self, ptr: u32, nu: i64) {
        let i = self.u2i(nu);
        self.insert(ptr, i as i64);
    }

    fn special_free(&mut self, ptr: u32) {
        if ptr != self.units_start {
            self.insert(ptr, 0);
        } else {
            self.units_start = self.units_start.saturating_add(UNIT_SIZE);
        }
    }

    fn move_up(&mut self, old: u32, nu: i64) -> u32 {
        let indx = self.u2i(nu);
        if old as u64 > self.units_start as u64 + 16 * 1024 || old > self.free[indx] {
            return old;
        }
        let ptr = self.remove(indx);
        self.copy_units(ptr, old, nu);
        if old != self.units_start {
            self.insert(old, indx as i64);
        } else {
            self.units_start = self.units_start.saturating_add(UNIT_SIZE * self.t.indx2units[indx]);
        }
        ptr
    }

    fn expand_text(&mut self) {
        let mut count = [0i64; NUM_INDEXES];
        let mut n = 0u64;
        if self.lo_unit != self.hi_unit {
            self.s32(self.lo_unit, 0);
        }
        let mut node = self.units_start;
        while self.g32(node) == EMPTY {
            self.s32(node, 0);
            let nu = self.g32(node.saturating_add(8));
            count[self.u2i(nu as i64)] += 1;
            node = node.saturating_add(UNIT_SIZE.saturating_mul(nu));
            if self.stuck(&mut n) {
                return;
            }
        }
        self.units_start = node;
        for (i, left) in count.iter_mut().enumerate() {
            let mut at: Option<u32> = None; // the free-list head, or the "next" field of the block before
            while *left != 0 {
                let mut node = match at {
                    None => self.free[i],
                    Some(w) => self.g32(w),
                };
                while self.g32(node) == 0 {
                    let nxt = self.g32(node.saturating_add(4));
                    match at {
                        None => self.free[i] = nxt,
                        Some(w) => self.s32(w, nxt as i64),
                    }
                    node = nxt;
                    self.stamps[i] -= 1;
                    *left -= 1;
                    if *left == 0 || self.stuck(&mut n) {
                        break;
                    }
                }
                at = Some(node.saturating_add(4));
                if self.stuck(&mut n) {
                    return;
                }
            }
        }
    }

    fn used(&self) -> i64 {
        let v: i64 = (0..NUM_INDEXES).map(|i| self.stamps[i] * self.t.indx2units[i] as i64).sum();
        (self.size as i64
            - (self.hi_unit as i64 - self.lo_unit as i64)
            - (self.units_start as i64 - self.text as i64)
            - UNIT_SIZE as i64 * v)
            & M32
    }

    // -- the model

    fn restart(&mut self) {
        self.free = [0; NUM_INDEXES];
        self.stamps = [0; NUM_INDEXES];
        self.text = self.align;
        self.hi_unit = self.text + self.size;
        self.lo_unit = self.hi_unit - self.size / 8 / UNIT_SIZE * 7 * UNIT_SIZE;
        self.units_start = self.lo_unit;
        self.glue_count = 0;
        self.order_fall = self.max_order as i64;
        self.init_rl = -(self.max_order.min(12) as i64) - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;
        self.hi_unit -= UNIT_SIZE;
        let c = self.hi_unit;
        self.min_context = c;
        self.max_context = c;
        self.s32(c + 8, 0);
        self.w8(c, 255);
        self.w8(c + 1, 0);
        self.set_summ(c, 257);
        self.found = self.lo_unit;
        self.lo_unit += UNIT_SIZE * 128;
        self.s32(c + 4, self.found as i64);
        for i in 0..256u32 {
            let s = self.found + 6 * i;
            self.w8(s, i as i64);
            self.w8(s + 1, 1);
            self.s32(s + 2, 0);
        }
        let mut i = 0usize;
        for m in 0..25usize {
            while self.ns2indx8[i] as usize == m {
                i += 1;
            }
            for (k, &esc) in INIT_BIN_ESC.iter().enumerate() {
                let val = BIN_SCALE - esc / (i as u32 + 1);
                for r in (0..64).step_by(8) {
                    self.bin_summ[m][k + r] = val;
                }
            }
        }
        let mut i = 0usize;
        for m in 0..24usize {
            while self.ns2indx8[i + 3] as usize == m + 3 {
                i += 1;
            }
            let shift = PERIOD_BITS - 4;
            for k in 0..32 {
                self.see[m][k] = See { summ: ((2 * i as u32 + 5) << shift) & 0xFFFF, shift, count: 7 };
            }
        }
    }

    fn refresh(&mut self, c: u32, old_nu: i64, scale: u32) {
        let i = self.r8(c);
        let mut s = self.shrink(self.g32(c + 4), old_nu, (i as i64 + 2) >> 1);
        self.s32(c + 4, s as i64);
        let mut flags = (self.r8(c + 1) & (0x10 + 0x04 * scale)) + hi_flag(self.r8(s));
        let mut esc = self.summ(c) as i64 - self.r8(s + 1) as i64;
        let f = (self.r8(s + 1) + scale) >> scale;
        self.w8(s + 1, f as i64);
        let mut total = f as i64;
        for _ in 0..i {
            s = s.saturating_add(6);
            esc -= self.r8(s + 1) as i64;
            let f = (self.r8(s + 1) + scale) >> scale;
            self.w8(s + 1, f as i64);
            total += f as i64;
            flags |= hi_flag(self.r8(s));
        }
        self.set_summ(c, total + (((esc & M32) + scale as i64) >> scale));
        self.w8(c + 1, (flags & 0xFF) as i64);
    }

    fn cut_off(&mut self, c: u32, order: u32, work: &mut u64) -> u32 {
        if self.stuck(work) {
            return 0;
        }
        if self.r8(c) == 0 {
            let s = c + 2;
            if self.g32(s + 2) >= self.units_start {
                let v = if order < self.max_order { self.cut_off(self.g32(s + 2), order + 1, work) } else { 0 };
                self.s32(s + 2, v as i64);
                if self.g32(s + 2) != 0 || order <= 9 {
                    return c;
                }
            }
            self.special_free(c);
            return 0;
        }
        let tmp = (self.r8(c) as i64 + 2) >> 1;
        let v = self.move_up(self.g32(c + 4), tmp);
        self.s32(c + 4, v as i64);
        let stats = self.g32(c + 4) as i64;
        let mut i = self.r8(c) as i64;
        let mut s = stats + 6 * i;
        while s >= stats {
            let su = s as u32;
            if self.g32(su + 2) < self.units_start {
                let s2 = (stats + 6 * i) as u32;
                i -= 1;
                self.s32(su + 2, 0);
                self.swap(su, s2);
            } else if order < self.max_order {
                let v = self.cut_off(self.g32(su + 2), order + 1, work);
                self.s32(su + 2, v as i64);
            } else {
                self.s32(su + 2, 0);
            }
            if self.is_bad() {
                return 0;
            }
            s -= 6;
        }
        if i != self.r8(c) as i64 && order != 0 {
            self.w8(c, i & 0xFF);
            let s = stats as u32;
            if i < 0 {
                self.free_units(s, tmp);
                self.special_free(c);
                return 0;
            }
            if i == 0 {
                let flags = (self.r8(c + 1) & 0x10) + hi_flag(self.r8(s));
                self.w8(c + 1, flags as i64);
                self.copy6(c + 2, s);
                self.free_units(s, tmp);
                let f = (self.r8(c + 3) + 11) >> 3;
                self.w8(c + 3, f as i64);
            } else {
                let scale = (self.summ(c) as i64 > 16 * i) as u32;
                self.refresh(c, tmp, scale);
            }
        }
        c
    }

    fn restore_model(&mut self, c1: u32) {
        let mut n = 0u64;
        self.text = self.align;
        let mut c = self.max_context;
        while c != c1 {
            let ns = (self.r8(c) as i64 - 1) & 0xFF;
            self.w8(c, ns);
            if ns == 0 {
                let s = self.g32(c + 4);
                let flags = (self.r8(c + 1) & 0x10) + hi_flag(self.r8(s));
                self.w8(c + 1, flags as i64);
                self.copy6(c + 2, s);
                self.special_free(s);
                let f = (self.r8(c + 3) + 11) >> 3;
                self.w8(c + 3, f as i64);
            } else {
                self.refresh(c, (ns + 3) >> 1, 0);
            }
            c = self.g32(c + 8);
            if self.stuck(&mut n) {
                return;
            }
        }
        while c != self.min_context {
            if self.r8(c) == 0 {
                let f = self.r8(c + 3);
                self.w8(c + 3, (f - (f >> 1)) as i64);
            } else {
                let v = (self.summ(c) + 4) & 0xFFFF;
                self.set_summ(c, v as i64);
                if v > 128 + 4 * self.r8(c) {
                    let nu = (self.r8(c) as i64 + 2) >> 1;
                    self.refresh(c, nu, 1);
                }
            }
            c = self.g32(c + 8);
            if self.stuck(&mut n) {
                return;
            }
        }
        if self.restore == RESTART || self.used() < (self.size >> 1) as i64 {
            self.restart();
            return;
        }
        while self.g32(self.max_context + 8) != 0 {
            self.max_context = self.g32(self.max_context + 8);
            if self.stuck(&mut n) {
                return;
            }
        }
        loop {
            let mut work = 0u64;
            self.cut_off(self.max_context, 0, &mut work);
            self.expand_text();
            if self.used() <= 3 * (self.size >> 2) as i64 || self.stuck(&mut n) {
                break;
            }
        }
        self.glue_count = 0;
        self.order_fall = self.max_order as i64;
    }

    fn create_successors(&mut self, skip: bool, mut s1: u32, mut c: u32) -> u32 {
        let fs = self.found;
        let up_branch = self.g32(fs + 2);
        let fsym = self.r8(fs);
        let mut ps = std::mem::take(&mut self.cs);
        ps.clear();
        if !skip {
            ps.push(fs);
        }
        let r = self.successors(&mut ps, up_branch, fsym, &mut s1, &mut c);
        self.cs = ps;
        r
    }

    fn successors(&mut self, ps: &mut Vec<u32>, up_branch: u32, fsym: u32, s1: &mut u32, c: &mut u32) -> u32 {
        let mut n = 0u64;
        while self.g32(*c + 8) != 0 {
            *c = self.g32(*c + 8);
            let s;
            if *s1 != 0 {
                s = *s1;
                *s1 = 0;
            } else if self.r8(*c) != 0 {
                s = self.seek(self.g32(*c + 4), fsym);
                if self.is_bad() {
                    return 0;
                }
                if self.r8(s + 1) < MAX_FREQ - 9 {
                    let f = self.r8(s + 1) + 1;
                    self.w8(s + 1, f as i64);
                    let v = self.summ(*c) as i64 + 1;
                    self.set_summ(*c, v);
                }
            } else {
                s = *c + 2;
                let suffix = self.g32(*c + 8);
                let inc = (self.r8(suffix) == 0 && self.r8(s + 1) < 24) as u32;
                let f = self.r8(s + 1) + inc;
                self.w8(s + 1, f as i64);
            }
            let succ = self.g32(s + 2);
            if succ != up_branch {
                *c = succ;
                if ps.is_empty() {
                    return *c;
                }
                break;
            }
            ps.push(s);
            if self.stuck(&mut n) {
                return 0;
            }
        }
        let up_sym = self.r8(up_branch);
        let flags = if fsym >= 0x40 { 0x10 } else { 0 } + hi_flag(up_sym);
        let up_freq: i64;
        if self.r8(*c) == 0 {
            up_freq = self.r8(*c + 3) as i64;
        } else {
            let s = self.seek(self.g32(*c + 4), up_sym);
            if self.is_bad() {
                return 0;
            }
            let cf = self.r8(s + 1) as i64 - 1;
            let s0 = (self.summ(*c) as i64 - self.r8(*c) as i64 - cf) & M32;
            if 2 * cf <= s0 {
                up_freq = 1 + (5 * cf > s0) as i64;
            } else {
                if s0 == 0 {
                    self.flag();
                    return 0;
                }
                up_freq = (1 + ((cf + 2 * s0 - 3) & M32) / s0) & 0xFF;
            }
        }
        while let Some(&last) = ps.last() {
            let c1;
            if self.hi_unit != self.lo_unit {
                self.hi_unit -= UNIT_SIZE;
                c1 = self.hi_unit;
            } else if self.free[0] != 0 {
                c1 = self.remove(0);
            } else {
                c1 = self.alloc_rare(0);
                if c1 == 0 {
                    return 0;
                }
            }
            self.w8(c1, 0);
            self.w8(c1 + 1, flags as i64);
            self.w8(c1 + 2, up_sym as i64);
            self.w8(c1 + 3, up_freq);
            self.s32(c1 + 4, up_branch as i64 + 1);
            self.s32(c1 + 8, *c as i64);
            ps.pop();
            self.s32(last + 2, c1 as i64);
            *c = c1;
            if self.is_bad() {
                return 0;
            }
        }
        *c
    }

    fn reduce_order(&mut self, mut s1: u32, mut c: u32) -> u32 {
        let mut n = 0u64;
        let c1 = c;
        let up_branch = self.text;
        let fsym = self.r8(self.found);
        self.s32(self.found + 2, up_branch as i64);
        self.order_fall += 1;
        let mut s;
        loop {
            if s1 != 0 {
                c = self.g32(c + 8);
                s = s1;
                s1 = 0;
            } else {
                if self.g32(c + 8) == 0 {
                    return c;
                }
                c = self.g32(c + 8);
                if self.r8(c) != 0 {
                    s = self.seek(self.g32(c + 4), fsym);
                    if self.is_bad() {
                        return 0;
                    }
                    if self.r8(s + 1) < MAX_FREQ - 9 {
                        let f = self.r8(s + 1) + 2;
                        self.w8(s + 1, f as i64);
                        let v = self.summ(c) as i64 + 2;
                        self.set_summ(c, v);
                    }
                } else {
                    s = c + 2;
                    let f = self.r8(s + 1);
                    self.w8(s + 1, (f + (f < 32) as u32) as i64);
                }
            }
            if self.g32(s + 2) != 0 {
                break;
            }
            self.s32(s + 2, up_branch as i64);
            self.order_fall += 1;
            if self.stuck(&mut n) {
                return 0;
            }
        }
        if self.g32(s + 2) <= up_branch {
            let s2 = self.found;
            self.found = s;
            let v = self.create_successors(false, 0, c);
            self.s32(s + 2, v as i64);
            self.found = s2;
        }
        if self.order_fall == 1 && c1 == self.max_context {
            let v = self.g32(s + 2);
            self.s32(self.found + 2, v as i64);
            self.text = self.text.wrapping_sub(1);
        }
        self.g32(s + 2)
    }

    fn update_model(&mut self) {
        let fs = self.found;
        let mut f_succ = self.g32(fs + 2);
        let ffreq = self.r8(fs + 1);
        let fsym = self.r8(fs);
        let mut s = 0u32;
        let minc = self.min_context;
        if ffreq < MAX_FREQ / 4 && self.g32(minc + 8) != 0 {
            let c = self.g32(minc + 8);
            if self.r8(c) == 0 {
                s = c + 2;
                if self.r8(s + 1) < 32 {
                    let f = self.r8(s + 1) + 1;
                    self.w8(s + 1, f as i64);
                }
            } else {
                s = self.g32(c + 4);
                if self.r8(s) != fsym {
                    s = self.seek(s.saturating_add(6), fsym);
                    if self.is_bad() {
                        return;
                    }
                    if self.r8(s + 1) >= self.r8(s.wrapping_sub(5)) {
                        self.swap(s, s.wrapping_sub(6));
                        s = s.wrapping_sub(6);
                    }
                }
                if self.r8(s + 1) < MAX_FREQ - 9 {
                    let f = self.r8(s + 1) + 2;
                    self.w8(s + 1, f as i64);
                    let v = self.summ(c) as i64 + 2;
                    self.set_summ(c, v);
                }
            }
        }
        let mut c = self.max_context;
        if self.order_fall == 0 && f_succ != 0 {
            let cs = self.create_successors(true, s, minc);
            if cs == 0 {
                self.s32(fs + 2, 0);
                self.restore_model(c);
            } else {
                self.s32(fs + 2, cs as i64);
                self.max_context = cs;
            }
            return;
        }
        self.w8(self.text, fsym as i64);
        self.text = self.text.saturating_add(1);
        let mut successor = self.text;
        if self.text >= self.units_start {
            self.restore_model(c);
            return;
        }
        if f_succ == 0 {
            let cs = self.reduce_order(s, minc);
            if cs == 0 {
                self.restore_model(c);
                return;
            }
            f_succ = cs;
        } else if f_succ < self.units_start {
            let cs = self.create_successors(false, s, minc);
            if cs == 0 {
                self.restore_model(c);
                return;
            }
            f_succ = cs;
        }
        self.order_fall -= 1;
        if self.order_fall == 0 {
            successor = f_succ;
            self.text = self.text.wrapping_sub((self.max_context != minc) as u32);
        }
        let ns = self.r8(minc) as i64;
        let s0 = (self.summ(minc) as i64 - ns - ffreq as i64) & M32;
        let flag = hi_flag(fsym);
        let mut n = 0u64;
        while c != minc {
            let ns1 = self.r8(c) as i64;
            if ns1 != 0 {
                if ns1 & 1 != 0 {
                    let old_nu = (ns1 + 1) >> 1;
                    let i = self.u2i(old_nu);
                    if i != self.u2i(old_nu + 1) {
                        let ptr = self.alloc(i + 1);
                        if ptr == 0 {
                            self.restore_model(c);
                            return;
                        }
                        let old = self.g32(c + 4);
                        self.copy_units(ptr, old, old_nu);
                        self.insert(old, i as i64);
                        self.s32(c + 4, ptr as i64);
                    }
                }
                let v = self.summ(c) as i64 + (3 * ns1 + 1 < ns) as i64;
                self.set_summ(c, v);
            } else {
                let s2 = self.alloc(0);
                if s2 == 0 {
                    self.restore_model(c);
                    return;
                }
                self.copy6(s2, c + 2);
                self.s32(c + 4, s2 as i64);
                let f = self.r8(s2 + 1);
                self.w8(s2 + 1, if f < MAX_FREQ / 4 - 1 { (f << 1) as i64 } else { (MAX_FREQ - 4) as i64 });
                let v = self.r8(s2 + 1) as i64 + self.init_esc as i64 + (ns > 2) as i64;
                self.set_summ(c, v);
            }
            let summ = self.summ(c) as i64;
            let mut cf = 2 * ffreq as i64 * (summ + 6);
            let sf = (s0 + summ) & M32;
            if cf < (6 * sf) & M32 {
                cf = 1 + (cf > sf) as i64 + (cf >= (4 * sf) & M32) as i64;
                self.set_summ(c, summ + 4);
            } else {
                cf = 4
                    + (cf > (9 * sf) & M32) as i64
                    + (cf > (12 * sf) & M32) as i64
                    + (cf > (15 * sf) & M32) as i64;
                self.set_summ(c, summ + cf);
            }
            let s2 = self.g32(c + 4).saturating_add(6 * (ns1 as u32 + 1));
            self.s32(s2.saturating_add(2), successor as i64);
            self.w8(s2, fsym as i64);
            self.w8(s2.saturating_add(1), cf);
            let fl = self.r8(c + 1) | flag;
            self.w8(c + 1, fl as i64);
            self.w8(c, ns1 + 1);
            c = self.g32(c + 8);
            if self.stuck(&mut n) {
                return;
            }
        }
        self.max_context = f_succ;
        self.min_context = f_succ;
    }

    fn rescale(&mut self) {
        let mc = self.min_context;
        let stats = self.g32(mc + 4);
        let mut s = self.found;
        if s < stats || !(s - stats).is_multiple_of(6) {
            self.flag(); // the found state isn't one of this context's
            return;
        }
        let tmp = self.get6(s);
        while s != stats {
            self.copy6(s, s - 6);
            s -= 6;
        }
        self.put6(s, tmp);
        let mut esc = self.summ(mc) as i64 - self.r8(s + 1) as i64;
        let adder = (self.order_fall != 0) as u32;
        let f = (((self.r8(s + 1) + 4) & 0xFF) + adder) >> 1;
        self.w8(s + 1, f as i64);
        let mut total = f as i64;
        let count = self.r8(mc);
        for _ in 0..count {
            s = s.saturating_add(6);
            esc -= self.r8(s + 1) as i64;
            let f = (self.r8(s + 1) + adder) >> 1;
            self.w8(s + 1, f as i64);
            total += f as i64;
            if f > self.r8(s - 5) {
                let mut s1 = s;
                let tmp = self.get6(s1);
                loop {
                    self.copy6(s1, s1 - 6);
                    s1 -= 6;
                    if s1 == stats || s1 < 6 || tmp[1] as u32 <= self.r8(s1 - 5) || self.is_bad() {
                        break;
                    }
                }
                self.put6(s1, tmp);
            }
            if self.is_bad() {
                return;
            }
        }
        if self.r8(s + 1) == 0 {
            let num_stats = self.r8(mc) as i64;
            let mut i = 0i64;
            loop {
                i += 1;
                s = s.wrapping_sub(6);
                if self.r8(s.saturating_add(1)) != 0 || self.is_bad() {
                    break;
                }
            }
            esc += i;
            self.w8(mc, num_stats - i);
            if self.r8(mc) == 0 {
                let mut tmp = self.get6(stats);
                let e = esc & M32;
                if e == 0 {
                    self.flag();
                    return;
                }
                tmp[1] = ((((2 * tmp[1] as i64 + e - 1) / e) & 0xFF).min((MAX_FREQ / 3) as i64)) as u8;
                let i = self.u2i((num_stats + 2) >> 1);
                self.insert(stats, i as i64);
                let flags = (self.r8(mc + 1) & 0x10) + hi_flag(tmp[0] as u32);
                self.w8(mc + 1, flags as i64);
                self.found = mc + 2;
                self.put6(mc + 2, tmp);
                return;
            }
            let (n0, n1) = ((num_stats + 2) >> 1, (self.r8(mc) as i64 + 2) >> 1);
            if n0 != n1 {
                let v = self.shrink(stats, n0, n1);
                self.s32(mc + 4, v as i64);
            }
            let fl = self.r8(mc + 1) & 0xF7;
            self.w8(mc + 1, fl as i64);
            let mut s = self.g32(mc + 4);
            let mut flags = self.r8(mc + 1) | hi_flag(self.r8(s));
            for _ in 0..self.r8(mc) {
                s = s.saturating_add(6);
                flags |= hi_flag(self.r8(s));
            }
            self.w8(mc + 1, flags as i64);
        }
        let esc = esc & M32;
        self.set_summ(mc, total + esc - (esc >> 1));
        let fl = self.r8(mc + 1) | 0x04;
        self.w8(mc + 1, fl as i64);
        self.found = self.g32(mc + 4);
    }

    fn make_esc_freq(&mut self, num_masked: u32) -> (SeeRef, u32) {
        let mc = self.min_context;
        let ns = self.r8(mc);
        if ns == 0xFF {
            return (SeeRef::Dummy, 1);
        }
        let Some(row) = pyidx(self.ns2indx8[ns as usize + 2] as i64 - 3, 24) else {
            self.flag();
            return (SeeRef::Dummy, 1);
        };
        let col = (self.summ(mc) > 11 * (ns + 1)) as usize
            + 2 * ((2 * ns < self.r8(self.g32(mc + 8)) + num_masked) as usize)
            + self.r8(mc + 1) as usize;
        if col >= 32 {
            self.flag();
            return (SeeRef::Dummy, 1);
        }
        let see = &mut self.see[row][col];
        let r = see.summ >> see.shift;
        see.summ = (see.summ - r) & 0xFFFF;
        (SeeRef::At(row, col), r + (r == 0) as u32)
    }

    fn next_context(&mut self) {
        let c = self.g32(self.found + 2);
        if self.order_fall == 0 && c >= self.units_start {
            self.min_context = c;
            self.max_context = c;
        } else {
            self.update_model();
            self.min_context = self.max_context;
        }
    }

    fn update1(&mut self) {
        let s = self.found;
        let f = self.r8(s + 1) + 4;
        self.w8(s + 1, f as i64);
        let v = self.summ(self.min_context) as i64 + 4;
        self.set_summ(self.min_context, v);
        if self.r8(s + 1) > self.r8(s.wrapping_sub(5)) {
            self.swap(s, s.wrapping_sub(6));
            self.found = s.wrapping_sub(6);
            if self.r8(s.wrapping_sub(5)) > MAX_FREQ {
                self.rescale();
            }
        }
        self.next_context();
    }

    fn update1_0(&mut self) {
        let mc = self.min_context;
        self.prev_success = (2 * self.r8(self.found + 1) >= self.summ(mc)) as u32;
        self.run_length += self.prev_success as i64;
        let v = self.summ(mc) as i64 + 4;
        self.set_summ(mc, v);
        let f = self.r8(self.found + 1) + 4;
        self.w8(self.found + 1, f as i64);
        if f > MAX_FREQ {
            self.rescale();
        }
        self.next_context();
    }

    fn update_bin(&mut self) {
        let f = self.r8(self.found + 1);
        self.w8(self.found + 1, (f + (f < 196) as u32) as i64);
        self.prev_success = 1;
        self.run_length += 1;
        self.next_context();
    }

    fn update2(&mut self) {
        let mc = self.min_context;
        let v = self.summ(mc) as i64 + 4;
        self.set_summ(mc, v);
        let f = self.r8(self.found + 1) + 4;
        self.w8(self.found + 1, f as i64);
        if f > MAX_FREQ {
            self.rescale();
        }
        self.run_length = self.init_rl;
        self.update_model();
        self.min_context = self.max_context;
    }

    /// The next byte, -1 at the end mark, -2 for damaged data.
    pub fn decode_symbol<R: Range>(&mut self, rc: &mut R) -> i32 {
        let r = self.decode_inner(rc);
        if self.is_bad() {
            return -2;
        }
        r
    }

    fn decode_inner<R: Range>(&mut self, rc: &mut R) -> i32 {
        let mc = self.min_context;
        let ns = self.r8(mc);
        if ns != 0 {
            let s = self.g32(mc + 4);
            let summ = self.summ(mc);
            let Some(count) = rc.threshold(summ) else { return -2 };
            // the context's states, read as one block: (symbol, freq, successor) in 6 bytes each
            let (base, n) = (s as usize, ns as usize + 1);
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
            rc.decode(hi, summ - hi);
            let mut mask = [true; 256]; // true: not masked
            for st in block.as_chunks::<6>().0 {
                mask[st[0] as usize] = false;
            }
            self.mask = mask;
        } else {
            let Some(row) = pyidx(self.r8(mc + 3) as i64 - 1, 260)
                .map(|j| self.ns2indx8[j] as usize)
                .filter(|&r| r < 25)
            else {
                return -2;
            };
            let col = self.t.ns2bsindx[self.r8(self.g32(mc + 8)) as usize] as i64
                + self.prev_success as i64
                + self.r8(mc + 1) as i64
                + ((self.run_length >> 26) & 0x20);
            if !(0..64).contains(&col) {
                return -2;
            }
            let col = col as usize;
            let prob = self.bin_summ[row][col];
            let Some(t) = rc.threshold(BIN_SCALE) else { return -2 };
            if t < prob {
                rc.decode(0, prob);
                self.bin_summ[row][col] = (prob + (1 << 7) - ((prob + 32) >> 7)) & 0xFFFF;
                self.found = mc + 2;
                let sym = self.r8(mc + 2) as i32;
                self.update_bin();
                return sym;
            }
            rc.decode(prob, BIN_SCALE.wrapping_sub(prob));
            let prob = prob.wrapping_sub((prob + 32) >> 7) & 0xFFFF;
            self.bin_summ[row][col] = prob;
            let Some(&esc) = EXP_ESCAPE.get((prob >> 10) as usize) else { return -2 };
            self.init_esc = esc;
            self.mask = [true; 256];
            let sym = self.r8(mc + 2) as usize & 0xFF;
            self.mask[sym] = false;
            self.prev_success = 0;
        }
        let mut ps = std::mem::take(&mut self.ps);
        let r = self.escapes(rc, &mut ps);
        self.ps = ps;
        r
    }

    fn escapes<R: Range>(&mut self, rc: &mut R, ps: &mut Vec<u32>) -> i32 {
        loop {
            let num_masked = self.r8(self.min_context);
            let mut n = 0u64;
            loop {
                self.order_fall += 1;
                let suffix = self.g32(self.min_context + 8);
                if suffix == 0 {
                    return -1;
                }
                self.min_context = suffix;
                if self.r8(suffix) != num_masked {
                    break;
                }
                if self.stuck(&mut n) {
                    return -2;
                }
            }
            let mc = self.min_context;
            let want = self.r8(mc) as i64 - num_masked as i64;
            if want < 0 {
                return -2;
            }
            ps.clear();
            let mut hi = 0u32;
            let mut s = self.g32(mc + 4) as usize;
            while ps.len() as i64 != want {
                let Some(st) = self.mem.get(s..s + 2) else { return -2 };
                if self.mask[st[0] as usize] {
                    hi += st[1] as u32;
                    ps.push(s as u32);
                }
                s += 6;
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
                let e = match see {
                    SeeRef::At(r, c) => &mut self.see[r][c],
                    SeeRef::Dummy => &mut self.dummy_see,
                };
                if e.shift < PERIOD_BITS {
                    e.count = e.count.wrapping_sub(1);
                    if e.count == 0 {
                        e.summ = (e.summ << 1) & 0xFFFF;
                        e.count = 3 << e.shift;
                        e.shift += 1;
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
            let e = match see {
                SeeRef::At(r, c) => &mut self.see[r][c],
                SeeRef::Dummy => &mut self.dummy_see,
            };
            e.summ = (e.summ + freq_sum) & 0xFFFF;
            for &p in ps.iter() {
                let sym = self.r8(p) as usize & 0xFF;
                self.mask[sym] = false;
            }
        }
    }
}

/// ZIP's PPMd (method 98) after its 2-byte header, which packport's Python reads: exactly as
/// many bytes as are asked for; the end mark or anything damaged before then is damage.
#[pyclass(module = "packport_native")]
pub struct Ppmd8Decoder {
    model: Model8,
    rc: Option<ZipCoder>,
    pending: Vec<u8>,
    finished: bool,
}

impl Ppmd8Decoder {
    fn run(&mut self, want: usize) -> Res<Vec<u8>> {
        let mut out = Vec::with_capacity(want.min(1 << 20));
        if self.rc.is_none() {
            if self.pending.len() < 4 && !self.finished {
                return Ok(out);
            }
            self.rc = Some(ZipCoder::new(Input { data: std::mem::take(&mut self.pending), pos: 0 }));
        }
        let rc = self.rc.as_mut().unwrap();
        while out.len() < want {
            if !self.finished && rc.inp.left() < MARGIN {
                break;
            }
            let c = self.model.decode_symbol(rc);
            if c < 0 {
                return Err(Damage::new("the ZIP archive is damaged (bad PPMd data)"));
            }
            out.push(c as u8);
        }
        Ok(out)
    }
}

#[pymethods]
impl Ppmd8Decoder {
    #[new]
    fn new(py: Python<'_>, order: u32, mem: u64, restore: u32) -> PyResult<Self> {
        if !(2..=16).contains(&order) || restore > 1 {
            return Err(crate::damaged(py, "PPMd settings packport doesn't read"));
        }
        let model = Model8::new(mem, order, restore).map_err(|m| crate::damaged(py, m))?;
        Ok(Ppmd8Decoder { model, rc: None, pending: Vec::new(), finished: false })
    }

    fn feed(&mut self, data: PyBackedBytes) {
        match self.rc.as_mut() {
            Some(rc) => {
                rc.inp.compact();
                rc.inp.data.extend_from_slice(&data);
            }
            None => self.pending.extend_from_slice(&data),
        }
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
        false // ZIP gives the size: the stream ends when that much is read
    }

    fn read<'py>(&mut self, py: Python<'py>, max_len: usize) -> PyResult<Bound<'py, PyBytes>> {
        let out = py.detach(|| self.run(max_len)).map_err(|e| raise(py, e))?;
        Ok(PyBytes::new(py, &out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ZIP file's first member, packed with PPMd: (its 2-byte PPMd header, the range-coded data
    /// after it, its size, its CRC-32).
    fn member(zip: &[u8]) -> (u32, &[u8], usize, u32) {
        let u16_at = |i: usize| u16::from_le_bytes([zip[i], zip[i + 1]]) as usize;
        let u32_at = |i: usize| u32::from_le_bytes([zip[i], zip[i + 1], zip[i + 2], zip[i + 3]]);
        assert_eq!(u16_at(8), 98);
        let start = 30 + u16_at(26) + u16_at(28);
        let packed = &zip[start..start + u32_at(18) as usize];
        (packed[0] as u32 | (packed[1] as u32) << 8, &packed[2..], u32_at(22) as usize, u32_at(14))
    }

    /// Up to size bytes decoded from data, stopping at the first symbol that isn't one.
    fn decode(v: u32, data: &[u8], size: usize) -> Vec<u8> {
        let mut model = Model8::new((((v >> 4) & 0xFF) as u64 + 1) << 20, (v & 15) + 1, v >> 12).unwrap();
        let mut rc = ZipCoder::new(Input { data: data.to_vec(), pos: 0 });
        let mut out = Vec::with_capacity(size);
        while out.len() < size {
            let c = model.decode_symbol(&mut rc);
            if c < 0 {
                break;
            }
            out.push(c as u8);
        }
        out
    }

    #[test]
    fn restart_method_member_decodes() {
        let (v, data, size, crc) = member(include_bytes!("../../tests/data/libarchive/test_read_format_zip_ppmd8.zipx"));
        assert_eq!(v >> 12, RESTART);
        let out = decode(v, data, size);
        assert_eq!((out.len(), crc32fast::hash(&out)), (912, crc));
    }

    #[test]
    fn cut_off_method_member_decodes() {
        // order 16 in 1 MB: the model fills up and is cut back many times
        let (v, data, size, crc) = member(include_bytes!("../../tests/data/made/ppmd_cut_off.zip"));
        assert_eq!(v >> 12, 1);
        let out = decode(v, data, size);
        assert_eq!((out.len(), crc32fast::hash(&out)), (233_982, crc));
    }

    #[test]
    fn damaged_data_never_panics() {
        let (v, data, size, crc) = member(include_bytes!("../../tests/data/made/ppmd_cut_off.zip"));
        let mut damaged = 0;
        for at in (0..data.len()).step_by(211) {
            let mut bad = data.to_vec();
            bad[at] ^= 0x5A;
            let out = decode(v, &bad, size);
            damaged += (out.len() < size || crc32fast::hash(&out) != crc) as u32;
        }
        assert!(damaged > 250, "{damaged}"); // nearly every change shows, as a stop or a wrong CRC
    }
}
