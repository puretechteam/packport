//! Canonical Huffman lookup tables, as bits.py builds them: 2^bits entries, each the
//! `symbol << 4 | length` of the code a peek of `bits` bits (most significant first) starts
//! with, or -1. Codes are assigned shortest first and, within a length, in symbol order.

use crate::{Damage, Res};

pub fn huffman(lengths: &[u32], bits: u32) -> Res<Vec<i32>> {
    let mut counts = vec![0u32; bits as usize + 1];
    for &n in lengths {
        if n > bits {
            return Err(Damage::new("The archive is damaged (a Huffman code is too long)"));
        }
        counts[n as usize] += 1;
    }
    counts[0] = 0;
    let mut first = vec![0u64; bits as usize + 2];
    let mut code = 0u64;
    for n in 1..=bits as usize {
        code = (code + counts[n - 1] as u64) << 1;
        first[n] = code;
    }
    for n in 1..=bits as usize {
        if first[n] + counts[n] as u64 > 1u64 << n {
            return Err(Damage::new("The archive is damaged (a Huffman table is over-full)"));
        }
    }
    let mut table = vec![-1i32; 1 << bits];
    for (sym, &n) in lengths.iter().enumerate() {
        if n > 0 {
            let c = first[n as usize];
            first[n as usize] += 1;
            let start = (c << (bits - n)) as usize;
            let span = 1usize << (bits - n);
            let e = (sym as i32) << 4 | n as i32;
            for slot in &mut table[start..start + span] {
                *slot = e;
            }
        }
    }
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::huffman;

    #[test]
    #[allow(clippy::identity_op)] // symbol << 4 | length, spelled out
    fn codes_are_canonical() {
        // lengths 1, 2, 2: codes 0, 10, 11 (most significant first)
        let t = huffman(&[1, 2, 2], 2).ok().unwrap();
        assert_eq!(t, vec![(0 << 4) | 1, (0 << 4) | 1, (1 << 4) | 2, (2 << 4) | 2]);
    }

    #[test]
    fn over_full_and_too_long_are_refused() {
        assert!(huffman(&[1, 1, 1], 3).is_err());
        assert!(huffman(&[16], 15).is_err());
    }
}
