//! Checksums the readers run over every byte: CRC-32 (with the CPU's carry-less multiply where it
//! has one) and CAB's data-block checksum.

use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;

/// The cabinet checksum: 32-bit little-endian words XORed, the 1-3 bytes left over taken high
/// byte first (cab.py's checksum()).
#[pyfunction]
#[pyo3(signature = (data, seed = 0))]
pub fn cab_checksum(py: Python<'_>, data: PyBackedBytes, seed: u32) -> u32 {
    py.detach(|| {
        let mut c = seed;
        let (words, rest) = data.as_chunks::<4>();
        for w in words {
            c ^= u32::from_le_bytes(*w);
        }
        let ul = match rest.len() {
            3 => (rest[0] as u32) << 16 | (rest[1] as u32) << 8 | rest[2] as u32,
            2 => (rest[0] as u32) << 8 | rest[1] as u32,
            1 => rest[0] as u32,
            _ => 0,
        };
        c ^ ul
    })
}


/// zlib.crc32(data, value), faster.
#[pyfunction]
#[pyo3(signature = (data, value = 0))]
pub fn crc32(py: Python<'_>, data: PyBackedBytes, value: u32) -> u32 {
    py.detach(|| {
        let mut h = crc32fast::Hasher::new_with_initial(value);
        h.update(&data);
        h.finalize()
    })
}
