//! packport's decoders in Rust: the same results as its pure-Python ones, faster. packport uses
//! them when this module is installed and falls back to Python when it isn't (or when
//! PACKPORT_PURE=1). Every decoder reads past the end of its input as zeros and reports damage
//! as packport's own PackportError, exactly as the Python code does; none of them panics on bad
//! input (out-of-range reads are checked).

use pyo3::prelude::*;

mod bcj2;
mod blocks;
mod deflate64;
mod huff;
mod lzh;
mod lzx;
mod misc;
mod ppmd7;
mod ppmd8;
mod ppmd_py;
mod rar3;
mod rar5;
mod xpress;

/// A packport.PackportError carrying msg.
pub fn damaged(py: Python<'_>, msg: &str) -> PyErr {
    match py.import("packport.entries").and_then(|m| m.getattr("PackportError")) {
        Ok(cls) => PyErr::from_value(cls.call1((msg,)).unwrap_or_else(|e| e.into_value(py).into_bound(py).into_any())),
        Err(e) => e,
    }
}

/// A decoding failure, carried out of code that runs without the GIL.
#[derive(Debug)]
pub struct Damage(pub String);

impl Damage {
    pub fn new(msg: impl Into<String>) -> Self {
        Damage(msg.into())
    }
}

pub type Res<T> = Result<T, Damage>;

pub fn raise(py: Python<'_>, d: Damage) -> PyErr {
    damaged(py, &d.0)
}

#[pymodule]
fn packport_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<lzx::LzxDecoder>()?;
    m.add_class::<deflate64::Deflate64Decoder>()?;
    m.add_class::<ppmd_py::Ppmd7Decoder>()?;
    m.add_class::<ppmd8::Ppmd8Decoder>()?;
    m.add_class::<rar5::Rar5Decoder>()?;
    m.add_class::<rar3::Rar29Decoder>()?;
    m.add_class::<bcj2::Bcj2Decoder>()?;
    m.add_class::<lzh::LzhDecoder>()?;
    m.add_function(wrap_pyfunction!(lzh::crc16, m)?)?;
    m.add_function(wrap_pyfunction!(blocks::lznt1_decompress, m)?)?;
    m.add_function(wrap_pyfunction!(blocks::adc_decompress, m)?)?;
    m.add_function(wrap_pyfunction!(blocks::lz4_block_decompress, m)?)?;
    m.add_function(wrap_pyfunction!(misc::cab_checksum, m)?)?;
    m.add_function(wrap_pyfunction!(misc::crc32, m)?)?;
    m.add_function(wrap_pyfunction!(xpress::xpress_decompress, m)?)?;
    Ok(())
}
