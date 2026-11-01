//! The PPMd decoders packport's Python calls: 7z's (PPMd var.H with 7z's range coder), fed a
//! piece at a time like the other streaming decoders (feed, finish, read, eof).

use crate::ppmd7::{Input, Model, Range7z};
use crate::{raise, Damage, Res};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;

const MARGIN: usize = 4096; // more input than one symbol can take, escapes and all

#[pyclass(module = "packport_native")]
pub struct Ppmd7Decoder {
    model: Model,
    rc: Option<Range7z>,
    pending: Vec<u8>,
    finished: bool,
    ended: bool,
}

impl Ppmd7Decoder {
    fn run(&mut self, want: usize) -> Res<Vec<u8>> {
        let mut out = Vec::with_capacity(want.min(1 << 20));
        if self.ended {
            return Ok(out);
        }
        if self.rc.is_none() {
            if self.pending.len() < 5 && !self.finished {
                return Ok(out);
            }
            let inp = Input { data: std::mem::take(&mut self.pending), pos: 0 };
            self.rc = Some(Range7z::new(inp).ok_or_else(|| Damage::new("The archive is damaged (a PPMd stream starts wrongly)"))?);
        }
        let rc = self.rc.as_mut().unwrap();
        while out.len() < want {
            if !self.finished && rc.inp.left() < MARGIN {
                break;
            }
            let c = self.model.decode_symbol(rc);
            if c < 0 || rc.bad {
                if c == -1 && !rc.bad {
                    self.ended = true;
                    break;
                }
                return Err(Damage::new("The 7z archive is damaged (bad PPMd data)"));
            }
            out.push(c as u8);
        }
        Ok(out)
    }
}

#[pymethods]
impl Ppmd7Decoder {
    #[new]
    fn new(py: Python<'_>, order: u32, mem: u64) -> PyResult<Self> {
        if !(2..=64).contains(&order) {
            return Err(crate::damaged(py, "The 7z archive is damaged (a PPMd order)"));
        }
        let mut model = Model::new(mem).map_err(|m| crate::damaged(py, m))?;
        model.init(order);
        Ok(Ppmd7Decoder { model, rc: None, pending: Vec::new(), finished: false, ended: false })
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
        self.ended
    }

    fn read<'py>(&mut self, py: Python<'py>, max_len: usize) -> PyResult<Bound<'py, PyBytes>> {
        let out = py.detach(|| self.run(max_len)).map_err(|e| raise(py, e))?;
        Ok(PyBytes::new(py, &out))
    }
}
