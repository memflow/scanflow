use memflow::prelude::v1::*;

use crate::pbar::PBar;
use iced_x86::{Decoder, DecoderOptions};
use pelite::PeFile;

use std::collections::BTreeMap;

use rayon::prelude::*;
use rayon_tlsctx::ThreadLocalCtx;

/// Describes a disassembler state.
#[derive(Default)]
pub struct Disasm {
    map: BTreeMap<Address, Address>,
    inverse_map: BTreeMap<Address, Vec<Address>>,
    globals: Vec<Address>,
}

impl Disasm {
    /// Reset the state
    pub fn reset(&mut self) {
        self.map.clear();
        self.inverse_map.clear();
        self.globals.clear();
    }

    /// Collect global variables to the state.
    ///
    /// Global variables can then be accessed through `map`, `inverse_map`, `globals` calls.
    ///
    /// # Arguments
    ///
    /// * `process` - target process to find the variables in
    pub fn collect_globals(&mut self, process: &mut (impl Process + Clone)) -> Result<()> {
        self.reset();
        let modules = process.module_list()?;

        const CHUNK_SIZE: usize = size::mb(2);

        let ctx = ThreadLocalCtx::new_locked(move || process.clone());
        let ctx_image = ThreadLocalCtx::new(|| vec![0; size::kb(128)]);
        let ctx_bytes = ThreadLocalCtx::new(|| vec![0; CHUNK_SIZE + 32]);

        let pb = PBar::new(modules.iter().map(|m| m.size as u64).sum::<u64>(), true);

        self.map.par_extend(
            modules
                .into_par_iter()
                .filter_map(|m| {
                    let mut process = unsafe { ctx.get() };
                    let mut image = unsafe { ctx_image.get() };

                    process
                        .virt_mem()
                        .virt_read_raw_into(m.base, &mut image)
                        .data_part()
                        .ok()?;

                    std::mem::drop(process);

                    let pefile = PeFile::from_bytes(image.as_slice())
                        .map_err(|_| ErrorKind::InvalidExeFile)
                        .ok()?;

                    const IMAGE_SCN_CNT_CODE: u32 = 0x20;

                    let ret = pefile
                        .section_headers()
                        .iter()
                        .filter(|s| (s.Characteristics & IMAGE_SCN_CNT_CODE) != 0)
                        .par_bridge()
                        .flat_map(|section| {
                            let mut process = unsafe { ctx.get() };
                            let mut bytes = unsafe { ctx_bytes.get() };

                            let start = m.base.as_u64() + section.VirtualAddress as u64;
                            let end = start + section.VirtualSize as u64;

                            let mut addr = start;

                            (addr..end)
                                .step_by(CHUNK_SIZE)
                                .filter_map(|_| {
                                    let end = std::cmp::min(end, addr + CHUNK_SIZE as u64);
                                    process
                                        .virt_mem()
                                        .virt_read_raw_into(addr.into(), &mut bytes)
                                        .data_part()
                                        .ok()?;

                                    let mut decoder = Decoder::new(
                                        ArchitectureObj::from(process.info().proc_arch)
                                            .bits()
                                            .into(),
                                        &bytes,
                                        DecoderOptions::NONE,
                                    );

                                    decoder.set_ip(addr);

                                    addr += CHUNK_SIZE as u64;

                                    Some(
                                        decoder
                                            .into_iter()
                                            .filter(|i| i.ip() < end) // we do not overflow the limit
                                            .inspect(|i| addr = i.ip() + i.len() as u64) // sets addr to next instruction addr
                                            .filter(|i| i.is_ip_rel_memory_operand()) // uses IP relative memory
                                            .filter(|i| i.near_branch_target() == 0) // is not a branch (call/jump)
                                            .map(|i| {
                                                (
                                                    Address::from(i.ip()),
                                                    Address::from(i.ip_rel_memory_address()),
                                                )
                                            })
                                            .collect::<Vec<_>>()
                                            .into_iter(),
                                    )
                                })
                                .flatten()
                                .collect::<Vec<_>>()
                                .into_par_iter()
                        })
                        .collect::<Vec<_>>()
                        .into_par_iter();

                    pb.add(m.size as u64);

                    Some(ret)
                })
                .flatten(),
        );

        for (&k, &v) in &self.map {
            self.inverse_map.entry(v).or_default().push(k);
        }

        self.globals = self.inverse_map.keys().copied().collect();

        pb.finish();

        Ok(())
    }

    pub fn map(&self) -> &BTreeMap<Address, Address> {
        &self.map
    }

    pub fn inverse_map(&self) -> &BTreeMap<Address, Vec<Address>> {
        &self.inverse_map
    }

    pub fn globals(&self) -> &Vec<Address> {
        &self.globals
    }
}
