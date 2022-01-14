use memflow::prelude::v1::*;

use crate::pbar::PBar;
use iced_x86::{Decoder, DecoderOptions};

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
    pub fn collect_globals(
        &mut self,
        process: &mut (impl Process + MemoryView + Clone),
    ) -> Result<()> {
        self.reset();
        let modules = process.module_list()?;

        const CHUNK_SIZE: usize = size::mb(2);

        let ctx = ThreadLocalCtx::new_locked(move || process.clone());
        let ctx_bytes = ThreadLocalCtx::new(|| vec![0; CHUNK_SIZE + 32]);
        let sections = ThreadLocalCtx::new(|| Vec::<SectionInfo>::new());

        let pb = PBar::new(modules.iter().map(|m| m.size as u64).sum::<u64>(), true);

        self.map.par_extend(
            modules
                .into_par_iter()
                .filter_map(|m| {
                    let mut process = unsafe { ctx.get() };
                    let mut sections = unsafe { sections.get() };

                    sections.clear();

                    process
                        .module_section_list_callback(&m, (&mut *sections).into())
                        .ok()?;

                    std::mem::drop(process);

                    let ret = sections
                        .iter()
                        .filter(|s| s.name.as_ref() == ".text")
                        .par_bridge()
                        .flat_map(|section| {
                            let mut process = unsafe { ctx.get() };
                            let mut bytes = unsafe { ctx_bytes.get() };

                            let start = section.base.to_umem();
                            let end = start + section.size;

                            let mut addr = start;

                            (addr..end)
                                .step_by(CHUNK_SIZE)
                                .filter_map(|_| {
                                    let end = std::cmp::min(end, addr + CHUNK_SIZE as umem);
                                    process
                                        .read_raw_into(addr.into(), &mut bytes)
                                        .data_part()
                                        .ok()?;

                                    let mut decoder = Decoder::new(
                                        ArchitectureObj::from(process.info().proc_arch)
                                            .bits()
                                            .into(),
                                        &bytes,
                                        DecoderOptions::NONE,
                                    );

                                    decoder.set_ip(addr as u64);

                                    addr += CHUNK_SIZE as umem;

                                    Some(
                                        decoder
                                            .into_iter()
                                            .filter(|i| (i.ip() as umem) < end) // we do not overflow the limit
                                            .inspect(|i| addr = (i.ip() as umem) + i.len() as umem) // sets addr to next instruction addr
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
