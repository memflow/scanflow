use crate::pbar::PBar;
use memflow::prelude::v1::*;
use rayon::prelude::*;
use rayon_tlsctx::ThreadLocalCtx;

/// Describes a value scanner state.
///
/// Value scanner goes through all memory of the program and finds matching data. The matches can
/// then be filtered after data has changed which can allow to find needed memory address.
///
/// That match can then be joined with `PointerMap`'s offset scanner, alongside `Sigmaker` to
/// create reliable code signature alongside offset tree for the variable.
#[derive(Default)]
pub struct ValueScanner {
    scanned: bool,
    matches: Vec<Address>,
    mem_map: Vec<MemoryRange>,
}

impl ValueScanner {
    /// Reset the value scanner.
    pub fn reset(&mut self) {
        self.scanned = false;
        self.matches.clear();
        self.mem_map.clear();
    }

    /// Scan for specific data in the value scanner.
    ///
    /// First call will scan entire memory range for data, while consequitive calls will filter the
    /// data until its reset.
    ///
    /// # Arguments
    ///
    /// * `mem` - memory object to scan for values in
    /// * `data` - data to scan or filter against
    pub fn scan_for(
        &mut self,
        proc: &mut (impl Process + MemoryView + Clone),
        data: &[u8],
    ) -> Result<()> {
        if !self.scanned {
            self.mem_map = proc.mapped_mem_range_vec(
                mem::mb(16) as _,
                Address::null(),
                ((1 as umem) << 47).into(),
            );

            let pb = PBar::new(
                self.mem_map
                    .iter()
                    .map(|MemData(size, _)| size.to_umem() as u64)
                    .sum::<u64>(),
                true,
            );

            let ctx = ThreadLocalCtx::new_locked(move || proc.clone());
            let ctx_buf = ThreadLocalCtx::new(|| vec![0; 0x1000 + data.len() - 1]);

            self.matches
                .par_extend(self.mem_map.par_iter().flat_map(|&MemData(address, size)| {
                    (0..size)
                        .into_iter()
                        .step_by(0x1000)
                        .par_bridge()
                        .filter_map(|off| {
                            let mut mem = unsafe { ctx.get() };
                            let mut buf = unsafe { ctx_buf.get() };

                            mem.read_raw_into(address + off, buf.as_mut_slice())
                                .data_part()
                                .ok()?;

                            pb.add(0x1000);

                            let ret = buf
                                .windows(data.len())
                                .enumerate()
                                .filter_map(|(o, buf)| {
                                    if buf == data {
                                        Some(address + off + o)
                                    } else {
                                        None
                                    }
                                })
                                .collect::<Vec<_>>()
                                .into_par_iter();

                            Some(ret)
                        })
                        .flatten()
                        .collect::<Vec<_>>()
                        .into_par_iter()
                }));

            self.scanned = true;
            pb.finish();
        } else {
            const CHUNK_SIZE: usize = 0x100;

            let old_matches = std::mem::replace(&mut self.matches, vec![]);

            let pb = PBar::new(old_matches.len() as u64, false);

            let ctx = ThreadLocalCtx::new_locked(move || proc.clone());
            let ctx_buf = ThreadLocalCtx::new(|| vec![0; CHUNK_SIZE * data.len()]);

            self.matches
                .par_extend(old_matches.par_chunks(CHUNK_SIZE).flat_map(|chunk| {
                    let mut mem = unsafe { ctx.get() };
                    let mut buf = unsafe { ctx_buf.get() };

                    if !data.is_empty() {
                        let mut batcher = mem.batcher();

                        for (&a, buf) in chunk.iter().zip(buf.chunks_mut(data.len())) {
                            batcher.read_raw_into(a, buf);
                        }
                    }

                    pb.add(chunk.len() as u64);

                    let mut out = vec![];

                    if !data.is_empty() {
                        out.extend(
                            chunk
                                .iter()
                                .zip(buf.chunks(data.len()))
                                .filter_map(|(&a, buf)| if buf == data { Some(a) } else { None }),
                        );
                    }

                    out.into_par_iter()
                }));
            pb.finish();
        }

        Ok(())
    }

    pub fn matches(&self) -> &Vec<Address> {
        &self.matches
    }

    pub fn matches_mut(&mut self) -> &mut Vec<Address> {
        &mut self.matches
    }
}
