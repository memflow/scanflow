use crate::pbar::PBar;
use memflow::error::*;
use memflow::mem::VirtualMemory;
use memflow::types::{size, Address};
use rayon::prelude::*;
use rayon_tlsctx::ThreadLocalCtx;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Bound::Included;

/// Describes pointer map state.
///
/// Pointer map stores addresses to data that contains addresses to valid memory regions.
///
/// It essentially allows to find links between memory locations.
#[derive(Default)]
pub struct PointerMap {
    map: BTreeMap<Address, Address>,
    inverse_map: BTreeMap<Address, Vec<Address>>,
    pointers: Vec<Address>,
}

impl PointerMap {
    /// Reset the pointer map state.
    pub fn reset(&mut self) {
        self.map.clear();
        self.inverse_map.clear();
        self.pointers.clear();
    }

    /// Create the pointer map state.
    ///
    /// # Arguments
    /// * `mem` - memory to scan for pointers in
    /// * `size_addr` - size of a pointer (4 bytes on 32 bit machines, 8 bytes on 64 bit machines).
    pub fn create_map(
        &mut self,
        mem: &mut (impl VirtualMemory + Clone),
        size_addr: usize,
    ) -> Result<()> {
        self.reset();

        let mem_map = mem.virt_page_map_range(size::mb(16), Address::null(), (1u64 << 47).into());

        let pb = PBar::new(
            mem_map.iter().map(|(_, size)| *size as u64).sum::<u64>(),
            true,
        );

        let ctx = ThreadLocalCtx::new_locked(move || mem.clone());
        let ctx_buf = ThreadLocalCtx::new(|| vec![0; 0x1000 + size_addr - 1]);

        self.map
            .par_extend(mem_map.par_iter().flat_map(|&(addr, size)| {
                (0..size)
                    .into_par_iter()
                    .step_by(0x1000)
                    .filter_map(|off| {
                        let mut mem = unsafe { ctx.get() };
                        let mut buf = unsafe { ctx_buf.get() };

                        mem.virt_read_raw_into(addr + off, buf.as_mut_slice())
                            .data_part()
                            .ok()?;

                        pb.add(0x1000);

                        let ret = buf
                            .windows(size_addr)
                            .enumerate()
                            .filter_map(|(o, buf)| {
                                let addr = addr + off + o;
                                let mut arr = [0; 8];
                                // TODO: Fix for Big Endian
                                arr[0..buf.len()].copy_from_slice(buf);
                                let out_addr = Address::from(u64::from_le_bytes(arr));
                                if mem_map
                                    .binary_search_by(|&(a, s)| {
                                        if out_addr >= a && out_addr < a + s {
                                            Ordering::Equal
                                        } else {
                                            a.cmp(&out_addr)
                                        }
                                    })
                                    .is_ok()
                                {
                                    Some((addr, out_addr))
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

        for (&k, &v) in &self.map {
            self.inverse_map.entry(v).or_default().push(k);
        }

        self.pointers = self.map.keys().copied().collect();

        pb.finish();

        Ok(())
    }

    /// Get the forward pointer map.
    pub fn map(&self) -> &BTreeMap<Address, Address> {
        &self.map
    }

    /// Get the inverse (back) pointer map.
    pub fn inverse_map(&self) -> &BTreeMap<Address, Vec<Address>> {
        &self.inverse_map
    }

    /// Get a list of pointers.
    pub fn pointers(&self) -> &Vec<Address> {
        &self.pointers
    }

    fn walk_down_range(
        &self,
        addr: Address,
        (lrange, urange): (usize, usize),
        max_levels: usize,
        level: usize,
        startpoints: &[Address],
        out: &mut Vec<(Address, Vec<(Address, isize)>)>,
        (final_addr, tmp): (Address, &mut Vec<(Address, isize)>),
        pb: &PBar,
        (pb_start, pb_end): (f32, f32),
    ) {
        let min = Address::from(addr.as_u64().saturating_sub(urange as _));
        let max = Address::from(addr.as_u64().saturating_add(lrange as _));

        // Find the lower bound
        let idx = startpoints.binary_search(&min).unwrap_or_else(|x| x);

        let mut iter = startpoints
            .iter()
            .skip(idx)
            .copied()
            .take_while(|&v| v <= max);

        // Pick next match
        let mut m = iter.next();

        // Go through the rest
        for e in iter {
            let off = signed_diff(addr, e).abs();
            // If abs offset is smaller, overwrite
            // < biasses more towards positive end
            if off < signed_diff(addr, m.unwrap()).abs() {
                m = Some(e);
            }
        }

        // Push match if found
        if let Some(e) = m {
            let off = signed_diff(addr, e);
            let mut cloned = tmp.clone();
            cloned.push((e, off));
            cloned.reverse();
            out.push((final_addr, cloned));
        }

        // Recurse downwards if possible
        if level < max_levels {
            let mut last = min;
            for (&k, vec) in self.inverse_map.range((Included(&min), Included(&max))) {
                // Calculate the starting fraction
                let frac_start = (last - min) as f32 / (max - min) as f32;
                let new_start = pb_start + (pb_end - pb_start) * frac_start;

                // Calculate the ending fraction
                let frac_end = (k - min) as f32 / (max - min) as f32;
                let new_end = pb_start + (pb_end - pb_start) * frac_end;

                last = k;

                let off = signed_diff(addr, k);
                tmp.push((k, off));

                // Calculate how much space each subitem uses in the fraction
                let part = (new_end - new_start) / vec.len() as f32;

                for (i, &v) in vec.iter().enumerate() {
                    self.walk_down_range(
                        v,
                        (lrange, urange),
                        max_levels,
                        level + 1,
                        startpoints,
                        out,
                        (final_addr, tmp),
                        pb,
                        (
                            new_start + part * i as f32,
                            new_start + part * (i + 1) as f32,
                        ),
                    );
                }
                tmp.pop();

                if (new_end - pb_start) >= 0.00001 {
                    pb.set((new_end * 100000.0).round() as u64);
                }
            }
        }
    }

    /// Find matches from specific entry point addresses.
    ///
    /// # Arguments
    ///
    /// * `range` - address bounds for memory address differences between pointers.
    /// * `max_depth` - how deep to scan inside the pointer map.
    /// * `search_for` - addresses to find the links for.
    /// * `entry_points` - valid entry point addresses.
    pub fn find_matches_addrs(
        &self,
        range: (usize, usize),
        max_depth: usize,
        search_for: &[Address],
        entry_points: &[Address],
    ) -> Vec<(Address, Vec<(Address, isize)>)> {
        let mut matches = vec![];

        let pb = PBar::new(100000, false);

        let part = 1.0 / search_for.len() as f32;

        matches.par_extend(search_for.par_iter().enumerate().flat_map(|(i, &m)| {
            let mut matches = vec![];

            self.walk_down_range(
                m,
                range,
                max_depth,
                1,
                entry_points,
                &mut matches,
                (m, &mut vec![]),
                &pb,
                (part * i as f32, part * (i + 1) as f32),
            );

            pb.set((100000.0 * part * (i + 1) as f32).round() as u64);

            matches.into_par_iter()
        }));

        pb.finish();

        matches
    }

    /// Find matches from all pointers.
    ///
    /// # Arguments
    ///
    /// * `range` - address bounds for memory address differences between pointers.
    /// * `max_depth` - how deep to scan inside the pointer map.
    /// * `search_for` - addresses to find the links for.
    pub fn find_matches(
        &self,
        range: (usize, usize),
        max_depth: usize,
        search_for: &[Address],
    ) -> Vec<(Address, Vec<(Address, isize)>)> {
        self.find_matches_addrs(range, max_depth, search_for, &self.pointers)
    }
}

pub fn signed_diff(a: Address, b: Address) -> isize {
    a.as_u64()
        .checked_sub(b.as_u64())
        .map(|a| a as isize)
        .unwrap_or_else(|| -((b - a) as isize))
}
