use memflow::prelude::v1::*;

use iced_x86::{Code, ConstantOffsets, Decoder, DecoderOptions, Instruction, OpKind, Register};
use pelite::PeFile;

use crate::disasm::Disasm;

const MAX_SIG_LENGTH: usize = 128;

struct Sigstate<'a> {
    start_ip: Address,
    buf: &'a [u8; MAX_SIG_LENGTH],
    decoder: Decoder<'a>,
    instrs: Vec<(Instruction, ConstantOffsets)>,
    mask: Vec<u8>,
}

impl Sigstate<'_> {
    fn add_single_instr(&mut self) -> bool {
        if !self.decoder.can_decode() {
            return false;
        }

        let instr = self.decoder.decode();

        if instr.code() == Code::INVALID {
            false
        } else {
            let constant_offsets = self.decoder.get_constant_offsets(&instr);
            self.mask.extend((0..instr.len()).map(|_| 0xff));
            let mask_len = self.mask.len();
            let instr_mask = &mut self.mask[(mask_len - instr.len())..];
            Self::mask_instr(&instr, &constant_offsets, instr_mask);
            self.instrs.push((instr, constant_offsets));
            true
        }
    }

    fn mask_instr(instr: &Instruction, offsets: &ConstantOffsets, mask: &mut [u8]) {
        if let Register::EIP
        | Register::RIP
        | Register::ES
        | Register::CS
        | Register::SS
        | Register::DS
        | Register::FS
        | Register::GS
        | Register::None = instr.memory_base()
        {
            Self::mask_mem(offsets, mask);
        }

        if let Ok(OpKind::NearBranch16)
        | Ok(OpKind::NearBranch32)
        | Ok(OpKind::NearBranch64)
        | Ok(OpKind::FarBranch16)
        | Ok(OpKind::FarBranch32) = instr.try_op_kind(0)
        {
            Self::mask_branch(&offsets, mask, 1);
        }
    }

    fn mask_branch(offsets: &ConstantOffsets, mask: &mut [u8], unmasked_branch_size: usize) {
        if offsets.has_immediate() {
            let off = offsets.immediate_offset();
            let size = offsets.immediate_size();
            if size > unmasked_branch_size {
                for (i, b) in mask.iter_mut().enumerate() {
                    if i >= off && i < off + size {
                        *b = 0;
                    }
                }
            }
        }
    }

    fn mask_mem(offsets: &ConstantOffsets, mask: &mut [u8]) {
        if offsets.has_displacement() {
            let off = offsets.displacement_offset();
            let size = offsets.displacement_size();
            for (i, b) in mask.iter_mut().enumerate() {
                if i >= off && i < off + size {
                    *b = 0;
                }
            }
        }
    }
}

/// Sigmaker state.
///
/// Sigmaker allows to find IDA-style code signatures for various global variables.
#[derive(Default)]
pub struct Sigmaker {}

impl Sigmaker {
    fn has_unique_matches(
        states: &[Sigstate],
        virt_mem: &mut impl VirtualMemory,
        ranges: &[(Address, usize)],
        out: &mut Vec<String>,
    ) -> Result<bool> {
        let mut sigs: Vec<_> = states
            .iter()
            .map(|s| (s.start_ip, s.buf, &s.mask, 0))
            .collect();

        const CHUNK_SIZE: usize = size::kb(4);
        let mut buf = vec![0; CHUNK_SIZE + MAX_SIG_LENGTH - 1];

        for &(addr, size) in ranges {
            for off in (0..size).step_by(CHUNK_SIZE) {
                let addr = addr + off;
                virt_mem
                    .virt_read_raw_into(addr, buf.as_mut_slice())
                    .data_part()?;

                for (off, w) in buf.windows(MAX_SIG_LENGTH).enumerate() {
                    let addr = addr + off;
                    for (start_ip, bytes, mask, dup_matches) in sigs.iter_mut() {
                        let win_iter = w.iter().zip(mask.iter()).map(|(&w, &m)| w & m);
                        let bytes_iter = bytes.iter().zip(mask.iter()).map(|(&w, &m)| w & m);
                        if win_iter.eq(bytes_iter) && addr != *start_ip {
                            *dup_matches += 1;
                        }
                    }
                }
            }
        }

        let mut has_unique = false;

        for (_, buf, mask, dup_matches) in sigs {
            if dup_matches == 0 {
                has_unique = true;
                out.push(Self::bytes_to_string(buf, mask));
            }
        }

        Ok(has_unique)
    }

    fn bytes_to_string(bytes: &[u8], mask: &[u8]) -> String {
        bytes
            .iter()
            .zip(mask.iter())
            .map(|(&b, &m)| {
                if m == 0 {
                    "?".to_string()
                } else {
                    format!("{:02X}", b)
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Find code signatures for the given target global.
    ///
    /// * `process` - target profcess
    /// * `disasm` - instance to disassembler state
    /// * `target_global` - target global variable to sig
    pub fn find_sigs(
        process: &mut impl Process,
        disasm: &Disasm,
        target_global: Address,
    ) -> Result<Vec<String>> {
        let addrs = disasm
            .inverse_map()
            .get(&target_global)
            .ok_or(ErrorKind::InvalidArgument)?;

        let module = process
            .module_list()?
            .into_iter()
            .find(|m| m.base <= target_global && m.base + m.size > target_global)
            .ok_or(ErrorKind::ModuleNotFound)?;

        let mut image = vec![0; size::kb(128)];

        process
            .virt_mem()
            .virt_read_raw_into(module.base, &mut image)
            .data_part()?;

        let pefile = PeFile::from_bytes(&image).map_err(|_| ErrorKind::InvalidExeFile)?;

        const IMAGE_SCN_CNT_CODE: u32 = 0x20;

        let ranges: Vec<(Address, usize)> = pefile
            .section_headers()
            .iter()
            .filter(|s| (s.Characteristics & IMAGE_SCN_CNT_CODE) != 0)
            .map(|s| {
                (
                    module.base + s.VirtualAddress as usize,
                    s.VirtualSize as usize,
                )
            })
            .collect();

        let mut bufs: Vec<(Address, [u8; MAX_SIG_LENGTH])> =
            addrs.iter().map(|&a| (a, [0; MAX_SIG_LENGTH])).collect();

        let mut read_list: Vec<_> = bufs
            .iter_mut()
            .map(|(a, b)| VirtualReadData(*a, b))
            .collect();

        process
            .virt_mem()
            .virt_read_raw_list(&mut read_list)
            .data_part()?;

        let bitness = ArchitectureObj::from(process.info().proc_arch)
            .bits()
            .into();

        let mut states: Vec<_> = bufs
            .iter()
            .map(|(start_ip, buf)| {
                let mut decoder = Decoder::new(bitness, buf, DecoderOptions::NONE);
                decoder.set_ip(start_ip.as_u64());
                Sigstate {
                    start_ip: *start_ip,
                    buf,
                    decoder,
                    instrs: vec![],
                    mask: vec![],
                }
            })
            .collect();

        let mut out = vec![];

        loop {
            let mut added = false;
            for s in states.iter_mut() {
                if s.add_single_instr() {
                    added = true;
                }
            }
            if !added || Self::has_unique_matches(&states, process.virt_mem(), &ranges, &mut out)? {
                break;
            }
        }

        Ok(out)
    }
}
