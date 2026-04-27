#![no_main]

use goblin::elf::Elf;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(elf) = Elf::parse(data) {
        let _ = elf.entry;
        let _ = elf.is_64;
        let _ = elf.little_endian;
        let _ = elf.section_headers.len();
        let _ = elf.program_headers.len();
    }
});