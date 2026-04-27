#![no_main]

use goblin::Object;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(object) = Object::parse(data) {
        match object {
            Object::Elf(elf) => {
                let _ = elf.entry;
                let _ = elf.section_headers.len();
                let _ = elf.program_headers.len();
            }
            Object::PE(pe) => {
                let _ = pe.entry;
                let _ = pe.sections.len();
                let _ = pe.image_base;
            }
            Object::Mach(mach) => {
                let _ = format!("{mach:?}").len();
            }
            Object::Archive(archive) => {
                let _ = archive.len();
            }
            Object::COFF(coff) => {
                let _ = coff.sections.len();
            }
            Object::TE(te) => {
                let _ = te.sections.len();
                let _ = te.header.image_base;
            }
            Object::Unknown(magic) => {
                let _ = magic;
            }
            _ => {}
        }
    }
});