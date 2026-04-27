#![no_main]

use goblin::pe::PE;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(pe) = PE::parse(data) {
        let _ = pe.entry;
        let _ = pe.image_base;
        let _ = pe.is_lib;
        let _ = pe.sections.len();
    }
});