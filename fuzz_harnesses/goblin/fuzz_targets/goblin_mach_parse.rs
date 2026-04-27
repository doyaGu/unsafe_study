#![no_main]

use goblin::mach::Mach;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(mach) = Mach::parse(data) {
        let _ = format!("{mach:?}").len();
    }
});