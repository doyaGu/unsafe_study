#![no_main]

use libfuzzer_sys::fuzz_target;

// Targeted fuzz: bstr alignment-sensitive SIMD paths.
// Miri found UB in ascii.rs:80 by reading usize from an unaligned pointer.
// Strategy: construct BStr slices that start at odd offsets.
fuzz_target!(|data: &[u8]| {
    use bstr::ByteSlice;

    if data.is_empty() {
        return;
    }

    let _ = data.find_byte(b'\n');
    let _ = data.find(b"needle");
    let _ = data.to_str();

    {
        let mut buf = vec![0u8; data.len() + 2];
        buf[1..1 + data.len()].copy_from_slice(data);
        let s = &buf[1..1 + data.len()];
        let _ = s.to_str();
        let _ = s.find_byte(b'\n');
        let _ = s.find(b"needle");
        for _line in s.lines() {}
        for _word in s.words() {}
    }

    {
        let mut buf = vec![0u8; data.len() + 4];
        buf[3..3 + data.len()].copy_from_slice(data);
        let s = &buf[3..3 + data.len()];
        let _ = s.to_str();
        let _ = s.find_byte(b'\n');
        let _ = s.rfind_byte(b'\n');
    }

    {
        let mut buf = vec![0u8; data.len() + 6];
        buf[5..5 + data.len()].copy_from_slice(data);
        let s = &buf[5..5 + data.len()];
        let _ = s.to_str();
        for _line in s.lines() {}
    }
});