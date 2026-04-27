use goblin::Object;

#[test]
fn goblin_parses_minimal_object_bytes() {
    let mut elf = [0u8; 64];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16] = 2;
    elf[18] = 62;
    elf[52] = 64;

    let _ = Object::parse(&elf);
}

#[test]
fn goblin_parses_minimal_pe_bytes() {
    let mut pe = vec![0u8; 0x100];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c] = 0x40;
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    pe[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
    pe[0x54..0x56].copy_from_slice(&0xF0u16.to_le_bytes());
    pe[0x58..0x5a].copy_from_slice(&0x20Bu16.to_le_bytes());

    let _ = Object::parse(&pe);
}
