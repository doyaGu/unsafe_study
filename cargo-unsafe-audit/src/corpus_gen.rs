use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::models::InputKind;

// =========================================================================
// Seed Corpus Generator
// =========================================================================

/// Generate seed corpus files for a fuzz target.
pub fn generate_seed_corpus(
    corpus_dir: &Path,
    input_kind: InputKind,
    target_name: &str,
) -> Result<Vec<std::path::PathBuf>> {
    fs::create_dir_all(corpus_dir)?;

    let mut files = Vec::new();

    // Common seeds for all input types
    // 1. Empty input
    files.push(write_seed(corpus_dir, "empty", b"")?);

    // 2. Minimal valid input
    let minimal = match input_kind {
        InputKind::Bytes | InputKind::Read => b"\x00".to_vec(),
        InputKind::Str => b"a".to_vec(),
        InputKind::Other => b"\x00".to_vec(),
    };
    files.push(write_seed(corpus_dir, "minimal", &minimal)?);

    // 3. Type-specific seeds
    match input_kind {
        InputKind::Bytes | InputKind::Read => {
            files.push(write_seed(corpus_dir, "zeros_256", &vec![0u8; 256])?);
            files.push(write_seed(corpus_dir, "ff_256", &vec![0xFFu8; 256])?);
            files.push(write_seed(corpus_dir, "ascending", &(0u8..=255).collect::<Vec<_>>())?);
            files.push(write_seed(corpus_dir, "short_8", b"ABCDEFGH")?);
            files.push(write_seed(corpus_dir, "long_4k", &vec![b'A'; 4096])?);
        }
        InputKind::Str => {
            files.push(write_seed(corpus_dir, "ascii_text", b"hello world\n")?);
            files.push(write_seed(corpus_dir, "unicode", "日本語テスト\n".as_bytes())?);
            files.push(write_seed(corpus_dir, "long_line", &vec![b'x'; 1024])?);
            files.push(write_seed(corpus_dir, "multi_line", b"line1\nline2\nline3\n")?);
            files.push(write_seed(corpus_dir, "special_chars", b"\"'\\{}\x00\r\n\t")?);
        }
        InputKind::Other => {
            files.push(write_seed(corpus_dir, "small_16", &vec![0u8; 16])?);
            files.push(write_seed(corpus_dir, "medium_128", &vec![0u8; 128])?);
        }
    }

    // 4. Domain-specific hints based on target name
    let name_lower = target_name.to_lowercase();

    if name_lower.contains("http") || name_lower.contains("request") || name_lower.contains("response") {
        files.push(write_seed(corpus_dir, "http_get",
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")?);
        files.push(write_seed(corpus_dir, "http_post",
            b"POST /api HTTP/1.1\r\nContent-Length: 4\r\n\r\ntest")?);
        files.push(write_seed(corpus_dir, "http_malformed",
            b"GET /\r\nInvalid Header:\r\n\r\n")?);
        files.push(write_seed(corpus_dir, "http_chunked",
            b"4\r\nWiki\r\n5\r\npedia\r\ne\r\n in\r\n\r\nchunks\r\n0\r\n\r\n")?);
    }

    if name_lower.contains("json") || name_lower.contains("serde") {
        files.push(write_seed(corpus_dir, "json_object",
            br#"{"key": "value", "num": 42, "arr": [1,2,3]}"#)?);
        files.push(write_seed(corpus_dir, "json_array",
            br#"[1, "two", null, true, false, {"nested": "obj"}]"#)?);
        files.push(write_seed(corpus_dir, "json_malformed",
            br#"{broken json"#)?);
        files.push(write_seed(corpus_dir, "json_deep_nest",
            &format!("{}", "{}[".repeat(50)).as_bytes())?);
        files.push(write_seed(corpus_dir, "json_string_escapes",
            br#""\u0000\n\r\t\\\"""#)?);
    }

    if name_lower.contains("xml") {
        files.push(write_seed(corpus_dir, "xml_simple",
            b"<root><item>text</item></root>")?);
        files.push(write_seed(corpus_dir, "xml_malformed",
            b"<root><unclosed>")?);
        files.push(write_seed(corpus_dir, "xml_attributes",
            br#"<root a="1" b='2'><c/></root>"#)?);
    }

    if name_lower.contains("toml") {
        files.push(write_seed(corpus_dir, "toml_simple",
            b"[section]\nkey = \"value\"\nnum = 42\n")?);
        files.push(write_seed(corpus_dir, "toml_malformed",
            b"key = \n[section\n")?);
    }

    if name_lower.contains("goblin") || name_lower.contains("elf") || name_lower.contains("binary") {
        // Minimal ELF header (64-bit)
        let mut elf = vec![
            0x7f, b'E', b'L', b'F', // magic
            2,    // 64-bit
            1,    // little-endian
            1,    // ELF version
            0,    // OS/ABI
            0, 0, 0, 0, 0, 0, 0, 0, // padding
            2, 0, // ET_EXEC
            0x3e, 0, // x86-64
            1, 0, 0, 0, // ELF version
        ];
        elf.extend_from_slice(&[0u8; 48]); // pad to 64 bytes
        files.push(write_seed(corpus_dir, "elf_minimal", &elf)?);

        // Minimal Mach-O
        let macho = vec![
            0xfe, 0xed, 0xfa, 0xce, // MH_MAGIC
            0, 0, 0, 0, // reserved
        ];
        files.push(write_seed(corpus_dir, "macho_minimal", &macho)?);
    }

    if name_lower.contains("markdown") || name_lower.contains("cmark") {
        files.push(write_seed(corpus_dir, "md_simple",
            b"# Hello\n\nParagraph **bold** *italic*\n")?);
        files.push(write_seed(corpus_dir, "md_links",
            b"[link](url)\n![img](src)\n")?);
        files.push(write_seed(corpus_dir, "md_deep_nest",
            &(0..100).map(|i| format!("{}* item {}\n", "  ".repeat(i % 10), i))
                .collect::<String>()
                .as_bytes())?);
    }

    if name_lower.contains("memchr") || name_lower.contains("search") || name_lower.contains("find") {
        files.push(write_seed(corpus_dir, "search_needle",
            b"haystack with needle inside")?);
        files.push(write_seed(corpus_dir, "search_aligned",
            &vec![b'a'; 64])?);
        files.push(write_seed(corpus_dir, "search_unaligned",
            &[b'x', b'y', 0, 0, b'z'][..])?);
    }

    Ok(files)
}

fn write_seed(dir: &Path, name: &str, data: &[u8]) -> Result<std::path::PathBuf> {
    let path = dir.join(name);
    fs::write(&path, data)
        .with_context(|| format!("writing seed corpus file {}", path.display()))?;
    Ok(path)
}
