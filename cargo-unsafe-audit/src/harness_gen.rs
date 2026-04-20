use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::models::{FuzzTarget, InputKind};

// =========================================================================
// Harness Generator -- produce fuzz harness source code
// =========================================================================

/// Generate a complete `fuzz/` directory for the target crate.
///
/// Creates:
/// - `fuzz/Cargo.toml`
/// - `fuzz/fuzz_targets/<name>.rs` for each target
pub fn generate_fuzz_workspace(
    crate_dir: &Path,
    crate_name: &str,
    targets: &[FuzzTarget],
    output_dir: Option<&Path>,
) -> Result<PathBuf> {
    if targets.is_empty() {
        bail!("No fuzzable targets discovered -- cannot generate harness");
    }

    let fuzz_dir = match output_dir {
        Some(dir) => dir.to_path_buf(),
        None => crate_dir.join("fuzz"),
    };

    // Create directory structure
    let fuzz_targets_dir = fuzz_dir.join("fuzz_targets");
    fs::create_dir_all(&fuzz_targets_dir)
        .with_context(|| format!("creating {}", fuzz_targets_dir.display()))?;

    // Generate harness files
    let mut harness_names = Vec::new();
    for target in targets {
        let harness_name = sanitize_harness_name(&target.full_path);
        let harness_path = fuzz_targets_dir.join(format!("{}.rs", harness_name));
        let code = generate_harness_code(crate_name, target)?;
        fs::write(&harness_path, &code)
            .with_context(|| format!("writing {}", harness_path.display()))?;
        harness_names.push((harness_name, target));
    }

    // Generate fuzz/Cargo.toml
    let cargo_toml = generate_fuzz_cargo_toml(crate_dir, crate_name, &harness_names);
    fs::write(fuzz_dir.join("Cargo.toml"), &cargo_toml)
        .with_context(|| "writing fuzz/Cargo.toml")?;

    // Create empty corpus directories
    for (name, _) in &harness_names {
        let corpus_dir = fuzz_dir.join("corpus").join(name);
        fs::create_dir_all(&corpus_dir)?;
    }

    Ok(fuzz_dir)
}

fn sanitize_harness_name(full_path: &str) -> String {
    full_path
        .replace("::", "_")
        .replace(|c: char| !c.is_alphanumeric() && c != '_', "")
        .to_lowercase()
}

fn generate_harness_code(crate_name: &str, target: &FuzzTarget) -> Result<String> {
    let lib_use = format!("use {}::*;", crate_name);

    let body = match target.input_kind {
        InputKind::Bytes => generate_bytes_harness(crate_name, target),
        InputKind::Str => generate_str_harness(crate_name, target),
        InputKind::Read => generate_read_harness(crate_name, target),
        InputKind::Other => generate_arbitrary_harness(crate_name, target),
    };

    Ok(body)
}

fn generate_bytes_harness(crate_name: &str, target: &FuzzTarget) -> String {
    let call = generate_call(crate_name, target, "data");

    format!(
r#"#![no_main]
use libfuzzer_sys::fuzz_target;
use {crate_name}::*;

fuzz_target!(|data: &[u8]| {{
    let _ = {{ {call} }};
}});
"#
    )
}

fn generate_str_harness(crate_name: &str, target: &FuzzTarget) -> String {
    let call = generate_call(crate_name, target, "s");

    format!(
r#"#![no_main]
use libfuzzer_sys::fuzz_target;
use {crate_name}::*;

fuzz_target!(|data: &[u8]| {{
    if let Ok(s) = std::str::from_utf8(data) {{
        let _ = {{ {call} }};
    }}
}});
"#
    )
}

fn generate_read_harness(crate_name: &str, target: &FuzzTarget) -> String {
    let call = generate_call(crate_name, target, "cursor");

    format!(
r#"#![no_main]
use libfuzzer_sys::fuzz_target;
use {crate_name}::*;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {{
    let cursor = Cursor::new(data);
    let _ = {{ {call} }};
}});
"#
    )
}

fn generate_arbitrary_harness(crate_name: &str, target: &FuzzTarget) -> String {
    // Fallback: just pass raw bytes and let the user customize
    let call = generate_call(crate_name, target, "data");

    format!(
r#"#![no_main]
use libfuzzer_sys::fuzz_target;
use {crate_name}::*;

// NOTE: Auto-generated harness for non-standard input type.
// You may need to customize this to properly construct input.
fuzz_target!(|data: &[u8]| {{
    let _ = {{ {call} }};
}});
"#
    )
}

fn generate_call(crate_name: &str, target: &FuzzTarget, input_var: &str) -> String {
    if target.is_method {
        // For methods, we need to construct the receiver.
        // For common parser patterns: Type::method(&mut buffer)
        // Try the simplest form: call the method path directly
        // e.g. httparse::Request::parse(&mut input_var)
        if target.full_path.contains("::parse") {
            format!("{full_path}(&mut {input_var} as &mut &_)",
                full_path = target.full_path)
        } else {
            format!("{full_path}({input_var})",
                full_path = target.full_path)
        }
    } else {
        // Free function: crate::func(input)
        format!("{full_path}({input_var})",
            full_path = target.full_path)
    }
}

fn generate_fuzz_cargo_toml(
    crate_dir: &Path,
    crate_name: &str,
    harnesses: &[(String, &FuzzTarget)],
) -> String {
    let mut bins = String::new();
    for (name, _) in harnesses {
        bins.push_str(&format!(
            r#"[[bin]]
name = "{name}"
path = "fuzz_targets/{name}.rs"

"#
        ));
    }

    // Determine dependency path
    // If crate_dir is absolute, use it; otherwise relative
    let dep_path = crate_dir.canonicalize()
        .unwrap_or_else(|_| crate_dir.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/");

    format!(
r#"[package]
name = "{crate_name}-fuzz"
version = "0.0.0"
publish = false
edition = "2021"

[dependencies]
libfuzzer-sys = "0.4"
{crate_name} = {{ path = "{dep_path}" }}

{bins}
"#
    )
}
