use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct CoverageTools {
    pub llvm_cov: PathBuf,
    pub llvm_profdata: PathBuf,
}

impl CoverageTools {
    pub fn detect() -> Result<Self> {
        let sysroot = rustc_sysroot()?;
        detect_from_sysroot(&sysroot)
    }
}

pub fn export_json_from_profraw(
    profraw_dir: &Path,
    objects: &[PathBuf],
    output_json: &Path,
) -> Result<()> {
    let tools = CoverageTools::detect()?;
    export_json_with_tools(&tools, profraw_dir, objects, output_json)
}

fn rustc_sysroot() -> Result<PathBuf> {
    let output = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .context("running `rustc --print sysroot`")?;
    if !output.status.success() {
        bail!(
            "`rustc --print sysroot` failed with status {:?}",
            output.status.code()
        );
    }
    let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if sysroot.is_empty() {
        bail!("rustc sysroot output was empty");
    }
    Ok(PathBuf::from(sysroot))
}

fn detect_from_sysroot(sysroot: &Path) -> Result<CoverageTools> {
    let rustlib = sysroot.join("lib").join("rustlib");
    let entries = std::fs::read_dir(&rustlib)
        .with_context(|| format!("reading rustlib directory {}", rustlib.display()))?;
    for entry in entries.filter_map(|entry| entry.ok()) {
        let bin_dir = entry.path().join("bin");
        let llvm_cov = bin_dir.join("llvm-cov");
        let llvm_profdata = bin_dir.join("llvm-profdata");
        if llvm_cov.exists() && llvm_profdata.exists() {
            return Ok(CoverageTools {
                llvm_cov,
                llvm_profdata,
            });
        }
    }
    bail!(
        "llvm tools not found under {}; install `llvm-tools-preview` for the active toolchain",
        rustlib.display()
    )
}

fn export_json_with_tools(
    tools: &CoverageTools,
    profraw_dir: &Path,
    objects: &[PathBuf],
    output_json: &Path,
) -> Result<()> {
    if objects.is_empty() {
        bail!("at least one coverage object path is required");
    }
    let profraws = collect_profraw_files(profraw_dir)?;
    if profraws.is_empty() {
        bail!("no .profraw files found in {}", profraw_dir.display());
    }

    let tempdir = tempfile::tempdir().context("creating temp dir for coverage export")?;
    let profdata_path = tempdir.path().join("merged.profdata");

    let mut profdata_cmd = Command::new(&tools.llvm_profdata);
    profdata_cmd.arg("merge").arg("-sparse");
    for profraw in &profraws {
        profdata_cmd.arg(profraw);
    }
    profdata_cmd.arg("-o").arg(&profdata_path);
    let profdata_output = profdata_cmd
        .output()
        .with_context(|| format!("running {}", tools.llvm_profdata.display()))?;
    if !profdata_output.status.success() {
        bail!(
            "llvm-profdata merge failed: {}",
            String::from_utf8_lossy(&profdata_output.stderr).trim()
        );
    }

    let mut cov_cmd = Command::new(&tools.llvm_cov);
    cov_cmd.arg("export");
    cov_cmd.arg("-instr-profile").arg(&profdata_path);
    cov_cmd.arg(&objects[0]);
    for object in objects.iter().skip(1) {
        cov_cmd.arg("-object").arg(object);
    }
    let cov_output = cov_cmd
        .output()
        .with_context(|| format!("running {}", tools.llvm_cov.display()))?;
    if !cov_output.status.success() {
        bail!(
            "llvm-cov export failed: {}",
            String::from_utf8_lossy(&cov_output.stderr).trim()
        );
    }

    std::fs::write(output_json, &cov_output.stdout)
        .with_context(|| format!("writing {}", output_json.display()))?;
    Ok(())
}

pub(super) fn collect_profraw_files(profraw_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = std::fs::read_dir(profraw_dir)
        .with_context(|| format!("reading {}", profraw_dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("profraw"))
        .collect::<Vec<_>>();
    files.sort();
    Ok(files)
}

pub(super) fn coverage_env(profraw_dir: &Path) -> std::collections::BTreeMap<String, String> {
    let mut env = std::collections::BTreeMap::new();
    env.insert("CARGO_INCREMENTAL".into(), "0".into());
    let rustflags = match std::env::var("RUSTFLAGS") {
        Ok(existing) if !existing.trim().is_empty() => {
            format!("{existing} -C instrument-coverage")
        }
        _ => "-C instrument-coverage".into(),
    };
    env.insert("RUSTFLAGS".into(), rustflags);
    env.insert(
        "LLVM_PROFILE_FILE".into(),
        profraw_dir.join("miri-%p-%m.profraw").display().to_string(),
    );
    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn detects_llvm_tools_under_sysroot() {
        let temp = tempfile::tempdir().unwrap();
        let bin_dir = temp.path().join("lib/rustlib/x86_64-unknown-linux-gnu/bin");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(bin_dir.join("llvm-cov"), "").unwrap();
        fs::write(bin_dir.join("llvm-profdata"), "").unwrap();

        let tools = detect_from_sysroot(temp.path()).unwrap();
        assert!(tools.llvm_cov.ends_with("llvm-cov"));
        assert!(tools.llvm_profdata.ends_with("llvm-profdata"));
    }

    #[test]
    fn export_json_runs_profdata_then_cov() {
        let temp = tempfile::tempdir().unwrap();
        let profraw_dir = temp.path().join("profraw");
        fs::create_dir_all(&profraw_dir).unwrap();
        fs::write(profraw_dir.join("one.profraw"), b"raw").unwrap();
        let object = temp.path().join("obj");
        fs::write(&object, b"bin").unwrap();
        let output_json = temp.path().join("coverage.json");

        let log = temp.path().join("log.txt");
        let llvm_profdata = temp.path().join("llvm-profdata");
        let llvm_cov = temp.path().join("llvm-cov");
        write_test_script(
            &llvm_profdata,
            format!(
                "#!/bin/bash\nprintf 'profdata %s\\n' \"$*\" >> \"{}\"\nout=\"\"\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"-o\" ]; then out=\"$2\"; break; fi\n  shift\n done\nprintf 'merged' > \"$out\"\n",
                log.display()
            ),
        );
        write_test_script(
            &llvm_cov,
            format!(
                "#!/bin/bash\nprintf 'cov %s\\n' \"$*\" >> \"{}\"\nprintf '{{\"data\":[]}}'\n",
                log.display()
            ),
        );

        let tools = CoverageTools {
            llvm_cov,
            llvm_profdata,
        };
        export_json_with_tools(&tools, &profraw_dir, &[object], &output_json).unwrap();

        assert_eq!(fs::read_to_string(output_json).unwrap(), "{\"data\":[]}");
        let log_text = fs::read_to_string(log).unwrap();
        assert!(log_text.contains("profdata merge -sparse"));
        assert!(log_text.contains("cov export -instr-profile"));
    }

    #[cfg(unix)]
    fn write_test_script(path: &Path, body: String) {
        fs::write(path, body).unwrap();
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).unwrap();
    }

    #[cfg(not(unix))]
    fn write_test_script(path: &Path, body: String) {
        fs::write(path, body).unwrap();
    }
}
