<#
.SYNOPSIS
  Run the full unsafe-study pipeline: cargo-geiger, Miri, fuzzing, report.

.PARAMETER TargetCrates
  Comma-separated list of crate directory names under targets/.

.PARAMETER FuzzTimeSecs
  Seconds to run each fuzz target (default: 3600 = 1 hour).

.PARAMETER SkipGeiger
  Skip the cargo-geiger phase.

.PARAMETER SkipMiri
  Skip the Miri phase.

.PARAMETER SkipFuzz
  Skip the fuzzing phase.

.PARAMETER ReportPath
  Path for the final summary report (default: report/study_report.md).
#>
[CmdletBinding()]
param(
  [string[]]$TargetCrates = @(),
  [int]$FuzzTimeSecs = 3600,
  [switch]$SkipGeiger,
  [switch]$SkipMiri,
  [switch]$SkipFuzz,
  [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"

# ── Paths ──────────────────────────────────────────────────────────────────
$projectRoot = Split-Path -Parent $PSCommandPath | Split-Path -Parent
# If run from scripts/, go up one level; if run from project root, stay
if ((Split-Path -Leaf $projectRoot) -ne "unsafe_study") {
  $projectRoot = Split-Path -Parent $PSCommandPath
}
$targetsDir   = Join-Path $projectRoot "targets"
$geigerDir    = Join-Path $projectRoot "geiger_reports"
$miriDir      = Join-Path $projectRoot "miri_reports"
$fuzzTargDir  = Join-Path $projectRoot "fuzz_targets"
$fuzzCorpDir  = Join-Path $projectRoot "fuzz_corpus"
$findingsDir  = Join-Path $projectRoot "fuzz_findings"
$reportDir    = Join-Path $projectRoot "report"
$extensionsHarnessDir = Join-Path $projectRoot "extensions_harness"

if (-not $ReportPath) {
  $ReportPath = Join-Path $reportDir "study_report.md"
}

$now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# ── Discover target crates ─────────────────────────────────────────────────
if ($TargetCrates.Count -eq 0) {
  if (Test-Path $targetsDir) {
    $TargetCrates = Get-ChildItem -Path $targetsDir -Directory | Select-Object -ExpandProperty Name
  }
}
if ($TargetCrates.Count -eq 0) {
  throw "No target crates found. Clone crates into targets/ or pass -TargetCrates."
}

Write-Host "═══════════════════════════════════════════════════════════"
Write-Host " unsafe_study pipeline"
Write-Host " Date     : $now"
Write-Host " Targets  : $($TargetCrates -join ', ')"
Write-Host " Fuzz time: ${FuzzTimeSecs}s per target"
Write-Host "═══════════════════════════════════════════════════════════"

# ── Report header ──────────────────────────────────────────────────────────
$report = New-Object System.Collections.Generic.List[string]
$report.Add("# Unsafe Study Report")
$report.Add("")
$report.Add("- Generated: $now")
$report.Add("- Crates: $($TargetCrates -join ', ')")
$report.Add("- Summary: (pending)")
$report.Add("")

$harnessTestFiles = @{
  "memchr" = "more_crates"
  "winnow" = "more_crates"
  "toml_parser" = "more_crates"
  "simd-json" = "simd_json_triage"
  "quick-xml" = "api_smoke"
  "goblin" = "api_smoke"
  "toml_edit" = "api_smoke"
  "pulldown-cmark" = "api_smoke"
  "roxmltree" = "api_smoke"
}
$harnessTestNames = @{
  "memchr" = "memchr_handles_unaligned_public_inputs"
  "winnow" = "winnow_parses_ascii_and_unicode_boundaries"
  "toml_parser" = "toml_parser_lexes_and_parses_nested_inputs"
  "simd-json" = "simd_json_borrowed_value_parses_object_with_strings"
  "quick-xml" = "quick_xml_streams_events"
  "goblin" = "goblin_parses_minimal_object_bytes"
  "toml_edit" = "toml_edit_parses_and_mutates_document"
  "pulldown-cmark" = "pulldown_cmark_renders_html"
  "roxmltree" = "roxmltree_builds_tree"
}

# ── Helper: append section to report ──────────────────────────────────────
function Add-Section([string]$heading, [string[]]$content) {
  $report.Add("## $heading")
  $report.Add("")
  foreach ($line in $content) { $report.Add($line) }
  $report.Add("")
}

# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: Cargo-Geiger
# ══════════════════════════════════════════════════════════════════════════
$geigerResults = @{}

if (-not $SkipGeiger) {
  Write-Host ""
  Write-Host "──── Phase 2: cargo-geiger ────"
  New-Item -ItemType Directory -Force -Path $geigerDir | Out-Null
  $null = & cargo geiger --help 2>$null
  if ($LASTEXITCODE -ne 0) {
    Write-Host "  cargo-geiger is not installed; marking geiger phase as unavailable"
    foreach ($crate in $TargetCrates) {
      $geigerResults[$crate] = "MISSING TOOL"
    }
  } else {
    foreach ($crate in $TargetCrates) {
      $crateDir = Join-Path $targetsDir $crate
      if (-not (Test-Path $crateDir)) {
        Write-Warning "Crate directory not found: $crateDir — skipping geiger"
        continue
      }
      $jsonOut = Join-Path $geigerDir "$crate.json"
      $textOut = Join-Path $geigerDir "$crate.txt"

      Write-Host "  [$crate] Running cargo geiger..."
      Push-Location $crateDir
      try {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'

        # JSON report
        $geigerJson = & cargo geiger --output-format Json 2>&1
        [System.IO.File]::WriteAllLines($jsonOut, ($geigerJson | Out-String), [System.Text.Encoding]::UTF8)

        # Human-readable report
        $geigerText = & cargo geiger 2>&1
        [System.IO.File]::WriteAllLines($textOut, ($geigerText | Out-String), [System.Text.Encoding]::UTF8)

        $ErrorActionPreference = $prevEap

        $geigerResults[$crate] = "OK"
        Write-Host "  [$crate] Geiger output → $jsonOut"
      } catch {
        $geigerResults[$crate] = "FAILED: $($_.Exception.Message)"
        Write-Warning "  [$crate] Geiger failed: $_"
      } finally {
        Pop-Location
      }
    }
  }

  # Report section
  $geigerLines = @()
  $geigerLines += "| Crate | Geiger Status | Report |"
  $geigerLines += "|-------|---------------|--------|"
  foreach ($crate in $TargetCrates) {
    $status = if ($geigerResults.ContainsKey($crate)) { $geigerResults[$crate] } else { "SKIPPED" }
    $geigerLines += "| $crate | $status | geiger_reports/$crate.json |"
  }
  Add-Section "Phase 2: Hotspot Mining (cargo-geiger)" $geigerLines
}

# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: Miri
# ══════════════════════════════════════════════════════════════════════════
$miriResults = @{}

if (-not $SkipMiri) {
  Write-Host ""
  Write-Host "──── Phase 3: Miri ────"
  New-Item -ItemType Directory -Force -Path $miriDir | Out-Null

  $env:MIRIFLAGS = "-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance"

  foreach ($crate in $TargetCrates) {
    $crateDir = Join-Path $targetsDir $crate
    if (-not (Test-Path $crateDir)) {
      Write-Warning "Crate directory not found: $crateDir — skipping Miri"
      continue
    }
    $logFile = Join-Path $miriDir "$crate.log"
    $testFile = if ($harnessTestFiles.ContainsKey($crate)) { $harnessTestFiles[$crate] } else { $null }
    $testName = if ($harnessTestNames.ContainsKey($crate)) { $harnessTestNames[$crate] } else { $null }

    if ($testFile -and $testName) {
      Write-Host "  [$crate] Running targeted cargo miri test via extensions_harness..."
      Push-Location $extensionsHarnessDir
      try {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'

        $miriOut = & cargo miri test --test $testFile $testName -- --exact 2>&1
        $ErrorActionPreference = $prevEap

        [System.IO.File]::WriteAllLines($logFile, ($miriOut | Out-String), [System.Text.Encoding]::UTF8)

        if ($LASTEXITCODE -ne 0) {
          $miriResults[$crate] = "UB DETECTED (exit $LASTEXITCODE)"
          Write-Host "  [$crate] Miri found issues — see $logFile"
        } else {
          $miriResults[$crate] = "CLEAN"
          Write-Host "  [$crate] Miri clean"
        }
      } catch {
        $miriResults[$crate] = "ERROR: $($_.Exception.Message)"
        Write-Warning "  [$crate] Miri error: $_"
      } finally {
        Pop-Location
      }
    } else {
      Write-Host "  [$crate] Running cargo miri test..."
      Push-Location $crateDir
      try {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'

        $miriOut = & cargo miri test 2>&1
        $ErrorActionPreference = $prevEap

        [System.IO.File]::WriteAllLines($logFile, ($miriOut | Out-String), [System.Text.Encoding]::UTF8)

        if ($LASTEXITCODE -ne 0) {
          $miriResults[$crate] = "UB DETECTED (exit $LASTEXITCODE)"
          Write-Host "  [$crate] Miri found issues — see $logFile"
        } else {
          $miriResults[$crate] = "CLEAN"
          Write-Host "  [$crate] Miri clean"
        }
      } catch {
        $miriResults[$crate] = "ERROR: $($_.Exception.Message)"
        Write-Warning "  [$crate] Miri error: $_"
      } finally {
        Pop-Location
      }
    }
  }

  # Report section
  $miriLines = @()
  $miriLines += "| Crate | Miri Result | Log |"
  $miriLines += "|-------|-------------|-----|"
  foreach ($crate in $TargetCrates) {
    $status = if ($miriResults.ContainsKey($crate)) { $miriResults[$crate] } else { "SKIPPED" }
    $miriLines += "| $crate | $status | miri_reports/$crate.log |"
  }
  $miriLines += ""
  $miriLines += "MIRIFLAGS: ``-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance``"
  Add-Section "Phase 3: Miri Testing" $miriLines
}

# ══════════════════════════════════════════════════════════════════════════
# PHASE 4: Fuzzing
# ══════════════════════════════════════════════════════════════════════════
$fuzzResults = @{}

if (-not $SkipFuzz) {
  Write-Host ""
  Write-Host "──── Phase 4: Fuzzing ────"
  New-Item -ItemType Directory -Force -Path $findingsDir | Out-Null
  $env:CARGO_NET_OFFLINE = "true"
  $env:ASAN_OPTIONS = "detect_odr_violation=0:detect_leaks=0"

  foreach ($crate in $TargetCrates) {
    $crateDir = Join-Path $targetsDir $crate
    if (-not (Test-Path $crateDir)) {
      Write-Warning "Crate directory not found: $crateDir — skipping fuzz"
      continue
    }

    # Look for fuzz/ directory inside the crate (set up by cargo fuzz init)
    $fuzzDir = Join-Path $crateDir "fuzz"
    if (-not (Test-Path $fuzzDir)) {
      Write-Host "  [$crate] No fuzz/ directory — skipping (run cargo fuzz init first)"
      $fuzzResults[$crate] = "NO FUZZ DIR"
      continue
    }

    # Discover fuzz targets
    $targetsListOut = $null
    Push-Location $crateDir
    try {
      $prevEap = $ErrorActionPreference
      $ErrorActionPreference = 'Continue'
      $targetsListOut = & cargo fuzz list 2>&1
      $ErrorActionPreference = $prevEap
    } catch {
      Write-Warning "  [$crate] cargo fuzz list failed: $_"
      $fuzzResults[$crate] = "LIST FAILED"
      Pop-Location
      continue
    }

    $fuzzNames = ($targetsListOut | ForEach-Object { $_.ToString().Trim() }) | Where-Object { $_ -and $_ -notmatch "^\s*$" }
    if ($fuzzNames.Count -eq 0) {
      Write-Host "  [$crate] No fuzz targets found"
      $fuzzResults[$crate] = "NO TARGETS"
      Pop-Location
      continue
    }

    $crateFindings = @()
    foreach ($target in $fuzzNames) {
      Write-Host "  [$crate] Fuzzing target '$target' for ${FuzzTimeSecs}s..."
      $logFile = Join-Path $findingsDir "$crate`_$target.log"

      try {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $fuzzOut = & cargo fuzz run $target -- -max_total_time=$FuzzTimeSecs 2>&1
        $ErrorActionPreference = $prevEap

        [System.IO.File]::WriteAllLines($logFile, ($fuzzOut | Out-String), [System.Text.Encoding]::UTF8)

        if ($LASTEXITCODE -ne 0) {
          $logText = [System.IO.File]::ReadAllText($logFile)
          if ($logText.Contains("failed to build fuzz script") -or $logText.Contains("failed to get `libfuzzer-sys`") -or $logText.Contains("download of config.json failed")) {
            $crateFindings += "$target : BUILD FAILED"
            Write-Host "  [$crate/$target] Fuzz build failed — see $logFile"
          } else {
            $crateFindings += "$target : CRASH (see $logFile)"
            Write-Host "  [$crate/$target] Crash found — see $logFile"
          }
        } else {
          $crateFindings += "$target : clean"
          Write-Host "  [$crate/$target] Clean run"
        }
      } catch {
        $crateFindings += "$target : ERROR $($_.Exception.Message)"
        Write-Warning "  [$crate/$target] Error: $_"
      }
    }

    Pop-Location
    $fuzzResults[$crate] = $crateFindings -join "; "
  }

  # Report section
  $fuzzLines = @()
  $fuzzLines += "| Crate | Fuzz Results |"
  $fuzzLines += "|-------|-------------|"
  foreach ($crate in $TargetCrates) {
    $status = if ($fuzzResults.ContainsKey($crate)) { $fuzzResults[$crate] } else { "SKIPPED" }
    $fuzzLines += "| $crate | $status |"
  }
  $fuzzLines += ""
  $fuzzLines += "Time budget per target: ${FuzzTimeSecs}s"
  Add-Section "Phase 4: Fuzzing" $fuzzLines
}

# ══════════════════════════════════════════════════════════════════════════
# PHASE 5: Summary & Write Report
# ══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "──── Phase 5: Writing report ────"

$summaryLines = @()
$summaryLines += "| Crate | Geiger | Miri | Fuzz |"
$summaryLines += "|-------|--------|------|------|"
foreach ($crate in $TargetCrates) {
  $g = if ($geigerResults.ContainsKey($crate)) { $geigerResults[$crate] } else { "—" }
  $m = if ($miriResults.ContainsKey($crate))   { $miriResults[$crate] }   else { "—" }
  $f = if ($fuzzResults.ContainsKey($crate))    { $fuzzResults[$crate] }    else { "—" }
  $summaryLines += "| $crate | $g | $m | $f |"
}
Add-Section "Cross-Crate Summary" $summaryLines

$report[4] = "- Summary: $($TargetCrates.Count) crates processed"

# Write report
New-Item -ItemType Directory -Force -Path (Split-Path $ReportPath) | Out-Null
[System.IO.File]::WriteAllLines($ReportPath, $report, [System.Text.Encoding]::UTF8)
Write-Host "Report written to $ReportPath"
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════"
Write-Host " Done. $($TargetCrates.Count) crates processed."
Write-Host "═══════════════════════════════════════════════════════════"
