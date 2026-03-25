# Unsafe Study Report

- Generated: 2026-03-11 20:45:17
- Crates: memchr winnow toml_parser simd-json quick-xml goblin toml_edit pulldown-cmark roxmltree
- Summary: 9 crates processed


## Phase 2: Hotspot Mining (cargo-geiger)

| Crate | Geiger Status | Report |
|-------|---------------|--------|
| memchr | OK | geiger_reports/memchr.json |
| winnow | OK | geiger_reports/winnow.json |
| toml_parser | OK | geiger_reports/toml_parser.json |
| simd-json | OK | geiger_reports/simd-json.json |
| quick-xml | OK | geiger_reports/quick-xml.json |
| goblin | OK | geiger_reports/goblin.json |
| toml_edit | OK | geiger_reports/toml_edit.json |
| pulldown-cmark | OK | geiger_reports/pulldown-cmark.json |
| roxmltree | OK | geiger_reports/roxmltree.json |


## Phase 3: Miri Testing

| Crate | Miri Result | Log |
|-------|-------------|-----|
| memchr | CLEAN | miri_reports/memchr.log |
| winnow | CLEAN | miri_reports/winnow.log |
| toml_parser | CLEAN | miri_reports/toml_parser.log |
| simd-json | CLEAN | miri_reports/simd-json.log |
| quick-xml | CLEAN | miri_reports/quick-xml.log |
| goblin | CLEAN | miri_reports/goblin.log |
| toml_edit | CLEAN | miri_reports/toml_edit.log |
| pulldown-cmark | CLEAN | miri_reports/pulldown-cmark.log |
| roxmltree | CLEAN | miri_reports/roxmltree.log |

MIRIFLAGS: `-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance`


## Phase 4: Fuzzing

| Crate | Fuzz Results |
|-------|-------------|
| memchr | memchr_search: clean;  |
| winnow | winnow_parse: clean;  |
| toml_parser | toml_parser_parse: clean;  |
| simd-json | simd_json_parse: clean;  |
| quick-xml | quick_xml_read: clean;  |
| goblin | goblin_object_parse: clean;  |
| toml_edit | toml_edit_parse: CRASH;  |
| pulldown-cmark | pulldown_cmark_parse: CRASH;  |
| roxmltree | roxmltree_parse: clean;  |

Time budget per target: 3600s


## Cross-Crate Summary

| Crate | Geiger | Miri | Fuzz |
|-------|--------|------|------|
| memchr | OK | CLEAN | memchr_search: clean;  |
| winnow | OK | CLEAN | winnow_parse: clean;  |
| toml_parser | OK | CLEAN | toml_parser_parse: clean;  |
| simd-json | OK | CLEAN | simd_json_parse: clean;  |
| quick-xml | OK | CLEAN | quick_xml_read: clean;  |
| goblin | OK | CLEAN | goblin_object_parse: clean;  |
| toml_edit | OK | CLEAN | toml_edit_parse: CRASH;  |
| pulldown-cmark | OK | CLEAN | pulldown_cmark_parse: CRASH;  |
| roxmltree | OK | CLEAN | roxmltree_parse: clean;  |

