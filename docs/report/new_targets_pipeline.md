# Unsafe Study Report

- Generated: 2026-03-11 20:45:17
- Crates: memchr winnow toml_parser simd-json quick-xml goblin toml_edit pulldown-cmark roxmltree
- Summary: 9 crates processed


## Phase 2: Hotspot Mining (cargo-geiger)

| Crate | Geiger Status | Report |
|-------|---------------|--------|
| memchr | OK | evidence/geiger/memchr.json |
| winnow | OK | evidence/geiger/winnow.json |
| toml_parser | OK | evidence/geiger/toml_parser.json |
| simd-json | OK | evidence/geiger/simd-json.json |
| quick-xml | OK | evidence/geiger/quick-xml.json |
| goblin | OK | evidence/geiger/goblin.json |
| toml_edit | OK | evidence/geiger/toml_edit.json |
| pulldown-cmark | OK | evidence/geiger/pulldown-cmark.json |
| roxmltree | OK | evidence/geiger/roxmltree.json |


## Phase 3: Miri Testing

| Crate | Miri Result | Log |
|-------|-------------|-----|
| memchr | CLEAN | evidence/miri/memchr.log |
| winnow | CLEAN | evidence/miri/winnow.log |
| toml_parser | CLEAN | evidence/miri/toml_parser.log |
| simd-json | CLEAN | evidence/miri/simd-json.log |
| quick-xml | CLEAN | evidence/miri/quick-xml.log |
| goblin | CLEAN | evidence/miri/goblin.log |
| toml_edit | CLEAN | evidence/miri/toml_edit.log |
| pulldown-cmark | CLEAN | evidence/miri/pulldown-cmark.log |
| roxmltree | CLEAN | evidence/miri/roxmltree.log |

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

