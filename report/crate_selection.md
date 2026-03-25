# Target Crate Selection

## Selection Criteria

Each target crate must satisfy:
1. **Input-driven API** -- public `parse`, `decode`, `from_bytes`, `from_slice`, or similar
2. **Existing test suite** -- builds and passes on the pinned nightly toolchain
3. **Measurable `unsafe`** -- either directly in the crate or via a key dependency
4. **Mid-size** -- not trivially small, not overwhelmingly large
5. **Miri-compatible** -- no hard FFI dependency that blocks Miri entirely

## Selected Crates

### 1. `httparse`

| Property | Value |
|----------|-------|
| Version  | latest (to be pinned at clone time) |
| Domain   | HTTP/1.1 request/response parsing |
| API      | `Request::parse(&[u8])`, `Response::parse(&[u8])` |
| unsafe   | Direct -- SIMD-accelerated header scanning in hot loop |
| Tests    | ~60 unit tests, all pure Rust |
| Miri     | Expected compatible (no FFI) |
| Repo     | https://github.com/seanmonstar/httparse |

**Why**: Small and focused crate with well-documented direct `unsafe` for
performance. The parsing API accepts raw `&[u8]`, making it ideal for fuzzing.
The `unsafe` blocks are concentrated in SIMD/SSE2 header scanning -- a good
hotspot mapping target.

### 2. `serde_json`

| Property | Value |
|----------|-------|
| Version  | latest |
| Domain   | JSON serialization/deserialization |
| API      | `from_slice(&[u8])`, `from_str(&str)`, `from_reader(R)` |
| unsafe   | Direct (number parsing, string indexing) + via `serde` dependency |
| Tests    | Extensive test suite |
| Miri     | Expected compatible (pure Rust) |
| Repo     | https://github.com/serde-rs/json |

**Why**: Ubiquitous crate exercising both direct `unsafe` and pulling it in
through `serde` core. The JSON parsing path accepts arbitrary bytes, creating a
natural fuzz surface. Hotspot mapping will show unsafe spread across the
dependency graph (serde, itoa, ryu).

### 3. `bstr`

| Property | Value |
|----------|-------|
| Version  | latest |
| Domain   | Byte string handling (non-UTF-8-safe) |
| API      | `ByteSlice` trait methods, `BString` constructors |
| unsafe   | Direct -- UTF-8 boundary tricks, SIMD find operations |
| Tests    | Comprehensive property tests |
| Miri     | Expected compatible (pure Rust) |
| Repo     | https://github.com/BurntSushi/bstr |

**Why**: Uses `unsafe` for efficient byte-level string operations and UTF-8
boundary manipulation. Input can be arbitrary `&[u8]`, perfect for fuzzing.
Authored by BurntSushi (also behind regex), with a well-maintained codebase that
will yield clean geiger output.

## Candidate Crates (Backup)

### `image`
- **Risk**: Heavy C dependencies (zlib-ng-sys, etc.) may block Miri entirely.
- **Fallback plan**: If top 3 crates yield insufficient unsafe diversity, add
  `image` with Miri phase marked as N/A (FFI limitation documented).

### `regex-automata`
- **Risk**: Very large crate; geiger scan may be slow. Dense unsafe in DFA table
  construction could overwhelm annotation effort.
- **Fallback plan**: Use if one of the primary three must be dropped.

## Validation Checklist

For each selected crate, before proceeding to Phase 2:

- [ ] `git clone` at pinned commit into `targets/<crate>/`
- [ ] `cargo test` passes on nightly-2026-02-01
- [ ] `cargo geiger` runs without error
- [ ] `cargo miri test` runs at least a subset of tests without hard failure
- [ ] Fuzz target compiles with `cargo fuzz build`

## Additional Target Intake (2026-03-11)

To widen the study beyond the original three crates, we ran a second intake
pass over parser/search crates that were already available locally or could be
evaluated from crate-indexed package pages without depending on a fresh network
fetch. All nine candidates below were brought into `targets/` and evaluated
against the same geiger/Miri/fuzz pipeline shape.

### Priority A

#### `memchr`

| Property | Value |
|----------|-------|
| Version  | 2.8.0 |
| Domain   | Byte / substring search |
| API      | `memchr`, `memrchr`, `memmem::Finder` |
| unsafe   | Direct SIMD + raw-pointer search backends |
| Tests    | Studied through local harness + crate-local fuzz target |
| Miri     | Clean in targeted harness |

**Why**: This is the most important shared dependency from the original study.
Adding it directly lets us separate "consumer crate" effects from the
underlying SIMD search implementation that previously triggered the alignment
false positive under serde_json.

#### `simd-json`

| Property | Value |
|----------|-------|
| Version  | 0.17.0 |
| Domain   | SIMD JSON parsing |
| API      | `from_slice`, `to_borrowed_value`, `to_owned_value` |
| unsafe   | Explicitly heavy; SIMD intrinsics plus performance-driven unsafe |
| Fit      | Very strong |

**Why**: High-value direct comparison point against `serde_json`. The project
explicitly documents that it uses "a lot of unsafe code" and already emphasizes
tests and fuzzing around that surface.

#### `quick-xml`

| Property | Value |
|----------|-------|
| Version  | 0.39.2 |
| Domain   | Streaming XML reader / writer |
| API      | pull `Reader`, `Writer`, Serde-backed decode paths |
| unsafe   | Effectively none in the crate; `#![forbid(unsafe_code)]` |
| Fit      | Strong |

**Why**: A mature, input-facing parser with broad real-world use and a clear
fuzzing surface. It expands the corpus beyond JSON / TOML / HTTP into XML while
still matching the "parse arbitrary bytes / text" study style.

### Priority B

#### `winnow`

| Property | Value |
|----------|-------|
| Version  | 0.7.14 |
| Domain   | Parser combinators |
| API      | `ascii::dec_uint`, `token::take_while`, `token::take_till` |
| unsafe   | Direct unchecked stream slicing |
| Tests    | Studied through local harness + crate-local fuzz target |
| Miri     | Clean in targeted harness |

**Why**: winnow adds a different unsafe style from SIMD-heavy crates: zero-copy
parser infrastructure built on unchecked slice projection and UTF-8 boundary
assumptions.

#### `toml_parser`

| Property | Value |
|----------|-------|
| Version  | 1.0.9+spec-1.1.0 |
| Domain   | TOML lexing / parsing |
| API      | `Source::lex`, `parser::parse_document` |
| unsafe   | Feature-gated fast paths (`unsafe` feature) |
| Tests    | Studied through local harness + crate-local fuzz target |
| Miri     | Clean in targeted harness |

**Why**: toml_parser is a useful contrast case because unsafe is opt-in. That
lets the study examine a crate that treats unchecked slicing as an explicit
performance mode rather than the default implementation strategy.

#### `goblin`

| Property | Value |
|----------|-------|
| Version  | 0.10.5 |
| Domain   | ELF / PE / Mach-O binary parsing |
| API      | zero-copy binary parsers for executable formats |
| unsafe   | Likely meaningful in zero-copy / layout-sensitive code |
| Fit      | Strong, but more domain-specific |

**Why**: Binary-format parsing is a good stress case for alignment, endianness,
and layout assumptions. It is fuzz-oriented and likely to produce different
unsafe patterns from text parsers.

#### `toml_edit`

| Property | Value |
|----------|-------|
| Version  | 0.25.4+spec-1.1.0 |
| Domain   | Format-preserving TOML parsing / editing |
| API      | document parse + mutation |
| unsafe   | No direct `unsafe` matches in `src/` during intake sweep |
| Fit      | Moderate-to-strong |

**Why**: Strong ecosystem relevance and a natural input surface. It is less
interesting if its direct unsafe footprint is small, but still a good candidate
for a mainstream configuration-parser case study.

### Priority C

#### `pulldown-cmark`

| Property | Value |
|----------|-------|
| Version  | 0.13.1 |
| Domain   | CommonMark parsing |
| API      | `Parser::new` plus HTML rendering |
| unsafe   | Mostly safe; direct `unsafe` is behind the optional `simd` feature |
| Fit      | Lower |

**Why**: It is a high-quality parser crate, but its own documentation says it
is written in pure Rust except for an opt-in SIMD feature. That makes it less
aligned with the "measurable unsafe by default" selection rule.

#### `roxmltree`

| Property | Value |
|----------|-------|
| Version  | 0.21.1 |
| Domain   | Read-only XML tree parser |
| API      | `Document::parse` |
| unsafe   | Negligible |
| Fit      | Negative control |

**Why**: roxmltree is useful as a low-unsafe XML comparison point. It is worth
keeping in `targets/` because it gives a nearly-safe parser baseline against
which `quick-xml` and other text parsers can be contrasted.
