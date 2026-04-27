# syntax=docker/dockerfile:1.7

FROM ubuntu:22.04

SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

ARG DEBIAN_FRONTEND=noninteractive
ARG TOOLCHAIN=nightly-2026-02-01

ENV TZ=UTC \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        git \
        jq \
        libssl-dev \
        lld \
        pkg-config \
        python3 \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --profile minimal --default-toolchain none

RUN rustup toolchain install stable --profile minimal \
    && rustup toolchain install "${TOOLCHAIN}" \
        --profile minimal \
        --component miri,rust-src,rustfmt,clippy \
    && rustup default "${TOOLCHAIN}"

RUN cargo +stable install cargo-geiger --locked \
    && cargo +stable install cargo-fuzz --locked \
    && cargo miri setup

WORKDIR /workspace/unsafe_study
COPY . .

RUN rm -rf targets \
    && mkdir -p targets \
    && clone_git_target() { \
        local name="$1"; \
        local url="$2"; \
        local ref="$3"; \
        local sha="$4"; \
        git clone --depth 1 --branch "$ref" "$url" "targets/$name"; \
        test "$(git -C "targets/$name" rev-parse HEAD)" = "$sha"; \
        rm -rf "targets/$name/.git"; \
    } \
    && fetch_crate_target() { \
        local name="$1"; \
        local version="$2"; \
        local url="$3"; \
        mkdir -p "targets/$name"; \
        curl -LsSf "$url" | tar -xz --strip-components=1 -C "targets/$name"; \
        grep -q "^name = \"$name\"" "targets/$name/Cargo.toml"; \
        grep -q "^version = \"$version\"" "targets/$name/Cargo.toml"; \
    } \
    && clone_git_target bstr https://github.com/BurntSushi/bstr.git 1.12.1 a90f36f0de8c984662c49fb5742027ca24a88cbb \
    && clone_git_target httparse https://github.com/seanmonstar/httparse.git v1.10.1 9f29e79f9832dbd0ae5220acb17c1866745bdecd \
    && clone_git_target memchr https://github.com/BurntSushi/memchr.git 2.8.0 886ca4ca4820297191c6e9f7b023dc356f31a4d1 \
    && clone_git_target pulldown-cmark https://github.com/pulldown-cmark/pulldown-cmark.git v0.13.1 fe3603834daa30450ab9586b6bc58dba4fe1674d \
    && clone_git_target quick-xml https://github.com/tafia/quick-xml.git v0.39.2 5611c894f6b9fd5301c266167a6d3a7ef005dedd \
    && clone_git_target roxmltree https://github.com/RazrFalcon/roxmltree.git v0.21.1 67644e16f43c34cadc9e163163dd1aaf7ebe205e \
    && clone_git_target serde_json https://github.com/serde-rs/json.git v1.0.149 4f6dbfac79647d032b0997b5ab73022340c6dab7 \
    && clone_git_target simd-json https://github.com/simd-lite/simd-json.git v0.17.0 f8e5d67cf8379ca50a582249b1a3865f6180caac \
    && clone_git_target winnow https://github.com/winnow-rs/winnow.git v0.7.14 faa62149eb96a07878bf66515c19af84df158c07 \
    && fetch_crate_target goblin 0.10.5 https://crates.io/api/v1/crates/goblin/0.10.5/download \
    && fetch_crate_target toml_edit 0.25.4+spec-1.1.0 https://crates.io/api/v1/crates/toml_edit/0.25.4%2Bspec-1.1.0/download \
    && fetch_crate_target toml_parser 1.0.9+spec-1.1.0 https://crates.io/api/v1/crates/toml_parser/1.0.9%2Bspec-1.1.0/download \
    && git -C targets/simd-json apply --check /workspace/unsafe_study/patches/simd-json/0001-fix-nightly-unused-imports.patch \
    && git -C targets/simd-json apply /workspace/unsafe_study/patches/simd-json/0001-fix-nightly-unused-imports.patch \
    && python3 - <<'PY'
from pathlib import Path

manifest = Path('/workspace/unsafe_study/targets/simd-json/fuzz/Cargo.toml')
text = manifest.read_text()
block = '\n[[bin]]\nname = "fuzz_target_1"\npath = "fuzz_targets/fuzz_target_1.rs"\n'
if block not in text:
    raise SystemExit('expected stale simd-json fuzz_target_1 entry to be present')
manifest.write_text(text.replace(block, '\n', 1))
PY

RUN cargo test --manifest-path unsafe-audit/Cargo.toml

CMD ["bash"]
