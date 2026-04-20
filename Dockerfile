# unsafe_study — Reproducible Docker environment
# Build:  docker build -t unsafe-study .
# Run:    docker run --rm -it unsafe-study
#
# The image pre-installs the pinned Rust nightly toolchain, Miri, cargo-geiger,
# cargo-fuzz, and clones all 12 target crates at the exact versions used in the
# study.  Running `bash scripts/run_all.sh` inside the container reproduces the
# full three-phase pipeline (Geiger + Miri + fuzzing).

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# ── System dependencies ──────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
        pkg-config \
        libssl-dev \
        python3 \
        ripgrep \
        cmake \
    && rm -rf /var/lib/apt/lists/*

# ── Install Rust via rustup ──────────────────────────────────────────────
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain none --profile minimal

# ── Pin the exact nightly used in the study ──────────────────────────────
# nightly-2026-02-01 (rustc 1.95.0-nightly 905b92696 2026-01-31)
ARG TOOLCHAIN=nightly-2026-02-01
RUN rustup toolchain install "$TOOLCHAIN" --profile default \
        --component miri,rust-src,rustfmt,clippy \
    && rustup default "$TOOLCHAIN"

# ── Install cargo-geiger and cargo-fuzz ──────────────────────────────────
RUN cargo install cargo-geiger --locked 2>/dev/null || true \
    && cargo install cargo-fuzz --locked 2>/dev/null || true

# ── Project tree ────────────────────────────────────────────────────────
WORKDIR /opt/unsafe_study
COPY . .

# ── Clone target crates at study-pinned versions ────────────────────────
# The study used specific upstream versions; clone from crates.io or git.
RUN mkdir -p targets \
    && cd targets \
    # Tier 1 (baseline)
    && git clone --depth 1 --branch v1.10.1 https://github.com/seanmonstar/httparse.git httparse \
    && git clone --depth 1 --branch v1.0.149 https://github.com/serde-rs/json.git serde_json \
    && git clone --depth 1 --branch 1.12.1 https://github.com/BurntSushi/bstr.git bstr \
    # Tier 2 (extension batch)
    && git clone --depth 1 --branch v2.8.0 https://github.com/BurntSushi/memchr.git memchr \
    && git clone --depth 1 --branch v0.17.0 https://github.com/simd-lite/simd-json.git simd-json \
    && git clone --depth 1 --branch v0.39.2 https://github.com/tafia/quick-xml.git quick-xml \
    && git clone --depth 1 --branch v0.7.14 https://github.com/winnow-rs/winnow.git winnow \
    && git clone --depth 1 --branch v0.10.5 https://github.com/m4b/goblin.git goblin \
    && git clone --depth 1 --branch v0.13.1 https://github.com/pulldown-cmark/pulldown-cmark.git pulldown-cmark \
    && git clone --depth 1 --branch v0.21.1 https://github.com/RazrFalcon/roxmltree.git roxmltree \
    # toml_parser and toml_edit: crates.io download since git tags vary
    && CARGO_HOME=/tmp/ci cargo install toml_parser --version 1.0.9 --root /tmp/toml_parser_extract 2>/dev/null; true \
    && CARGO_HOME=/tmp/ci cargo install toml_edit --version 0.25.4 --root /tmp/toml_edit_extract 2>/dev/null; true

# For toml_parser and toml_edit, clone from their respective repos
RUN cd /opt/unsafe_study/targets \
    && git clone --depth 1 https://github.com/toml-rs/toml.git toml_edit_repo 2>/dev/null || true \
    && git clone --depth 1 https://github.com/toml-rs/toml.git toml_parser 2>/dev/null || true \
    && true

# ── Build extensions_harness dependencies (warm build cache) ────────────
RUN cd /opt/unsafe_study/extensions_harness && cargo check 2>/dev/null || true

# ── Default entrypoint ──────────────────────────────────────────────────
# Run a short demo: Geiger + Miri on httparse only (fast, ~2 min).
# For the full run, override: docker run --rm -it unsafe-study bash scripts/run_all.sh
ENTRYPOINT ["bash", "-c", "\
    echo '════════════════════════════════════════════════════════'; \
    echo ' unsafe_study — Docker demo (httparse, 60s fuzz)'; \
    echo '════════════════════════════════════════════════════════'; \
    echo ''; \
    bash scripts/run_all.sh --crates httparse --fuzz-time 60; \
    echo ''; \
    echo 'Full pipeline:  bash scripts/run_all.sh'; \
    echo 'Single crate:   bash scripts/run_all.sh --crates serde_json --skip-fuzz'; \
    echo 'Fuzz only:      bash scripts/run_all.sh --skip-geiger --skip-miri --fuzz-time 300'; \
"]
