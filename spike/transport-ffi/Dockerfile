# Spike A1 path (1): official Rust bindings -> native liblogosdelivery (Nim).
# Build:  docker build --platform linux/arm64 -t ffi-spike -f Dockerfile .   (context = this dir)
# Stage "lib" builds liblogosdelivery.so from the logos-delivery rev the bindings pin
# (LOGOS_DELIVERY_REV file in the bindings repo). Stage "app" builds the spike binary.

FROM rust:1.92-bookworm AS lib
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG LOGOS_DELIVERY_REV=0f2188c09779cc84116db344bbb43ccfe6a27c35
ARG MAKE_JOBS=6
ARG DISABLE_RLN=false
# chronicles log level is a COMPILE-time switch in the library (runtime logLevel config does not filter); TRACE is the upstream default
ARG LOG_LEVEL=ERROR
RUN date -u +%FT%TZ > /t_apt_start && apt-get update && \
    apt-get install -y --no-install-recommends cmake patchelf pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/* && date -u +%FT%TZ > /t_apt_end
WORKDIR /src
RUN git init logos-delivery && cd logos-delivery && \
    git remote add origin https://github.com/logos-messaging/logos-delivery && \
    git fetch --depth 1 origin ${LOGOS_DELIVERY_REV} && git checkout --detach FETCH_HEAD && \
    git log -n1 --format='logos-delivery %H %cd'
WORKDIR /src/logos-delivery
# only zerokit (RLN, Rust) is a git submodule at this rev; Nim deps come via nimble (nimble.lock)
RUN date -u +%FT%TZ && git submodule update --init --depth 1 vendor/zerokit && date -u +%FT%TZ
# WORKAROUND (arm64): nimble 0.26.0 downloads "nim-2.2.6-linux_x64.tar.xz" even on aarch64; that x86-64
# binary runs under qemu-user inside the arm64 container and segfaults at random while nimble evaluates
# .nimble files (see results/a1-ffi/lib-build-3/4 logs). Build a native Nim 2.2.6 and pre-seed nimbledeps.
ARG NIM_PKG_DIR=nim-2.2.6-b3179cffd77e51d16ea343b5493d895e8bc8c085
RUN if [ "$(uname -m)" = "aarch64" ]; then \
      date -u +%FT%TZ && git clone --depth 1 --branch v2.2.6 https://github.com/nim-lang/Nim /opt/nim && \
      cd /opt/nim && time sh build_all.sh && date -u +%FT%TZ && \
      mkdir -p /src/logos-delivery/nimbledeps/pkgs2/${NIM_PKG_DIR} && \
      cp -a /opt/nim/. /src/logos-delivery/nimbledeps/pkgs2/${NIM_PKG_DIR}/ && \
      printf '{"version":1,"metaData":{"url":"https://github.com/nim-lang/Nim.git","downloadMethod":"git","vcsRevision":"","files":[],"binaries":[],"specialVersions":["2.2.6"]}}' \
        > /src/logos-delivery/nimbledeps/pkgs2/${NIM_PKG_DIR}/nimblemeta.json ; \
    fi
# Makefile installs nimble + the locked Nim toolchain (nimble setup) and builds the library
RUN date -u +%FT%TZ && time make -j${MAKE_JOBS} DISABLE_RLN=${DISABLE_RLN} LOG_LEVEL=${LOG_LEVEL} liblogosdelivery && date -u +%FT%TZ && \
    ls -l build && (cd build && ls -l *.so* ) && \
    cd /src/logos-delivery && (ls nimbledeps/pkgs2 | grep -i '^nim-' ; nimbledeps/pkgs2/nim-*/bin/nim --version; file nimbledeps/pkgs2/nim-*/bin/nim)

FROM rust:1.92-bookworm AS app
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# only the library crosses over (keeps this stage small; the "lib" stage image is several GB)
COPY --from=lib /src/logos-delivery/build/liblogosdelivery.so /libdir/liblogosdelivery.so
ENV LOGOS_DELIVERY_LIB_DIR=/libdir \
    LOGOS_DELIVERY_RELOCATABLE=1 \
    CARGO_TERM_COLOR=never
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY .cargo ./.cargo
RUN date -u +%FT%TZ && time cargo build --release --locked && date -u +%FT%TZ && \
    ls -l target/release/ffi-spike && \
    mkdir -p /out && cp target/release/ffi-spike /libdir/liblogosdelivery.so /out/ && \
    (cd /out && ldd ./ffi-spike && ldd ./liblogosdelivery.so && ls -l /out && strip -o /tmp/lib.stripped.so liblogosdelivery.so && ls -l /tmp/lib.stripped.so)

FROM debian:bookworm-slim AS run
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates procps libgomp1 libstdc++6 && rm -rf /var/lib/apt/lists/*
COPY --from=app /out/ /opt/ffi/
WORKDIR /opt/ffi
ENTRYPOINT ["/opt/ffi/ffi-spike"]
