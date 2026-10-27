#!/usr/bin/env bash
# Reproducible build of mr_ed25519 in a pinned container (same PG major as the ECS cluster: 18).
# Usage: ops/pg/mr_ed25519/build.sh <outdir>. Writes mr_ed25519.so + SHA256SUMS to <outdir>.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?outdir}; mkdir -p "$out"
IMAGE="docker.io/library/postgres:18-bookworm@sha256:9551dd5bf356409a21b31248f49b33bba9bb1877365f3a7e933aecd9af3cf52d"
SODIUM_SHA256="ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19"
DEV_PKG="postgresql-server-dev-18=18.6-1.pgdg12+2"
# R43-P3: toolchain pinned to the bookworm versions the golden .so was built with (drift = apt error, not a silent new .so)
TOOLCHAIN="gcc=4:12.2.0-3 gcc-12=12.2.0-14+deb12u1 cpp-12=12.2.0-14+deb12u1 libgcc-12-dev=12.2.0-14+deb12u1 binutils=2.40-2 binutils-x86-64-linux-gnu=2.40-2 make=4.3-4.1"
echo "$SODIUM_SHA256  $here/vendor/libsodium-1.0.20.tar.gz" | sha256sum -c - >/dev/null
# R43-P3: works outside a git checkout too (archive/snapshot); then SOURCE_DATE_EPOCH may be given explicitly
EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$here" log -1 --format=%ct -- . 2>/dev/null || true)}; EPOCH=${EPOCH:-1760000000}
podman run --rm --network=host -v "$here:/src:ro" -v "$(cd "$out" && pwd):/out" -e SOURCE_DATE_EPOCH="$EPOCH" "$IMAGE" bash -euo pipefail -c "
  export LC_ALL=C TZ=UTC DEBIAN_FRONTEND=noninteractive
  mv /etc/apt/sources.list.d/pgdg.list /tmp/pgdg.list; apt-get update -qq >/dev/null; apt-get install -y -qq --no-install-recommends ca-certificates >/dev/null
  sed s,http://apt.postgresql.org,https://apt.postgresql.org, /tmp/pgdg.list > /etc/apt/sources.list.d/pgdg.list
  apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends $TOOLCHAIN $DEV_PKG >/dev/null
  mkdir -p /build && cd /build && tar xzf /src/vendor/libsodium-1.0.20.tar.gz
  FL='-O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -ffile-prefix-map=/build=. -fdebug-prefix-map=/build=. -frandom-seed=mr_ed25519 -g0'
  cd libsodium-stable 2>/dev/null || cd libsodium-1.0.20
  CFLAGS=\"\$FL\" ./configure -q --disable-shared --enable-static --with-pic --prefix=/build/sodium >/dev/null
  make -s -j\$(nproc) >/dev/null 2>&1 && make -s install >/dev/null
  mkdir -p /build/ext && cp /src/mr_ed25519.c /src/mr_ed25519.control /src/mr_ed25519--1.0.sql /src/Makefile /build/ext/ && cd /build/ext
  make -s with_llvm=no CFLAGS=\"\$FL\" LDFLAGS='-Wl,--build-id=sha1 -Wl,-z,relro,-z,now' >/dev/null
  strip --strip-unneeded mr_ed25519.so
  if readelf -d mr_ed25519.so | grep -Eq 'RPATH|RUNPATH'; then echo 'rpath present' >&2; exit 1; fi
  if readelf -d mr_ed25519.so | grep NEEDED | grep -v 'libc.so'; then echo 'unexpected NEEDED' >&2; exit 1; fi
  cp mr_ed25519.so /out/
  cd /out && sha256sum mr_ed25519.so > SHA256SUMS
  cd /src && sha256sum mr_ed25519.control mr_ed25519--1.0.sql mr_ed25519.c vendor/libsodium-1.0.20.tar.gz >> /out/SHA256SUMS
  pg_config --version >> /out/BUILDINFO
"
cat "$out/SHA256SUMS"
