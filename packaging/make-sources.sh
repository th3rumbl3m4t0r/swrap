#!/bin/bash
# Source tarballs for packaging/swrap.spec: the committed tree (git archive of HEAD) and the
# vendored crates (cargo vendor, from Cargo.lock), both into <out> (default: ~/rpmbuild/SOURCES).
# Then: rpmbuild -ba packaging/swrap.spec
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
out=${1:-$HOME/rpmbuild/SOURCES}
ver=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
mkdir -p "$out"
git archive --format=tar.gz --prefix="swrap-$ver/" -o "$out/swrap-$ver.tar.gz" HEAD
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cargo vendor --locked --versioned-dirs "$tmp/vendor" >/dev/null
tar -C "$tmp" -czf "$out/swrap-$ver-vendor.tar.gz" vendor
ls -la "$out/swrap-$ver.tar.gz" "$out/swrap-$ver-vendor.tar.gz"
