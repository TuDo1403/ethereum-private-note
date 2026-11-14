#!/bin/sh
# Installs the vault, recover and publish binaries from a GitHub release.
#
#   curl -fsSL https://github.com/TuDo1403/ethereum-private-note/releases/download/vX.Y.Z/install.sh | sh
#
# The release workflow stamps the tag into VERSION below, so the script you fetch from a release
# installs that same release. Run from the repository it refuses, because there is no release to
# pick. EPN_VERSION overrides the tag; EPN_INSTALL_DIR the destination (default ~/.local/bin).
#
# The tarball is checked against the release's SHA256SUMS. Both come from the same place, so that
# only catches a corrupt or truncated download. To prove the binaries were built by this
# repository's CI, run the `gh attestation verify` command printed at the end on the tarball.
set -eu

REPO="TuDo1403/ethereum-private-note"
VERSION="${EPN_VERSION:-@VERSION@}"
DEST="${EPN_INSTALL_DIR:-$HOME/.local/bin}"

die() { echo "install.sh: $*" >&2; exit 1; }

# We cd into a temp dir below, so a relative destination would resolve there and be deleted.
case "$DEST" in /*) ;; *) DEST="$PWD/$DEST" ;; esac

case "$VERSION" in
  @*) die "no version stamped: use the install.sh from a release page, or set EPN_VERSION=vX.Y.Z" ;;
esac

# Release asset names use these os-arch pairs (see the build matrix in release.yml).
os=$(uname -s) arch=$(uname -m)
case "$os-$arch" in
  Linux-x86_64)                name=linux-x86_64 ;;
  Linux-aarch64 | Linux-arm64) name=linux-aarch64 ;;
  Darwin-x86_64)               name=macos-x86_64 ;;
  Darwin-arm64)                name=macos-aarch64 ;;
  *) die "no prebuilt binaries for $os $arch; build from source (see README.md)" ;;
esac

if command -v sha256sum >/dev/null 2>&1; then sha256() { sha256sum "$@"; }
elif command -v shasum >/dev/null 2>&1; then sha256() { shasum -a 256 "$@"; }
else die "need sha256sum or shasum to verify the download"; fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

pkg="epn-$VERSION-$name"
base="https://github.com/$REPO/releases/download/$VERSION"
echo "Downloading $pkg.tar.gz"
# --fail-early: curl reports only the last transfer's status otherwise, so a missing tarball would
# surface as a checksum mismatch.
curl --fail-early --proto '=https' -fsSL -O "$base/$pkg.tar.gz" -O "$base/SHA256SUMS"

# Check only this tarball's line: SHA256SUMS lists every platform and we fetch one.
grep " $pkg.tar.gz\$" SHA256SUMS > expected || die "$pkg.tar.gz is not listed in SHA256SUMS"
sha256 -c expected >/dev/null || die "checksum mismatch for $pkg.tar.gz; not installing"

tar -xzf "$pkg.tar.gz"
# Check everything is there before replacing anything: a half-installed set would mix two releases.
for bin in vault recover publish; do
  [ -f "$pkg/$bin" ] || die "$pkg.tar.gz has no $bin; not installing"
done
mkdir -p "$DEST"
for bin in vault recover publish; do
  install -m 755 "$pkg/$bin" "$DEST/$bin"
done

echo "Installed vault, recover and publish $VERSION to $DEST"
case ":$PATH:" in
  *":$DEST:"*) ;;
  *) echo "Note: $DEST is not on your PATH." ;;
esac
# The attestation covers the tarball, not the extracted binaries, so it has to be fetched again.
echo "To verify the build provenance, download $base/$pkg.tar.gz and run:"
echo "  gh attestation verify $pkg.tar.gz --repo $REPO"
