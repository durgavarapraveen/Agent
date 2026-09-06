#!/usr/bin/env bash
# Pin the Kali rolling base image by SHA-256 digest.
#
# Usage: ./scripts/pin_kali_digest.sh [--check]
#
# Without arguments: pulls the current `kalilinux/kali-rolling`, resolves its
# digest, and prints a `--build-arg KALI_ROLLING_DIGEST=...` line ready to
# paste into `docker-compose.yml` or your CI. It ALSO rewrites the
# `ARG KALI_ROLLING_DIGEST=` default at the top of `Dockerfile` to that
# resolved digest.
#
# With `--check`: only prints. Exits 1 if the current Dockerfile digest is
# stale relative to what upstream is serving today. Suitable for CI.

set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker CLI required" >&2
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKERFILE="${REPO_ROOT}/Dockerfile"

if [ ! -f "$DOCKERFILE" ]; then
    echo "ERROR: Dockerfile not found at $DOCKERFILE" >&2
    exit 2
fi

echo "→ pulling kalilinux/kali-rolling to resolve digest..."
docker pull kalilinux/kali-rolling >/dev/null

# `docker inspect` returns a JSON blob; extract the first RepoDigest for the tag.
DIGEST_LINE="$(docker inspect --format='{{index .RepoDigests 0}}' kalilinux/kali-rolling)"
if [ -z "$DIGEST_LINE" ]; then
    echo "ERROR: could not resolve digest for kalilinux/kali-rolling" >&2
    exit 2
fi

echo "→ resolved: $DIGEST_LINE"

CURRENT_DEFAULT="$(grep -E '^ARG KALI_ROLLING_DIGEST=' "$DOCKERFILE" | head -1 || true)"

if [ "${1:-}" = "--check" ]; then
    if echo "$CURRENT_DEFAULT" | grep -q "$DIGEST_LINE"; then
        echo "✓ Dockerfile already pins to the current digest."
        exit 0
    else
        echo "⚠ Dockerfile is stale."
        echo "  Current default: $CURRENT_DEFAULT"
        echo "  Latest upstream: ARG KALI_ROLLING_DIGEST=$DIGEST_LINE"
        exit 1
    fi
fi

# In-place rewrite the default. Portable BSD/GNU sed.
if grep -q '^ARG KALI_ROLLING_DIGEST=' "$DOCKERFILE"; then
    ESCAPED="$(printf '%s' "$DIGEST_LINE" | sed 's/[\/&]/\\&/g')"
    if sed --version >/dev/null 2>&1; then
        sed -i "s|^ARG KALI_ROLLING_DIGEST=.*|ARG KALI_ROLLING_DIGEST=${ESCAPED}|" "$DOCKERFILE"
    else
        sed -i '' "s|^ARG KALI_ROLLING_DIGEST=.*|ARG KALI_ROLLING_DIGEST=${ESCAPED}|" "$DOCKERFILE"
    fi
    echo "→ updated Dockerfile."
else
    echo "ERROR: Dockerfile has no 'ARG KALI_ROLLING_DIGEST=' line to update." >&2
    exit 2
fi

echo
echo "Pass this at build time to override without editing the file:"
echo "  docker build --build-arg KALI_ROLLING_DIGEST='$DIGEST_LINE' -t antigravity-kali ."
