#!/usr/bin/env bash
# TUBSS Container Test Runner
# Usage: bash test/run_tests.sh
# Requires: docker, run from repo root
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

echo "=========================================="
echo " TUBSS Container Test Runner"
echo "=========================================="

passed=0
failed=0

run_test() {
    local version="$1"
    local dockerfile="$2"
    local image="tubss-test-ubuntu-${version}"

    echo ""
    echo "--- Testing Ubuntu ${version} ---"

    echo "[1/4] Building test image..."
    docker build -f "$dockerfile" -t "$image" "$REPO_DIR" --quiet

    echo "[2/4] Syntax check..."
    docker run --rm "$image" bash -n /usr/local/bin/tubss_setup.sh \
        && echo "  Syntax: OK" \
        || { echo "  Syntax: FAIL"; failed=$((failed + 1)); return; }

    echo "[3/4] Shellcheck (if available)..."
    docker run --rm "$image" bash -c \
        "command -v shellcheck && shellcheck /usr/local/bin/tubss_setup.sh || echo '  shellcheck not available — skipping'"

    echo "[4/4] Dry run (package install check in non-interactive mode)..."
    docker run --rm --privileged "$image" bash -c "
        export DEBIAN_FRONTEND=noninteractive
        # Verify apt works and packages are resolvable
        apt-get update -qq && apt-get install -y --dry-run \
            curl ufw unattended-upgrades apparmor net-tools htop vim build-essential rsync \
            > /dev/null 2>&1 && echo '  Package resolution: OK'
    " || { echo "  Package dry-run: FAIL"; failed=$((failed + 1)); return; }

    echo "Ubuntu ${version}: PASS"
    passed=$((passed + 1))
}

run_test "24.04" "$SCRIPT_DIR/Dockerfile"
run_test "22.04" "$SCRIPT_DIR/Dockerfile.2204"

echo ""
echo "=========================================="
echo " Results: ${passed} passed, ${failed} failed"
echo "=========================================="

[[ $failed -eq 0 ]] || exit 1
