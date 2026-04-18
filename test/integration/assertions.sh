#!/usr/bin/env bash
# Assertion helpers for integration tests. Sourced by run.sh.
set -uo pipefail

PASS=0
FAIL=0
FAILED_TESTS=()

_report() {
    local name=$1 result=$2 detail=${3:-}
    if [[ "$result" == "PASS" ]]; then
        PASS=$((PASS+1))
        echo "  [PASS] $name"
    else
        FAIL=$((FAIL+1))
        FAILED_TESTS+=("$name")
        echo "  [FAIL] $name${detail:+ — $detail}"
    fi
}

assert_pkg_installed() {
    local pkg=$1
    if dpkg-query -W -f='${Status}\n' "$pkg" 2>/dev/null | grep -q '^install ok installed$'; then
        _report "package installed: $pkg" PASS
    else
        _report "package installed: $pkg" FAIL "not installed"
    fi
}

assert_service_enabled() {
    local svc=$1
    if systemctl is-enabled "$svc" 2>/dev/null | grep -qE '^(enabled|static)$'; then
        _report "service enabled: $svc" PASS
    else
        _report "service enabled: $svc" FAIL "not enabled"
    fi
}

assert_file_exists() {
    local path=$1
    if [[ -f "$path" ]]; then
        _report "file exists: $path" PASS
    else
        _report "file exists: $path" FAIL "missing"
    fi
}

assert_file_absent() {
    local path=$1
    if [[ ! -e "$path" ]]; then
        _report "file absent: $path" PASS
    else
        _report "file absent: $path" FAIL "exists unexpectedly"
    fi
}

assert_file_contains() {
    local path=$1 pattern=$2
    if grep -qE "$pattern" "$path" 2>/dev/null; then
        _report "file contains pattern: $path ~ $pattern" PASS
    else
        _report "file contains pattern: $path ~ $pattern" FAIL "pattern not found"
    fi
}

summary() {
    echo ""
    echo "=========================================="
    echo "Integration test results: $PASS passed, $FAIL failed"
    echo "=========================================="
    if (( FAIL > 0 )); then
        echo "Failed tests:"
        printf '  - %s\n' "${FAILED_TESTS[@]}"
        return 1
    fi
    return 0
}
