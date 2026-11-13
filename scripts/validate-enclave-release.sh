#!/bin/bash
# Run from a clean checkout of the release commit on real Apple Silicon.
set -euo pipefail
cd "$(dirname "$0")/.."
test "$(uname -s)" = Darwin
test "$(uname -m)" = arm64
test -z "$(git status --porcelain)" || { echo 'Hardware validation requires a clean checkout' >&2; exit 1; }
commit=$(git rev-parse HEAD)
evidence=$(mktemp -d "${TMPDIR:-/tmp}/qcat-enclave-evidence.XXXXXX")
make helper
helper="$PWD/bin/qcat-se"
export QCAT_TEST_ENCLAVE=1 QCAT_ENCLAVE_HELPER="$helper"
go test -count=1 -json -run '^TestSecureEnclaveStandardLibraryInteroperability$' ./internal/crypto/provider/se > "$evidence/test.json"
# Require an actual named test pass. Package success alone includes skips.
python3 - "$evidence/test.json" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
name = 'TestSecureEnclaveStandardLibraryInteroperability'
results = [r['Action'] for r in rows if r.get('Test') == name]
if 'pass' not in results or 'skip' in results or 'fail' in results:
    sys.exit('Missing, skipped or failed real Enclave interoperability test')
PY
{
 echo "commit: $commit"
 echo "macOS: $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
 echo "hardware: $(sysctl -n hw.model) / $(sysctl -n machdep.cpu.brand_string)"
 echo "go: $(go version)"
 echo "helper SHA256: $(shasum -a 256 "$helper")"
 echo "helper built by: make helper (swift/qcat-se.swift at $commit)"
 echo "result: PASS (both roles, signature verification and KEM confirmation)"
} > "$evidence/metadata.txt"
echo "Hardware evidence: $evidence"
