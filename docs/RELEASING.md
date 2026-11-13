# Release hardware validation

General macOS CI tests and building qcat-se do not prove Secure Enclave
interoperability. Hosted CI is deliberately separate from this manual hardware
gate. A draft release must not be published until these steps are complete.

1. On a supported Apple Silicon Mac with macOS 26+, check out the exact tag
   commit with a clean tree. Run `bash scripts/validate-enclave-release.sh`.
   This builds the intended helper and enables the real hardware test with
   `QCAT_TEST_ENCLAVE=1` and its absolute `QCAT_ENCLAVE_HELPER` path.
2. Retain both generated files (`metadata.txt` and `test.json`). Metadata records
   commit, OS/build, hardware, Go version, helper source and helper SHA256.
   Attach them to the draft release and link them in the release notes.
3. Compare the recorded commit with the tag's resolved commit. Any change to
   the release commit requires a fresh run. Record the operator and test date
   in the release notes.
4. Confirm the named test passed without skipping. It executes the Enclave
   client and server-signing roles: Enclave signatures verify in Go, Go server
   signatures verify in the client path, and Enclave KEM decapsulation confirms
   the same key as Go encapsulation. A failure, missing test, skip or unavailable
   device blocks publication; ordinary CI success is not a substitute.
5. Only then manually publish the draft after reviewing checksums and artifacts.

This is an explicit operator checklist, not an automated GitHub branch or release
protection rule. No hardware-validation result is asserted by checking in this
procedure. Do not publish without the per-commit evidence.
