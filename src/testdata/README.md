# Test TLS material

Used only by the CIMD fetcher tests (`src/test_https.rs`), which run a local
HTTPS server for `cimd.test` and `*.cimd.test`.

- `cimd-test-ca.pem`: certificate of "mcp-oauth test CA". Its private key is
  not committed, so nothing else can be signed under it.
- `cimd-test-leaf.pem`, `cimd-test-leaf.key`: leaf certificate and private key
  for `cimd.test` / `*.cimd.test`, signed by that CA. Test-only; trusted
  nowhere outside these tests (the tests add the CA to their own client).
  Listed in `.gitleaksignore` for that reason.
