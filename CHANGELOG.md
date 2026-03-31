# Changelog

## v1.0.0 (2026-04-01)

### Initial Release

- chore: upgrade dependencies (#20)
- build(deps): bump actions/checkout from 4 to 6 (#14)
- harden: migrate golangci-lint v2 and fix security/lint warnings (#19)
- fix: forward query string to upstream in proxy and SSE handlers (#13) (#18)
- fix: use YAML literal block scalar for mock-mcp inline Python (#16) (#17)
- fix: remove unused OPA_URL config and respect token exp in cache TTL
- docs: harvest retrospective
- docs: add CHANGELOG.md for v1.0.0
- feat #5: integration tests, ADRs, and documentation (#12)
- feat #4: audit logging (rebased on main) (#11)
- feat #3: OAuth token verification middleware (rebased on main) (#8)
- feat #2: implement MCP proxy with JSON-RPC routing, SSE streaming, and input validation (#7)
- feat #1: CI/CD, test framework, and local dev environment (#6)
- Initial project scaffold from idea #1