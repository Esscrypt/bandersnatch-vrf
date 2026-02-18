# Contributing to bandersnatch-vrf

This package is part of [Peanut Butter AND JAM (PBNJ)](https://github.com/Esscrypt/peanutbutterandjam).

Development setup, code style, and pull request process are defined at the **repository root**. Please read and follow:

**[CONTRIBUTING.md](../../CONTRIBUTING.md)** (in the monorepo root)

From the repo root:

- Clone, install, build: `git submodule update --init --recursive && bun install && bun run build`
- Format and lint: `bun run format` and `bun run lint`
- Type-check: `bun check`
- Tests: `bun run test` (from root or from `packages/bandersnatch-vrf`: `bun run test`)

For bandersnatch-vrf–specific work (e.g. Ring VRF, WASM/W3F backends), run tests from this package:

```bash
cd packages/bandersnatch-vrf
bun run test
bun run build:native   # if working on W3F/Rust ring proof
```

### Opening issues and pull requests

This repo (bandersnatch-vrf submodule) has its own issue and PR templates in [.github/](.github/). Use them when opening issues or PRs **in this repository**:

- **[Bug report](.github/ISSUE_TEMPLATE/bug_report.md)** — [Open new issue (bug)](https://github.com/Esscrypt/bandersnatch-vrf/issues/new?template=bug_report.md)
- **[Feature request](.github/ISSUE_TEMPLATE/feature_request.md)** — [Open new issue (feature)](https://github.com/Esscrypt/bandersnatch-vrf/issues/new?template=feature_request.md)
- **[Pull request template](.github/PULL_REQUEST_TEMPLATE.md)** — checklist and description format for PRs

When contributing to the **parent monorepo** (PBNJ), use the [monorepo templates](https://github.com/Esscrypt/peanutbutterandjam/issues/new) and root [CONTRIBUTING.md](https://github.com/Esscrypt/peanutbutterandjam/blob/main/CONTRIBUTING.md) (including JAM Prize / copyright requirement).

Questions: [GitHub Issues (this repo)](https://github.com/Esscrypt/bandersnatch-vrf/issues) or [PBNJ Issues](https://github.com/Esscrypt/peanutbutterandjam/issues).
