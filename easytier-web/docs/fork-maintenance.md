# Native MCP fork maintenance

This fork maintains native Streamable HTTP MCP support inside `easytier-web`.
The MCP server shares the existing API listener and dispatches through the
existing management handlers. It does not require a separate service.

## Branches and upstream

- Upstream: `https://github.com/EasyTier/EasyTier.git`
- Fork: `https://github.com/AndroidArch/EasyTier.git`
- `main`: upstream baseline; keep custom MCP changes on a separate branch.
- `feat/native-http-mcp`: native MCP implementation and documentation.
- Initial upstream baseline: `5af90471bfe654d097f7e488a2699f2850db7dd2`.

Keep upstream changes and MCP changes in separate commits. Do not reset a
custom branch to upstream or force-push a shared branch when upgrading.

## Update procedure

Start from a clean working tree, with runtime databases and credentials backed
up separately. The following commands assume the remotes above are configured:

```sh
git fetch upstream --tags
git fetch origin
git switch feat/native-http-mcp
git switch -c upgrade/native-mcp-YYYYMMDD
git merge upstream/main
```

Resolve integration conflicts in `easytier-web/Cargo.toml`, `src/main.rs`, and
`src/restful/mod.rs`. Review authentication extensions, handler paths, request
schemas, response shapes, and ownership checks even if Git reports no conflicts.
Keep the implementation and protocol tests in `src/restful/mcp.rs` and
`src/restful/mcp_tests.rs`. Do not replace `Cargo.lock` blindly; resolve dependency
changes using the Rust toolchain required by the selected upstream commit.

The current integration is always compiled, but disabled at runtime unless
`ET_MCP_ENABLED=true`. There is no Cargo `mcp` feature in this implementation.

## Verification

With upstream native build prerequisites installed:

```sh
cargo check -p easytier-web --locked
cargo test -p easytier-web restful::mcp --locked
pnpm install --frozen-lockfile
pnpm --dir easytier-web/frontend build
cargo build -p easytier-web --features embed --release --locked
```

Follow upstream's release workflow when bundling additional frontend components
or targeting Linux musl. Build and verify the exact deployment target; a host
build alone is not evidence that a cross-platform release works.

Before deployment, start the candidate against a consistent copy of the existing
SQLite database on separate ports. Verify migration integrity, existing accounts
and configuration records, dashboard assets, MCP initialization, tool discovery,
account-scoped reads, invalid-token rejection, and disabled writes. Use a temporary
database for tests that change accounts or configurations.

Open an upgrade PR into `feat/native-http-mcp`, record the new upstream commit
and checks performed, and review it before updating production.

## Release and rollback

Use a custom release identifier such as `2.7.0-leliven.1`, and record the exact
upstream/custom commit SHAs, target, enabled features, and binary SHA256.
Do not imply that a version label alone identifies this fork's contents.

Back up the existing binary, a consistent SQLite snapshot, and service configuration
before replacing a release. Database migrations may make the new database
incompatible with the previous binary. A rollback must use the matching database
backup and account for writes made after the upgrade.

Keep deployment-specific environment files, tokens, databases, logs, backups,
and generated artifacts outside Git. Use placeholders in documentation.

For MCP configuration and tool behavior, see [mcp.md](mcp.md).
