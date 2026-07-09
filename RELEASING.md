# Releasing

Releases are automated with [release-please](https://github.com/googleapis/release-please).
It turns the conventional-commit history on `main` (already enforced by the PR title lint)
into release PRs, changelogs, tags, and GitHub releases.

## How it works

1. **Merge PRs to `main` as usual.** Squash-merge titles follow conventional commits
   (`feat:`, `fix:`, `perf:`, ...), which is enforced by `lint-pr-title.yml`.
2. **Release-please maintains a release PR** (titled `chore(release): vX.Y.Z-rc.N`).
   Every push to `main` updates it: it accumulates the pending changelog and bumps the
   version in `package.json`, `build.zig.zon`, and `.release-please-manifest.json`.
3. **Merging the release PR cuts the release.** Release-please creates the git tag
   (`vX.Y.Z-rc.N`), a GitHub release with the changelog, and updates `CHANGELOG.md`.
4. **Publishing to npm happens automatically.** `publish-bindings.yml` triggers on
   release publication and checks out the release tag, so the published package matches
   the tagged commit exactly. The npm dist-tag is derived from the version
   (`0.1.2-rc.11` → `rc`, `0.1.2` → `latest`).

There is deliberately no manual publish trigger: the only path to npm is a reviewed
release PR. The publish workflow additionally refuses to run if the release tag does
not match `package.json`. If a publish run fails (flaky runner, npm outage), rerun the
failed run — `gh run rerun <run-id>` — which re-executes against the same tag.

The version in `.release-please-manifest.json` is the source of truth for the last
released version. Do not hand-edit `package.json` versions in regular PRs.

## Cutting a release

Merge the open release PR. That's it — tag, GitHub release, changelog, and npm publish
follow automatically.

To skip a change from the changelog or force a specific version, see the
[release-please docs](https://github.com/googleapis/release-please/blob/main/README.md)
(`release-as`, `Release-As:` commit footers, etc.).

## Version bumping rules

Configured in `release-please-config.json`:

- The project is on a prerelease train (`versioning: prerelease`, `prerelease-type: rc`):
  releases bump `0.1.2-rc.N` → `0.1.2-rc.N+1`.
- Pre-1.0 semantics (`bump-minor-pre-major`, `bump-patch-for-minor-pre-major`):
  breaking changes bump minor, features bump patch.

### Graduating to a stable release

When ready to ship `0.1.2` (dropping the `-rc.N` suffix), set `"prerelease": false` in
`release-please-config.json`. The next release PR will propose the stable version.
Set it back to `true` (and the next rc train starts) after the stable release is cut.

## One-time cleanup after the first release

`release-please-config.json` currently pins `"last-release-sha"` to the `v0.1.2-rc.9`
release commit. This is a bootstrap workaround: the `v0.1.2-rc.10` tag points to a
commit that is not on `main`, so release-please cannot anchor the changelog range on
its own. **Remove the `last-release-sha` line once the first release-please release
is merged** — it is never ignored automatically, and leaving it in place would make
every future changelog collect commits all the way back to `v0.1.2-rc.9`.

## Repository secrets

`RELEASE_PLEASE_TOKEN` (required): a fine-grained PAT or GitHub App token with
`contents: write` and `pull-requests: write` on this repo. GitHub Actions does not
trigger workflows for events created with the default `GITHUB_TOKEN`, so without this
secret CI would not run on release PRs and `publish-bindings.yml` would never fire on
release publication. Since publishing has no manual trigger, the release-please
workflow fails fast if the secret is missing rather than creating releases that
silently never reach npm.
