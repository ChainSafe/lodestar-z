# Deployment Notes

## Fix Implementation Policy

When implementing a fix:
- always consult Lodestar-TS first to understand the intended behavior before inventing a local fix
- always devil's-advocate the proposed change and review it for regressions, retry loops, thrash, and other AI-slop behavior
- do not ship temporary workarounds or backstops at this stage of development
- reach at least Lodestar-TS parity before attempting any new behavior or local divergence

## Nogroup Host

Target host:
- `devops@nogroup-rs2000-0`

Remote source tree:
- `/home/devops/src/lodestar-z-beacon-node-3`

Remote Zig toolchain:
- `/home/devops/opt/zig-0.16.0/zig`

Systemd service:
- `beacon.service`

Service runner:
- `/home/beacon/beacon_run.sh`

Live binary path:
- `/home/beacon/lodestar-z/lodestar-z`

Important ownership detail:
- `/home/beacon` is `0751` so non-owners can traverse it without listing it
- `/home/beacon/lodestar-z` is owned by `devops:devops`
- the live binary under `/home/beacon/lodestar-z/lodestar-z` is developer-writable
- `devops` has passwordless `sudo`
- `sudo` is still required for `systemctl restart`, but not for installing the binary

## Deployment Lane

Use one persistent remote worktree and keep its caches hot.

Do:
- sync source into `/home/devops/src/lodestar-z-beacon-node-3`
- keep remote `.zig-cache`, `zig-out`, and the global Zig cache in place
- build in that same directory every time with the same Zig version and flags
- install the finished binary directly into `/home/beacon/lodestar-z/lodestar-z`
- restart `beacon.service`
- verify the running SHA and recent logs

Do not:
- build in a fresh temp directory for normal deploys
- sync `zig-pkg`, `.zig-cache`, or `zig-out*` from local to remote
- use the old feature-branch-style deploy directory for new rollouts

## Recommended Commands

Source-only sync:

```bash
rsync -az --delete \
  --exclude='.git' \
  --exclude='.zig-cache' \
  --exclude='zig-out*' \
  --exclude='zig-pkg' \
  /home/cayman/Code/lodestar-z-beacon-node-3/ \
  devops@nogroup-rs2000-0:/home/devops/src/lodestar-z-beacon-node-3/
```

Remote build:

```bash
ssh devops@nogroup-rs2000-0 \
  'cd /home/devops/src/lodestar-z-beacon-node-3 && /home/devops/opt/zig-0.16.0/zig build -Doptimize=ReleaseSafe'
```

Install live binary:

```bash
ssh devops@nogroup-rs2000-0 \
  'install -m 0755 /home/devops/src/lodestar-z-beacon-node-3/zig-out/bin/lodestar-z /home/beacon/lodestar-z/lodestar-z'
```

Restart:

```bash
ssh devops@nogroup-rs2000-0 'sudo systemctl restart beacon.service'
```

Verify:

```bash
ssh devops@nogroup-rs2000-0 'systemctl is-active beacon.service'
ssh devops@nogroup-rs2000-0 'systemctl show beacon.service -p MainPID'
ssh devops@nogroup-rs2000-0 'sha256sum /home/beacon/lodestar-z/lodestar-z'
ssh devops@nogroup-rs2000-0 'journalctl -u beacon.service -n 40 --no-pager'
```

## Why This Is The Fast Path

Zig 0.16.0 has much better incremental compilation support, but the reliable speedup for this repository comes first from preserving cache directories and reusing the same build tree.

Practical consequence:
- the remote worktree should stay stable
- `.zig-cache` should stay on disk
- `/home/devops/.cache/zig` should stay on disk
- repeated `zig build -Doptimize=ReleaseSafe` invocations in the same tree should get faster than rebuilding from a fresh checkout

## Incremental Compilation Policy

For production deploy artifacts:
- prefer plain `zig build -Doptimize=ReleaseSafe`
- do not enable `-fincremental` in the deploy lane by default yet

Reason:
- Zig 0.16.0 release notes say incremental compilation is much improved, but still has known bugs and remains disabled by default

For local development loops:
- `zig build -fincremental --watch` is worth testing
- if it proves stable for this repo, it can be adopted for edit-build-test cycles
- keep it out of the release deploy path until it has earned trust here

## Operational Notes

- `beacon_run.sh` hard-codes the live binary path and current hoodi/no_group runtime flags
- if deployment fails at the install step now, check `/home/beacon` mode and `/home/beacon/lodestar-z` ownership first
- if sync is unexpectedly slow, check whether `zig-pkg` was excluded
- if build speed regresses, check whether the remote worktree or `.zig-cache` was recreated
