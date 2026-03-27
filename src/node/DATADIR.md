# Data Directory Layout

This document defines the directory structure used by lodestar-z.

## Directory Tree

```
<dataDir>/                              # --data-dir (default: ~/.local/share/lodestar-z/<network>/)
├── beacon-node/
│   ├── db/                             # LMDB environment (chain data)
│   │   ├── data.mdb                    # LMDB data file
│   │   └── lock.mdb                    # LMDB lock file
│   ├── network/
│   │   ├── enr-key                     # secp256k1 private key for ENR/discv5
│   │   └── peer-db/                    # persistent peer scores/metadata
│   └── state-cache/                    # (future: persistent checkpoint states)
├── validator/
│   ├── slashing-protection.db          # append-only slashing protection
│   ├── keystores/                      # EIP-2335 keystore files
│   │   ├── 0x1234...abcd/
│   │   │   └── voting-keystore.json
│   │   └── 0x5678...ef01/
│   │       └── voting-keystore.json
│   └── secrets/                        # password files (one per keystore)
│       ├── 0x1234...abcd
│       └── 0x5678...ef01
├── logs/                               # (if --log-file enabled)
│   └── lodestar-z.log
└── jwt.hex                             # Engine API JWT secret
```

## Path Resolution

### Root data directory

`--data-dir` sets the root. When omitted, the default is:

- **Linux/BSD:** `$XDG_DATA_HOME/lodestar-z/<network>/`  
  Falls back to `~/.local/share/lodestar-z/<network>/` when `XDG_DATA_HOME` is unset.
- **macOS:** `~/Library/Application Support/lodestar-z/<network>/`

### Network subdirectory

`--network` determines the subdirectory under the base:

| Network | Default path |
|---------|-------------|
| `mainnet` | `~/.local/share/lodestar-z/mainnet/` |
| `sepolia` | `~/.local/share/lodestar-z/sepolia/` |
| `hoodi` | `~/.local/share/lodestar-z/hoodi/` |
| `holesky` | `~/.local/share/lodestar-z/holesky/` |
| `goerli` | `~/.local/share/lodestar-z/goerli/` |
| `minimal` | `~/.local/share/lodestar-z/minimal/` |

Custom networks (via `--params-file`) use `custom-<hash>/`.

### Override flags

Individual paths can be overridden independently of `--data-dir`:

| Flag | Default (relative to `--data-dir`) |
|------|------------------------------------|
| `--db-path` | `beacon-node/db` |
| `--jwt-secret` | `jwt.hex` (auto-generated on first run) |
| `--log-file` | `logs/lodestar-z.log` |

### BN / VC co-location

- BN and VC can share the same `--data-dir`; they use non-overlapping subdirs (`beacon-node/` vs `validator/`).
- The validator client can also run standalone with a separate `--data-dir` and `--beacon-node-url`.

## JWT Secret

The file `jwt.hex` contains the Engine API shared secret as 64 hex characters (32 bytes), optionally prefixed with `0x`. On first run the node auto-generates a random secret and writes it. The same secret must be provided to the execution engine (`--authrpc.jwtsecret` in Geth, etc.).

## Node Identity

`beacon-node/network/enr-key` stores the hex-encoded secp256k1 secret key used for discv5 and libp2p. It is generated on first run and persisted so the node keeps a stable identity across restarts.

## Validator Keystores

EIP-2335 encrypted keystores are stored as `keystores/<pubkey>/voting-keystore.json`. Corresponding password files live in `secrets/<pubkey>` (plain text, one password per file). The pubkey directory name should be the full `0x`-prefixed BLS public key hex string.
