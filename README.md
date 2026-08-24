# lodestar-z

Zig consensus modules for [Lodestar](https://github.com/chainsafe/lodestar), the TypeScript Ethereum consensus client.
Modules are implemented in Zig and exposed to Node.js through NAPI bindings.

## Installation

```sh
zig fetch --save git+https://github.com/ChainSafe/lodestar-z
```

### Spec Test Compliance

`lodestar-z` is compliant against the spec tests version specified in `build.zig.zon`
under `options_modules.spec_test_options`.

## Contributing to Lodestar-z

We welcome all contributions, but are strict about quality.
Before contributing, please read [CONTRIBUTING](./CONTRIBUTING.md) and the
relevant links inside (most importantly, our [AI_POLICY](./AI_POLICY.md)).

We may deprioritize or close low-effort issues and pull requests at our discretion.

## License

Apache-2.0
