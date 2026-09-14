# Native network package releases

`pnpm network:package` runs the production packaging CLI. Its regression tests remain under
`test/interop` and run with `pnpm test:network-package`.

Pack a clean native checkout using its existing non-instrumented build record:

```sh
pnpm network:package pack --native-dir /path/to/native --out /path/to/lodestar-z.tgz --build-record /path/to/build-record.json
```

Install into a new release and publish its directory through an atomic symlink replacement:

```sh
pnpm network:package install --host-dir /path/to/host-template --manifest /path/to/lodestar-z.tgz.json --evidence-dir /path/to/evidence --release-dir /path/to/releases/native-001 --active-link /path/to/current
pnpm network:package verify --host-dir /path/to/current --manifest /path/to/lodestar-z.tgz.json
```

The template must contain the built host and its installed dependency graph. Installation copies
it, excluding `.git`, then runs the pinned package manager offline with scripts disabled and
package imports copied, so dependency files cannot share writable hardlinks with the template. It
verifies the addon, package exports, workspace consumers, source manifests, and unrelated
dependencies before publishing `current`. Launch the host through that link. Existing processes
retain their loaded code until restarted.

The release and evidence directories must be new and outside the template; `current` must be
absent or a symlink. The copy preserves internal symlinks, rejects links escaping the template,
and caps inventory at 250,000 entries and 32 GiB. Failed installation removes its incomplete
release, retains failure evidence, and leaves the previous link and template unchanged. Previously
published releases remain available for rollback by changing the link.
