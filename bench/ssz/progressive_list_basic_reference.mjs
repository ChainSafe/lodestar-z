// Pass the built ChainSafe SSZ lib/index.js path as the first argument.
import assert from "node:assert/strict";
import {resolve} from "node:path";
import {pathToFileURL} from "node:url";

const {ProgressiveListBasicType, UintNumberType} = await import(
  pathToFileURL(resolve(process.argv[2])).href
);
const itemCount = 1 << 20;
const scatterIndex = (i) => (i * 104729 + 17) % itemCount;
console.log(`${process.version}, 1M items, 2 warmups, 9 samples, milliseconds`);

for (const bytes of [1, 8]) {
  const type = new ProgressiveListBasicType(new UintNumberType(bytes));
  const values = Array.from({length: itemCount}, (_, i) => i % 127);
  const base = type.toViewDU(values);
  base.hashTreeRoot();
  for (const work of ["sparse", "clustered", "dense", "bulk_read"]) {
    const expected = values.slice();
    const count = work === "sparse" ? 512 : work === "clustered" ? 4096 : work === "dense" ? itemCount : 0;
    const indexAt = (i) => work === "sparse" ? scatterIndex(i) : work === "clustered" ? i % 128 : i;
    for (let i = 0; i < count; i++) expected[indexAt(i)] += 1;
    const expectedRoot = Buffer.from(type.hashTreeRoot(expected));
    const samples = [];
    for (let sample = 0; sample < 11; sample++) {
      const start = process.hrtime.bigint();
      const view = base.clone(true);
      let output;
      if (work === "bulk_read") {
        output = view.getAll();
      } else {
        for (let i = 0; i < count; i++) {
          const index = indexAt(i);
          view.set(index, view.get(index) + 1);
        }
      }
      const root = Buffer.from(view.hashTreeRoot());
      const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
      assert.deepEqual(root, expectedRoot);
      if (output) assert.deepEqual(output, expected);
      if (sample >= 2) samples.push(elapsed);
    }
    samples.sort((a, b) => a - b);
    console.log(`u${bytes * 8} ${work}: ${samples[4].toFixed(3)} [${samples[0].toFixed(3)}, ${samples[8].toFixed(3)}]`);
  }
}
