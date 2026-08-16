import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const metadata = JSON.parse(await readFile(new URL("../source-metadata.json", import.meta.url), "utf8"));
test("source metadata records the exact clean native commit", () => {
    assert.equal(metadata.picomemo.commit, "06f4ca967005dbdc22fe775f67f25d75936b7cdc");
    assert.equal(metadata.picomemo.tree, "d3c941ec4070ebdb2f4ee5d52d7494d4fd45e26f");
    assert.equal(metadata.picomemo.dirty, false);
    assert.equal("patchSha256" in metadata.picomemo, false);
});
for (const [file, property] of [["picomemo.d.mts", "declarationSha256"], ["picomemo.mjs", "loaderSha256"], ["picomemo.wasm", "wasmSha256"]]) {
    test(`${file} retains its reviewed bytes`, async () => {
        const content = await readFile(new URL(`../dist/generated/${file}`, import.meta.url));
        assert.equal(createHash("sha256").update(content).digest("hex"), metadata.artifacts[property]);
    });
}
