import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const metadata = JSON.parse(await readFile(new URL("../source-metadata.json", import.meta.url), "utf8"));
test("source metadata records the exact clean native commit", () => {
    assert.equal(metadata.picomemo.commit, "a4bad0297ea72ee75fbdb4afc899f65e8d85ae74");
    assert.equal(metadata.picomemo.tree, "011b0bd1a0f4109856f7dfb633383efbe313cd3e");
    assert.equal(metadata.picomemo.dirty, false);
    assert.equal("patchSha256" in metadata.picomemo, false);
});
for (const [file, property] of [["picomemo.d.mts", "declarationSha256"], ["picomemo.mjs", "loaderSha256"], ["picomemo.wasm", "wasmSha256"]]) {
    test(`${file} retains its reviewed bytes`, async () => {
        const content = await readFile(new URL(`../dist/generated/${file}`, import.meta.url));
        assert.equal(createHash("sha256").update(content).digest("hex"), metadata.artifacts[property]);
    });
}
