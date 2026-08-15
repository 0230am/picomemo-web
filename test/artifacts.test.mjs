import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const metadata = JSON.parse(await readFile(new URL("../source-metadata.json", import.meta.url), "utf8"));
for (const [file, property] of [["picomemo.d.mts", "declarationSha256"], ["picomemo.mjs", "loaderSha256"], ["picomemo.wasm", "wasmSha256"]]) {
    test(`${file} retains its reviewed bytes`, async () => {
        const content = await readFile(new URL(`../dist/generated/${file}`, import.meta.url));
        assert.equal(createHash("sha256").update(content).digest("hex"), metadata.artifacts[property]);
    });
}

