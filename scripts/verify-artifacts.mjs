import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";

const directory = path.resolve(process.argv[2] ?? "src/generated");
const metadata = JSON.parse(await readFile(new URL("../source-metadata.json", import.meta.url), "utf8"));
const expected = new Map([
    ["picomemo.d.mts", metadata.artifacts.declarationSha256],
    ["picomemo.mjs", metadata.artifacts.loaderSha256],
    ["picomemo.wasm", metadata.artifacts.wasmSha256],
]);

for (const [file, digest] of expected) {
    const content = await readFile(path.join(directory, "generated", file).replace(`${path.sep}generated${path.sep}generated${path.sep}`, `${path.sep}generated${path.sep}`));
    const actual = createHash("sha256").update(content).digest("hex");
    if (actual !== digest) throw new Error(`${file} SHA-256 changed: expected ${digest}, received ${actual}.`);
}

console.log(`Verified locked declaration, loader, and WASM in ${directory}.`);

