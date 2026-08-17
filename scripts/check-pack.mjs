import { execFileSync } from "node:child_process";

const npm = process.env.npm_execpath;
if (!npm) throw new Error("Run this check through npm run pack:check.");
const result = JSON.parse(execFileSync(process.execPath, [npm, "pack", "--dry-run", "--json"], { encoding: "utf8" }))[0];
const files = result.files.map(({ path }) => path).sort();
const required = [
    "LICENSE",
    "LICENSES/HACL-KaRaMeL-MIT.txt",
    "LICENSES/NOTICE.txt",
    "LICENSES/emscripten-LICENSE.txt",
    "LICENSES/mbedtls-LICENSE.txt",
    "LICENSES/musl-COPYRIGHT.txt",
    "LICENSES/picomemo-ISC.txt",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "dist/generated/picomemo.d.mts",
    "dist/generated/picomemo.mjs",
    "dist/generated/picomemo.wasm",
    "dist/index.d.ts",
    "dist/index.js",
    "dist/metadata.d.ts",
    "dist/metadata.js",
    "dist/types.d.ts",
    "dist/types.js",
    "dist/uniform-random.d.ts",
    "dist/uniform-random.js",
    "dist/worker.d.ts",
    "dist/worker.js",
    "package.json",
    "source-metadata.json",
].sort();
if (JSON.stringify(files) !== JSON.stringify(required)) throw new Error(`Unexpected npm package contents:\n${files.join("\n")}`);
console.log(JSON.stringify({ filename: result.filename, size: result.size, unpackedSize: result.unpackedSize, files }, null, 2));
