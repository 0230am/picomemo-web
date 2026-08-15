import { cp, mkdir } from "node:fs/promises";
import path from "node:path";

const source = path.resolve("src/generated");
const target = path.resolve("dist/generated");
await mkdir(target, { recursive: true });
for (const file of ["picomemo.d.mts", "picomemo.mjs", "picomemo.wasm"]) await cp(path.join(source, file), path.join(target, file));

