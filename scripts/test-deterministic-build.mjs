import { createHash } from "node:crypto";
import { readFile, rm } from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";

const root = path.resolve(import.meta.dirname, "..");
const first = path.join(root, ".cache/determinism-a");
const second = path.join(root, ".cache/determinism-b");
for (const directory of [first, second]) {
    if (!directory.startsWith(`${path.join(root, ".cache")}${path.sep}`)) throw new Error("Unsafe deterministic build path.");
    await rm(directory, { recursive: true, force: true });
    const result = spawnSync(process.execPath, [path.join(root, "scripts/build-wasm.mjs"), `--output=${path.relative(root, directory)}`], { cwd: root, stdio: "inherit", env: process.env });
    if (result.status !== 0) throw new Error(`Locked build failed with exit code ${result.status}.`);
}
for (const file of ["picomemo.d.mts", "picomemo.mjs", "picomemo.wasm"]) {
    const left = createHash("sha256").update(await readFile(path.join(first, file))).digest("hex");
    const right = createHash("sha256").update(await readFile(path.join(second, file))).digest("hex");
    if (left !== right) throw new Error(`${file} was not byte-identical across clean builds.`);
    console.log(`${file} ${left}`);
}

