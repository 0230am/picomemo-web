import path from "node:path";
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";

const root = path.resolve(import.meta.dirname, "..");
const lock = JSON.parse(await readFile(path.join(root, "build-lock.json"), "utf8"));
const environment = path.resolve(process.env.PICOMEMO_PYTHON_ENV ?? path.join(root, ".cache/picomemo-python-2.1.0"));
const python = process.platform === "win32" ? path.join(environment, "Scripts/python.exe") : path.join(environment, "bin/python");
const picomemo = path.resolve(process.env.PICOMEMO_SOURCE_DIR ?? path.join(root, `.cache/picomemo-${lock.picomemo.tag}-${lock.picomemo.commit}`));
const work = path.join(root, ".cache/picomemo-interop-2.1.0");
const script = path.join(picomemo, "test/initsession.py");
const binary = path.join(work, "omemo-interop.cjs");
const result = spawnSync(python, [script, "bundle2", binary], {
	cwd: work,
	env: { ...process.env, PYTHONPATH: path.join(work, "o") },
	encoding: "utf8"
});
process.stdout.write(result.stdout);
process.stderr.write(result.stderr);
if (result.error) throw result.error;
if (result.status !== 0) throw new Error(`Bidirectional interoperability failed with exit code ${result.status}.`);
if (!result.stdout.includes("Bidirectional python-twomemo OMEMO 2 interop succeeded")) throw new Error("Interoperability did not emit the locked success marker.");
console.log("BIDIRECTIONAL INTEROPERABILITY PASSED: initial and established OMEMO 2 messages succeeded against python-omemo/Twomemo in both directions.");
