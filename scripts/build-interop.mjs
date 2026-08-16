import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { assertEmscripten, assertMbedTLS, assertPinnedGit } from "./cache-integrity.mjs";

const root = path.resolve(import.meta.dirname, "..");
const lock = JSON.parse(await readFile(path.join(root, "build-lock.json"), "utf8"));
const picomemo = path.resolve(process.env.PICOMEMO_SOURCE_DIR ?? path.join(root, `.cache/picomemo-${lock.picomemo.tag}-${lock.picomemo.commit}`));
const mbedtls = path.resolve(process.env.PICOMEMO_MBEDTLS_DIR ?? path.join(root, `.cache/mbedtls-${lock.mbedtls.version}-${lock.mbedtls.sourceInputsSha256.slice(0, 12)}-${lock.mbedtls.buildConfigurationSha256.slice(0, 12)}`));
const emsdk = path.resolve(process.env.PICOMEMO_EMSDK_DIR ?? path.join(root, `.cache/emsdk-${lock.emscripten.version}`));
const work = path.join(root, ".cache/picomemo-interop-2.1.0");
const fixtures = path.join(work, "o");
const emcc = path.join(emsdk, "upstream/emscripten", process.platform === "win32" ? "emcc.exe" : "emcc");
const archive = path.resolve(process.env.PICOMEMO_MBEDTLS_ARCHIVE ?? path.join(root, `.cache/mbedtls-${lock.mbedtls.version}.tar.bz2`));

await assertPinnedGit(picomemo, lock.picomemo.commit, lock.picomemo.tree, "picomemo source", lock.picomemo.patchSha256);
await assertEmscripten(emsdk, lock.emscripten);
await assertMbedTLS({ archive, directory: mbedtls, lock: lock.mbedtls });
await mkdir(fixtures, { recursive: true });
const generator = gitShow("test/generate.c")
	.replace("FILE *f;", "FILE *f;\n\nstatic int PicomemoWebFixtureRandom(void *p, size_t n) {\n  uint8_t *bytes = p;\n  for (size_t i = 0; i < n; i++) bytes[i] = (uint8_t)(i * 31 + n);\n  return 0;\n}")
	.replace("  struct omemoStore store;", "  omemoSetCallbacks(NULL, NULL, PicomemoWebFixtureRandom);\n  struct omemoStore store;");
const generatorSource = path.join(work, "generate.c");
await writeFile(generatorSource, generator);
compile(generatorSource, path.join(work, "generate.cjs"), true);
run("node", [path.join(work, "generate.cjs"), path.join(fixtures, "store2.inc"), path.join(fixtures, "bundle2.py")], work);
compile(generatorSource, path.join(work, "generate0.cjs"), true, false);
run("node", [path.join(work, "generate0.cjs"), path.join(fixtures, "store.inc"), path.join(fixtures, "bundle.py")], work);

const omemoPath = path.join(picomemo, "omemo.c").replaceAll("\\", "/");
const tests = (await readFile(path.join(picomemo, "test/omemo.c"), "utf8")).replace('#include "../omemo.c"', `#include "${omemoPath}"`);
const vectorsSource = path.join(work, "omemo-vectors.c");
const interopSource = path.join(work, "omemo-interop.c");
await writeFile(vectorsSource, tests);
await writeFile(interopSource, gitShow("test/interop-omemo2.c"));
compile(vectorsSource, path.join(work, "omemo-vectors.cjs"), false);
compile(interopSource, path.join(work, "omemo-interop.cjs"), true);
run("node", [path.join(work, "omemo-vectors.cjs")], work);
console.log("UPSTREAM VECTORS PASSED: exact pinned picomemo OMEMO 2 suite succeeded.");

for (const version of ["omemo0", "omemo2"]) {
	const generatedPath = path.join(picomemo, `gen/${version}.c`).replaceAll("\\", "/");
	const generatedTests = (await readFile(path.join(picomemo, "test/omemo.c"), "utf8"))
		.replace('#include "../omemo.c"', `#include "${generatedPath}"`)
		.replaceAll("OMEMO_", `${version.toUpperCase()}_`)
		.replace(/omemo([A-Z])/g, `${version}$1`)
		.replaceAll(`${version}Driver`, "omemoDriver");
	const source = path.join(work, `${version}-generated-vectors.c`);
	const output = path.join(work, `${version}-generated-vectors.cjs`);
	await writeFile(source, generatedTests);
	compileGenerated(source, output, version === "omemo2");
	run("node", [output], work);
}
console.log("GENERATED NATIVE VECTORS PASSED: OMEMO0 and OMEMO2 generated cores preserve session/skipped state across authenticated and padding failures.");

function compile(source, output, includeCore, omemo2 = true) {
	const args = [
		source,
		...(includeCore ? [path.join(picomemo, "omemo.c")] : []),
		path.join(picomemo, "gen/omemo2.c"),
		path.join(picomemo, "hacl.c"),
		path.join(picomemo, "mbedtls.c"),
		path.join(mbedtls, "library/libmbedcrypto.a"),
		...(omemo2 ? ["-DOMEMO2"] : []),
		"-I", work,
		"-I", picomemo,
		"-I", path.join(picomemo, "gen"),
		"-I", path.join(mbedtls, "include"),
		"-O2", "-flto", "-s", "EXIT_RUNTIME=1", "-s", "NODERAWFS=1"
	];
	args.push("-o", output);
	run(emcc, args, root);
}

function compileGenerated(source, output, omemo2) {
	const args = [
		source,
		path.join(picomemo, "hacl.c"),
		path.join(picomemo, "mbedtls.c"),
		path.join(mbedtls, "library/libmbedcrypto.a"),
		...(omemo2 ? ["-DOMEMO2"] : []),
		"-I", work,
		"-I", picomemo,
		"-I", path.join(picomemo, "gen"),
		"-I", path.join(mbedtls, "include"),
		"-O2", "-flto", "-s", "EXIT_RUNTIME=1", "-s", "NODERAWFS=1",
		"-o", output,
	];
	run(emcc, args, root);
}

function gitShow(file) {
	const result = spawnSync("git", ["-c", `safe.directory=${picomemo}`, "-C", picomemo, "show", `HEAD:${file}`], { encoding: "utf8" });
	if (result.status !== 0) throw new Error(`Could not read pinned picomemo ${file}.`);
	return result.stdout;
}

function run(command, args, cwd) {
	const result = spawnSync(command, args, { cwd, stdio: "inherit" });
	if (result.error) throw result.error;
	if (result.status !== 0) throw new Error(`${path.basename(command)} failed with exit code ${result.status}.`);
}
