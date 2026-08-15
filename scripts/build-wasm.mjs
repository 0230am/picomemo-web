import { copyFile, mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { assertEmscripten, assertMbedTLS, assertPinnedGit, sha256 } from "./cache-integrity.mjs";

const root = path.resolve(import.meta.dirname, "..");
const lock = JSON.parse(await readFile(path.join(root, "build-lock.json"), "utf8"));
const source = path.resolve(process.env.PICOMEMO_SOURCE_DIR ?? path.join(root, `.cache/picomemo-${lock.picomemo.tag}-${lock.picomemo.commit}`));
const emsdk = path.resolve(process.env.PICOMEMO_EMSDK_DIR ?? path.join(root, `.cache/emsdk-${lock.emscripten.version}`));
const mbedtls = path.resolve(process.env.PICOMEMO_MBEDTLS_DIR ?? path.join(root, `.cache/mbedtls-${lock.mbedtls.version}-${lock.mbedtls.sourceInputsSha256.slice(0, 12)}-${lock.mbedtls.buildConfigurationSha256.slice(0, 12)}`));
const archive = path.resolve(process.env.PICOMEMO_MBEDTLS_ARCHIVE ?? path.join(root, `.cache/mbedtls-${lock.mbedtls.version}.tar.bz2`));
const sourcePathRoot = path.resolve(process.env.PICOMEMO_SOURCE_PATH_ROOT ?? root);
const outputArgument = process.argv.find((argument) => argument.startsWith("--output="));
const output = path.resolve(root, outputArgument?.slice("--output=".length) ?? ".cache/generated");
if (!output.startsWith(`${root}${path.sep}`)) throw new Error("WASM output must remain inside the repository.");

await assertPinnedGit(source, lock.picomemo.commit, lock.picomemo.tree, "picomemo source");
await assertEmscripten(emsdk, lock.emscripten);
await assertMbedTLS({ archive, directory: mbedtls, lock: lock.mbedtls });
await mkdir(output, { recursive: true });

const emcc = path.join(emsdk, "upstream/emscripten", process.platform === "win32" ? "emcc.exe" : "emcc");
const exports = "['_malloc','_free','_picomemoWebInitialize','_picomemoWebSetupStore','_picomemoWebGetBundle','_picomemoWebReplenishStore','_picomemoWebInitiateSession','_picomemoWebEncryptKey','_picomemoWebGetSessionIdentity','_picomemoWebMaintainSession','_picomemoWebDecryptKey','_picomemoWebEncryptMessage','_picomemoWebDecryptMessage','_picomemoWeb0SetupStore','_picomemoWeb0GetBundle','_picomemoWeb0ReplenishStore','_picomemoWeb0InitiateSession','_picomemoWeb0EncryptKey','_picomemoWeb0GetSessionIdentity','_picomemoWeb0DecryptKey','_picomemoWeb0EncryptMessage','_picomemoWeb0DecryptMessage','_picomemoWebHeapSize']";
const runtimeExports = "['HEAPU8','HEAPU32']";
run(emcc, [
    path.join(root, "native/picomemo_web.c"),
    path.join(source, "gen/omemo0.c"), path.join(source, "gen/omemo2.c"), path.join(source, "hacl.c"), path.join(source, "mbedtls.c"),
    path.join(mbedtls, "library/libmbedcrypto.a"),
    "-I", source, "-I", path.join(source, "gen"), "-I", path.join(mbedtls, "include"),
    `-ffile-prefix-map=${sourcePathRoot}=.`, `-ffile-prefix-map=${root}=.`,
    "-O2", "-flto", "-s", "MODULARIZE=1", "-s", "EXPORT_ES6=1", "-s", "ENVIRONMENT=worker", "-s", "FILESYSTEM=0",
    "-s", "ALLOW_MEMORY_GROWTH=1", "-s", "INITIAL_MEMORY=16777216", "-s", "MAXIMUM_MEMORY=67108864", "-s", "STACK_SIZE=1048576",
    "-s", "MALLOC=emmalloc", "-s", "ASSERTIONS=1", "-s", "DYNAMIC_EXECUTION=0",
    "-s", `EXPORTED_FUNCTIONS=${exports}`, "-s", `EXPORTED_RUNTIME_METHODS=${runtimeExports}`, "-o", path.join(output, "picomemo.mjs"),
]);
await copyFile(path.join(root, "native/picomemo.d.mts"), path.join(output, "picomemo.d.mts"));

for (const [file, expected] of [["picomemo.d.mts", lock.productionArtifact.declarationSha256], ["picomemo.mjs", lock.productionArtifact.loaderSha256], ["picomemo.wasm", lock.productionArtifact.wasmSha256]]) {
    const actual = await sha256(path.join(output, file));
    if (actual !== expected) throw new Error(`${file} changed during the locked source build: expected ${expected}, received ${actual}.`);
}
console.log(`Locked source build reproduced all reviewed artifacts in ${output}.`);

function run(command, args) {
    const result = spawnSync(command, args, { cwd: root, stdio: "inherit" });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`${path.basename(command)} failed with exit code ${result.status}.`);
}
