import { createHash } from "node:crypto";
import { createWriteStream, existsSync } from "node:fs";
import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { Readable } from "node:stream";
import { finished } from "node:stream/promises";
import { spawnSync } from "node:child_process";
import { assertEmscripten, assertMbedTLS, assertPinnedGit, hashJSON, hashMbedTLSInputs, MBEDTLS_BUILD_CONFIGURATION, sha256 } from "./cache-integrity.mjs";

const root = path.resolve(import.meta.dirname, "..");
const cache = path.join(root, ".cache");
const lock = JSON.parse(await readFile(path.join(root, "build-lock.json"), "utf8"));
const source = path.join(cache, `picomemo-${lock.picomemo.tag}-${lock.picomemo.commit}`);
const emsdk = path.join(cache, `emsdk-${lock.emscripten.version}`);
const mbedtls = path.join(cache, `mbedtls-${lock.mbedtls.version}-${lock.mbedtls.sourceInputsSha256.slice(0, 12)}-${lock.mbedtls.buildConfigurationSha256.slice(0, 12)}`);
const archive = path.join(cache, `mbedtls-${lock.mbedtls.version}.tar.bz2`);
const pythonEnvironment = path.join(cache, "picomemo-python-2.1.0");

await mkdir(cache, { recursive: true });
await clonePinned(lock.picomemo.repository, lock.picomemo.commit, source);
await assertPinnedGit(source, lock.picomemo.commit, lock.picomemo.tree, "picomemo source");
const emsdkExisted = existsSync(emsdk);
await clonePinned(lock.emscripten.repository, lock.emscripten.version, emsdk);
if (!emsdkExisted) installEmscripten();
await assertEmscripten(emsdk, lock.emscripten);
await downloadPinned(lock.mbedtls.url, archive, lock.mbedtls.sha256);
await prepareMbedTLS();
await preparePython();
console.log("Locked picomemo source, Emscripten, Mbed TLS, and Python interoperability environment are ready.");

async function clonePinned(repository, commit, directory) {
    if (existsSync(directory)) return;
    const staging = `${directory}.bootstrap`;
    if (existsSync(staging)) throw new Error(`Incomplete bootstrap directory exists: ${staging}. Remove it manually after inspection.`);
    run("git", ["clone", "--filter=blob:none", "--no-checkout", repository, staging]);
    run("git", ["-C", staging, "fetch", "--depth=1", "origin", commit]);
    run("git", ["-C", staging, "checkout", "--detach", commit]);
    await rename(staging, directory);
}

function installEmscripten() {
    const script = path.join(emsdk, process.platform === "win32" ? "emsdk.bat" : "emsdk");
    if (process.platform === "win32") {
        run("cmd.exe", ["/d", "/s", "/c", `"${script}" install ${lock.emscripten.version}`]);
        run("cmd.exe", ["/d", "/s", "/c", `"${script}" activate ${lock.emscripten.version}`]);
    } else {
        run(script, ["install", lock.emscripten.version]);
        run(script, ["activate", lock.emscripten.version]);
    }
}

async function downloadPinned(url, target, expected) {
    if (!existsSync(target)) {
        const response = await fetch(url, { redirect: "follow" });
        if (!response.ok || !response.body) throw new Error(`Download failed: ${response.status} ${url}`);
        await finished(Readable.fromWeb(response.body).pipe(createWriteStream(target, { flags: "wx" })));
    }
    if (await sha256(target) !== expected) throw new Error(`Downloaded archive hash changed: ${target}.`);
}

async function prepareMbedTLS() {
    if (existsSync(mbedtls)) {
        await assertMbedTLS({ archive, directory: mbedtls, lock: lock.mbedtls });
        return;
    }
    const staging = `${mbedtls}.bootstrap`;
    if (existsSync(staging)) throw new Error(`Incomplete Mbed TLS bootstrap exists: ${staging}. Remove it manually after inspection.`);
    await mkdir(staging);
    run("tar", ["-xjf", archive, "-C", staging, "--strip-components=1"]);
    if (await hashMbedTLSInputs(staging) !== lock.mbedtls.sourceInputsSha256) throw new Error("Extracted Mbed TLS source inputs changed.");
    if (hashJSON(MBEDTLS_BUILD_CONFIGURATION) !== lock.mbedtls.buildConfigurationSha256) throw new Error("Mbed TLS build configuration changed.");
    const python = await findEmscriptenPython();
    run(python, ["-m", "pip", "install", "-r", path.join(staging, "scripts/basic.requirements.txt")]);
    const emmake = path.join(emsdk, "upstream/emscripten", process.platform === "win32" ? "emmake.exe" : "emmake");
    run(emmake, ["make", "-C", staging, `PYTHON=${python}`, "lib"]);
    if (await sha256(path.join(staging, "library/libmbedcrypto.a")) !== lock.mbedtls.librarySha256) throw new Error("Mbed TLS library output changed.");
    await writeFile(path.join(staging, ".picomemo-web-build.json"), `${JSON.stringify({ schemaVersion: 1, archiveSha256: lock.mbedtls.sha256, sourceInputsSha256: lock.mbedtls.sourceInputsSha256, buildConfigurationSha256: lock.mbedtls.buildConfigurationSha256, emscriptenCommit: lock.emscripten.commit, librarySha256: lock.mbedtls.librarySha256 }, null, 2)}\n`, { flag: "wx" });
    await rename(staging, mbedtls);
    await assertMbedTLS({ archive, directory: mbedtls, lock: lock.mbedtls });
}

async function findEmscriptenPython() {
    for (const entry of await readdir(path.join(emsdk, "python"), { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        const candidate = path.join(emsdk, "python", entry.name, process.platform === "win32" ? "python.exe" : "bin/python3");
        if (existsSync(candidate)) return candidate;
    }
    throw new Error("Pinned Emscripten Python runtime was not found.");
}

async function preparePython() {
    const executable = process.platform === "win32" ? path.join(pythonEnvironment, "Scripts/python.exe") : path.join(pythonEnvironment, "bin/python");
    const host = process.env.PYTHON ?? "python";
    const version = spawnSync(host, ["-c", "import platform; print(platform.python_version())"], { encoding: "utf8" });
    if (version.status !== 0 || version.stdout.trim() !== lock.pythonInterop.python) throw new Error(`Python ${lock.pythonInterop.python} is required; set PYTHON to that interpreter.`);
    if (!existsSync(pythonEnvironment)) {
        run(host, ["-m", "venv", pythonEnvironment]);
        run(executable, ["-m", "pip", "install", "--require-hashes", "-r", path.join(root, "test/interop/requirements.lock")]);
    }
    const packages = spawnSync(executable, ["-m", "pip", "list", "--format=json", "--disable-pip-version-check"], { encoding: "utf8" });
    if (packages.status !== 0) throw new Error("Could not audit Python interoperability environment.");
    const installed = new Map(JSON.parse(packages.stdout).map((item) => [item.name.toLowerCase(), item.version]));
    if (installed.get("pip") !== lock.pythonInterop.pip || installed.get("omemo") !== lock.pythonInterop.omemo || installed.get("twomemo") !== lock.pythonInterop.twomemo) throw new Error("Python interoperability package versions do not match the lock.");
}

function run(command, args) {
    const result = spawnSync(command, args, { cwd: root, stdio: "inherit" });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`${path.basename(command)} failed with exit code ${result.status}.`);
}
