import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";

export const MBEDTLS_BUILD_CONFIGURATION = Object.freeze({
    schemaVersion: 1,
    command: ["emmake", "make", "-C", "$MBEDTLS", "PYTHON=$EMSDK_PYTHON", "lib"],
    target: "wasm32-emscripten",
    environmentOverrides: {},
});

export async function assertPinnedGit(directory, expectedCommit, expectedTree, name) {
    const head = git(directory, ["rev-parse", "HEAD"]);
    if (head !== expectedCommit) throw new Error(`${name} is not at locked commit ${expectedCommit}.`);
    const tree = git(directory, ["rev-parse", "HEAD^{tree}"]);
    if (expectedTree && tree !== expectedTree) throw new Error(`${name} does not have locked tree ${expectedTree}.`);
    const status = git(directory, ["status", "--porcelain=v1", "--untracked-files=all"]);
    if (status !== "") throw new Error(`${name} worktree is dirty:\n${status}`);
}

export async function assertEmscripten(directory, lock) {
    await assertPinnedGit(directory, lock.commit, undefined, "Emscripten SDK");
    const emcc = path.join(directory, "upstream/emscripten", process.platform === "win32" ? "emcc.exe" : "emcc");
    if (!existsSync(emcc)) throw new Error("The locked Emscripten compiler is missing.");
    const version = spawnSync(emcc, ["--version"], { encoding: "utf8" });
    if (version.status !== 0 || version.stdout.split(/\r?\n/)[0] !== lock.emccVersion) throw new Error("Emscripten compiler identity does not match the lock.");
}

export async function assertMbedTLS({ archive, directory, lock }) {
    if (await sha256(archive) !== lock.sha256) throw new Error("Mbed TLS archive does not match its lock.");
    if (await hashMbedTLSInputs(directory) !== lock.sourceInputsSha256) throw new Error("Mbed TLS extracted source inputs do not match their lock.");
    if (hashJSON(MBEDTLS_BUILD_CONFIGURATION) !== lock.buildConfigurationSha256) throw new Error("Mbed TLS build configuration does not match its lock.");
    if (await sha256(path.join(directory, "library/libmbedcrypto.a")) !== lock.librarySha256) throw new Error("Mbed TLS library does not match its lock.");
}

export async function hashMbedTLSInputs(directory) {
    const files = await collectFiles(directory);
    const hash = createHash("sha256");
    for (const relative of files) {
        hash.update(relative);
        hash.update("\0");
        hash.update(await sha256(path.join(directory, relative)));
        hash.update("\0");
    }
    return hash.digest("hex");
}

export function hashJSON(value) { return createHash("sha256").update(JSON.stringify(value)).digest("hex"); }
export async function sha256(file) { return createHash("sha256").update(await readFile(file)).digest("hex"); }

async function collectFiles(directory) {
    const files = [];
    await visit("");
    return files.sort();

    async function visit(relative) {
        for (const entry of await readdir(path.join(directory, relative), { withFileTypes: true })) {
            const child = path.join(relative, entry.name);
            if (isBuildOutput(child)) continue;
            if (entry.isDirectory()) await visit(child);
            else if (entry.isFile()) files.push(child.replaceAll("\\", "/"));
            else throw new Error(`Unsupported Mbed TLS cache entry: ${child}.`);
        }
    }
}

function isBuildOutput(relative) {
    const normalized = relative.replaceAll("\\", "/");
    return normalized === ".picomemo-web-build.json" ||
        normalized === "library/psa_crypto_driver_wrappers.h" || normalized === "library/psa_crypto_driver_wrappers_no_static.c" ||
        normalized === "tests/seedfile" || /(?:^|\/)__pycache__\//.test(normalized) || /\.(?:a|d|o|pyc)$/i.test(normalized);
}

function git(directory, args) {
    const result = spawnSync("git", ["-c", `safe.directory=${directory}`, "-C", directory, ...args], { encoding: "utf8" });
    if (result.status !== 0) throw new Error(`Could not verify ${directory}: ${result.stderr.trim()}`);
    return result.stdout.trim();
}
