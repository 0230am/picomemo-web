import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { assertMbedTLS, assertPinnedGit, gitPatchSha256, hashJSON, hashMbedTLSInputs, MBEDTLS_BUILD_CONFIGURATION, sha256 } from "../scripts/cache-integrity.mjs";

test("rejects commit, tree, tracked, and untracked source mutations", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "picomemo-web-cache-"));
    try {
        git(directory, ["init", "-q"]);
        await writeFile(path.join(directory, "source.txt"), "locked\n");
        git(directory, ["add", "source.txt"]);
        git(directory, ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "locked"]);
        const commit = git(directory, ["rev-parse", "HEAD"]);
        const tree = git(directory, ["rev-parse", "HEAD^{tree}"]);
        await assertPinnedGit(directory, commit, tree, "test source");
        await assert.rejects(assertPinnedGit(directory, "0".repeat(40), tree, "test source"), /locked commit/);
        await assert.rejects(assertPinnedGit(directory, commit, "0".repeat(40), "test source"), /locked tree/);
        await writeFile(path.join(directory, "untracked.txt"), "mutation\n");
        await assert.rejects(assertPinnedGit(directory, commit, tree, "test source"), /dirty/);
        await rm(path.join(directory, "untracked.txt"));
        await writeFile(path.join(directory, "source.txt"), "reviewed patch\n");
        const patchSha256 = gitPatchSha256(directory);
        await assertPinnedGit(directory, commit, tree, "test source", patchSha256);
        await assert.rejects(assertPinnedGit(directory, commit, tree, "test source", "0".repeat(64)), /patch/);
        await writeFile(path.join(directory, "untracked.txt"), "mutation\n");
        await assert.rejects(assertPinnedGit(directory, commit, tree, "test source", patchSha256), /untracked/);
    } finally {
        await rm(directory, { recursive: true, force: true });
    }
});

test("rejects Mbed TLS archive, extracted-input, configuration, and library mutations", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "picomemo-web-mbedtls-"));
    const source = path.join(directory, "source");
    const archive = path.join(directory, "archive.tar.bz2");
    try {
        await mkdir(path.join(source, "library"), { recursive: true });
        await writeFile(path.join(source, "input.c"), "locked source\n");
        await writeFile(path.join(source, "library/libmbedcrypto.a"), "locked library\n");
        await writeFile(archive, "locked archive\n");
        const lock = {
            sha256: await sha256(archive),
            sourceInputsSha256: await hashMbedTLSInputs(source),
            buildConfigurationSha256: hashJSON(MBEDTLS_BUILD_CONFIGURATION),
            librarySha256: await sha256(path.join(source, "library/libmbedcrypto.a")),
        };
        await assertMbedTLS({ archive, directory: source, lock });
        await assert.rejects(assertMbedTLS({ archive, directory: source, lock: { ...lock, buildConfigurationSha256: "0".repeat(64) } }), /configuration/);
        await writeFile(path.join(source, "input.c"), "mutated source\n");
        await assert.rejects(assertMbedTLS({ archive, directory: source, lock }), /source inputs/);
        await writeFile(path.join(source, "input.c"), "locked source\n");
        await writeFile(path.join(source, "library/libmbedcrypto.a"), "mutated library\n");
        await assert.rejects(assertMbedTLS({ archive, directory: source, lock }), /library/);
        await writeFile(path.join(source, "library/libmbedcrypto.a"), "locked library\n");
        await writeFile(archive, "mutated archive\n");
        await assert.rejects(assertMbedTLS({ archive, directory: source, lock }), /archive/);
    } finally {
        await rm(directory, { recursive: true, force: true });
    }
});

function git(directory, args) {
    const result = spawnSync("git", ["-c", `safe.directory=${directory}`, "-C", directory, ...args], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
}
