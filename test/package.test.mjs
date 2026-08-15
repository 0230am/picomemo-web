import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

test("runtime sources have no application-framework dependencies", async () => {
    const root = path.resolve(import.meta.dirname, "..");
    const implementationFiles = [
        ...(await collect(path.join(root, "src"))),
        ...(await collect(path.join(root, "native"))),
        ...(await collect(path.join(root, "scripts"))),
    ];
    const files = [
        ...implementationFiles,
        path.join(root, "README.md"),
        path.join(root, "build-lock.json"),
        path.join(root, "package.json"),
        path.join(root, "source-metadata.json"),
    ];
    const implementation = (await Promise.all(implementationFiles.map((file) => readFile(file, "utf8")))).join("\n");
    for (const forbidden of [/\bsvelte\b/i, /\bxmpp\b/i, /indexeddb/i, /\bpep\b/i, /\bmam\b/i, /\$lib\//i]) assert.equal(forbidden.test(implementation), false, String(forbidden));
    const packageSource = (await Promise.all(files.map((file) => readFile(file, "utf8")))).join("\n");
    assert.equal(/\bclover\b/i.test(packageSource), false, "package-owned sources must not contain Clover references");
});

test("published README documents a usable browser integration", async () => {
    const readme = await readFile(new URL("../README.md", import.meta.url), "utf8");
    for (const required of [
        "## Install",
        "## Complete two-party round trip",
        "## State model",
        "## Payload and key transport",
        "## Session maintenance",
        "## API",
        "## Worker lifecycle and errors",
        "## Content Security Policy",
        "npm install picomemo@experimental",
        "createPicomemoBackend",
        "decryptKey",
        "terminate",
    ]) assert.ok(readme.includes(required), `README is missing ${required}`);
});

async function collect(directory) {
    const files = [];
    for (const entry of await readdir(directory, { withFileTypes: true })) {
        const file = path.join(directory, entry.name);
        if (entry.isDirectory()) files.push(...await collect(file));
        else if (entry.isFile() && !/\.(?:wasm|png|jpg|gif)$/i.test(entry.name)) files.push(file);
    }
    return files;
}
