import assert from "node:assert/strict";
import test from "node:test";
import { createPicomemoBackend, isPicomemoBackendVersionCompatible, PicomemoError, PICOMEMO_BACKEND_VERSION, PICOMEMO_COMPATIBLE_BACKEND_VERSIONS, PICOMEMO_DEFAULT_MESSAGE_JUMP, PICOMEMO_DEFAULT_RETAINED_SKIPPED_KEYS, PICOMEMO_HARD_MAXIMUM_MESSAGE_JUMP, PICOMEMO_HARD_MAXIMUM_RETAINED_SKIPPED_KEYS, PICOMEMO_MAXIMUM_SESSION_STATE_BYTES, PICOMEMO_METADATA, PICOMEMO_SESSION_STATE_VERSION } from "../dist/index.js";

test("exports exact source and artifact metadata", () => {
    assert.equal(PICOMEMO_BACKEND_VERSION, "1.2.1+a4bad0297ea72ee75fbdb4afc899f65e8d85ae74");
    assert.equal(PICOMEMO_METADATA.source.tree, "011b0bd1a0f4109856f7dfb633383efbe313cd3e");
    assert.equal(PICOMEMO_METADATA.source.dirty, false);
    assert.equal(PICOMEMO_DEFAULT_MESSAGE_JUMP, 2000);
    assert.equal(PICOMEMO_HARD_MAXIMUM_MESSAGE_JUMP, 2000);
    assert.equal(PICOMEMO_DEFAULT_RETAINED_SKIPPED_KEYS, 2000);
    assert.equal(PICOMEMO_HARD_MAXIMUM_RETAINED_SKIPPED_KEYS, 2000);
    assert.equal(PICOMEMO_MAXIMUM_SESSION_STATE_BYTES, 137044);
    assert.equal(PICOMEMO_SESSION_STATE_VERSION, 2);
    assert.deepEqual(PICOMEMO_COMPATIBLE_BACKEND_VERSIONS, ["1.2.1+ff75cfc41b9ea8e27e4fe961c08dd2bd8b922317", "1.2.1+ff75cfc41b9ea8e27e4fe961c08dd2bd8b922317.patch.1679cf6a8025"]);
    assert.equal(isPicomemoBackendVersionCompatible(PICOMEMO_BACKEND_VERSION), true);
    assert.equal(isPicomemoBackendVersionCompatible(PICOMEMO_COMPATIBLE_BACKEND_VERSIONS[0]), true);
    assert.equal(isPicomemoBackendVersionCompatible("unknown"), false);
});

test("uses a caller-provided dedicated Worker factory and validates responses", async () => {
    let request;
    const worker = new FakeWorker((value) => {
        request = value;
        return { id: value.id, ok: true, value: Uint8Array.of(1, 2, 3) };
    });
    const backend = createPicomemoBackend({ protocol: "legacy", workerFactory: () => worker });
    assert.equal(backend.id, "picomemo:legacy");
    assert.deepEqual(await backend.createIdentity(), Uint8Array.of(1, 2, 3));
    assert.equal(request.operation, "setup");
    assert.equal(request.protocol, "legacy");
    backend.terminate();
});

test("termination rejects pending work and creates no fallback", async () => {
    const worker = new FakeWorker(() => undefined);
    const backend = createPicomemoBackend({ protocol: "omemo2", workerFactory: () => worker });
    const pending = backend.createIdentity();
    backend.terminate();
    await assert.rejects(pending, /terminated/);
    assert.equal(worker.terminated, true);
});

test("rejects invalid protocols", () => {
    assert.throws(() => createPicomemoBackend({ protocol: "other" }), /protocol/);
});

test("rejects unreasonable ratchet limits before constructing a Worker", () => {
    let constructed = false;
    const workerFactory = () => { constructed = true; return new FakeWorker(() => undefined); };
    assert.throws(() => createPicomemoBackend({ protocol: "legacy", maximumMessageJump: 2001, workerFactory }), /maximum message jump/);
    assert.throws(() => createPicomemoBackend({ protocol: "legacy", maximumRetainedSkippedKeys: 2001, workerFactory }), /maximum retained skipped keys/);
    assert.equal(constructed, false);
});

test("reconstructs validated structured ratchet errors", async () => {
    const worker = new FakeWorker((request) => ({
        id: request.id,
        ok: false,
        error: {
            category: "jump-too-large",
            protocol: "legacy",
            operation: "decrypt",
            limit: { kind: "message-jump", configured: 23 },
            counters: { requestedMessageJump: 24, retainedSkippedKeys: 7 },
        },
    }));
    const backend = createPicomemoBackend({ protocol: "legacy", workerFactory: () => worker });
    await assert.rejects(backend.decryptKey(Uint8Array.of(1), undefined, false, Uint8Array.of(1), 23, 17), (error) => {
        assert.ok(error instanceof PicomemoError);
        assert.equal(error.category, "jump-too-large");
        assert.equal(error.protocol, "legacy");
        assert.equal(error.operation, "decrypt");
        assert.deepEqual(error.limit, { kind: "message-jump", configured: 23 });
        assert.deepEqual(error.counters, { requestedMessageJump: 24, retainedSkippedKeys: 7 });
        return true;
    });
});

for (const [name, error, invoke] of [
    ["unknown category", { category: "unknown", protocol: "legacy", operation: "decrypt" }, (backend) => backend.decryptKey(Uint8Array.of(1), undefined, false, Uint8Array.of(1), 23, 17)],
    ["unknown field", { category: "authentication-failed", protocol: "legacy", operation: "decrypt", secret: "not allowed" }, (backend) => backend.decryptKey(Uint8Array.of(1), undefined, false, Uint8Array.of(1), 23, 17)],
    ["wrong protocol", { category: "backend-failure", protocol: "omemo2", operation: "setup" }, (backend) => backend.createIdentity()],
    ["wrong operation", { category: "backend-failure", protocol: "legacy", operation: "decrypt" }, (backend) => backend.createIdentity()],
    ["ratchet category outside decrypt", { category: "jump-too-large", protocol: "legacy", operation: "setup", limit: { kind: "message-jump", configured: 23 }, counters: { requestedMessageJump: 24, retainedSkippedKeys: 7 } }, (backend) => backend.createIdentity()],
    ["wrong configured limit", { category: "jump-too-large", protocol: "legacy", operation: "decrypt", limit: { kind: "message-jump", configured: 22 }, counters: { requestedMessageJump: 24, retainedSkippedKeys: 7 } }, (backend) => backend.decryptKey(Uint8Array.of(1), undefined, false, Uint8Array.of(1), 23, 17)],
    ["inconsistent jump counter", { category: "jump-too-large", protocol: "legacy", operation: "decrypt", limit: { kind: "message-jump", configured: 23 }, counters: { requestedMessageJump: 23, retainedSkippedKeys: 7 } }, (backend) => backend.decryptKey(Uint8Array.of(1), undefined, false, Uint8Array.of(1), 23, 17)],
    ["inconsistent retained counter", { category: "skipped-key-capacity", protocol: "legacy", operation: "decrypt", limit: { kind: "retained-skipped-keys", configured: 17 }, counters: { requestedMessageJump: 1, retainedSkippedKeys: 16 } }, (backend) => backend.decryptKey(Uint8Array.of(1), undefined, false, Uint8Array.of(1), 23, 17)],
    ["uncorrelated worker request", { category: "backend-failure", protocol: "unknown", operation: "worker-request" }, (backend) => backend.createIdentity()],
]) test(`rejects structured Worker error with ${name}`, async () => {
    const worker = new FakeWorker((request) => ({ id: request.id, ok: false, error }));
    const backend = createPicomemoBackend({ protocol: "legacy", workerFactory: () => worker });
    await assert.rejects(invoke(backend), /invalid error response/);
    assert.equal(worker.terminated, true);
});

for (const [name, mutate] of [
    ["bundle field", (bundle) => ({ ...bundle, extra: true })],
    ["nested PreKey field", (bundle) => ({ ...bundle, preKeys: [{ ...bundle.preKeys[0], extra: true }] })],
]) test(`rejects unknown ${name} in a successful Worker response`, async () => {
    const valid = {
        identityKey: new Uint8Array(32),
        signedPreKey: new Uint8Array(32),
        signedPreKeySignature: new Uint8Array(64),
        signedPreKeyId: 1,
        preKeys: [{ id: 2, publicKey: new Uint8Array(32) }],
    };
    const worker = new FakeWorker((request) => ({ id: request.id, ok: true, value: mutate(valid) }));
    const backend = createPicomemoBackend({ protocol: "legacy", workerFactory: () => worker });
    await assert.rejects(backend.createBundle(Uint8Array.of(1)), /invalid success response/);
    assert.equal(worker.terminated, true);
});

test("malformed nested success terminates the Worker and rejects every concurrent pending request", async () => {
    let responses = 0;
    const worker = new FakeWorker((request) => {
        if (responses++ > 0) return undefined;
        return {
            id: request.id,
            ok: true,
            value: {
                identityKey: new Uint8Array(32),
                signedPreKey: new Uint8Array(32),
                signedPreKeySignature: new Uint8Array(64),
                signedPreKeyId: 1,
                preKeys: [{ id: 2, publicKey: new Uint8Array(32), extra: true }],
            },
        };
    });
    const backend = createPicomemoBackend({ protocol: "legacy", workerFactory: () => worker });
    const malformed = backend.createBundle(Uint8Array.of(1));
    const concurrent = backend.createIdentity();
    await assert.rejects(malformed, /invalid success response/);
    await assert.rejects(concurrent, /invalid success response/);
    assert.equal(worker.terminated, true);
});

test("invalid successful Worker responses identify the protocol, operation, and rejected field", async () => {
    const worker = new FakeWorker((request) => ({
        id: request.id,
        ok: true,
        value: {
            localState: Uint8Array.of(1),
            state: { session: Uint8Array.of(1), skippedKeys: new Uint8Array(4) },
            identityKey: new Uint8Array(32),
            key: new Uint8Array(31),
        },
    }));
    const backend = createPicomemoBackend({ protocol: "legacy", workerFactory: () => worker });
    await assert.rejects(
        backend.decryptKey(Uint8Array.of(1), undefined, true, Uint8Array.of(1)),
        /invalid success response for legacy\/decrypt: The OMEMO Worker returned an invalid legacy decrypted key length 31 \(expected 32\)/,
    );
    assert.equal(worker.terminated, true);
});

test("rejects unknown bundle input fields before constructing a Worker", async () => {
    let constructed = false;
    const bundle = {
        identityKey: new Uint8Array(32),
        signedPreKey: new Uint8Array(32),
        signedPreKeySignature: new Uint8Array(64),
        signedPreKeyId: 1,
        preKeys: [{ id: 2, publicKey: new Uint8Array(32), extra: true }],
    };
    const backend = createPicomemoBackend({ protocol: "legacy", workerFactory: () => { constructed = true; return new FakeWorker(() => undefined); } });
    await assert.rejects(backend.buildOutgoingSession(Uint8Array.of(1), bundle), /PreKey/);
    assert.equal(constructed, false);
});

class FakeWorker {
    onmessage = null;
    onerror = null;
    onmessageerror = null;
    terminated = false;
    constructor(respond) { this.respond = respond; }
    postMessage(request) {
        const response = this.respond(request);
        if (response) queueMicrotask(() => this.onmessage?.({ data: response }));
    }
    terminate() { this.terminated = true; }
}
