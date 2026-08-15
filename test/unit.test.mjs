import assert from "node:assert/strict";
import test from "node:test";
import { createPicomemoBackend, PICOMEMO_BACKEND_VERSION, PICOMEMO_MAXIMUM_MESSAGE_JUMP, PICOMEMO_METADATA } from "../dist/index.js";

test("exports exact source and artifact metadata", () => {
    assert.equal(PICOMEMO_BACKEND_VERSION, "1.2.1+ff75cfc41b9ea8e27e4fe961c08dd2bd8b922317");
    assert.equal(PICOMEMO_METADATA.source.tree, "81f38825f67a4d3819f823be9e2821624047ba96");
    assert.equal(PICOMEMO_MAXIMUM_MESSAGE_JUMP, 128);
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

