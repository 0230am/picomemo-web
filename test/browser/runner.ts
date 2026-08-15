import { createPicomemoBackend, PICOMEMO_METADATA, type PicomemoBackend } from "../../dist/index.js";

interface Result { readonly name: string; readonly ok: boolean; readonly detail?: string; }
const results: Result[] = [];

void run().then(finish, (error: unknown) => {
    results.push({ name: "runner", ok: false, detail: error instanceof Error ? error.stack : String(error) });
    finish();
});

async function run(): Promise<void> {
    assert(PICOMEMO_METADATA.artifacts.wasmSha256 === "8cf0ddc7ec45849bd99ffa1c405e8a6aa9c26384b76f5afc9b5bd95d5c7e0e94", "metadata changed");
    await roundTrip("omemo2");
    await roundTrip("legacy");
    await boundsAndHeartbeat();
    await malformedRequestsFailClosed();

    const backend = createPicomemoBackend({ protocol: "omemo2" });
    const pending = backend.createIdentity();
    backend.terminate();
    await pending.then(() => { throw new Error("terminated Worker resolved pending work"); }, () => undefined);
    results.push({ name: "dedicated Worker termination", ok: true });
}

async function malformedRequestsFailClosed(): Promise<void> {
    const worker = new Worker(new URL("../../dist/worker.js", import.meta.url), { type: "module", name: "picomemo-protocol-test" });
    try {
        const missingProtocol = await post(worker, { id: 1, operation: "setup" });
        assert(!missingProtocol.ok && /envelope|protocol/.test(missingProtocol.error), "missing protocol silently defaulted");
        const extraField = await post(worker, { id: 2, operation: "setup", protocol: "omemo2", extra: true });
        assert(!extraField.ok && /envelope/.test(extraField.error), "extra Worker field was accepted");
        const invalidId = await post(worker, { id: Number.NaN, operation: "setup", protocol: "omemo2" });
        assert(!invalidId.ok && invalidId.id === 0, "invalid Worker request ID was accepted");
        results.push({ name: "strict Worker request-envelope validation", ok: true });
    } finally {
        worker.terminate();
    }
}

function post(worker: Worker, value: unknown): Promise<{ readonly id: number; readonly ok: boolean; readonly error: string }> {
    return new Promise((resolve, reject) => {
        worker.onmessage = (event: MessageEvent<{ readonly id: number; readonly ok: boolean; readonly error: string }>) => resolve(event.data);
        worker.onerror = () => reject(new Error("Worker request validation test failed."));
        worker.postMessage(value);
    });
}

async function roundTrip(protocol: "omemo2" | "legacy"): Promise<void> {
    const alice = createPicomemoBackend({ protocol });
    const bob = createPicomemoBackend({ protocol });
    try {
        const aliceLocal = await alice.createIdentity();
        const bobLocal = await bob.createIdentity();
        const aliceBundle = await alice.createBundle(aliceLocal);
        const bobBundle = await bob.createBundle(bobLocal);
        const aliceSession = await alice.buildOutgoingSession(aliceLocal, bobBundle);
        const outbound = await alice.encryptPayload(new TextEncoder().encode(`${protocol} to Bob`));
        const wrapped = await alice.encryptKey(aliceSession, outbound.key);
        const unwrapped = await bob.decryptKey(bobLocal, undefined, wrapped.keyExchange, wrapped.message);
        const plaintext = await bob.decryptPayload(unwrapped.key, outbound.payload, outbound.iv);
        const reply = await bob.encryptPayload(new TextEncoder().encode(`${protocol} to Alice`));
        const replyWrapped = await bob.encryptKey(unwrapped.sessionState, reply.key);
        const replyUnwrapped = await alice.decryptKey(aliceLocal, wrapped.sessionState, replyWrapped.keyExchange, replyWrapped.message);
        const replyPlaintext = await alice.decryptPayload(replyUnwrapped.key, reply.payload, reply.iv);
        assert(equal(unwrapped.identityKey, aliceBundle.identityKey), `${protocol} responder identity mismatch`);
        assert(equal(replyUnwrapped.identityKey, bobBundle.identityKey), `${protocol} initiator identity mismatch`);
        assert(wrapped.keyExchange && !replyWrapped.keyExchange, `${protocol} PreKey transition failed`);
        assert(new TextDecoder().decode(plaintext) === `${protocol} to Bob`, `${protocol} initial payload failed`);
        assert(new TextDecoder().decode(replyPlaintext) === `${protocol} to Alice`, `${protocol} reply payload failed`);
        results.push({ name: `${protocol} bidirectional Worker/WASM round trip`, ok: true });
    } finally {
        alice.terminate();
        bob.terminate();
    }
}

async function boundsAndHeartbeat(): Promise<void> {
    const alice = createPicomemoBackend({ protocol: "omemo2" });
    const bob = createPicomemoBackend({ protocol: "omemo2" });
    try {
        const aliceLocal = await alice.createIdentity();
        const bobLocal = await bob.createIdentity();
        let aliceState = await alice.buildOutgoingSession(aliceLocal, await bob.createBundle(bobLocal));
        const first = await alice.encryptKey(aliceState, key(1));
        aliceState = first.sessionState;
        const bobFirst = await bob.decryptKey(bobLocal, undefined, first.keyExchange, first.message);
        const second = await alice.encryptKey(aliceState, key(2));
        const third = await alice.encryptKey(second.sessionState, key(3));
        const fourth = await alice.encryptKey(third.sessionState, key(4));
        await bob.decryptKey(bobFirst.localState, bobFirst.sessionState, fourth.keyExchange, fourth.message, 1).then(
            () => { throw new Error("message jump above bound was accepted"); },
            () => undefined,
        );
        const fourthPlain = await bob.decryptKey(bobFirst.localState, bobFirst.sessionState, fourth.keyExchange, fourth.message, 128);
        assert(equal(fourthPlain.key, key(4)), "bounded retry did not preserve input state");
        const secondPlain = await bob.decryptKey(fourthPlain.localState, fourthPlain.sessionState, second.keyExchange, second.message);
        assert(equal(secondPlain.key, key(2)), "exported skipped key did not decrypt out of order");

        const corrupt = fourth.message.slice();
        corrupt[corrupt.length - 1]! ^= 1;
        const before = bobFirst.sessionState.slice();
        await bob.decryptKey(bobFirst.localState, bobFirst.sessionState, fourth.keyExchange, corrupt).then(
            () => { throw new Error("corrupt authenticated message was accepted"); },
            () => undefined,
        );
        assert(equal(before, bobFirst.sessionState), "failed decrypt mutated caller state");

        let bobState = bobFirst.sessionState;
        let heartbeat;
        for (let index = 0; index < 64 && !heartbeat?.keyTransport; index++) {
            const outbound = await alice.encryptKey(aliceState, key(20 + index));
            aliceState = outbound.sessionState;
            const inbound = await bob.decryptKey(bobFirst.localState, bobState, outbound.keyExchange, outbound.message);
            bobState = inbound.sessionState;
            heartbeat = await bob.maintainSession(bobFirst.localState, bobState);
            bobState = heartbeat.sessionState;
        }
        assert(heartbeat?.keyTransport !== undefined && heartbeat.counters.received >= 53, "native heartbeat threshold failed");
        results.push({ name: "bounded skipped keys, failure atomicity, and native heartbeat", ok: true });
    } finally {
        alice.terminate();
        bob.terminate();
    }
}

function key(seed: number): Uint8Array { return Uint8Array.from({ length: 32 }, (_, index) => (seed + index) & 0xff); }
function equal(left: Uint8Array, right: Uint8Array): boolean { return left.length === right.length && left.every((value, index) => value === right[index]); }
function assert(condition: boolean, message: string): asserts condition { if (!condition) throw new Error(message); }
function finish(): void {
    const ok = results.length > 0 && results.every((result) => result.ok);
    document.title = ok ? "PASS" : "FAIL";
    const element = document.getElementById("result");
    if (element) element.textContent = JSON.stringify({ ok, results }, null, 2);
}
