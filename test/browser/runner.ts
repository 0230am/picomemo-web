import { createPicomemoBackend, PicomemoError, PICOMEMO_DEFAULT_MESSAGE_JUMP, PICOMEMO_DEFAULT_RETAINED_SKIPPED_KEYS, PICOMEMO_METADATA, type PicomemoBackend, type PicomemoErrorCategory } from "../../dist/index.js";

interface Result { readonly name: string; readonly ok: boolean; readonly detail?: string; }
const results: Result[] = [];

void run().then(finish, (error: unknown) => {
    results.push({ name: "runner", ok: false, detail: error instanceof Error ? error.stack : String(error) });
    finish();
});

async function run(): Promise<void> {
    assert(PICOMEMO_METADATA.artifacts.wasmSha256 === "02c145957eea82a4c7f01d855e4a45fd5584e2634dcaedbd685d4a2c06e4592f", "metadata changed");
    await roundTrip("omemo2");
    await roundTrip("legacy");
    await legacyIVProfiles();
    await dhRatchetBounds("omemo2");
    await dhRatchetBounds("legacy");
    await boundsAndHeartbeat();
    await maximumWindowAndCompatibility();
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
        assert(!missingProtocol.ok && missingProtocol.error.category === "backend-failure", "missing protocol silently defaulted");
        const extraField = await post(worker, { id: 2, operation: "setup", protocol: "omemo2", extra: true });
        assert(!extraField.ok && extraField.error.category === "backend-failure", "extra Worker field was accepted");
        const nestedState = await post(worker, { id: 3, operation: "encrypt", protocol: "omemo2", state: { session: new Uint8Array(1), skippedKeys: new Uint8Array(4), extra: true }, key: new Uint8Array(1) });
        assert(!nestedState.ok && nestedState.error.operation === "worker-request", "unknown nested state field was accepted");
        const nestedBundle = await post(worker, { id: 4, operation: "initiate", protocol: "omemo2", store: new Uint8Array(1), bundle: { identityKey: new Uint8Array(32), signedPreKey: new Uint8Array(32), signedPreKeySignature: new Uint8Array(64), signedPreKeyId: 1, preKeys: [{ id: 2, publicKey: new Uint8Array(32), extra: true }] } });
        assert(!nestedBundle.ok && nestedBundle.error.operation === "worker-request", "unknown nested bundle field was accepted");
        let requestId = 10;
        for (const protocol of ["omemo2", "legacy"] as const) {
            const fixture = createPicomemoBackend({ protocol });
            let localState: Uint8Array;
            let validBundle;
            try {
                localState = await fixture.createIdentity();
                validBundle = await fixture.createBundle(await fixture.createIdentity());
            } finally {
                fixture.terminate();
            }
            const mixedBundle = { ...validBundle, preKeys: [validBundle.preKeys[0]!, { ...validBundle.preKeys[1]!, publicKey: new Uint8Array(31) }] };
            for (let attempt = 0; attempt < 16; attempt++) {
                const response = await post(worker, { id: requestId++, operation: "initiate", protocol, store: localState, bundle: mixedBundle });
                assert(!response.ok && response.error.operation === "initiate", `${protocol} mixed-validity PreKey bundle was accepted`);
            }
        }
        const invalidId = await post(worker, { id: Number.NaN, operation: "setup", protocol: "omemo2" });
        assert(!invalidId.ok && invalidId.id === 0, "invalid Worker request ID was accepted");
        const omemo2IV = await post(worker, { id: 5, operation: "decrypt-payload", protocol: "omemo2", key: new Uint8Array(48), iv: new Uint8Array(12), payload: new Uint8Array(16) });
        assert(!omemo2IV.ok && omemo2IV.error.operation === "worker-request", "OMEMO 2 Worker accepted a transmitted IV");
        const missingLegacyIV = await post(worker, { id: 6, operation: "decrypt-payload", protocol: "legacy", key: new Uint8Array(32), payload: new Uint8Array(16) });
        assert(!missingLegacyIV.ok && missingLegacyIV.error.operation === "worker-request", "Legacy Worker accepted a missing IV");
        results.push({ name: "strict Worker request-envelope validation", ok: true });
    } finally {
        worker.terminate();
    }
}

function post(worker: Worker, value: unknown): Promise<{ readonly id: number; readonly ok: boolean; readonly error: { readonly category: string; readonly protocol: string; readonly operation: string } }> {
    return new Promise((resolve, reject) => {
        worker.onmessage = (event: MessageEvent<{ readonly id: number; readonly ok: boolean; readonly error: { readonly category: string; readonly protocol: string; readonly operation: string } }>) => resolve(event.data);
        worker.onerror = () => reject(new Error("Worker request validation test failed."));
        worker.postMessage(value);
    });
}

async function maximumWindowAndCompatibility(): Promise<void> {
    const alice = createPicomemoBackend({ protocol: "legacy" });
    const bob = createPicomemoBackend({ protocol: "legacy" });
    try {
        const aliceLocal = await alice.createIdentity();
        const bobLocal = await bob.createIdentity();
        let aliceState = await alice.buildOutgoingSession(aliceLocal, await bob.createBundle(bobLocal));
        const first = await alice.encryptKey(aliceState, key(1));
        aliceState = first.sessionState;
        const bobFirst = await bob.decryptKey(bobLocal, undefined, first.keyExchange, first.message);
        const following: { readonly message: Uint8Array; readonly keyExchange: boolean; readonly expected: Uint8Array }[] = [];
        for (let index = 0; index < PICOMEMO_DEFAULT_MESSAGE_JUMP + 3; index++) {
            const expected = key(40 + index);
            const encrypted = await alice.encryptKey(aliceState, expected);
            aliceState = encrypted.sessionState;
            following.push({ message: encrypted.message, keyExchange: encrypted.keyExchange, expected });
        }

        const oldCapacity = await bob.decryptKey(bobFirst.localState, bobFirst.sessionState, following[128]!.keyExchange, following[128]!.message, 128, 128);
        const oldV1 = toImplicitV1(oldCapacity.sessionState);
        const migrated = await bob.decryptKey(oldCapacity.localState, oldV1, following[0]!.keyExchange, following[0]!.message);
        assert(equal(migrated.key, following[0]!.expected) && isV2(migrated.sessionState), "implicit-v1 session did not migrate to v2 without reset");
        const migratedAgain = await bob.decryptKey(migrated.localState, migrated.sessionState, following[1]!.keyExchange, following[1]!.message);
        assert(equal(migratedAgain.key, following[1]!.expected), "migrated v2 session did not round-trip");

        const oneAbove = following[PICOMEMO_DEFAULT_MESSAGE_JUMP + 1]!;
        const unchanged = bobFirst.sessionState.slice();
        await expectCategory(bob.decryptKey(bobFirst.localState, bobFirst.sessionState, oneAbove.keyExchange, oneAbove.message), "jump-too-large");
        assert(equal(unchanged, bobFirst.sessionState), "jump rejection mutated caller state");
        let replayState = bobFirst.sessionState;
        for (let index = 0; index <= PICOMEMO_DEFAULT_MESSAGE_JUMP + 1; index++) {
            const inbound = await bob.decryptKey(bobFirst.localState, replayState, following[index]!.keyExchange, following[index]!.message);
            assert(equal(inbound.key, following[index]!.expected), "oldest-to-newest replay failed after rejected jump");
            replayState = inbound.sessionState;
        }

        const latencies: number[] = [];
        let start = performance.now();
        const atMaximum = await bob.decryptKey(bobFirst.localState, bobFirst.sessionState, following[PICOMEMO_DEFAULT_MESSAGE_JUMP]!.keyExchange, following[PICOMEMO_DEFAULT_MESSAGE_JUMP]!.message);
        latencies.push(performance.now() - start);
        for (let sample = 1; sample < 7; sample++) {
            start = performance.now();
            await bob.decryptKey(bobFirst.localState, bobFirst.sessionState, following[PICOMEMO_DEFAULT_MESSAGE_JUMP]!.keyExchange, following[PICOMEMO_DEFAULT_MESSAGE_JUMP]!.message);
            latencies.push(performance.now() - start);
        }
        assert(equal(atMaximum.key, following[PICOMEMO_DEFAULT_MESSAGE_JUMP]!.expected), "jump exactly at maximum failed");
        assert(atMaximum.sessionState.length <= 137044, "maximum session state exceeds the exported bound");
        const wasmInitialHeapBytes = await probeInitialWasmHeap();
        assert(wasmInitialHeapBytes === 16 * 1024 * 1024, "native initial WASM heap changed");
        const retainedStates = Array.from({ length: 20 }, () => atMaximum.sessionState.slice());
        const twentyRetainedSerializedBytes = retainedStates.reduce((sum, state) => sum + state.length, 0);
        const operatedStates = await Promise.all(retainedStates.map((state) => bob.decryptKey(atMaximum.localState, state, following[0]!.keyExchange, following[0]!.message)));
        assert(operatedStates.every((state) => equal(state.key, following[0]!.expected)), "20-session maximum-window operation failed");
        const twentyOperatedSerializedBytes = operatedStates.reduce((sum, state) => sum + state.sessionState.length, 0);
        await expectCategory(bob.decryptKey(atMaximum.localState, atMaximum.sessionState, following[PICOMEMO_DEFAULT_MESSAGE_JUMP + 2]!.keyExchange, following[PICOMEMO_DEFAULT_MESSAGE_JUMP + 2]!.message), "skipped-key-capacity");

        const malformed = Uint8Array.of(3, 3, 0, 0, 0, 0, 0, 0, 0);
        await expectCategory(bob.decryptKey(bobFirst.localState, bobFirst.sessionState, false, malformed), "malformed-message");
        const corrupt = following[0]!.message.slice();
        corrupt[corrupt.length - 1]! ^= 1;
        await expectCategory(bob.decryptKey(bobFirst.localState, bobFirst.sessionState, following[0]!.keyExchange, corrupt), "authentication-failed");
        await expectCategory(bob.decryptKey(migrated.localState, migrated.sessionState, following[0]!.keyExchange, following[0]!.message), "duplicate-or-old");

        const serializedBytes = atMaximum.sessionState.length;
        const nativeSessionBytes = new DataView(atMaximum.sessionState.buffer, atMaximum.sessionState.byteOffset, atMaximum.sessionState.byteLength).getUint32(8, true);
        const fixedOutputCapacityBytes = 16384 + 1024 + 4 + PICOMEMO_DEFAULT_RETAINED_SKIPPED_KEYS * 68 + 64 + 32 + 32;
        const nativeSkippedStateBytes = PICOMEMO_DEFAULT_RETAINED_SKIPPED_KEYS * 68 + 24;
        const initialNativeSessionBytes = new DataView(bobFirst.sessionState.buffer, bobFirst.sessionState.byteOffset, bobFirst.sessionState.byteLength).getUint32(8, true);
        const initialSkippedStateBytes = bobFirst.sessionState.length - 16 - initialNativeSessionBytes;
        const forwardJumpCopiedInputBytes = bobFirst.localState.length + initialNativeSessionBytes + initialSkippedStateBytes + following[PICOMEMO_DEFAULT_MESSAGE_JUMP]!.message.length;
        const forwardJumpJournalPayloadBytes = PICOMEMO_DEFAULT_RETAINED_SKIPPED_KEYS * 80;
        const forwardJumpAccountedPayloadBytes = forwardJumpCopiedInputBytes + fixedOutputCapacityBytes + nativeSkippedStateBytes + forwardJumpJournalPayloadBytes;
        const fullRetainedSkippedStateBytes = serializedBytes - 16 - nativeSessionBytes;
        const fullRetainedCopiedInputBytes = atMaximum.localState.length + nativeSessionBytes + fullRetainedSkippedStateBytes + following[0]!.message.length;
        const fullRetainedJournalPayloadBytes = 80;
        const fullRetainedAccountedPayloadBytes = fullRetainedCopiedInputBytes + fixedOutputCapacityBytes + nativeSkippedStateBytes + fullRetainedJournalPayloadBytes;
        latencies.sort((left, right) => left - right);
        results.push({
            name: "2,000-key typed limits, v1 migration, v2 round-trip, and transactional replay",
            ok: true,
            detail: JSON.stringify({ serializedBytes, nativeSessionBytes, localStateBytes: atMaximum.localState.length, wasmInitialHeapBytes, twentySessions: retainedStates.length, twentyRetainedSerializedBytes, twentyOperatedSerializedBytes, reviewedTransientAllocation: { kind: "accounted-payload-calculation-not-live-heap-measurement", exclusions: "allocator-overhead+native-store-session-message-backup-stack+js-clone-and-envelope", maximumForwardJump: { copiedInputBytes: forwardJumpCopiedInputBytes, fixedOutputCapacityBytes, nativeSkippedStateBytes, transactionJournalPayloadBytes: forwardJumpJournalPayloadBytes, accountedPayloadBytes: forwardJumpAccountedPayloadBytes }, fullRetainedReplay: { copiedInputBytes: fullRetainedCopiedInputBytes, fixedOutputCapacityBytes, nativeSkippedStateBytes, transactionJournalPayloadBytes: fullRetainedJournalPayloadBytes, accountedPayloadBytes: fullRetainedAccountedPayloadBytes } }, maximumJumpLatencyMs: { minimum: round(latencies[0]!), median: round(latencies[3]!), p95: round(latencies[6]!), samples: 7 }, configuredJump: PICOMEMO_DEFAULT_MESSAGE_JUMP, configuredRetained: PICOMEMO_DEFAULT_RETAINED_SKIPPED_KEYS }),
        });
    } finally {
        alice.terminate();
        bob.terminate();
    }
}

function probeInitialWasmHeap(): Promise<number> {
    return new Promise((resolve, reject) => {
        const worker = new Worker(new URL("./heap-probe.ts", import.meta.url), { type: "module", name: "picomemo-heap-probe" });
        worker.onmessage = (event: MessageEvent<unknown>) => {
            worker.terminate();
            if (!isRecord(event.data) || !hasExactKeys(event.data, ["wasmInitialHeapBytes"]) || !Number.isSafeInteger(event.data.wasmInitialHeapBytes)) reject(new Error("Invalid native heap probe response."));
            else resolve(event.data.wasmInitialHeapBytes as number);
        };
        worker.onerror = () => { worker.terminate(); reject(new Error("Native heap probe failed.")); };
    });
}

async function expectCategory(promise: Promise<unknown>, category: PicomemoErrorCategory): Promise<PicomemoError> {
    return promise.then(
        () => { throw new Error(`expected ${category}`); },
        (error: unknown) => {
            assert(error instanceof PicomemoError, `${category} did not use PicomemoError`);
            assert(error.category === category, `expected ${category}, received ${error.category}`);
            return error;
        },
    );
}

function toImplicitV1(state: Uint8Array): Uint8Array {
    assert(isV2(state), "expected v2 session state");
    const output = new Uint8Array(state.length - 8);
    output.set(state.subarray(8, 16), 0);
    output.set(state.subarray(16), 8);
    return output;
}

function isV2(state: Uint8Array): boolean { return state.length >= 16 && state[0] === 0x50 && state[1] === 0x4d && state[2] === 0x53 && state[3] === 0x53 && state[4] === 2; }

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
        const corruptLocal = new Uint8Array(bobLocal.length).fill(0x80);
        await expectCategory(bob.decryptKey(corruptLocal, undefined, wrapped.keyExchange, wrapped.message), "backend-failure");
        const unwrapped = await bob.decryptKey(bobLocal, undefined, wrapped.keyExchange, wrapped.message);
        const outboundIV = "iv" in outbound ? outbound.iv : undefined;
        assert(protocol === "legacy" ? outboundIV?.length === 12 : outboundIV === undefined, `${protocol} encrypted payload exposed an invalid IV shape`);
        const plaintext = protocol === "legacy" && outboundIV
            ? await bob.decryptPayload(unwrapped.key, outbound.payload, outboundIV)
            : await bob.decryptPayload(unwrapped.key, outbound.payload);
        const reply = await bob.encryptPayload(new TextEncoder().encode(`${protocol} to Alice`));
        const replyWrapped = await bob.encryptKey(unwrapped.sessionState, reply.key);
        const replyUnwrapped = await alice.decryptKey(aliceLocal, wrapped.sessionState, replyWrapped.keyExchange, replyWrapped.message);
        const replyIV = "iv" in reply ? reply.iv : undefined;
        const replyPlaintext = protocol === "legacy" && replyIV
            ? await alice.decryptPayload(replyUnwrapped.key, reply.payload, replyIV)
            : await alice.decryptPayload(replyUnwrapped.key, reply.payload);
        if (protocol === "omemo2") {
            const paddingVector = await alice.encryptPayload(new Uint8Array(20).fill(0x5a));
            for (const kind of ["zero", "oversized", "inconsistent"] as const) {
                const authenticatedCorruption = await authenticatedBadPadding(paddingVector.key, paddingVector.payload, kind);
                await expectCategory(alice.decryptPayload(authenticatedCorruption.key, authenticatedCorruption.payload), "backend-failure");
            }
        }
        const followup = await alice.encryptKey(replyUnwrapped.sessionState, key(91));
        const currentBobSession = replyWrapped.sessionState;
        const corruptSession = currentBobSession.slice();
        const nativeSessionLength = new DataView(corruptSession.buffer, corruptSession.byteOffset, corruptSession.byteLength).getUint32(8, true);
        corruptSession.fill(0x80, 16, 16 + nativeSessionLength);
        await expectCategory(bob.decryptKey(unwrapped.localState, corruptSession, followup.keyExchange, followup.message), "backend-failure");
        const retried = await bob.decryptKey(unwrapped.localState, currentBobSession, followup.keyExchange, followup.message);
        assert(equal(retried.key, key(91)), `${protocol} valid retry after corrupt persisted state failed`);
        const rawWorker = new Worker(new URL("../../dist/worker.js", import.meta.url), { type: "module", name: `picomemo-${protocol}-corrupt-skipped` });
        try {
            const session = currentBobSession.slice(16, 16 + nativeSessionLength);
            const corruptSkipped = await post(rawWorker, { id: 1, operation: "decrypt", protocol, store: unwrapped.localState, state: { session, skippedKeys: Uint8Array.of(1, 0, 0, 0) }, maximumMessageJump: 2000, maximumRetainedSkippedKeys: 2000, preKey: followup.keyExchange, message: followup.message });
            assert(!corruptSkipped.ok && corruptSkipped.error.category === "backend-failure" && corruptSkipped.error.protocol === protocol && corruptSkipped.error.operation === "decrypt", `${protocol} corrupt skipped state was misclassified`);
        } finally {
            rawWorker.terminate();
        }
        assert(equal(unwrapped.identityKey, aliceBundle.identityKey), `${protocol} responder identity mismatch`);
        assert(equal(replyUnwrapped.identityKey, bobBundle.identityKey), `${protocol} initiator identity mismatch`);
        assert(wrapped.keyExchange && !replyWrapped.keyExchange, `${protocol} PreKey transition failed`);
        assert(new TextDecoder().decode(plaintext) === `${protocol} to Bob`, `${protocol} initial payload failed`);
        assert(new TextDecoder().decode(replyPlaintext) === `${protocol} to Alice`, `${protocol} reply payload failed`);
        results.push({ name: `${protocol} bidirectional Worker/WASM round trip and corrupt-state retry`, ok: true });
    } finally {
        alice.terminate();
        bob.terminate();
    }
}

async function legacyIVProfiles(): Promise<void> {
    const backend = createPicomemoBackend({ protocol: "legacy" });
    try {
        const key = new Uint8Array(32);
        const iv = new Uint8Array(16);
        const plaintext = new Uint8Array(16);
        const vectors = [
            { ivn: 12, ciphertext: "0388dace60b6a392f328c2b971b2fe78", tag: "ab6e47d42cec13bdf53a67b21257bddf" },
            { ivn: 16, ciphertext: "a3b22b8449afafbcd6c09f2cfa9de2be", tag: "d8b820bab954bd1647d8a9c3d534e7a3" },
        ] as const;
        for (const vector of vectors) {
            const ciphertext = fromHex(vector.ciphertext);
            key.set(fromHex(vector.tag), 16);
            const keyBefore = key.slice();
            const ciphertextBefore = ciphertext.slice();
            assert(equal(await backend.decryptPayload(key, ciphertext, iv.subarray(0, vector.ivn)), plaintext), `Legacy ${vector.ivn}-byte IV vector failed`);
            assert(equal(key, keyBefore) && equal(ciphertext, ciphertextBefore), `Legacy ${vector.ivn}-byte IV vector mutated caller input`);
        }
        for (const ivn of [11, 13, 15, 17]) {
            await backend.decryptPayload(key, new Uint8Array(16), new Uint8Array(ivn)).then(
                () => { throw new Error(`Legacy ${ivn}-byte IV was accepted`); },
                () => undefined,
            );
        }
        const tampered = fromHex(vectors[0].ciphertext);
        key.set(fromHex(vectors[0].tag), 16);
        tampered[0]! ^= 1;
        await expectCategory(backend.decryptPayload(key, tampered, iv.subarray(0, 12)), "backend-failure");
        results.push({ name: "Legacy canonical 12-byte and historical 16-byte IV Worker/WASM vectors", ok: true });
    } finally {
        backend.terminate();
    }
}

async function authenticatedBadPadding(key: Uint8Array, payload: Uint8Array, kind: "zero" | "oversized" | "inconsistent"): Promise<{ readonly key: Uint8Array; readonly payload: Uint8Array }> {
    assert(key.length === 48 && payload.length >= 32 && payload.length % 16 === 0, "invalid OMEMO 2 padding test vector");
    const material = await crypto.subtle.importKey("raw", key.slice(0, 32), "HKDF", false, ["deriveBits"]);
    const derived = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("OMEMO Payload") }, material, 80 * 8));
    const corruptedPayload = payload.slice();
    if (kind === "inconsistent") corruptedPayload[corruptedPayload.length - 18]! ^= 1;
    else corruptedPayload[corruptedPayload.length - 17]! ^= 12 ^ (kind === "zero" ? 0 : 17);
    const hmacKey = await crypto.subtle.importKey("raw", derived.slice(32, 64), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, corruptedPayload));
    const authenticatedKey = key.slice();
    authenticatedKey.set(mac.subarray(0, 16), 32);
    return { key: authenticatedKey, payload: corruptedPayload };
}

async function dhRatchetBounds(protocol: "omemo2" | "legacy"): Promise<void> {
    const alice = createPicomemoBackend({ protocol });
    const bob = createPicomemoBackend({ protocol });
    try {
        const aliceLocal = await alice.createIdentity();
        const bobLocal = await bob.createIdentity();
        let aliceState = await alice.buildOutgoingSession(aliceLocal, await bob.createBundle(bobLocal));
        const first = await alice.encryptKey(aliceState, key(110));
        aliceState = first.sessionState;
        const bobFirst = await bob.decryptKey(bobLocal, undefined, first.keyExchange, first.message);
        const oldChain: { readonly message: Uint8Array; readonly keyExchange: boolean }[] = [];
        for (let index = 0; index < 2000; index++) {
            const message = await alice.encryptKey(aliceState, key(120 + index));
            aliceState = message.sessionState;
            oldChain.push(message);
        }
        const bobNearCapacity = await bob.decryptKey(bobFirst.localState, bobFirst.sessionState, oldChain[1999]!.keyExchange, oldChain[1999]!.message, 1999, 1999);
        const reply = await bob.encryptKey(bobNearCapacity.sessionState, key(130));
        const aliceAfterReply = await alice.decryptKey(aliceLocal, aliceState, reply.keyExchange, reply.message);
        const newZero = await alice.encryptKey(aliceAfterReply.sessionState, key(140));
        const newOne = await alice.encryptKey(newZero.sessionState, key(141));
        const newTwo = await alice.encryptKey(newOne.sessionState, key(142));
        const unchanged = reply.sessionState.slice();
        await expectCategory(bob.decryptKey(bobNearCapacity.localState, reply.sessionState, newOne.keyExchange, newOne.message, 0, 2000), "jump-too-large");
        assert(equal(unchanged, reply.sessionState), `${protocol} forced-DH zero-jump rejection mutated caller state`);
        const exactJump = await bob.decryptKey(bobNearCapacity.localState, reply.sessionState, newOne.keyExchange, newOne.message, 1, 2000);
        const recoveredZero = await bob.decryptKey(exactJump.localState, exactJump.sessionState, newZero.keyExchange, newZero.message, 1, 2000);
        assert(equal(recoveredZero.key, key(140)), `${protocol} forced-DH exact jump did not retain the old key`);
        await expectCategory(bob.decryptKey(bobNearCapacity.localState, reply.sessionState, newTwo.keyExchange, newTwo.message, 1, 2000), "jump-too-large");
        const capacity = await expectCategory(bob.decryptKey(bobNearCapacity.localState, reply.sessionState, newTwo.keyExchange, newTwo.message, 2, 2000), "skipped-key-capacity");
        assert(capacity.counters?.requestedMessageJump === 2 && capacity.counters.retainedSkippedKeys === 1999, `${protocol} forced-DH capacity diagnostics changed`);
        assert(equal(unchanged, reply.sessionState), `${protocol} forced-DH capacity rejection mutated caller state`);
        const orderedZero = await bob.decryptKey(bobNearCapacity.localState, reply.sessionState, newZero.keyExchange, newZero.message, 2, 2000);
        const orderedOne = await bob.decryptKey(orderedZero.localState, orderedZero.sessionState, newOne.keyExchange, newOne.message, 2, 2000);
        const orderedTwo = await bob.decryptKey(orderedOne.localState, orderedOne.sessionState, newTwo.keyExchange, newTwo.message, 2, 2000);
        assert(equal(orderedTwo.key, key(142)), `${protocol} forced-DH ordered retry failed`);
        results.push({ name: `${protocol} forced-DH exact jump and near-capacity precedence`, ok: true });
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
function fromHex(value: string): Uint8Array { return Uint8Array.from(value.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16)); }
function round(value: number): number { return Math.round(value * 100) / 100; }
function equal(left: Uint8Array, right: Uint8Array): boolean { return left.length === right.length && left.every((value, index) => value === right[index]); }
function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null; }
function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean { const keys = Object.keys(value); return keys.length === expected.length && keys.every((key) => expected.includes(key)); }
function assert(condition: boolean, message: string): asserts condition { if (!condition) throw new Error(message); }
function finish(): void {
    const ok = results.length > 0 && results.every((result) => result.ok);
    document.title = ok ? "PASS" : "FAIL";
    const element = document.getElementById("result");
    if (element) element.textContent = JSON.stringify({ ok, results }, null, 2);
}
