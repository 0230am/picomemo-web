/// <reference lib="webworker" />

import createPicomemoModule from "./generated/picomemo.mjs";
import type { PicomemoBundle, PicomemoProtocol, PicomemoWorkerRequest, PicomemoWorkerResponse, PicomemoWorkerSessionState } from "./types.js";

const scope = self as DedicatedWorkerGlobalScope;

if (typeof document !== "undefined" || typeof Window !== "undefined") throw new Error("picomemo may only run in a dedicated Worker.");
if (scope.constructor.name !== "DedicatedWorkerGlobalScope") throw new Error("picomemo requires a dedicated Worker.");

const modulePromise = createPicomemoModule({ locateFile: (file) => new URL(`./generated/${file}`, import.meta.url).href });

scope.onmessage = (event: MessageEvent<unknown>) => {
    const responseId = isRecord(event.data) && Number.isSafeInteger(event.data.id) && (event.data.id as number) >= 1 ? event.data.id as number : 0;
    void Promise.resolve().then(() => validateRequest(event.data)).then(handle).then(
        (value) => respond({ id: responseId, ok: true, value }),
        (error: unknown) => respond({ id: responseId, ok: false, error: error instanceof Error ? error.message : String(error) }),
    );
};

type Module = Awaited<ReturnType<typeof createPicomemoModule>>;

async function handle(request: PicomemoWorkerRequest): Promise<unknown> {
    const module = await modulePromise;
    module._picomemoWebInitialize();
    const protocol = request.operation === "fingerprint" ? "omemo2" : request.protocol;

    switch (request.operation) {
        case "setup": return setup(module, protocol);
        case "fingerprint": return fingerprint(request.identityKey);
        case "bundle": return bundle(module, protocol, request.store);
        case "replenish": return replenish(module, protocol, request.store);
        case "initiate": return initiate(module, protocol, request.store, request.bundle);
        case "encrypt": return encrypt(module, protocol, request.state, request.key);
        case "decrypt": return decrypt(module, protocol, request.store, request.state, request.maximumMessageJump, request.preKey, request.message);
        case "maintain": return maintain(module, protocol, request.store, request.state);
        case "encrypt-payload": return encryptPayload(module, protocol, request.plaintext);
        case "decrypt-payload": return decryptPayload(module, protocol, request.key, request.iv, request.payload);
    }
}

function validateRequest(value: unknown): PicomemoWorkerRequest {
    if (!isRecord(value) || !Number.isSafeInteger(value.id) || (value.id as number) < 1 || typeof value.operation !== "string") throw new TypeError("Invalid picomemo Worker request envelope.");
    const common = ["id", "operation"];
    const shapes: Record<string, readonly string[]> = {
        setup: [...common, "protocol"],
        fingerprint: [...common, "identityKey"],
        bundle: [...common, "protocol", "store"],
        replenish: [...common, "protocol", "store"],
        initiate: [...common, "protocol", "store", "bundle"],
        encrypt: [...common, "protocol", "state", "key"],
        decrypt: [...common, "protocol", "store", "state", "maximumMessageJump", "preKey", "message"],
        maintain: [...common, "protocol", "store", "state"],
        "encrypt-payload": [...common, "protocol", "plaintext"],
        "decrypt-payload": [...common, "protocol", "key", "payload", ...(value.iv === undefined ? [] : ["iv"])],
    };
    const expected = shapes[value.operation];
    if (!expected || Object.keys(value).length !== expected.length || Object.keys(value).some((key) => !expected.includes(key))) throw new TypeError("Invalid picomemo Worker request envelope.");
    if (value.operation !== "fingerprint" && value.protocol !== "omemo2" && value.protocol !== "legacy") throw new TypeError("Invalid picomemo Worker protocol.");
    switch (value.operation) {
        case "setup": break;
        case "fingerprint": if (!(value.identityKey instanceof Uint8Array)) throw new TypeError("Invalid picomemo Worker request envelope."); break;
        case "bundle":
        case "replenish": if (!(value.store instanceof Uint8Array)) throw new TypeError("Invalid picomemo Worker request envelope."); break;
        case "initiate": if (!(value.store instanceof Uint8Array) || !isRecord(value.bundle)) throw new TypeError("Invalid picomemo Worker request envelope."); break;
        case "encrypt": if (!isRecord(value.state) || !(value.key instanceof Uint8Array)) throw new TypeError("Invalid picomemo Worker request envelope."); break;
        case "decrypt": if (!(value.store instanceof Uint8Array) || !isRecord(value.state) || !Number.isInteger(value.maximumMessageJump) || typeof value.preKey !== "boolean" || !(value.message instanceof Uint8Array)) throw new TypeError("Invalid picomemo Worker request envelope."); break;
        case "maintain": if (!(value.store instanceof Uint8Array) || !isRecord(value.state)) throw new TypeError("Invalid picomemo Worker request envelope."); break;
        case "encrypt-payload": if (!(value.plaintext instanceof Uint8Array)) throw new TypeError("Invalid picomemo Worker request envelope."); break;
        case "decrypt-payload": if (!(value.key instanceof Uint8Array) || !(value.payload instanceof Uint8Array) || (value.iv !== undefined && !(value.iv instanceof Uint8Array))) throw new TypeError("Invalid picomemo Worker request envelope."); break;
    }
    return value as unknown as PicomemoWorkerRequest;
}

async function fingerprint(identityKey: Uint8Array): Promise<string> {
    exact(identityKey, 32, "identity key");
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", identityKey.slice().buffer));
    return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("").match(/.{1,8}/g)?.join(" ") ?? "";
}

function setup(module: Module, protocol: PicomemoProtocol): Uint8Array {
    return withAllocations(module, [16384], ([out]) => copy(module, out, checked(protocol === "legacy" ? module._picomemoWeb0SetupStore(out, 16384) : module._picomemoWebSetupStore(out, 16384), "setup store")));
}

function bundle(module: Module, protocol: PicomemoProtocol, store: Uint8Array): PicomemoBundle {
    bounded(store, 16384, "store");
    return withBytes(module, [store], ([storePointer]) => withAllocations(module, [32, 32, 64, 8, 400, 3200], ([identity, signedPreKey, signature, metadata, preKeyIds, preKeys]) => {
        checked(protocol === "legacy"
            ? module._picomemoWeb0GetBundle(storePointer, store.length, identity, signedPreKey, signature, metadata, preKeyIds, preKeys)
            : module._picomemoWebGetBundle(storePointer, store.length, identity, signedPreKey, signature, metadata, preKeyIds, preKeys), "read bundle");
        const count = module.HEAPU32[(metadata >>> 2) + 1];
        if (count < 1 || count > 100) throw new Error("picomemo returned an invalid PreKey count.");
        identifier(module.HEAPU32[metadata >>> 2], "signed PreKey ID");
        for (let index = 0; index < count; index++) identifier(module.HEAPU32[(preKeyIds >>> 2) + index], "PreKey ID");

        return {
            identityKey: copy(module, identity, 32),
            signedPreKey: copy(module, signedPreKey, 32),
            signedPreKeySignature: copy(module, signature, 64),
            signedPreKeyId: module.HEAPU32[metadata >>> 2],
            preKeys: Object.freeze(Array.from({ length: count }, (_, index) => Object.freeze({
                id: module.HEAPU32[(preKeyIds >>> 2) + index],
                publicKey: copy(module, preKeys + index * 32, 32),
            }))),
        };
    }));
}

function replenish(module: Module, protocol: PicomemoProtocol, store: Uint8Array): Uint8Array {
    bounded(store, 16384, "store");
    return withBytes(module, [store], ([storePointer]) => withAllocations(module, [16384], ([out]) => copy(module, out, checked(protocol === "legacy" ? module._picomemoWeb0ReplenishStore(storePointer, store.length, out, 16384) : module._picomemoWebReplenishStore(storePointer, store.length, out, 16384), "replenish PreKeys"))));
}

function initiate(module: Module, protocol: PicomemoProtocol, store: Uint8Array, remote: PicomemoBundle): PicomemoWorkerSessionState {
    bounded(store, 16384, "store");
    exact(remote.identityKey, 32, "identity key");
    exact(remote.signedPreKey, 32, "signed PreKey");
    exact(remote.signedPreKeySignature, 64, "signed PreKey signature");
    if (!Array.isArray(remote.preKeys) || remote.preKeys.length < 1 || remote.preKeys.length > 100) throw new RangeError("Invalid PreKeys.");
    const selected = remote.preKeys[0];
    exact(selected.publicKey, 32, "PreKey");
    identifier(remote.signedPreKeyId, "signed PreKey ID");
    identifier(selected.id, "PreKey ID");

    return withBytes(module, [store, remote.identityKey, remote.signedPreKey, remote.signedPreKeySignature, selected.publicKey], ([storePointer, identity, signedPreKey, signature, preKey]) => withAllocations(module, [1024], ([out]) => {
        const length = checked(protocol === "legacy"
            ? module._picomemoWeb0InitiateSession(storePointer, store.length, identity, signedPreKey, signature, remote.signedPreKeyId, preKey, selected.id, out, 1024)
            : module._picomemoWebInitiateSession(storePointer, store.length, identity, signedPreKey, signature, remote.signedPreKeyId, preKey, selected.id, out, 1024), "initiate session");
        return { session: copy(module, out, length), skippedKeys: new Uint8Array(4) };
    }));
}

function encrypt(module: Module, protocol: PicomemoProtocol, state: PicomemoWorkerSessionState, key: Uint8Array): { state: PicomemoWorkerSessionState; message: Uint8Array; preKey: boolean } {
    boundedState(state);
    if (protocol === "legacy" ? key.length !== 32 : key.length < 1 || key.length > 48) throw new RangeError("Invalid key material length.");

    return withBytes(module, [state.session, key], ([session, keyPointer]) => withAllocations(module, [1024, 512, 12], ([sessionOut, messageOut, metadata]) => {
        checked(protocol === "legacy"
            ? module._picomemoWeb0EncryptKey(session, state.session.length, keyPointer, key.length, sessionOut, 1024, messageOut, 512, metadata)
            : module._picomemoWebEncryptKey(session, state.session.length, keyPointer, key.length, sessionOut, 1024, messageOut, 512, metadata), "encrypt key");
        const offset = metadata >>> 2;
        return {
            state: { session: copy(module, sessionOut, module.HEAPU32[offset]), skippedKeys: state.skippedKeys.slice() },
            message: copy(module, messageOut, module.HEAPU32[offset + 1]),
            preKey: module.HEAPU32[offset + 2] !== 0,
        };
    }));
}

function decrypt(module: Module, protocol: PicomemoProtocol, store: Uint8Array, state: PicomemoWorkerSessionState, maximumMessageJump: number, preKey: boolean, message: Uint8Array): { localState: Uint8Array; state: PicomemoWorkerSessionState; identityKey: Uint8Array; key: Uint8Array } {
    bounded(store, 16384, "store");
    boundedState(state);
    bounded(message, 512, "encrypted key message");
    if (!Number.isInteger(maximumMessageJump) || maximumMessageJump < 0 || maximumMessageJump > 128) throw new RangeError("Invalid maximum message jump.");

    return withBytes(module, [store, state.session, state.skippedKeys, message], ([storePointer, session, skipped, messagePointer]) => withAllocations(module, [16384, 1024, 9000, 64, 16, 32], ([storeOut, sessionOut, skippedOut, keyOut, metadata, identity]) => {
        checked(protocol === "legacy"
            ? module._picomemoWeb0DecryptKey(storePointer, store.length, session, state.session.length, skipped, state.skippedKeys.length, maximumMessageJump, Number(preKey), messagePointer, message.length, storeOut, 16384, sessionOut, 1024, skippedOut, 9000, keyOut, 64, metadata)
            : module._picomemoWebDecryptKey(storePointer, store.length, session, state.session.length, skipped, state.skippedKeys.length, maximumMessageJump, Number(preKey), messagePointer, message.length, storeOut, 16384, sessionOut, 1024, skippedOut, 9000, keyOut, 64, metadata), "decrypt key");
        const offset = metadata >>> 2;
        checked(protocol === "legacy"
            ? module._picomemoWeb0GetSessionIdentity(sessionOut, module.HEAPU32[offset + 1], identity)
            : module._picomemoWebGetSessionIdentity(sessionOut, module.HEAPU32[offset + 1], identity), "read session identity");
        return {
            localState: copy(module, storeOut, module.HEAPU32[offset]),
            state: { session: copy(module, sessionOut, module.HEAPU32[offset + 1]), skippedKeys: copy(module, skippedOut, module.HEAPU32[offset + 2]) },
            identityKey: copy(module, identity, 32),
            key: copy(module, keyOut, module.HEAPU32[offset + 3]),
        };
    }));
}

function maintain(module: Module, protocol: PicomemoProtocol, store: Uint8Array, state: PicomemoWorkerSessionState): { state: PicomemoWorkerSessionState; counters: { sent: number; received: number; previousSent: number }; keyTransport?: { message: Uint8Array; preKey: boolean } } {
    if (protocol !== "omemo2") throw new Error("picomemo session maintenance is only available for OMEMO 2.");
    if (!("_picomemoWebMaintainSession" in module) || typeof module._picomemoWebMaintainSession !== "function") throw new Error("The locked picomemo artifact does not support session maintenance.");
    const maintainSession = module._picomemoWebMaintainSession as (store: number, storeLength: number, session: number, sessionLength: number, sessionOut: number, sessionCapacity: number, messageOut: number, messageCapacity: number, metadata: number) => number;
    bounded(store, 16384, "store");
    boundedState(state);

    return withBytes(module, [store, state.session], ([storePointer, session]) => withAllocations(module, [1024, 512, 24], ([sessionOut, messageOut, metadata]) => {
        checked(maintainSession(storePointer, store.length, session, state.session.length, sessionOut, 1024, messageOut, 512, metadata), "maintain session");
        const offset = metadata >>> 2;
        const messageLength = module.HEAPU32[offset + 1];
        const result = {
            state: { session: copy(module, sessionOut, module.HEAPU32[offset]), skippedKeys: state.skippedKeys.slice() },
            counters: { sent: module.HEAPU32[offset + 3], received: module.HEAPU32[offset + 4], previousSent: module.HEAPU32[offset + 5] },
        };
        return messageLength === 0 ? result : { ...result, keyTransport: { message: copy(module, messageOut, messageLength), preKey: module.HEAPU32[offset + 2] !== 0 } };
    }));
}

function encryptPayload(module: Module, protocol: PicomemoProtocol, plaintext: Uint8Array): { key: Uint8Array; payload: Uint8Array; iv?: Uint8Array } {
    if (plaintext.length < 1 || plaintext.length > 1024 * 1024) throw new RangeError("Invalid payload plaintext.");
    if (protocol === "legacy") return withBytes(module, [plaintext], ([plaintextPointer]) => withAllocations(module, [plaintext.length, 32, 12], ([payload, key, iv]) => {
        const length = checked(module._picomemoWeb0EncryptMessage(plaintextPointer, plaintext.length, payload, plaintext.length, key, iv), "encrypt payload");
        return { key: copy(module, key, 32), iv: copy(module, iv, 12), payload: copy(module, payload, length) };
    }));
    const capacity = plaintext.length + 16;
    return withBytes(module, [plaintext], ([plaintextPointer]) => withAllocations(module, [capacity, 48], ([payload, key]) => {
        const length = checked(module._picomemoWebEncryptMessage(plaintextPointer, plaintext.length, payload, capacity, key), "encrypt payload");
        return { key: copy(module, key, 48), payload: copy(module, payload, length) };
    }));
}

function decryptPayload(module: Module, protocol: PicomemoProtocol, key: Uint8Array, iv: Uint8Array | undefined, payload: Uint8Array): Uint8Array {
    if (protocol === "legacy") {
        exact(key, 32, "payload key");
        if (!(iv instanceof Uint8Array)) throw new RangeError("Invalid payload IV.");
        exact(iv, 12, "payload IV");
        if (payload.length < 1 || payload.length > 1024 * 1024) throw new RangeError("Invalid encrypted payload.");
        return withBytes(module, [key, iv, payload], ([keyPointer, ivPointer, payloadPointer]) => withAllocations(module, [payload.length], ([plaintext]) => copy(module, plaintext, checked(module._picomemoWeb0DecryptMessage(keyPointer, key.length, ivPointer, iv.length, payloadPointer, payload.length, plaintext, payload.length), "decrypt payload"))));
    }
    exact(key, 48, "payload key");
    if (payload.length < 16 || payload.length > 1024 * 1024 || payload.length % 16 !== 0) throw new RangeError("Invalid encrypted payload.");
    return withBytes(module, [key, payload], ([keyPointer, payloadPointer]) => withAllocations(module, [payload.length], ([plaintext]) => copy(module, plaintext, checked(module._picomemoWebDecryptMessage(keyPointer, key.length, payloadPointer, payload.length, plaintext, payload.length), "decrypt payload"))));
}

function checked(result: number, operation: string): number {
    if (result < 0) throw new Error(`picomemo ${operation} failed (${result}).`);
    return result;
}

function copy(module: Module, pointer: number, length: number): Uint8Array {
    return module.HEAPU8.slice(pointer, pointer + length);
}

function boundedState(state: PicomemoWorkerSessionState): void {
    bounded(state.session, 1024, "session");
    bounded(state.skippedKeys, 9000, "skipped-key state");
}

function bounded(value: Uint8Array, maximum: number, name: string): void {
    if (!(value instanceof Uint8Array) || value.length > maximum) throw new RangeError(`Invalid ${name}.`);
}

function exact(value: Uint8Array, length: number, name: string): void {
    if (!(value instanceof Uint8Array) || value.length !== length) throw new RangeError(`Invalid ${name}.`);
}

function identifier(value: number, name: string): void {
    if (!Number.isInteger(value) || value < 1 || value > 0xffffffff) throw new RangeError(`Invalid ${name}.`);
}

function withBytes<T>(module: Module, values: readonly Uint8Array[], callback: (pointers: readonly number[]) => T): T {
    const pointers = values.map((value) => {
        const pointer = module._malloc(Math.max(value.length, 1));
        module.HEAPU8.set(value, pointer);
        return pointer;
    });

    try {
        return callback(pointers);
    } finally {
        for (let index = 0; index < pointers.length; index++) {
            module.HEAPU8.fill(0, pointers[index], pointers[index] + values[index].length);
            module._free(pointers[index]);
        }
    }
}

function withAllocations<T>(module: Module, sizes: readonly number[], callback: (pointers: readonly number[]) => T): T {
    const pointers = sizes.map((size) => {
        const pointer = module._malloc(size);
        module.HEAPU8.fill(0, pointer, pointer + size);
        return pointer;
    });

    try {
        return callback(pointers);
    } finally {
        for (let index = 0; index < pointers.length; index++) {
            module.HEAPU8.fill(0, pointers[index], pointers[index] + sizes[index]);
            module._free(pointers[index]);
        }
    }
}

function respond(response: PicomemoWorkerResponse): void {
    scope.postMessage(response);
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null;
}
