import { PICOMEMO_BACKEND_VERSION, PICOMEMO_DEFAULT_MESSAGE_JUMP, PICOMEMO_DEFAULT_RETAINED_SKIPPED_KEYS, PICOMEMO_HARD_MAXIMUM_MESSAGE_JUMP, PICOMEMO_HARD_MAXIMUM_RETAINED_SKIPPED_KEYS, PICOMEMO_MAXIMUM_SESSION_STATE_BYTES, PICOMEMO_METADATA } from "./metadata.js";
import type { CreatePicomemoBackendOptions, PicomemoBackend, PicomemoBundle, PicomemoDecryptedKey, PicomemoEncryptedKey, PicomemoEncryptedPayload, PicomemoErrorCategory, PicomemoErrorCounters, PicomemoErrorData, PicomemoErrorLimit, PicomemoErrorOperation, PicomemoProtocol, PicomemoSessionMaintenance, PicomemoWorkerRequest, PicomemoWorkerResponse, PicomemoWorkerSessionState } from "./types.js";

const MAXIMUM_LOCAL_STATE_BYTES = 16384;
const MAXIMUM_SKIPPED_KEY_STATE_BYTES = 4 + PICOMEMO_HARD_MAXIMUM_RETAINED_SKIPPED_KEYS * 68;
const SESSION_STATE_MAGIC = Uint8Array.of(0x50, 0x4d, 0x53, 0x53);

interface WorkerEncryptedKey { readonly state: PicomemoWorkerSessionState; readonly message: Uint8Array; readonly preKey: boolean; }
interface WorkerDecryptedKey { readonly localState: Uint8Array; readonly state: PicomemoWorkerSessionState; readonly identityKey: Uint8Array; readonly key: Uint8Array; }
interface WorkerSessionMaintenance {
    readonly state: PicomemoWorkerSessionState;
    readonly counters: { readonly sent: number; readonly received: number; readonly previousSent: number };
    readonly keyTransport?: { readonly message: Uint8Array; readonly preKey: boolean };
}

interface PendingWorkerRequest {
    readonly protocol: PicomemoProtocol;
    readonly operation: PicomemoWorkerRequest["operation"];
    readonly maximumMessageJump?: number;
    readonly maximumRetainedSkippedKeys?: number;
    resolve(value: unknown): void;
    reject(error: unknown): void;
}

type RequestWithoutId = PicomemoWorkerRequest extends infer Request
    ? Request extends PicomemoWorkerRequest ? Omit<Request, "id"> : never
    : never;

/** Structured, secret-free cryptographic failure returned by Picomemo. */
export class PicomemoError extends Error {
    readonly category: PicomemoErrorCategory;
    readonly protocol: PicomemoProtocol | "unknown";
    readonly operation: PicomemoErrorOperation;
    readonly limit?: PicomemoErrorLimit;
    readonly counters?: PicomemoErrorCounters;

    constructor(data: PicomemoErrorData) {
        super(errorMessage(data));
        this.name = "PicomemoError";
        this.category = data.category;
        this.protocol = data.protocol;
        this.operation = data.operation;
        this.limit = data.limit;
        this.counters = data.counters;
    }
}

class WorkerPicomemoBackend {
    readonly id: string;
    readonly version = PICOMEMO_BACKEND_VERSION;
    readonly protocol: PicomemoProtocol;

    private worker: Worker | undefined;
    private readonly pending = new Map<number, PendingWorkerRequest>();
    private readonly unavailableCallbacks = new Set<() => void>();
    private requestId = 0;
    private terminated = false;
    private readonly maximumMessageJump: number;
    private readonly maximumRetainedSkippedKeys: number;

    private readonly workerFactory: () => Worker;

    constructor(options: CreatePicomemoBackendOptions) {
        this.protocol = options.protocol;
        this.maximumMessageJump = validateLimit(options.maximumMessageJump ?? PICOMEMO_DEFAULT_MESSAGE_JUMP, PICOMEMO_HARD_MAXIMUM_MESSAGE_JUMP, "maximum message jump");
        this.maximumRetainedSkippedKeys = validateLimit(options.maximumRetainedSkippedKeys ?? PICOMEMO_DEFAULT_RETAINED_SKIPPED_KEYS, PICOMEMO_HARD_MAXIMUM_RETAINED_SKIPPED_KEYS, "maximum retained skipped keys");
        this.workerFactory = options.workerFactory ?? (() => new Worker(new URL("./worker.js", import.meta.url), { type: "module", name: "picomemo" }));
        this.id = `picomemo:${this.protocol}`;
    }

    async createIdentity(): Promise<Uint8Array> {
        return expectBytes(await this.request({ operation: "setup", protocol: this.protocol }), 1, MAXIMUM_LOCAL_STATE_BYTES, "local state");
    }

    async fingerprint(identityKey: Uint8Array): Promise<string> {
        validateInputBytes(identityKey, 32, 32, "identity key");
        const value = await this.request({ operation: "fingerprint", protocol: this.protocol, identityKey });
        if (typeof value !== "string" || !/^[0-9a-f]{8}( [0-9a-f]{8}){7}$/.test(value)) throw new TypeError("The OMEMO Worker returned an invalid fingerprint.");
        return value;
    }

    async createBundle(localState: Uint8Array): Promise<PicomemoBundle> {
        validateInputBytes(localState, 1, MAXIMUM_LOCAL_STATE_BYTES, "local state");
        return expectBundle(await this.request({ operation: "bundle", protocol: this.protocol, store: localState }));
    }

    async replenishPreKeys(localState: Uint8Array): Promise<Uint8Array> {
        validateInputBytes(localState, 1, MAXIMUM_LOCAL_STATE_BYTES, "local state");
        return expectBytes(await this.request({ operation: "replenish", protocol: this.protocol, store: localState }), 1, MAXIMUM_LOCAL_STATE_BYTES, "local state");
    }

    async buildOutgoingSession(localState: Uint8Array, bundle: PicomemoBundle): Promise<Uint8Array> {
        validateInputBytes(localState, 1, MAXIMUM_LOCAL_STATE_BYTES, "local state");
        const remote = validateBundleInput(bundle);
        const state = expectSessionState(await this.request({
            operation: "initiate",
            protocol: this.protocol,
            store: localState,
            bundle: remote,
        }));
        return encodeSessionState(state);
    }

    async encryptKey(sessionState: Uint8Array, key: Uint8Array): Promise<PicomemoEncryptedKey> {
        validateInputBytes(key, this.protocol === "legacy" ? 32 : 1, this.protocol === "legacy" ? 32 : 48, "key material");
        const result = expectEncryptedKey(await this.request({ operation: "encrypt", protocol: this.protocol, state: decodeSessionState(sessionState), key }));
        return { sessionState: encodeSessionState(result.state), message: result.message, keyExchange: result.preKey };
    }

    async decryptKey(localState: Uint8Array, sessionState: Uint8Array | undefined, keyExchange: boolean, message: Uint8Array, maximumMessageJump = this.maximumMessageJump, maximumRetainedSkippedKeys = this.maximumRetainedSkippedKeys): Promise<PicomemoDecryptedKey> {
        validateInputBytes(localState, 1, MAXIMUM_LOCAL_STATE_BYTES, "local state");
        validateInputBytes(message, 1, 512, "encrypted key");
        if (typeof keyExchange !== "boolean") throw new TypeError("Invalid OMEMO key-exchange flag.");
        validateLimit(maximumMessageJump, PICOMEMO_HARD_MAXIMUM_MESSAGE_JUMP, "maximum message jump");
        validateLimit(maximumRetainedSkippedKeys, PICOMEMO_HARD_MAXIMUM_RETAINED_SKIPPED_KEYS, "maximum retained skipped keys");
        const result = expectDecryptedKey(await this.request({
            operation: "decrypt",
            protocol: this.protocol,
            store: localState,
            state: sessionState ? decodeSessionState(sessionState) : emptySessionState(),
            maximumMessageJump,
            maximumRetainedSkippedKeys,
            preKey: keyExchange,
            message,
        }));
        if (this.protocol === "legacy" && result.key.length !== 32) throw new TypeError("The OMEMO Worker returned an invalid legacy decrypted key.");
        return { localState: result.localState, sessionState: encodeSessionState(result.state), identityKey: result.identityKey, key: result.key };
    }

    async maintainSession(localState: Uint8Array, sessionState: Uint8Array): Promise<PicomemoSessionMaintenance> {
        if (this.protocol !== "omemo2") throw new Error("Session maintenance is only available for OMEMO 2.");
        validateInputBytes(localState, 1, MAXIMUM_LOCAL_STATE_BYTES, "local state");
        const result = expectSessionMaintenance(await this.request({ operation: "maintain", protocol: this.protocol, store: localState, state: decodeSessionState(sessionState) }));
        const maintainedState = encodeSessionState(result.state);
        return {
            sessionState: maintainedState,
            counters: result.counters,
            ...(result.keyTransport ? { keyTransport: { sessionState: maintainedState, message: result.keyTransport.message, keyExchange: result.keyTransport.preKey } } : {}),
        };
    }

    async encryptPayload(plaintext: Uint8Array): Promise<PicomemoEncryptedPayload> {
        validateInputBytes(plaintext, 1, 1024 * 1024, "payload plaintext");
        return expectEncryptedPayload(await this.request({ operation: "encrypt-payload", protocol: this.protocol, plaintext }), this.protocol);
    }

    async decryptPayload(key: Uint8Array, payload: Uint8Array, iv?: Uint8Array): Promise<Uint8Array> {
        validateInputBytes(key, this.protocol === "legacy" ? 32 : 48, this.protocol === "legacy" ? 32 : 48, "payload key");
        validateInputBytes(payload, this.protocol === "legacy" ? 1 : 16, 1024 * 1024, "encrypted payload");
        if (this.protocol === "legacy") {
            validateInputBytes(iv, 12, 16, "payload IV");
            if (iv.length !== 12 && iv.length !== 16) throw new TypeError("Invalid OMEMO payload IV.");
            return expectBytes(await this.request({ operation: "decrypt-payload", protocol: "legacy", key, payload, iv }), 1, 1024 * 1024, "payload plaintext");
        }
        if (iv !== undefined) throw new TypeError("OMEMO 2 payload decryption does not accept a transmitted IV.");
        if (payload.length % 16 !== 0) throw new TypeError("Invalid encrypted payload.");
        return expectBytes(await this.request({ operation: "decrypt-payload", protocol: "omemo2", key, payload }), 1, 1024 * 1024, "payload plaintext");
    }

    onUnavailable(callback: () => void): () => void {
        this.unavailableCallbacks.add(callback);
        return () => this.unavailableCallbacks.delete(callback);
    }

    terminate(): void {
        if (this.terminated) return;
        this.terminated = true;
        this.worker?.terminate();
        this.worker = undefined;
        this.fail(new Error("The OMEMO cryptographic Worker was terminated."));
    }

    private request(request: RequestWithoutId): Promise<unknown> {
        if (this.terminated) return Promise.reject(new Error("The OMEMO cryptographic Worker is terminated."));
        if (this.pending.size >= 64) return Promise.reject(new Error("The OMEMO cryptographic Worker request queue is full."));
        const id = ++this.requestId;

        return new Promise<unknown>((resolve, reject) => {
            this.pending.set(id, {
                protocol: this.protocol,
                operation: request.operation,
                ...(request.operation === "decrypt" ? { maximumMessageJump: request.maximumMessageJump, maximumRetainedSkippedKeys: request.maximumRetainedSkippedKeys } : {}),
                resolve,
                reject,
            });
            try {
                this.getWorker().postMessage({ ...request, id });
            } catch (error: unknown) {
                this.handleWorkerFailure(error instanceof Error ? error : new Error("The OMEMO cryptographic Worker request failed."));
            }
        });
    }

    private getWorker(): Worker {
        if (this.worker) return this.worker;
        const worker = this.workerFactory();
        worker.onmessage = (event: MessageEvent<PicomemoWorkerResponse>) => this.handleResponse(event.data);
        worker.onerror = () => this.handleWorkerFailure(new Error("The OMEMO cryptographic Worker failed."));
        worker.onmessageerror = () => this.handleWorkerFailure(new Error("The OMEMO cryptographic Worker returned an invalid message."));
        this.worker = worker;
        return worker;
    }

    private handleResponse(response: PicomemoWorkerResponse): void {
        if (!isRecord(response) || !Number.isSafeInteger(response.id) || typeof response.ok !== "boolean") {
            this.handleWorkerFailure(new Error("The OMEMO cryptographic Worker returned an invalid response."));
            return;
        }

        const pending = this.pending.get(response.id);
        if (!pending) {
            this.handleWorkerFailure(new Error("The OMEMO cryptographic Worker returned an unexpected response."));
            return;
        }
        if (response.ok && hasExactKeys(response, ["id", "ok", "value"])) {
            let value: unknown;
            try {
                value = expectSuccessValue(response.value, pending);
            } catch {
                this.handleWorkerFailure(new Error("The OMEMO cryptographic Worker returned an invalid success response."));
                return;
            }
            this.pending.delete(response.id);
            pending.resolve(value);
        } else if (!response.ok && hasExactKeys(response, ["id", "ok", "error"])) {
            let error: PicomemoError;
            try {
                error = new PicomemoError(expectErrorData(response.error, pending));
            } catch {
                this.handleWorkerFailure(new Error("The OMEMO cryptographic Worker returned an invalid error response."));
                return;
            }
            this.pending.delete(response.id);
            pending.reject(error);
        } else this.handleWorkerFailure(new Error("The OMEMO cryptographic Worker returned an invalid error response."));
    }

    private fail(error: Error): void {
        for (const pending of this.pending.values()) pending.reject(error);
        this.pending.clear();
    }

    private handleWorkerFailure(error: Error): void {
        const wasTerminated = this.terminated;
        this.worker?.terminate();
        this.worker = undefined;
        this.terminated = true;
        this.fail(error);
        if (!wasTerminated) for (const callback of [...this.unavailableCallbacks]) callback();
    }
}

function expectSuccessValue(value: unknown, pending: PendingWorkerRequest): unknown {
    switch (pending.operation) {
        case "setup":
        case "replenish": return expectBytes(value, 1, MAXIMUM_LOCAL_STATE_BYTES, "local state");
        case "fingerprint":
            if (typeof value !== "string" || !/^[0-9a-f]{8}( [0-9a-f]{8}){7}$/.test(value)) throw new TypeError("The OMEMO Worker returned an invalid fingerprint.");
            return value;
        case "bundle": return expectBundle(value);
        case "initiate": return expectSessionState(value);
        case "encrypt": return expectEncryptedKey(value);
        case "decrypt": {
            const result = expectDecryptedKey(value);
            if (pending.protocol === "legacy" && result.key.length !== 32) throw new TypeError("The OMEMO Worker returned an invalid legacy decrypted key.");
            return result;
        }
        case "maintain": return expectSessionMaintenance(value);
        case "encrypt-payload": return expectEncryptedPayload(value, pending.protocol);
        case "decrypt-payload": return expectBytes(value, 1, 1024 * 1024, "payload plaintext");
    }
}

function encodeSessionState(state: PicomemoWorkerSessionState): Uint8Array {
    const validated = expectSessionState(state);
    const output = new Uint8Array(16 + validated.session.length + validated.skippedKeys.length);
    const view = new DataView(output.buffer);
    output.set(SESSION_STATE_MAGIC, 0);
    view.setUint16(4, 2, true);
    view.setUint16(6, 0, true);
    view.setUint32(8, validated.session.length, true);
    view.setUint32(12, validated.skippedKeys.length, true);
    output.set(validated.session, 16);
    output.set(validated.skippedKeys, 16 + validated.session.length);
    return output;
}

function decodeSessionState(value: Uint8Array): PicomemoWorkerSessionState {
    if (!(value instanceof Uint8Array) || value.length < 8 || value.length > PICOMEMO_MAXIMUM_SESSION_STATE_BYTES) throw new TypeError("Invalid picomemo session envelope.");
    const view = new DataView(value.buffer, value.byteOffset, value.byteLength);
    const versioned = SESSION_STATE_MAGIC.every((byte, index) => value[index] === byte);
    if (versioned && (value.length < 16 || view.getUint16(4, true) !== 2 || view.getUint16(6, true) !== 0)) throw new TypeError("Invalid picomemo session envelope.");
    const headerLength = versioned ? 16 : 8;
    const sessionLength = view.getUint32(versioned ? 8 : 0, true);
    const skippedLength = view.getUint32(versioned ? 12 : 4, true);
    if (sessionLength < 1 || sessionLength > 1024 || skippedLength < 4 || skippedLength > MAXIMUM_SKIPPED_KEY_STATE_BYTES || value.length !== headerLength + sessionLength + skippedLength) throw new TypeError("Invalid picomemo session envelope.");
    validateSkippedKeyState(value.subarray(headerLength + sessionLength));
    return { session: value.slice(headerLength, headerLength + sessionLength), skippedKeys: value.slice(headerLength + sessionLength) };
}

function expectBundle(value: unknown): PicomemoBundle {
    if (!isRecord(value) || !hasExactKeys(value, ["identityKey", "signedPreKey", "signedPreKeySignature", "signedPreKeyId", "preKeys"]) || !Array.isArray(value.preKeys)) throw new TypeError("The OMEMO Worker returned an invalid bundle.");
    const preKeys = value.preKeys.map((preKey) => {
        if (!isRecord(preKey) || !hasExactKeys(preKey, ["id", "publicKey"])) throw new TypeError("The OMEMO Worker returned an invalid PreKey.");
        return Object.freeze({ id: expectIdentifier(preKey.id, "PreKey ID"), publicKey: expectBytes(preKey.publicKey, 32, 32, "PreKey") });
    });
    if (preKeys.length < 1 || preKeys.length > 100) throw new TypeError("The OMEMO Worker returned an invalid PreKey count.");
    return {
        identityKey: expectBytes(value.identityKey, 32, 32, "identity key"),
        signedPreKey: expectBytes(value.signedPreKey, 32, 32, "signed PreKey"),
        signedPreKeySignature: expectBytes(value.signedPreKeySignature, 64, 64, "signed PreKey signature"),
        signedPreKeyId: expectIdentifier(value.signedPreKeyId, "signed PreKey ID"),
        preKeys,
    };
}

function validateBundleInput(value: PicomemoBundle): PicomemoBundle {
    if (!isRecord(value) || !hasExactKeys(value, ["identityKey", "signedPreKey", "signedPreKeySignature", "signedPreKeyId", "preKeys"]) || !Array.isArray(value.preKeys) || value.preKeys.length < 1 || value.preKeys.length > 100) throw new TypeError("Invalid picomemo bundle.");
    validateInputBytes(value.identityKey, 32, 32, "bundle identity key");
    validateInputBytes(value.signedPreKey, 32, 32, "bundle signed PreKey");
    validateInputBytes(value.signedPreKeySignature, 64, 64, "bundle signed PreKey signature");
    const signedPreKeyId = validateInputIdentifier(value.signedPreKeyId, "bundle signed PreKey ID");
    const preKeys = value.preKeys.map((preKey) => {
        if (!isRecord(preKey) || !hasExactKeys(preKey, ["id", "publicKey"])) throw new TypeError("Invalid OMEMO bundle PreKey.");
        validateInputBytes(preKey.publicKey, 32, 32, "bundle PreKey");
        return { id: validateInputIdentifier(preKey.id, "bundle PreKey ID"), publicKey: preKey.publicKey };
    });
    return { identityKey: value.identityKey, signedPreKey: value.signedPreKey, signedPreKeySignature: value.signedPreKeySignature, signedPreKeyId, preKeys };
}

function expectSessionState(value: unknown): PicomemoWorkerSessionState {
    if (!isRecord(value) || !hasExactKeys(value, ["session", "skippedKeys"])) throw new TypeError("The OMEMO Worker returned invalid session state.");
    const skippedKeys = expectBytes(value.skippedKeys, 4, MAXIMUM_SKIPPED_KEY_STATE_BYTES, "skipped-key state");
    validateSkippedKeyState(skippedKeys);
    return { session: expectBytes(value.session, 1, 1024, "session"), skippedKeys };
}

function expectEncryptedKey(value: unknown): WorkerEncryptedKey {
    if (!isRecord(value) || !hasExactKeys(value, ["state", "message", "preKey"]) || typeof value.preKey !== "boolean") throw new TypeError("The OMEMO Worker returned an invalid encrypted key.");
    return { state: expectSessionState(value.state), message: expectBytes(value.message, 1, 512, "encrypted key"), preKey: value.preKey };
}

function expectDecryptedKey(value: unknown): WorkerDecryptedKey {
    if (!isRecord(value) || !hasExactKeys(value, ["localState", "state", "identityKey", "key"])) throw new TypeError("The OMEMO Worker returned an invalid decrypted key.");
    return {
        localState: expectBytes(value.localState, 1, MAXIMUM_LOCAL_STATE_BYTES, "local state"),
        state: expectSessionState(value.state),
        identityKey: expectBytes(value.identityKey, 32, 32, "session identity key"),
        key: expectBytes(value.key, 1, 48, "decrypted key"),
    };
}

function expectSessionMaintenance(value: unknown): WorkerSessionMaintenance {
    const expectedKeys = isRecord(value) && value.keyTransport !== undefined ? ["state", "counters", "keyTransport"] : ["state", "counters"];
    if (!isRecord(value) || !hasExactKeys(value, expectedKeys) || !isRecord(value.counters) || !hasExactKeys(value.counters, ["sent", "received", "previousSent"])) throw new TypeError("The OMEMO Worker returned invalid session maintenance.");
    const result: WorkerSessionMaintenance = {
        state: expectSessionState(value.state),
        counters: {
            sent: expectCounter(value.counters.sent, "sent counter"),
            received: expectCounter(value.counters.received, "received counter"),
            previousSent: expectCounter(value.counters.previousSent, "previous-sent counter"),
        },
    };
    if (value.keyTransport === undefined) return result;
    if (!isRecord(value.keyTransport) || !hasExactKeys(value.keyTransport, ["message", "preKey"]) || typeof value.keyTransport.preKey !== "boolean") throw new TypeError("The OMEMO Worker returned invalid session maintenance key transport.");
    return { ...result, keyTransport: { message: expectBytes(value.keyTransport.message, 1, 512, "session maintenance key transport"), preKey: value.keyTransport.preKey } };
}

function expectEncryptedPayload(value: unknown, protocol: PicomemoProtocol): PicomemoEncryptedPayload {
    const expectedKeys = protocol === "legacy" ? ["key", "iv", "payload"] : ["key", "payload"];
    if (!isRecord(value) || !hasExactKeys(value, expectedKeys)) throw new TypeError("The OMEMO Worker returned an invalid encrypted payload.");
    const payload = expectBytes(value.payload, protocol === "legacy" ? 1 : 16, 1024 * 1024, "encrypted payload");
    if (protocol === "legacy") return { key: expectBytes(value.key, 32, 32, "payload key"), iv: expectBytes(value.iv, 12, 12, "payload IV"), payload };
    if (payload.length % 16 !== 0) throw new TypeError("The OMEMO Worker returned an invalid encrypted payload.");
    return { key: expectBytes(value.key, 48, 48, "payload key"), payload };
}

function expectBytes(value: unknown, minimum: number, maximum: number, name: string): Uint8Array {
    if (!(value instanceof Uint8Array) || value.length < minimum || value.length > maximum) throw new TypeError(`The OMEMO Worker returned invalid ${name}.`);
    return value;
}

function validateInputBytes(value: unknown, minimum: number, maximum: number, name: string): asserts value is Uint8Array {
    if (!(value instanceof Uint8Array) || value.length < minimum || value.length > maximum) throw new TypeError(`Invalid OMEMO ${name}.`);
}

function validateInputIdentifier(value: unknown, name: string): number {
    if (!Number.isInteger(value) || (value as number) < 1 || (value as number) > 0xffffffff) throw new TypeError(`Invalid OMEMO ${name}.`);
    return value as number;
}

function expectIdentifier(value: unknown, name: string): number {
    if (!Number.isInteger(value) || (value as number) < 1 || (value as number) > 0xffffffff) throw new TypeError(`The OMEMO Worker returned an invalid ${name}.`);
    return value as number;
}

function expectCounter(value: unknown, name: string): number {
    if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 0xffffffff) throw new TypeError(`The OMEMO Worker returned an invalid ${name}.`);
    return value as number;
}

function expectErrorData(value: unknown, pending: PendingWorkerRequest): PicomemoErrorData {
    if (!isRecord(value)) throw new TypeError("Invalid Picomemo error data.");
    const optionalKeys = [...(value.limit === undefined ? [] : ["limit"]), ...(value.counters === undefined ? [] : ["counters"])];
    if (!hasExactKeys(value, ["category", "protocol", "operation", ...optionalKeys])) throw new TypeError("Invalid Picomemo error data.");
    const categories: readonly PicomemoErrorCategory[] = ["jump-too-large", "skipped-key-capacity", "duplicate-or-old", "authentication-failed", "malformed-message", "backend-failure"];
    const operations: readonly PicomemoErrorOperation[] = ["setup", "fingerprint", "bundle", "replenish", "initiate", "encrypt", "decrypt", "maintain", "encrypt-payload", "decrypt-payload", "worker-request"];
    if (!categories.includes(value.category as PicomemoErrorCategory) || value.protocol !== pending.protocol || value.operation !== pending.operation || !operations.includes(value.operation as PicomemoErrorOperation)) throw new TypeError("Invalid Picomemo error data.");
    const category = value.category as PicomemoErrorCategory;
    const limit = value.limit === undefined ? undefined : expectErrorLimit(value.limit);
    const counters = value.counters === undefined ? undefined : expectErrorCounters(value.counters);
    if (category !== "backend-failure" && pending.operation !== "decrypt") throw new TypeError("Invalid Picomemo error category for operation.");
    const maximumMessageJump = pending.maximumMessageJump;
    const maximumRetainedSkippedKeys = pending.maximumRetainedSkippedKeys;
    if (category === "jump-too-large" && (maximumMessageJump === undefined || maximumRetainedSkippedKeys === undefined || limit?.kind !== "message-jump" || limit.configured !== maximumMessageJump || !hasCompleteErrorCounters(counters) || counters.requestedMessageJump <= maximumMessageJump || counters.retainedSkippedKeys > maximumRetainedSkippedKeys)) throw new TypeError("Invalid Picomemo jump error data.");
    if (category === "skipped-key-capacity" && (maximumMessageJump === undefined || maximumRetainedSkippedKeys === undefined || limit?.kind !== "retained-skipped-keys" || limit.configured !== maximumRetainedSkippedKeys || !hasCompleteErrorCounters(counters) || counters.requestedMessageJump > maximumMessageJump || !exceedsRetainedCapacity(counters.requestedMessageJump, counters.retainedSkippedKeys, maximumRetainedSkippedKeys))) throw new TypeError("Invalid Picomemo capacity error data.");
    if (category !== "jump-too-large" && category !== "skipped-key-capacity" && (limit !== undefined || counters !== undefined)) throw new TypeError("Invalid Picomemo error metadata.");
    return { category, protocol: pending.protocol, operation: pending.operation, ...(limit ? { limit } : {}), ...(counters ? { counters } : {}) };
}

function hasCompleteErrorCounters(value: PicomemoErrorCounters | undefined): value is Required<PicomemoErrorCounters> {
    return value?.requestedMessageJump !== undefined && value.retainedSkippedKeys !== undefined;
}

function exceedsRetainedCapacity(requested: number, retained: number, maximum: number): boolean {
    return retained > maximum || requested > maximum - retained;
}

function expectErrorLimit(value: unknown): PicomemoErrorLimit {
    if (!isRecord(value) || !hasExactKeys(value, ["kind", "configured"]) || (value.kind !== "message-jump" && value.kind !== "retained-skipped-keys")) throw new TypeError("Invalid Picomemo error limit.");
    const maximum = value.kind === "message-jump" ? PICOMEMO_HARD_MAXIMUM_MESSAGE_JUMP : PICOMEMO_HARD_MAXIMUM_RETAINED_SKIPPED_KEYS;
    return { kind: value.kind, configured: validateLimit(value.configured, maximum, "error limit") };
}

function expectErrorCounters(value: unknown): PicomemoErrorCounters {
    if (!isRecord(value)) throw new TypeError("Invalid Picomemo error counters.");
    const keys = Object.keys(value);
    if (keys.length < 1 || keys.some((key) => key !== "requestedMessageJump" && key !== "retainedSkippedKeys")) throw new TypeError("Invalid Picomemo error counters.");
    const requestedMessageJump = value.requestedMessageJump === undefined ? undefined : expectUnsigned(value.requestedMessageJump, 0xffffffff, "requested message jump");
    const retainedSkippedKeys = value.retainedSkippedKeys === undefined ? undefined : expectUnsigned(value.retainedSkippedKeys, PICOMEMO_HARD_MAXIMUM_RETAINED_SKIPPED_KEYS, "retained skipped keys");
    return { ...(requestedMessageJump === undefined ? {} : { requestedMessageJump }), ...(retainedSkippedKeys === undefined ? {} : { retainedSkippedKeys }) };
}

function validateSkippedKeyState(value: Uint8Array): void {
    if (value.length < 4) throw new TypeError("Invalid picomemo skipped-key state.");
    const count = new DataView(value.buffer, value.byteOffset, value.byteLength).getUint32(0, true);
    if (count > PICOMEMO_HARD_MAXIMUM_RETAINED_SKIPPED_KEYS || value.length !== 4 + count * 68) throw new TypeError("Invalid picomemo skipped-key state.");
}

function validateLimit(value: unknown, maximum: number, name: string): number {
    if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > maximum) throw new RangeError(`Invalid ${name}.`);
    return value as number;
}

function expectUnsigned(value: unknown, maximum: number, name: string): number {
    if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > maximum) throw new TypeError(`Invalid ${name}.`);
    return value as number;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
    const keys = Object.keys(value);
    return keys.length === expected.length && keys.every((key) => expected.includes(key));
}

function errorMessage(data: PicomemoErrorData): string {
    const messages: Record<PicomemoErrorCategory, string> = {
        "jump-too-large": "The Picomemo ratchet jump exceeds the configured limit.",
        "skipped-key-capacity": "The Picomemo retained skipped-key capacity is exhausted.",
        "duplicate-or-old": "The Picomemo message is a duplicate or is too old to decrypt.",
        "authentication-failed": "The Picomemo message authentication failed.",
        "malformed-message": "The Picomemo message is malformed.",
        "backend-failure": "The Picomemo backend operation failed.",
    };
    return messages[data.category];
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null;
}

function emptySessionState(): PicomemoWorkerSessionState {
    return { session: new Uint8Array(), skippedKeys: new Uint8Array(4) };
}

/**
 * Creates a lazy dedicated-Worker backend for OMEMO 2 or legacy OMEMO.
 * Call `terminate()` when the backend is no longer needed.
 */
export function createPicomemoBackend<Protocol extends PicomemoProtocol>(options: CreatePicomemoBackendOptions<Protocol>): PicomemoBackend<Protocol> {
    if (!options || (options.protocol !== "omemo2" && options.protocol !== "legacy")) throw new TypeError("Invalid picomemo protocol.");
    // The runtime protocol check and immutable instance protocol make this the
    // protocol-specific public surface selected by the caller's literal.
    return new WorkerPicomemoBackend(options) as unknown as PicomemoBackend<Protocol>;
}

export { isPicomemoBackendVersionCompatible, PICOMEMO_BACKEND_VERSION, PICOMEMO_COMPATIBLE_BACKEND_VERSIONS, PICOMEMO_DEFAULT_MESSAGE_JUMP, PICOMEMO_DEFAULT_RETAINED_SKIPPED_KEYS, PICOMEMO_HARD_MAXIMUM_MESSAGE_JUMP, PICOMEMO_HARD_MAXIMUM_RETAINED_SKIPPED_KEYS, PICOMEMO_MAXIMUM_MESSAGE_JUMP, PICOMEMO_MAXIMUM_SESSION_STATE_BYTES, PICOMEMO_METADATA, PICOMEMO_SESSION_STATE_VERSION } from "./metadata.js";
export type { CreatePicomemoBackendOptions, PicomemoBackend, PicomemoBundle, PicomemoDecryptedKey, PicomemoEncryptedKey, PicomemoEncryptedPayload, PicomemoErrorCategory, PicomemoErrorCounters, PicomemoErrorData, PicomemoErrorLimit, PicomemoErrorOperation, PicomemoLegacyEncryptedPayload, PicomemoOMEMO2EncryptedPayload, PicomemoPayloadDecryptArguments, PicomemoProtocol, PicomemoSessionMaintenance } from "./types.js";
