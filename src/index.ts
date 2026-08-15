import { PICOMEMO_BACKEND_VERSION, PICOMEMO_MAXIMUM_MESSAGE_JUMP, PICOMEMO_METADATA } from "./metadata.js";
import type { CreatePicomemoBackendOptions, PicomemoBackend, PicomemoBundle, PicomemoDecryptedKey, PicomemoEncryptedKey, PicomemoEncryptedPayload, PicomemoProtocol, PicomemoSessionMaintenance, PicomemoWorkerRequest, PicomemoWorkerResponse, PicomemoWorkerSessionState } from "./types.js";

const MAXIMUM_LOCAL_STATE_BYTES = 16384;
const MAXIMUM_SESSION_STATE_BYTES = 10000;

interface WorkerEncryptedKey { readonly state: PicomemoWorkerSessionState; readonly message: Uint8Array; readonly preKey: boolean; }
interface WorkerDecryptedKey { readonly localState: Uint8Array; readonly state: PicomemoWorkerSessionState; readonly identityKey: Uint8Array; readonly key: Uint8Array; }
interface WorkerSessionMaintenance {
    readonly state: PicomemoWorkerSessionState;
    readonly counters: { readonly sent: number; readonly received: number; readonly previousSent: number };
    readonly keyTransport?: { readonly message: Uint8Array; readonly preKey: boolean };
}

type RequestWithoutId = PicomemoWorkerRequest extends infer Request
    ? Request extends PicomemoWorkerRequest ? Omit<Request, "id"> : never
    : never;

class WorkerPicomemoBackend implements PicomemoBackend {
    readonly id: string;
    readonly version = PICOMEMO_BACKEND_VERSION;
    readonly protocol: PicomemoProtocol;

    private worker: Worker | undefined;
    private readonly pending = new Map<number, { resolve(value: unknown): void; reject(error: unknown): void }>();
    private readonly unavailableCallbacks = new Set<() => void>();
    private requestId = 0;
    private terminated = false;

    private readonly workerFactory: () => Worker;

    constructor(options: CreatePicomemoBackendOptions) {
        this.protocol = options.protocol;
        this.workerFactory = options.workerFactory ?? (() => new Worker(new URL("./worker.js", import.meta.url), { type: "module", name: "picomemo" }));
        this.id = `picomemo:${this.protocol}`;
    }

    async createIdentity(): Promise<Uint8Array> {
        return expectBytes(await this.request({ operation: "setup", protocol: this.protocol }), 1, MAXIMUM_LOCAL_STATE_BYTES, "local state");
    }

    async fingerprint(identityKey: Uint8Array): Promise<string> {
        validateInputBytes(identityKey, 32, 32, "identity key");
        const value = await this.request({ operation: "fingerprint", identityKey });
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

    async decryptKey(localState: Uint8Array, sessionState: Uint8Array | undefined, keyExchange: boolean, message: Uint8Array, maximumMessageJump = PICOMEMO_MAXIMUM_MESSAGE_JUMP): Promise<PicomemoDecryptedKey> {
        validateInputBytes(localState, 1, MAXIMUM_LOCAL_STATE_BYTES, "local state");
        validateInputBytes(message, 1, 512, "encrypted key");
        if (typeof keyExchange !== "boolean") throw new TypeError("Invalid OMEMO key-exchange flag.");
        if (!Number.isInteger(maximumMessageJump) || maximumMessageJump < 0 || maximumMessageJump > PICOMEMO_MAXIMUM_MESSAGE_JUMP) throw new RangeError("Invalid maximum message jump.");
        const result = expectDecryptedKey(await this.request({
            operation: "decrypt",
            protocol: this.protocol,
            store: localState,
            state: sessionState ? decodeSessionState(sessionState) : emptySessionState(),
            maximumMessageJump,
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
        if (this.protocol === "legacy") validateInputBytes(iv, 12, 12, "payload IV");
        else if (payload.length % 16 !== 0) throw new TypeError("Invalid encrypted payload.");
        return expectBytes(await this.request({ operation: "decrypt-payload", protocol: this.protocol, key, payload, ...(iv ? { iv } : {}) }), 1, 1024 * 1024, "payload plaintext");
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
            this.pending.set(id, { resolve, reject });
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
        if (!response || !Number.isSafeInteger(response.id) || typeof response.ok !== "boolean") {
            this.handleWorkerFailure(new Error("The OMEMO cryptographic Worker returned an invalid response."));
            return;
        }

        const pending = this.pending.get(response.id);
        if (!pending) {
            this.handleWorkerFailure(new Error("The OMEMO cryptographic Worker returned an unexpected response."));
            return;
        }
        if (response.ok) {
            this.pending.delete(response.id);
            pending.resolve(response.value);
        } else if (typeof response.error === "string" && response.error.length > 0 && response.error.length <= 1024) {
            this.pending.delete(response.id);
            pending.reject(new Error(response.error));
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

function encodeSessionState(state: PicomemoWorkerSessionState): Uint8Array {
    const validated = expectSessionState(state);
    const output = new Uint8Array(8 + validated.session.length + validated.skippedKeys.length);
    const view = new DataView(output.buffer);
    view.setUint32(0, validated.session.length, true);
    view.setUint32(4, validated.skippedKeys.length, true);
    output.set(validated.session, 8);
    output.set(validated.skippedKeys, 8 + validated.session.length);
    return output;
}

function decodeSessionState(value: Uint8Array): PicomemoWorkerSessionState {
    if (!(value instanceof Uint8Array) || value.length < 8 || value.length > MAXIMUM_SESSION_STATE_BYTES) throw new TypeError("Invalid picomemo session envelope.");
    const view = new DataView(value.buffer, value.byteOffset, value.byteLength);
    const sessionLength = view.getUint32(0, true);
    const skippedLength = view.getUint32(4, true);
    if (sessionLength < 1 || sessionLength > 1024 || skippedLength < 4 || skippedLength > 9000 || value.length !== 8 + sessionLength + skippedLength) throw new TypeError("Invalid picomemo session envelope.");
    return { session: value.slice(8, 8 + sessionLength), skippedKeys: value.slice(8 + sessionLength) };
}

function expectBundle(value: unknown): PicomemoBundle {
    if (!isRecord(value) || !Array.isArray(value.preKeys)) throw new TypeError("The OMEMO Worker returned an invalid bundle.");
    const preKeys = value.preKeys.map((preKey) => {
        if (!isRecord(preKey)) throw new TypeError("The OMEMO Worker returned an invalid PreKey.");
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
    if (!isRecord(value) || !Array.isArray(value.preKeys) || value.preKeys.length < 1 || value.preKeys.length > 100) throw new TypeError("Invalid picomemo bundle.");
    validateInputBytes(value.identityKey, 32, 32, "bundle identity key");
    validateInputBytes(value.signedPreKey, 32, 32, "bundle signed PreKey");
    validateInputBytes(value.signedPreKeySignature, 64, 64, "bundle signed PreKey signature");
    const signedPreKeyId = validateInputIdentifier(value.signedPreKeyId, "bundle signed PreKey ID");
    const preKeys = value.preKeys.map((preKey) => {
        if (!isRecord(preKey)) throw new TypeError("Invalid OMEMO bundle PreKey.");
        validateInputBytes(preKey.publicKey, 32, 32, "bundle PreKey");
        return { id: validateInputIdentifier(preKey.id, "bundle PreKey ID"), publicKey: preKey.publicKey };
    });
    return { identityKey: value.identityKey, signedPreKey: value.signedPreKey, signedPreKeySignature: value.signedPreKeySignature, signedPreKeyId, preKeys };
}

function expectSessionState(value: unknown): PicomemoWorkerSessionState {
    if (!isRecord(value)) throw new TypeError("The OMEMO Worker returned invalid session state.");
    return { session: expectBytes(value.session, 1, 1024, "session"), skippedKeys: expectBytes(value.skippedKeys, 4, 9000, "skipped-key state") };
}

function expectEncryptedKey(value: unknown): WorkerEncryptedKey {
    if (!isRecord(value) || typeof value.preKey !== "boolean") throw new TypeError("The OMEMO Worker returned an invalid encrypted key.");
    return { state: expectSessionState(value.state), message: expectBytes(value.message, 1, 512, "encrypted key"), preKey: value.preKey };
}

function expectDecryptedKey(value: unknown): WorkerDecryptedKey {
    if (!isRecord(value)) throw new TypeError("The OMEMO Worker returned an invalid decrypted key.");
    return {
        localState: expectBytes(value.localState, 1, MAXIMUM_LOCAL_STATE_BYTES, "local state"),
        state: expectSessionState(value.state),
        identityKey: expectBytes(value.identityKey, 32, 32, "session identity key"),
        key: expectBytes(value.key, 1, 48, "decrypted key"),
    };
}

function expectSessionMaintenance(value: unknown): WorkerSessionMaintenance {
    if (!isRecord(value) || !isRecord(value.counters)) throw new TypeError("The OMEMO Worker returned invalid session maintenance.");
    const result: WorkerSessionMaintenance = {
        state: expectSessionState(value.state),
        counters: {
            sent: expectCounter(value.counters.sent, "sent counter"),
            received: expectCounter(value.counters.received, "received counter"),
            previousSent: expectCounter(value.counters.previousSent, "previous-sent counter"),
        },
    };
    if (value.keyTransport === undefined) return result;
    if (!isRecord(value.keyTransport) || typeof value.keyTransport.preKey !== "boolean") throw new TypeError("The OMEMO Worker returned invalid session maintenance key transport.");
    return { ...result, keyTransport: { message: expectBytes(value.keyTransport.message, 1, 512, "session maintenance key transport"), preKey: value.keyTransport.preKey } };
}

function expectEncryptedPayload(value: unknown, protocol: PicomemoProtocol): PicomemoEncryptedPayload {
    if (!isRecord(value)) throw new TypeError("The OMEMO Worker returned an invalid encrypted payload.");
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
export function createPicomemoBackend(options: CreatePicomemoBackendOptions): PicomemoBackend {
    if (!options || (options.protocol !== "omemo2" && options.protocol !== "legacy")) throw new TypeError("Invalid picomemo protocol.");
    return new WorkerPicomemoBackend(options);
}

export { PICOMEMO_BACKEND_VERSION, PICOMEMO_MAXIMUM_MESSAGE_JUMP, PICOMEMO_METADATA } from "./metadata.js";
export type { CreatePicomemoBackendOptions, PicomemoBackend, PicomemoBundle, PicomemoDecryptedKey, PicomemoEncryptedKey, PicomemoEncryptedPayload, PicomemoProtocol, PicomemoSessionMaintenance } from "./types.js";
