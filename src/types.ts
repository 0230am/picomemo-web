/** Selects the OMEMO 2 or legacy OMEMO cryptographic implementation. */
export type PicomemoProtocol = "omemo2" | "legacy";

/** Safe failure categories returned by the native ratchet boundary. */
export type PicomemoErrorCategory =
    | "jump-too-large"
    | "skipped-key-capacity"
    | "duplicate-or-old"
    | "authentication-failed"
    | "malformed-message"
    | "backend-failure";

/** Operations that may be reported by a structured Picomemo failure. */
export type PicomemoErrorOperation = PicomemoWorkerRequest["operation"] | "worker-request";

/** Configured bound relevant to a ratchet-limit failure. */
export interface PicomemoErrorLimit {
    readonly kind: "message-jump" | "retained-skipped-keys";
    readonly configured: number;
}

/** Non-secret counters available when a ratchet-limit failure is detected. */
export interface PicomemoErrorCounters {
    readonly requestedMessageJump?: number;
    readonly retainedSkippedKeys?: number;
}

/** Strict, secret-free error data transported across the Worker boundary. */
export interface PicomemoErrorData {
    readonly category: PicomemoErrorCategory;
    readonly protocol: PicomemoProtocol | "unknown";
    readonly operation: PicomemoErrorOperation;
    readonly limit?: PicomemoErrorLimit;
    readonly counters?: PicomemoErrorCounters;
}

/** Public device bundle derived from serialized local state. */
export interface PicomemoBundle {
    /** 32-byte public identity key. */
    readonly identityKey: Uint8Array;
    /** 32-byte public signed PreKey. */
    readonly signedPreKey: Uint8Array;
    /** 64-byte signature over `signedPreKey`. */
    readonly signedPreKeySignature: Uint8Array;
    /** Unsigned 32-bit signed-PreKey identifier. */
    readonly signedPreKeyId: number;
    /** Available public one-time PreKeys. */
    readonly preKeys: readonly { readonly id: number; readonly publicKey: Uint8Array }[];
}

/** Result of wrapping key material for one remote device. */
export interface PicomemoEncryptedKey {
    /** Replacement opaque session state; persist it before sending. */
    readonly sessionState: Uint8Array;
    /** Serialized encrypted key message for the remote device. */
    readonly message: Uint8Array;
    /** Whether `message` is an initial PreKey/key-exchange message. */
    readonly keyExchange: boolean;
}

/** Result of decrypting key material from one remote device. */
export interface PicomemoDecryptedKey {
    /** Replacement opaque local state. */
    readonly localState: Uint8Array;
    /** Replacement opaque session state. */
    readonly sessionState: Uint8Array;
    /** Authenticated 32-byte public identity key of the remote device. */
    readonly identityKey: Uint8Array;
    /** Decrypted payload key material. */
    readonly key: Uint8Array;
}

/** OMEMO 2 ratchet maintenance result. */
export interface PicomemoSessionMaintenance {
    /** Replacement opaque session state. */
    readonly sessionState: Uint8Array;
    /** Current native ratchet counters. */
    readonly counters: {
        readonly sent: number;
        readonly received: number;
        readonly previousSent: number;
    };
    /** Optional heartbeat key transport that should be sent to the remote device. */
    readonly keyTransport?: PicomemoEncryptedKey;
}

/** OMEMO 2 encrypted message body and key material. Its IV is derived internally. */
export interface PicomemoOMEMO2EncryptedPayload {
    /** 48-byte payload key and authentication tag. */
    readonly key: Uint8Array;
    /** Encrypted message body. */
    readonly payload: Uint8Array;
    readonly iv?: never;
}

/** Legacy encrypted message body, wrapped key material, and transmitted IV. */
export interface PicomemoLegacyEncryptedPayload {
    /** 32-byte payload key and authentication tag. */
    readonly key: Uint8Array;
    /** AES-GCM ciphertext without the authentication tag. */
    readonly payload: Uint8Array;
    /** Canonical 12-byte transmitted IV. */
    readonly iv: Uint8Array;
}

export type PicomemoEncryptedPayload<Protocol extends PicomemoProtocol = PicomemoProtocol> = Protocol extends "legacy" ? PicomemoLegacyEncryptedPayload : PicomemoOMEMO2EncryptedPayload;
export type PicomemoPayloadDecryptArguments<Protocol extends PicomemoProtocol> = Protocol extends "legacy"
    ? readonly [key: Uint8Array, payload: Uint8Array, iv: Uint8Array]
    : readonly [key: Uint8Array, payload: Uint8Array];

/** Dedicated-Worker cryptographic backend. Serialized states are immutable inputs and replacement outputs. */
export interface PicomemoBackend<Protocol extends PicomemoProtocol = PicomemoProtocol> {
    /** Stable backend identifier containing the selected protocol. */
    readonly id: string;
    /** Locked native picomemo tag and commit identity. */
    readonly version: string;
    /** Protocol selected when the backend was created. */
    readonly protocol: Protocol;

    /** Creates new opaque local account/device state containing private identity and PreKey material. */
    createIdentity(): Promise<Uint8Array>;

    /** Formats a 32-byte public identity key as eight lowercase hexadecimal groups. */
    fingerprint(identityKey: Uint8Array): Promise<string>;

    /** Derives the public device bundle from opaque local state without changing that state. */
    createBundle(localState: Uint8Array): Promise<PicomemoBundle>;

    /** Returns replacement local state with replenished one-time PreKeys. */
    replenishPreKeys(localState: Uint8Array): Promise<Uint8Array>;

    /** Creates opaque outgoing session state for a validated remote bundle. */
    buildOutgoingSession(localState: Uint8Array, bundle: PicomemoBundle): Promise<Uint8Array>;

    /** Wraps key material and returns replacement session state plus the wire message. */
    encryptKey(sessionState: Uint8Array, key: Uint8Array): Promise<PicomemoEncryptedKey>;

    /**
     * Decrypts a key message and returns replacement local/session states.
     * Pass `undefined` when receiving the initial PreKey message without an existing session.
     */
    decryptKey(
        localState: Uint8Array,
        sessionState: Uint8Array | undefined,
        keyExchange: boolean,
        message: Uint8Array,
        maximumMessageJump?: number,
        maximumRetainedSkippedKeys?: number,
    ): Promise<PicomemoDecryptedKey>;

    /** Maintains an OMEMO 2 session and may produce a heartbeat key transport. */
    maintainSession(localState: Uint8Array, sessionState: Uint8Array): Promise<PicomemoSessionMaintenance>;

    /** Encrypts a non-empty plaintext of at most 1 MiB. */
    encryptPayload(plaintext: Uint8Array): Promise<PicomemoEncryptedPayload<Protocol>>;

    /** Decrypts OMEMO 2 without an IV or Legacy with its required transmitted IV. */
    decryptPayload(...arguments_: PicomemoPayloadDecryptArguments<Protocol>): Promise<Uint8Array>;

    /** Registers a callback for terminal Worker failure and returns an unsubscribe function. */
    onUnavailable(callback: () => void): () => void;

    /** Terminates the Worker, rejects pending calls, and permanently closes this backend instance. */
    terminate(): void;
}

/** Options accepted by `createPicomemoBackend`. */
export interface CreatePicomemoBackendOptions<Protocol extends PicomemoProtocol = PicomemoProtocol> {
    /** Cryptographic protocol implementation to use. */
    readonly protocol: Protocol;
    /** Default per-message forward-jump bound. */
    readonly maximumMessageJump?: number;
    /** Default total retained skipped-key bound for each session. */
    readonly maximumRetainedSkippedKeys?: number;
    /** Advanced override for constructing the dedicated module Worker. */
    readonly workerFactory?: () => Worker;
}

/** @internal Worker-only decoded session representation. */
export interface PicomemoWorkerSessionState {
    readonly session: Uint8Array;
    readonly skippedKeys: Uint8Array;
}

/** @internal Validated request protocol between the public backend and its Worker. */
export type PicomemoWorkerRequest =
    | { readonly id: number; readonly operation: "setup"; readonly protocol: PicomemoProtocol }
    | { readonly id: number; readonly operation: "fingerprint"; readonly protocol: PicomemoProtocol; readonly identityKey: Uint8Array }
    | { readonly id: number; readonly operation: "bundle"; readonly protocol: PicomemoProtocol; readonly store: Uint8Array }
    | { readonly id: number; readonly operation: "replenish"; readonly protocol: PicomemoProtocol; readonly store: Uint8Array }
    | { readonly id: number; readonly operation: "initiate"; readonly protocol: PicomemoProtocol; readonly store: Uint8Array; readonly bundle: PicomemoBundle }
    | { readonly id: number; readonly operation: "encrypt"; readonly protocol: PicomemoProtocol; readonly state: PicomemoWorkerSessionState; readonly key: Uint8Array }
    | { readonly id: number; readonly operation: "decrypt"; readonly protocol: PicomemoProtocol; readonly store: Uint8Array; readonly state: PicomemoWorkerSessionState; readonly maximumMessageJump: number; readonly maximumRetainedSkippedKeys: number; readonly preKey: boolean; readonly message: Uint8Array }
    | { readonly id: number; readonly operation: "maintain"; readonly protocol: PicomemoProtocol; readonly store: Uint8Array; readonly state: PicomemoWorkerSessionState }
    | { readonly id: number; readonly operation: "encrypt-payload"; readonly protocol: PicomemoProtocol; readonly plaintext: Uint8Array }
    | { readonly id: number; readonly operation: "decrypt-payload"; readonly protocol: "omemo2"; readonly key: Uint8Array; readonly payload: Uint8Array }
    | { readonly id: number; readonly operation: "decrypt-payload"; readonly protocol: "legacy"; readonly key: Uint8Array; readonly iv: Uint8Array; readonly payload: Uint8Array };

/** @internal Validated response protocol between the Worker and public backend. */
export type PicomemoWorkerResponse =
    | { readonly id: number; readonly ok: true; readonly value: unknown }
    | { readonly id: number; readonly ok: false; readonly error: PicomemoErrorData };
