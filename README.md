# picomemo

Experimental browser binding for [picomemo](https://github.com/mierenhoop/picomemo), providing legacy OMEMO and OMEMO 2 cryptographic operations through a dedicated Web Worker and WebAssembly.

The npm package ships ready-to-use JavaScript, TypeScript declarations, a module Worker, the Emscripten loader, and the compiled WASM binary. Application developers do not need Emscripten or a C toolchain.

## Install

```sh
npm install picomemo@experimental
```

The package requires a modern browser with module Workers, WebAssembly, `crypto.getRandomValues`, and a bundler that preserves Worker and WASM assets. It is tested with Vite and Microsoft Edge.

## Quick start

```ts
import { createPicomemoBackend } from "picomemo";

const backend = createPicomemoBackend({ protocol: "omemo2" });

// Keep this opaque byte array as the local account/device state.
let localState = await backend.createIdentity();

// Publish this bundle using the wire format required by your application.
const bundle = await backend.createBundle(localState);
console.log(await backend.fingerprint(bundle.identityKey));

backend.terminate();
```

`createIdentity()` returns serialized private state, not just a public identity key. Store it securely. The bundle returned by `createBundle()` contains the public identity key, signed PreKey, signature, and one-time PreKeys.

## Complete two-party round trip

The example below performs an initial OMEMO 2 exchange entirely in memory. In a real application, transport the public bundle and encrypted fields between devices and persist each returned state update.

```ts
import { createPicomemoBackend } from "picomemo";

const alice = createPicomemoBackend({ protocol: "omemo2" });
const bob = createPicomemoBackend({ protocol: "omemo2" });
const encoder = new TextEncoder();
const decoder = new TextDecoder();

let aliceLocalState = await alice.createIdentity();
let bobLocalState = await bob.createIdentity();

const bobBundle = await bob.createBundle(bobLocalState);
let aliceSessionState = await alice.buildOutgoingSession(
  aliceLocalState,
  bobBundle,
);

// Encrypt the message body, then wrap its payload key for Bob's device.
const encryptedPayload = await alice.encryptPayload(
  encoder.encode("hello Bob"),
);
const encryptedKey = await alice.encryptKey(
  aliceSessionState,
  encryptedPayload.key,
);
aliceSessionState = encryptedKey.sessionState;

// Send encryptedKey.message, encryptedKey.keyExchange,
// encryptedPayload.payload, and encryptedPayload.iv when present.
const decryptedKey = await bob.decryptKey(
  bobLocalState,
  undefined, // No existing session for Alice yet.
  encryptedKey.keyExchange,
  encryptedKey.message,
);
bobLocalState = decryptedKey.localState;
let bobSessionState = decryptedKey.sessionState;

const plaintext = await bob.decryptPayload(
  decryptedKey.key,
  encryptedPayload.payload,
);
console.log(decoder.decode(plaintext)); // "hello Bob"

// Persist aliceSessionState, bobLocalState, and bobSessionState before
// acknowledging or otherwise committing the message.
alice.terminate();
bob.terminate();
```

For subsequent messages, pass the stored session state instead of `undefined`. Every successful `encryptKey()`, `decryptKey()`, or `maintainSession()` call returns a replacement session state.

## State model

All state values are opaque `Uint8Array` instances:

- **Local state** belongs to one account/device identity. It contains private identity material, the signed PreKey, and one-time PreKeys.
- **Session state** belongs to one remote device. It contains the ratchet and bounded skipped-message keys.
- **Bundle** is public material derived from local state and may be published for peers.

Treat returned state as immutable replacement data. Do not edit it, concatenate it, or depend on its binary layout.

Persist related updates atomically. In particular, after `decryptKey()` succeeds, commit both `localState` and `sessionState` together before acknowledging the message. Serialize operations that use the same local or session record so concurrent calls cannot overwrite one another's returned state.

When the published one-time PreKeys are running low, replenish and republish:

```ts
localState = await backend.replenishPreKeys(localState);
const replacementBundle = await backend.createBundle(localState);
await saveLocalStateAndPublishBundle(localState, replacementBundle);
```

`saveLocalStateAndPublishBundle` represents application storage and transport code.

## Payload and key transport

`encryptPayload()` encrypts the message body and generates key material:

| Protocol | Payload key | IV | Payload |
| --- | ---: | ---: | --- |
| `omemo2` | 48 bytes | none | AES-CBC payload with authentication material in the key |
| `legacy` | 32 bytes | 12 bytes | legacy OMEMO payload |

Wrap the returned payload key separately for every recipient device with that device's session:

```ts
const payload = await backend.encryptPayload(plaintext);

for (const recipient of recipients) {
  const wrapped = await backend.encryptKey(recipient.sessionState, payload.key);
  recipient.sessionState = wrapped.sessionState;
  await sendEncryptedKey(recipient.deviceId, wrapped.message, wrapped.keyExchange);
}

await sendEncryptedPayload(payload.payload, payload.iv);
```

The application maps these byte arrays and flags to its chosen OMEMO wire format.

## Session maintenance

OMEMO 2 sessions expose native ratchet counters and may request a heartbeat key transport after a long receive-only run:

```ts
const maintenance = await backend.maintainSession(localState, sessionState);
sessionState = maintenance.sessionState;

if (maintenance.keyTransport) {
  sessionState = maintenance.keyTransport.sessionState;
  await sendEncryptedKey(
    remoteDeviceId,
    maintenance.keyTransport.message,
    maintenance.keyTransport.keyExchange,
  );
}
```

`maintainSession()` is available only for `protocol: "omemo2"`.

## API

### `createPicomemoBackend(options)`

Creates a lazy, dedicated-Worker backend. `options.protocol` is `"omemo2"` or `"legacy"`. The Worker starts on the first operation.

| Method | Result |
| --- | --- |
| `createIdentity()` | New serialized local state. |
| `fingerprint(identityKey)` | Lowercase public-key fingerprint grouped as eight 8-character blocks. |
| `createBundle(localState)` | Public identity, signed PreKey, signature, and one-time PreKeys. |
| `replenishPreKeys(localState)` | Replacement local state containing replenished PreKeys. |
| `buildOutgoingSession(localState, bundle)` | New session state for a remote bundle. |
| `encryptKey(sessionState, key)` | Replacement session state, encrypted key message, and PreKey/key-exchange flag. |
| `decryptKey(localState, sessionState, keyExchange, message, maximumMessageJump?, maximumRetainedSkippedKeys?)` | Replacement local/session states, authenticated remote identity key, and decrypted key material. |
| `maintainSession(localState, sessionState)` | Replacement OMEMO 2 state, ratchet counters, and optional heartbeat transport. |
| `encryptPayload(plaintext)` | Generated key, encrypted payload, and legacy IV when required. |
| `decryptPayload(key, payload)` | Decrypted OMEMO 2 plaintext. The IV is derived internally and is not part of the API or XML. |
| `decryptPayload(key, payload, iv)` | Decrypted Legacy plaintext. Encrypt emits a 12-byte IV; decrypt accepts canonical 12-byte and receive-only historical 16-byte IVs. |
| `onUnavailable(callback)` | Registers a callback for terminal Worker failure and returns an unsubscribe function. |
| `terminate()` | Terminates the Worker and rejects pending operations. The backend cannot be reused. |

`maximumMessageJump` and `maximumRetainedSkippedKeys` are independent bounded controls. Both default to `2,000`; neither may exceed its exported hard maximum of `2,000`. The first bounds derivation work for one received message. The second bounds all skipped message keys retained by one session. Values above the hard maximum are rejected before the Worker starts or cryptographic work is performed.

The 2,000-key default follows the classic libsignal forward-jump ceiling and remains a safety window for ordinary reordering, not an archive-processing strategy. At the maximum, a real legacy Worker/WASM regression produces a 136,339-byte v2 session envelope. The regression actually retains 20 full envelopes totaling 2,726,780 bytes and decrypts one retained old message in every session; the 20 replacement envelopes total 2,725,420 bytes. This is not represented as 20 simultaneous maximum forward jumps.

The exported native probe reports a fixed 16 MiB initial WASM heap. Reviewed transient allocation payload is calculated in two feasible scenarios rather than presented as a live heap measurement: a maximum forward jump accounts for 457,608 bytes, comprising 8,044 copied input bytes, 153,540 bytes of fixed output capacities, a 136,024-byte native skipped-key structure, and up to 160,000 bytes for 2,000 journal-node payloads; replay from a full retained state accounts for 433,688 bytes, comprising 144,044 copied input bytes, the same output and skipped-key capacities, and one 80-byte journal-node payload. Both calculations explicitly exclude allocator overhead, native store/session/message and backup stack objects, JavaScript structured-clone and envelope buffers, and the fixed WASM heap itself. Exact repeated latency measurements are recorded by the browser regression rather than treated as a portable performance guarantee.

The package also exports:

- `PICOMEMO_BACKEND_VERSION`: locked native tag and commit identity.
- `PICOMEMO_DEFAULT_MESSAGE_JUMP` and `PICOMEMO_HARD_MAXIMUM_MESSAGE_JUMP`.
- `PICOMEMO_DEFAULT_RETAINED_SKIPPED_KEYS` and `PICOMEMO_HARD_MAXIMUM_RETAINED_SKIPPED_KEYS`.
- `PICOMEMO_MAXIMUM_SESSION_STATE_BYTES` and `PICOMEMO_SESSION_STATE_VERSION`.
- `PICOMEMO_COMPATIBLE_BACKEND_VERSIONS` and `isPicomemoBackendVersionCompatible()` for ratchet-preserving storage compatibility checks.
- `PICOMEMO_METADATA`: package version, exact native source commit/tree, features, and artifact hashes.
- All public TypeScript interfaces used above.

## Worker lifecycle and errors

The default factory always creates a module-type dedicated Worker. There is no main-thread cryptographic fallback. Requests and responses are bounded and validated at the Worker boundary.

Native failures reject with `PicomemoError`. Its validated `category` is one of `jump-too-large`, `skipped-key-capacity`, `duplicate-or-old`, `authentication-failed`, `malformed-message`, or `backend-failure`. It also carries `protocol`, `operation`, and, for bounded ratchet failures only, a safe configured `limit` and non-secret counters. `requestedMessageJump` is the combined work requested by the message and `retainedSkippedKeys` is the pre-operation retained count at the failure boundary. Corrupt persisted local, session, or skipped-key state is conservatively classified as `backend-failure`, not as malformed ciphertext. The error never carries session state, key material, ciphertext, or plaintext. Worker errors and successes with unknown nested fields, mismatched request metadata, or invalid categories fail closed and terminate the Worker.

Jump and skipped-key-capacity failures return no replacement state. All inputs remain immutable, so retrying the same ciphertext from the previously persisted state is transactional. Authentication, malformed-message, cancellation, and Worker failures likewise return no partially advanced state.

An invalid argument rejects only that operation. A Worker crash, malformed Worker response, or explicit `terminate()` rejects all pending operations and permanently closes that backend instance. Create a new backend instance before retrying after terminal failure.

Use `onUnavailable()` to connect terminal failure to application recovery:

```ts
const unsubscribe = backend.onUnavailable(() => {
  showCryptographyUnavailable();
});

// Later:
unsubscribe();
backend.terminate();
```

## Content Security Policy

The Worker and WASM assets must be served from an allowed origin. A minimal policy for the cryptographic runtime is:

```http
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'
```

Add the directives needed by the rest of your application. Removing `'wasm-unsafe-eval'` makes initialization fail closed; the package does not fall back to main-thread or plaintext operation.

## Security and compatibility

- Keep local and session state in storage appropriate for private cryptographic material.
- Authenticate the remote `identityKey` returned by `decryptKey()` according to your application's trust policy.
- Never reuse a stale state value after an operation returned its replacement.
- Versions 0.2.0 and 0.2.1 accept the implicit-v1 session envelope emitted by 0.1.1 and deterministically emit v2 after the next successful session operation. The native ratchet and skipped-key entry bytes are not reinterpreted or replaced.
- `protocol: "omemo2"` implements the OMEMO 2 path from picomemo; `protocol: "legacy"` implements the legacy OMEMO path.
- The package is experimental and currently pins picomemo tag `1.2.1` plus downstream commit `06f4ca967005dbdc22fe775f67f25d75936b7cdc`.

## Reproducibility

`PICOMEMO_METADATA` and the published `source-metadata.json` record the exact source commit/tree, feature set, toolchain, and declaration/loader/WASM hashes.

For maintainers:

- `npm run bootstrap` fetches the exact source commit, installs the locked Emscripten SDK, verifies Mbed TLS, and prepares the hash-locked Python interoperability environment.
- `npm run build` compiles the TypeScript wrapper and copies the reviewed artifacts.
- `npm run build:wasm` rebuilds into `.cache/generated` and rejects unexplained artifact changes.
- `npm run test:determinism` performs two byte-identical builds.
- `npm run test:vectors` and `npm run test:interop` run upstream vectors and Python/Twomemo bidirectional interoperability.
- `npm run test:browser` exercises both protocols in a real Worker/WASM browser and verifies CSP failure behavior.
- `npm run pack:check` enforces the exact npm package allowlist.

The browser test launcher currently targets Microsoft Edge on Windows; this is a validation-harness limitation, not a runtime restriction.

## License

picomemo is ISC-licensed. Dependency notices and licenses are included in `THIRD_PARTY_NOTICES.md` and `LICENSES/`.
