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
  encryptedPayload.iv,
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
| `decryptKey(localState, sessionState, keyExchange, message, maximumMessageJump?)` | Replacement local/session states, authenticated remote identity key, and decrypted key material. |
| `maintainSession(localState, sessionState)` | Replacement OMEMO 2 state, ratchet counters, and optional heartbeat transport. |
| `encryptPayload(plaintext)` | Generated key, encrypted payload, and legacy IV when required. |
| `decryptPayload(key, payload, iv?)` | Decrypted plaintext. |
| `onUnavailable(callback)` | Registers a callback for terminal Worker failure and returns an unsubscribe function. |
| `terminate()` | Terminates the Worker and rejects pending operations. The backend cannot be reused. |

The optional `maximumMessageJump` defaults to `PICOMEMO_MAXIMUM_MESSAGE_JUMP` (`128`) and bounds how many skipped message keys may be derived during a decrypt attempt.

The package also exports:

- `PICOMEMO_BACKEND_VERSION`: locked native tag and commit identity.
- `PICOMEMO_MAXIMUM_MESSAGE_JUMP`: maximum accepted skipped-message bound.
- `PICOMEMO_METADATA`: package version, exact native source commit/tree, features, and artifact hashes.
- All public TypeScript interfaces used above.

## Worker lifecycle and errors

The default factory always creates a module-type dedicated Worker. There is no main-thread cryptographic fallback. Requests and responses are bounded and validated at the Worker boundary.

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
- `protocol: "omemo2"` implements the OMEMO 2 path from picomemo; `protocol: "legacy"` implements the legacy OMEMO path.
- The package is experimental and currently pins picomemo tag `1.2.1` plus commit `ff75cfc41b9ea8e27e4fe961c08dd2bd8b922317`.

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
