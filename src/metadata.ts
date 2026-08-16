/** Exact package, source, feature, toolchain-artifact identity for auditing. */
export const PICOMEMO_METADATA = Object.freeze({
    package: Object.freeze({ name: "picomemo", version: "0.2.0", status: "experimental-unofficial" }),
    source: Object.freeze({
        repository: "https://github.com/0230am/picomemo.git",
        upstreamRepository: "https://github.com/mierenhoop/picomemo.git",
        tag: "1.2.1",
        baseCommit: "616b7014ea293a1fd5f785b2535db5bdaa0acfdf",
        commit: "a4bad0297ea72ee75fbdb4afc899f65e8d85ae74",
        tree: "011b0bd1a0f4109856f7dfb633383efbe313cd3e",
        dirty: false,
    }),
    featureSet: "omemo0+omemo2",
    features: Object.freeze(["legacy-omemo", "omemo2", "dedicated-worker", "opaque-state", "typed-ratchet-errors", "request-correlated-worker-errors", "independent-ratchet-limits", "transactional-native-ratchet", "versioned-session-state"] as const),
    artifacts: Object.freeze({
        declarationSha256: "cf2cf53c64ecec5b7a828cec061e11c7e6e61b1275cda9a278fe3b5bd2c9cabe",
        loaderSha256: "3c54df4326d828425e5568c1986a460f824d0d2259f3d3511a0c7e589ebcf653",
        wasmSha256: "c0dd1f11af4984216282ce6ea609e074738e88b64f1ab424004792303a847713",
    }),
});

/** Native picomemo tag and commit used by this build. */
export const PICOMEMO_BACKEND_VERSION = `${PICOMEMO_METADATA.source.tag}+${PICOMEMO_METADATA.source.commit}`;
/** Prior backend identities whose opaque local/session states remain byte-compatible inputs. */
export const PICOMEMO_COMPATIBLE_BACKEND_VERSIONS = Object.freeze(["1.2.1+ff75cfc41b9ea8e27e4fe961c08dd2bd8b922317", "1.2.1+ff75cfc41b9ea8e27e4fe961c08dd2bd8b922317.patch.1679cf6a8025"] as const);
/** Returns whether a stored backend identity can be loaded without resetting its ratchet. */
export function isPicomemoBackendVersionCompatible(version: string): boolean {
    return version === PICOMEMO_BACKEND_VERSION || PICOMEMO_COMPATIBLE_BACKEND_VERSIONS.includes(version as typeof PICOMEMO_COMPATIBLE_BACKEND_VERSIONS[number]);
}
/** Largest skipped-message jump accepted by `decryptKey()`. */
export const PICOMEMO_DEFAULT_MESSAGE_JUMP = 2000;
/** Hard package ceiling for a single-message ratchet jump. */
export const PICOMEMO_HARD_MAXIMUM_MESSAGE_JUMP = 2000;
/** Default total skipped keys retained by one session. */
export const PICOMEMO_DEFAULT_RETAINED_SKIPPED_KEYS = 2000;
/** Hard package ceiling for total retained skipped keys in one session. */
export const PICOMEMO_HARD_MAXIMUM_RETAINED_SKIPPED_KEYS = 2000;
/** Maximum accepted opaque v2 session-state envelope size. */
export const PICOMEMO_MAXIMUM_SESSION_STATE_BYTES = 137044;
/** Current opaque session-state envelope version emitted by the package. */
export const PICOMEMO_SESSION_STATE_VERSION = 2;
/** @deprecated Use `PICOMEMO_DEFAULT_MESSAGE_JUMP`. */
export const PICOMEMO_MAXIMUM_MESSAGE_JUMP = PICOMEMO_DEFAULT_MESSAGE_JUMP;
