/** Exact package, source, feature, toolchain-artifact identity for auditing. */
export const PICOMEMO_METADATA = Object.freeze({
    package: Object.freeze({ name: "picomemo", version: "0.1.1", status: "experimental-unofficial" }),
    source: Object.freeze({
        repository: "https://github.com/0230am/picomemo.git",
        upstreamRepository: "https://github.com/mierenhoop/picomemo.git",
        tag: "1.2.1",
        baseCommit: "616b7014ea293a1fd5f785b2535db5bdaa0acfdf",
        commit: "ff75cfc41b9ea8e27e4fe961c08dd2bd8b922317",
        tree: "81f38825f67a4d3819f823be9e2821624047ba96",
    }),
    featureSet: "omemo0+omemo2",
    features: Object.freeze(["legacy-omemo", "omemo2", "dedicated-worker", "opaque-state", "bounded-skipped-keys"] as const),
    artifacts: Object.freeze({
        declarationSha256: "b094afe261c8f07f9314ef81b0af7fba14da6b60707db0e58e0e2518986d01e2",
        loaderSha256: "4cf18ad8f190f48bff989e3b9769984fc6dab85595e2b853cbcbd25cc0407095",
        wasmSha256: "8cf0ddc7ec45849bd99ffa1c405e8a6aa9c26384b76f5afc9b5bd95d5c7e0e94",
    }),
});

/** Native picomemo tag and commit used by this build. */
export const PICOMEMO_BACKEND_VERSION = `${PICOMEMO_METADATA.source.tag}+${PICOMEMO_METADATA.source.commit}`;
/** Largest skipped-message jump accepted by `decryptKey()`. */
export const PICOMEMO_MAXIMUM_MESSAGE_JUMP = 128;
