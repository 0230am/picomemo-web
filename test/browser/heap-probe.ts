/// <reference lib="webworker" />

import createPicomemoModule from "../../dist/generated/picomemo.mjs";

const scope = self as DedicatedWorkerGlobalScope;

void createPicomemoModule({ locateFile: (file) => new URL(`../../dist/generated/${file}`, import.meta.url).href }).then((module) => {
    scope.postMessage({ wasmInitialHeapBytes: module._picomemoWebHeapSize() });
});
