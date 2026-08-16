import { createPicomemoBackend } from "../../src/index.js";

declare const key: Uint8Array;
declare const payload: Uint8Array;
declare const iv: Uint8Array;
declare const workerFactory: () => Worker;

async function verifyProtocolSpecificPayloadAPI(): Promise<void> {
    const omemo2 = createPicomemoBackend({ protocol: "omemo2", workerFactory });
    const legacy = createPicomemoBackend({ protocol: "legacy", workerFactory });

    await omemo2.decryptPayload(key, payload);
    // @ts-expect-error OMEMO 2 has no transmitted payload IV.
    await omemo2.decryptPayload(key, payload, iv);
    await legacy.decryptPayload(key, payload, iv);
    // @ts-expect-error Legacy decryption requires its transmitted IV.
    await legacy.decryptPayload(key, payload);

    const omemo2Encrypted = await omemo2.encryptPayload(payload);
    const noTransmittedIV: undefined = omemo2Encrypted.iv;
    const legacyEncrypted = await legacy.encryptPayload(payload);
    const transmittedIV: Uint8Array = legacyEncrypted.iv;
    void noTransmittedIV;
    void transmittedIV;
}

void verifyProtocolSpecificPayloadAPI;
