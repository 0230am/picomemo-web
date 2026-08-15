interface PicomemoModule {
    readonly HEAPU8: Uint8Array;
    readonly HEAPU32: Uint32Array;
    _malloc(size: number): number;
    _free(pointer: number): void;
    _picomemoWebInitialize(): void;
    _picomemoWebSetupStore(out: number, capacity: number): number;
    _picomemoWebGetBundle(store: number, storeLength: number, identity: number, signedPreKey: number, signature: number, metadata: number, preKeyIds: number, preKeys: number): number;
    _picomemoWebReplenishStore(store: number, storeLength: number, out: number, capacity: number): number;
    _picomemoWebInitiateSession(store: number, storeLength: number, identity: number, signedPreKey: number, signature: number, signedPreKeyId: number, preKey: number, preKeyId: number, out: number, capacity: number): number;
    _picomemoWebEncryptKey(session: number, sessionLength: number, key: number, keyLength: number, sessionOut: number, sessionCapacity: number, messageOut: number, messageCapacity: number, metadata: number): number;
    _picomemoWebGetSessionIdentity(session: number, sessionLength: number, identity: number): number;
    _picomemoWebMaintainSession(store: number, storeLength: number, session: number, sessionLength: number, sessionOut: number, sessionCapacity: number, messageOut: number, messageCapacity: number, metadata: number): number;
    _picomemoWebDecryptKey(store: number, storeLength: number, session: number, sessionLength: number, skipped: number, skippedLength: number, maximumJump: number, preKey: number, message: number, messageLength: number, storeOut: number, storeCapacity: number, sessionOut: number, sessionCapacity: number, skippedOut: number, skippedCapacity: number, keyOut: number, keyCapacity: number, metadata: number): number;
    _picomemoWebEncryptMessage(plaintext: number, plaintextLength: number, payload: number, payloadCapacity: number, key: number): number;
    _picomemoWebDecryptMessage(key: number, keyLength: number, payload: number, payloadLength: number, plaintext: number, plaintextCapacity: number): number;
    _picomemoWeb0SetupStore(out: number, capacity: number): number;
    _picomemoWeb0GetBundle(store: number, storeLength: number, identity: number, signedPreKey: number, signature: number, metadata: number, preKeyIds: number, preKeys: number): number;
    _picomemoWeb0ReplenishStore(store: number, storeLength: number, out: number, capacity: number): number;
    _picomemoWeb0InitiateSession(store: number, storeLength: number, identity: number, signedPreKey: number, signature: number, signedPreKeyId: number, preKey: number, preKeyId: number, out: number, capacity: number): number;
    _picomemoWeb0EncryptKey(session: number, sessionLength: number, key: number, keyLength: number, sessionOut: number, sessionCapacity: number, messageOut: number, messageCapacity: number, metadata: number): number;
    _picomemoWeb0GetSessionIdentity(session: number, sessionLength: number, identity: number): number;
    _picomemoWeb0DecryptKey(store: number, storeLength: number, session: number, sessionLength: number, skipped: number, skippedLength: number, maximumJump: number, preKey: number, message: number, messageLength: number, storeOut: number, storeCapacity: number, sessionOut: number, sessionCapacity: number, skippedOut: number, skippedCapacity: number, keyOut: number, keyCapacity: number, metadata: number): number;
    _picomemoWeb0EncryptMessage(plaintext: number, plaintextLength: number, payload: number, payloadCapacity: number, key: number, iv: number): number;
    _picomemoWeb0DecryptMessage(key: number, keyLength: number, iv: number, ivLength: number, payload: number, payloadLength: number, plaintext: number, plaintextCapacity: number): number;
    _picomemoWebHeapSize(): number;
}

export default function createPicomemoModule(options?: { locateFile?(path: string): string }): Promise<PicomemoModule>;
