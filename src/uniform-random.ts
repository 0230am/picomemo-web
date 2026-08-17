const UINT32_RANGE = 0x1_0000_0000;

interface PreKey {
    readonly id: number;
    readonly publicKey: Uint8Array;
}

/** Validates the complete set before selecting an unbiased random PreKey. */
export function selectPreKey<T extends PreKey>(preKeys: readonly T[], readUint32: () => number): T {
    if (!Array.isArray(preKeys) || preKeys.length < 1 || preKeys.length > 100) throw new RangeError("Invalid PreKeys.");
    for (const preKey of preKeys) {
        if (!(preKey.publicKey instanceof Uint8Array) || preKey.publicKey.length !== 32) throw new RangeError("Invalid PreKey.");
        if (!Number.isInteger(preKey.id) || preKey.id < 1 || preKey.id > 0xffffffff) throw new RangeError("Invalid PreKey ID.");
    }
    return preKeys[uniformRandomIndex(preKeys.length, readUint32)]!;
}

/** Returns an unbiased index using rejection sampling over unsigned 32-bit entropy. */
export function uniformRandomIndex(length: number, readUint32: () => number): number {
    if (!Number.isSafeInteger(length) || length < 1 || length > UINT32_RANGE) throw new RangeError("Invalid uniform random range.");
    const limit = UINT32_RANGE - UINT32_RANGE % length;
    let value: number;
    do {
        value = readUint32();
        if (!Number.isSafeInteger(value) || value < 0 || value >= UINT32_RANGE) throw new RangeError("Invalid unsigned 32-bit random value.");
    } while (value >= limit);
    return value % length;
}
