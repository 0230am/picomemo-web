import asyncio
import subprocess
import sys
from pathlib import Path
from typing import Dict

import omemo
import x3dh
from doubleratchet.aead import AuthenticationFailedException
from omemo.backend import DecryptionFailed
from omemo.storage import JSONType, Just, Maybe, Nothing
from twomemo import twomemo


class StorageImpl(omemo.storage.Storage):
    def __init__(self) -> None:
        super().__init__()
        self.__data: Dict[str, JSONType] = {}

    async def _load(self, key: str) -> Maybe[JSONType]:
        return Just(self.__data[key]) if key in self.__data else Nothing()

    async def _store(self, key: str, value: JSONType) -> None:
        self.__data[key] = value

    async def _delete(self, key: str) -> None:
        self.__data.pop(key, None)


async def main() -> None:
    picomemo = Path(sys.argv[1]).resolve()
    test_binary = Path(sys.argv[2]).resolve()
    diagnose_reversed_ad = len(sys.argv) == 4 and sys.argv[3] == "--diagnose-reversed-ad"
    sys.path.insert(0, str(picomemo / "o"))
    import bundle2 as bundle
    pre_keys = {value: key for key, value in bundle.pks.items()}
    remote_bundle = twomemo.BundleImpl(
        "admin@localhost",
        7,
        x3dh.Bundle(bundle.ik, bundle.spk, bundle.spks, set(pre_keys)),
        bundle.spk_id,
        pre_keys,
    )
    backend = twomemo.Twomemo(StorageImpl())
    outbound = twomemo.PlainKeyMaterialImpl(b"\x55" * 32, b"\xaa" * 16)
    session, encrypted = await backend.build_session_active("user@localhost", 8, remote_bundle, outbound)
    (picomemo / "o" / "msg2.bin").write_bytes(session.key_exchange.serialize(encrypted.serialize()))

    subprocess.run(["node", str(test_binary)], cwd=picomemo, check=True)

    response = (picomemo / "o" / "resp2.bin").read_bytes()
    parsed = twomemo.EncryptedKeyMaterialImpl.parse(response, "user@localhost", 8)
    if diagnose_reversed_ad:
        session = twomemo.SessionImpl(
            session.bare_jid,
            session.device_id,
            session.initiation,
            session.key_exchange,
            session.associated_data[32:] + session.associated_data[:32],
            session.double_ratchet,
            session.confirmed,
        )
    try:
        decrypted = await backend.decrypt_key_material(session, parsed)
    except DecryptionFailed as error:
        cause = error.__cause__
        if not isinstance(cause, AuthenticationFailedException) or str(cause) != "Authentication tags do not match.":
            raise
        print(f"INTEROPERABILITY FAILURE: {type(error).__module__}.{type(error).__name__}: {error}")
        while cause is not None:
            print(f"CAUSED BY: {type(cause).__module__}.{type(cause).__name__}: {cause}")
            cause = cause.__cause__
        raise SystemExit(42) from None
    assert decrypted.key == b"\xcc" * 32
    assert decrypted.auth_tag == b"\xcc" * 16
    if diagnose_reversed_ad:
        print("DIAGNOSIS CONFIRMED: reversing only the fixed identity associated data authenticates picomemo's response.")
        return
    raise AssertionError("Unexpected interoperability success; re-review the rejected ADR before changing this sentinel.")


asyncio.run(main())
