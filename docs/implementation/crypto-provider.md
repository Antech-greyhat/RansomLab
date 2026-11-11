# Cryptography provider decision and security review

Recorded: 2026-11-04. Scope: `ransomlab/crypto.py` and synthetic in-memory tests in `tests/test_crypto.py`. This is an implementation review, not an independent cryptographic audit or certification.

## Explicit design change

Phase 0 proposed the external `cryptography` package. The implemented Windows path instead calls the operating system's **Microsoft CNG AES-256-GCM** provider through Python's standard-library `ctypes`. This uses an established AES/GCM implementation; RansomLab does not implement AES, GHASH, padding or a substitute cipher. The change avoids installing an unreviewed package on Windows and must remain visible in the project decision record.

This is a historical provider decision. The 2026-11-11 [Phase 0 architecture](../architecture.md) and [contribution workflow](../contributing.md) supersede earlier cross-phase/no-commit directions. Phase 0 preserves this provider without installing packages or configuring VMs. On non-Windows platforms the module requires a reviewed `cryptography` installation; the inherited fallback has no verified exact installation manifest. Missing imports produce `DependencyError` rather than a replacement cipher. The tested capability in this review is the Windows provider only.

## Provider and maintenance contract

| Concern | Implementation / constraint |
| --- | --- |
| Provider | `bcrypt.dll`, explicitly opened with `LOAD_LIBRARY_SEARCH_SYSTEM32`; provider name is `Microsoft Primitive Provider` |
| Algorithm | AES with `ChainingModeGCM`, 256-bit keys, 96-bit nonces and 128-bit authentication tags |
| Native ABI | Explicit 32-bit `ULONG`/`NTSTATUS`, 64-bit `ULONGLONG`, pointer-width handles and naturally aligned authenticated-mode structure |
| Operation style | One-shot authenticated encryption/decryption; no streaming or chained-call state |
| Payload limits | At most 1 MiB plaintext, 1 MiB plus 16 bytes ciphertext/tag, and 8 KiB associated data |
| Return format | Ciphertext followed by its fixed 16-byte tag; nonce and associated data are supplied separately |
| Maintenance | Windows servicing and provider updates; Python runtime maintenance also applies. No CNG binary is copied into the project |
| Verification environment | Existing Windows process, Python 3.14.3, 64-bit pointers; no inference of validation on every Windows build or other architecture |

`provider_name()` names the selected implementation; it is not a provider self-test or a current vulnerability assessment. Actual operations detect unavailable DLL/APIs and provider rejection. Keep the OS supported and patched, record the exact guest build during VM verification, and repeat applicable provider tests after relevant changes.

## Security behaviour

- The public adapter accepts byte strings only and exposes no file, directory, shell, network or operating-system administration API. Filesystem provenance and allowlisting remain the service/storage layer's responsibility.
- Key and nonce lengths are exact; wrong input types, excessive associated data and payload limits are rejected before native invocation.
- Native key-object property results must have the expected 32-bit output size and a positive allocation bounded to 64 KiB. Unexpected output lengths fail closed.
- Decryption checks the native authentication result before constructing a returned plaintext value. A bad tag, ciphertext, key, nonce or associated data raises `SafetyError`.
- Allocated native key, key-object, input, output, nonce, associated-data and tag buffers are overwritten during cleanup, including the authentication-failure path. Native handles are destroyed/closed first.
- Cleanup is attempted for both resources. If cleanup fails after an otherwise successful operation, the adapter raises an error instead of returning success. If an operation is already failing, its primary failure is preserved while cleanup continues.
- Provider-load errors become a generic dependency error; native error messages do not include payloads, keys or caller paths.

The service must generate fresh run keys and ensure nonce uniqueness under each key, including interrupted operations. It must bind ciphertext to the intended versioned run/fixture metadata using associated data, maintain clean recovery copies, and preserve durable operation intents/results. This byte adapter does not supply those higher-level guarantees. Synthetic known-answer tests intentionally use published fixed keys/nonces; operational code must not copy that pattern.

## Verification performed

Executed `python -m unittest discover -s tests -p 'test_crypto.py' -v`: **10 tests passed**.

Coverage includes:

1. AES-256-GCM known-answer vector with an all-zero 256-bit key, nonce and block.
2. Independent known-answer vector with nonempty associated data and a partial final block.
3. Empty/binary round trips and the exact 1 MiB payload/8 KiB associated-data boundaries.
4. Altered ciphertext, tag, key, nonce, associated data and truncated ciphertext.
5. Invalid types and lengths rejected before loading the provider.
6. Unavailable provider translated into a redacted dependency error.
7. Invalid native key-object property size/length rejected, with the algorithm handle closed.
8. Authentication-failure cleanup overwrites all captured native byte buffers.
9. Synthetic key/algorithm cleanup status failures block success without masking authentication failure.

Native fault tests delegate actual cryptographic/resource calls to CNG before changing a selected return status or property result. They do not leak a real native handle merely to simulate a cleanup failure. All cryptographic inputs are synthetic in-memory bytes; these tests do not modify fixture files or demonstrate filesystem containment.

## Limits and remaining review

Python immutable `bytes`, return values, interpreter copies and OS/provider-internal memory cannot be guaranteed erased by this wrapper. Buffer overwrites are a limited best-effort measure, not a claim of complete key zeroization. A same-account process, administrator, compromised Python runtime, or compromised OS can bypass local protections.

Passing vectors demonstrates correct results for the exercised ABI and cases; it does not prove the absence of all implementation defects, side channels or provider vulnerabilities. Windows patch status and current advisories were not audited by these tests. Native binding errors carry greater process-level risk than pure Python errors, so the wrapper is intentionally small and excludes configurable algorithms, tag lengths, streaming flags and native pointer inputs.

Before release, review the service's key/nonce lifecycle, ciphertext metadata framing, crash reconciliation, clean-copy recovery, tested guest versions and runtime access controls. Before enabling the fallback on Kali, approve an exact maintained `cryptography` distribution and its dependency/source/security inventory, then run equivalent known-answer and failure tests there.
