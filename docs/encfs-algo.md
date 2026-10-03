# EncFS Filename Encoding Specification

This file is AI generated from code in https://github.com/vgough/encfs (master branch for rust code, and 1.9.5 branch for C++ code)


## Scope

This document specifies filename and path-component encoding implemented by the Rust EncFS port in `encfs-src/src/crypto/ssl.rs`, `src/encfsctl.rs`, `src/fs.rs`, and `src/config.rs`. It covers the legacy `ssl/aes` filename codec used by the supplied V6 fixtures. It does not encrypt file contents, implement FUSE, or define the binary encoding of whole EncFS configuration files.

The library target is browser-compatible TypeScript using Web Crypto (`crypto.subtle`) for PBKDF2-HMAC-SHA1, HMAC-SHA1, and AES primitives. Initial compatibility scope: AES-128/192/256, cipher interface major version 3 or later, filename interfaces `nameio/stream` and `nameio/block`, V6 XML configs using PBKDF2, and path component chaining. Argon2id-based key recovery (normally V7) and Blowfish are not in scope unless separately added.

## Version Axes

Do not treat these version numbers as interchangeable:

| Version axis | Where it comes from | What the inspected Rust source does |
| --- | --- | --- |
| Config format | The loader identifies a valid Boost-serialized XML file as `ConfigType::V6`; V7 is protobuf with a magic header or V7 filename. | Selects config parsing and volume-key recovery. V6 uses its configured legacy KDF/key-wrap; V7 uses Argon2id and AEAD key wrapping. |
| Cipher interface | `cipherAlg.name/major/minor`, e.g. `ssl/aes` 3.0 in the supplied tests. | `SslCipher::calculate_iv` uses HMAC-SHA1 when `cipherAlg.major >= 3`; older cipher-interface majors use `set_iv_old`. This axis changes the IV derivation primitive. |
| Name interface mode | `nameAlg.name`, or V7's `NameEncodingMode`. | `SslCipher::set_name_encoding` selects block mode only when the name is exactly `nameio/block`; all other names select stream mode. The V7 loader maps mode 1 to `nameio/stream` and mode 2 to `nameio/block`. |
| Name interface version | `nameAlg.major/minor`, e.g. `nameio/block` 3.0 or 4.0. | The inspected filename cipher does not branch on these fields. Given the same interface name, key, IV, and mode, major/minor do not change its filename transform. |

The supplied tests are **legacy V6 config files**, not “name encoding version 6.” Their `cipherAlg` is `ssl/aes` 3.0. In particular, `DIRECT-CHAIN` uses the requested legacy filename interface `nameio/block` 3.0 and is checked against the real `direct-chain.lst` tree. `DIRECT-NOCHAIN` also declares `nameio/block` 3.0. The reverse fixture is a V6 config too, but declares `nameio/block` 4.0. The Rust port treats both name-interface versions as the same block mode. `uniqueIV` is a file-content/header setting, not a filename mode; `chainedNameIV` separately controls whether the component-derived IV is passed to the next path component.

## Inputs and State

A filename operation receives:

- The plaintext component as UTF-8 bytes for encoding, or the custom-base64 component for decoding.
- The volume encryption key `K` (16, 24, or 32 bytes for AES-128/192/256).
- The volume IV `V` (16 bytes for AES).
- The parent directory IV `P`, an unsigned 64-bit value. The root starts at `P = 0`.
- The selected filename mode: `stream` or `block`.

The operation returns the transformed component and a next-component IV `P'`. Path processing begins at zero. When `chainedNameIV` is true, the parent-IV pointer is present (including for the root component with value zero), and the next component receives `P = P'`. When chaining is false, the parent-IV pointer is absent; it is not a pointer to the integer zero. Root and current-directory markers are ignored; parent-directory (`..`) components are rejected. Sibling names do not affect each other.

## MAC and IV Derivation

All integer byte order below is explicit. `LE64(x)` is the eight-byte little-endian representation of `x`; `BE64(b)` interprets eight bytes as a big-endian integer.

For data `D` and an optional parent-IV pointer `P`, calculate:

1. If the pointer is present, `H = HMAC-SHA1(K, D || LE64(P))`. If it is absent, `H = HMAC-SHA1(K, D)`; append no bytes.
2. Initialize eight zero bytes `F`.
3. For digest indexes `i = 0..18`, set `F[i mod 8] ^= H[i]`. The last SHA-1 digest byte (`H[19]`) is deliberately omitted to match EncFS.
4. `MAC64 = BE64(F)`.
5. `MAC32 = high32(MAC64) XOR low32(MAC64)`.
6. `MAC16 = high16(MAC32) XOR low16(MAC32)`.

The returned next-component IV is `MAC64`. The stored filename checksum is `MAC16`, serialized as two big-endian bytes.

The per-name AES IV is derived from the checksum and, when present, the parent IV:

`nameSeed = uint64(MAC16) XOR P` when the parent-IV pointer is present; otherwise `nameSeed = uint64(MAC16)`.

For cipher interface major version >= 3:

`AES_IV = first16(HMAC-SHA1(K, V || LE64(nameSeed)))`

For older cipher interface versions, Rust uses its legacy seed-mixing function instead of HMAC; that legacy function is not in the initial TypeScript compatibility scope.

## Filename Modes

### `nameio/block`

For the supplied direct V6 fixtures this is `nameio/block` 3.0. The exact same Rust branch is used for `nameio/block` 4.0 because the implementation tests the interface name and does not inspect its major/minor values. AES block size is 16 bytes. Let `N` be the UTF-8 name bytes.

Encoding:

1. Set `q = 16 - (length(N) mod 16)`. This yields `q` in 1..16, including a full padding block when the name length is aligned.
2. Set `D = N || q repeated q times` (PKCS#7 padding).
3. Calculate `MAC64` and `MAC16` over `D`; append the parent IV only when the `chainedNameIV` pointer is enabled.
4. Calculate `AES_IV` using `MAC16 XOR P`.
5. Encrypt `D` with AES-CBC, no additional padding, key `K`, and `AES_IV`.
6. Serialize `BE16(MAC16) || ciphertext`.
7. Encode the bytes with EncFS filename Base64 (defined below).

Decoding:

1. Decode EncFS filename Base64. Require at least two checksum bytes.
2. Read `MAC16` from the first two bytes as big-endian. The remaining ciphertext must be non-empty and a multiple of 16 bytes.
3. Derive `AES_IV` from `MAC16 XOR P` and AES-CBC-decrypt the ciphertext.
4. Calculate `MAC64` and `MAC16` over the entire decrypted padded buffer. Compare the calculated checksum before interpreting/removing padding.
5. Read the final byte `q`; require `1 <= q <= 16` and `q <= length(D)`. The Rust implementation checks the final padding length but does not compare every padding byte. Valid EncFS output uses `q` repeated `q` times.
6. Remove the final `q` bytes and return the remaining UTF-8 name bytes and calculated `MAC64`.

The Rust cipher uses CBC without padding and applies/removes EncFS padding itself. Web Crypto AES-CBC applies PKCS#7 padding internally. An implementation may use native AES-CBC by adding the EncFS padding before encryption and discarding Web Crypto's extra final padding block; decryption of valid EncFS data returns the name with EncFS padding stripped, which must be reconstructed to verify `MAC16`. Invalid ciphertext error ordering or malformed-padding acceptance can differ from Rust because Web Crypto validates its padding internally.

### `nameio/stream`

Encoding:

1. Calculate `MAC64` and `MAC16` over the unpadded name `N`; append the parent IV only when the `chainedNameIV` pointer is enabled.
2. Set `AES_IV` from `MAC16 XOR P`.
3. Copy `N` to buffer `B` and apply `shuffle(B)`: for `i = 0..length(B)-2`, `B[i+1] ^= B[i]`.
4. AES-CFB encrypt `B` using `AES_IV`.
5. Reverse each consecutive group of at most 64 bytes (`flip_bytes`).
6. Apply `shuffle` again.
7. AES-CFB encrypt again, using the IV derived from seed `nameSeed + 1`.
8. Serialize `BE16(MAC16) || B`, then EncFS-Base64 encode. Return `MAC64` as next IV.

Decoding reverses those operations in this order:

1. Base64-decode and read the first two bytes as `MAC16`.
2. CFB-decrypt the remainder using the IV derived from `nameSeed + 1`.
3. Apply `unshuffle` (`B[i] ^= B[i-1]`, descending indexes), then reverse each group of at most 64 bytes.
4. CFB-decrypt using the IV derived from `nameSeed`.
5. Apply `unshuffle`.
6. Verify the MAC over the resulting unpadded name using parent IV `P`; return the name and `MAC64`.

AES-CFB is not directly exposed by Web Crypto. It can be implemented with the native AES primitive and JavaScript feedback logic: AES-CTR over a zero block with a chosen 16-byte counter produces the AES block encryption of that counter. Use that result as the CFB keystream and feed back ciphertext blocks exactly as standard full-block CFB does. Handle the final partial block without appending padding.

## EncFS Filename Base64

This is not RFC 4648 Base64 or Base64URL. Each symbol represents a six-bit value, emitted least-significant group first from the byte stream. For each input byte, append its bits to a little-endian bit accumulator; while at least six bits are available, emit the low six bits. Emit one final low-bit symbol if residual bits remain. Do not emit `=` padding.

The value-to-character alphabet is:

| Value | Character |
| ---: | :--- |
| 0 | `,` |
| 1 | `-` |
| 2..11 | `0`..`9` |
| 12..37 | `A`..`Z` |
| 38..63 | `a`..`z` |

Decoding maps the characters back to six-bit values and packs them least-significant group first into bytes. Any other character is invalid.

## V6 Configuration and Volume-Key Recovery

For the supplied V6 XML fixtures:

1. Parse the `<cfg>` fields: cipher interface, key size, name interface, `chainedNameIV`, salt, `kdfIterations`, and `encodedKeyData`.
2. `keyLen = keySize / 8`; for AES, `ivLen = 16`.
3. Derive `keyLen + ivLen` bytes with PBKDF2-HMAC-SHA1 using UTF-8 password bytes, `saltData`, and `kdfIterations`. Split into `userKey` and `userIV`.
4. Decode `encodedKeyData` using standard XML Base64. It contains `BE32(checksum) || encryptedVolumeKeyBlob`.
5. Decrypt the encrypted blob using the legacy two-pass stream transform with `userKey`, `userIV`, and seed `checksum` (the same shuffle/flip/CFB inverse described above, but with seeds `checksum + 1` then `checksum`).
6. Calculate EncFS MAC32 over the decrypted blob using HMAC-SHA1 keyed by `userKey` over only the blob (no IV appended); fold digest bytes 0..18 into eight bytes as above, interpret big-endian, then XOR the high and low 32-bit halves. Compare to `checksum`.
7. The volume blob starts with `keyLen` bytes of volume key `K`, followed by `ivLen` bytes of volume IV `V`.

The supplied V6 XML uses PBKDF2 with positive iterations. This is a consequence of the config format/KDF fields, not of `nameAlg.major`. Legacy iteration-free KDFs, Argon2id, V7 AEAD wrapping, and non-AES ciphers need separate support and tests.

## Path Operations

A path is transformed one component at a time. Initialize the root IV value to zero. If `chainedNameIV` is enabled, pass a present IV pointer to each normal component and update its value to the operation's returned `MAC64`; otherwise pass no IV pointer. Preserve component boundaries and separators when joining the transformed components. A path-level encode/decode is not equivalent to encrypting the whole path as one byte string.

Reverse mode changes whether the mounted view presents plaintext or encrypted names; it does not define a different filename primitive. Apply the same component codec and chaining rules.

## Compatibility Vectors and Real Fixtures

The Rust unit test `test_phase0_filename_header_block_known_vectors` leaves the filename mode at its default (`stream`): AES-256 key `44` repeated 32 bytes, volume IV `55` repeated 16 bytes, plaintext `phase0-name.txt`, and parent IV `0x0102030405060708` encode to `jXPDn,UNesj7jaXJf3CI3Z6` and return next IV `0xc9c55c89023378c7`.

The Rust `golden_cipher_vectors` test explicitly selects `nameio/block` 3.0 for its `fn_block` vector. For AES-256, use key byte `i * 0x11` for indexes `i=0..31`, IV byte `i * 0x22` for `i=0..15` (wrapping to 8 bits), plaintext `golden-name.txt`, and parent IV `0x0102030405060708`. The encoded component is `rjQCKbBNIDTsT3q,ljeJVmlQ`; the next IV is `0xddc790c64921f3eb`.

The end-to-end fixtures are in `encfs-tests/`: `direct-nochain`, `direct-chain`, and `reverse`, with expected outputs in the adjacent `.lst` manifests and plaintext tree in `ref/`. The test password is `test`. Each manifest has the root plus 15 descendants. The real-fixture tests must compare path sets, allowing traversal order to differ.

### Supplied fixtures

All three supplied trees are reproduced by the TypeScript implementation with the C++ 1.9.5 pointer semantics: `DIRECT-NOCHAIN`, `DIRECT-CHAIN`, and the V6 reverse config using `nameio/block` 4.0. See [encfs-rust-cpp-differences.md](encfs-rust-cpp-differences.md) for the reason the earlier Rust-based implementation produced different no-chain and reverse names.

## Coding Rules for the TypeScript Library

- Use TypeScript strict mode; export a small typed API for component and path encode/decode.
- Use `Uint8Array` for cryptographic inputs/outputs. Convert JS strings to UTF-8 explicitly; do not rely on platform locale or path encoding.
- Use `crypto.subtle` for PBKDF2-HMAC-SHA1, HMAC-SHA1, AES-CBC, and AES-CTR primitives. Do not add a pure-JavaScript AES or hash implementation.
- Keep EncFS-specific byte ordering, MAC folding, padding, shuffling, custom Base64, and IV chaining explicit and covered by byte-exact tests.
- Do not mutate caller-owned key, IV, or input buffers. Avoid logging passwords, keys, or decrypted names.
- Reject unsupported cipher/config versions and malformed paths or encoded components with typed errors; do not silently fall back to a different algorithm.
- Keep file-content encryption, FUSE operations, xattrs, and config writing outside the filename library API.
- Use independent fixed vectors plus the real fixtures; round-trip-only tests are insufficient because matching encoder/decoder bugs can cancel each other.
