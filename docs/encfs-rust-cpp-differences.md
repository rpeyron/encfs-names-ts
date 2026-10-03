# Rust and C++ EncFS Filename Differences

This file is AI generated from code in https://github.com/vgough/encfs (master branch for rust code, and 1.9.5 branch for C++ code)


## Scope

This note compares the filename/path codec in the bundled C++ EncFS v1.9.5 source (`encfs/encfs/`) with the Rust port (`encfs-src/src/`). It focuses on the V6 XML fixtures under `encfs-tests/` and the `ssl/aes` / `nameio/block` interface. The compatible TypeScript behavior follows the C++ v1.9.5 reference for these fixtures.

## Chained-IV Pointer Semantics

The key compatibility difference is whether the chained-IV argument is absent or points to the integer zero.

### C++ v1.9.5

`NameIO::_encodePath` and `_decodePath` in `encfs/encfs/NameIO.cpp` set the `uint64_t *iv` argument to `nullptr` whenever `chainedNameIV` is disabled. With chaining enabled, the pointer is present even for the root component, whose IV value is zero.

`SSL_Cipher::_checksum_64` in `encfs/encfs/SSL_Cipher.cpp` computes:

- Present pointer: `HMAC-SHA1(key, data || LE64(*chainedIV))`.
- Null pointer: `HMAC-SHA1(key, data)` with no IV bytes appended.

`BlockNameIO::encodeName`/`decodeName` pass that pointer into `MAC_16`. For block name interface version 3 or later, they also use `MAC16 XOR *iv` as the block-cipher seed when the pointer is present; absent pointer means the seed is just `MAC16`.

### Rust port

`SslCipher::encrypt_filename` and `decrypt_filename` take an unconditional `u64 iv`. Their filename `mac_16` calls `mac_64(data, iv)`, and `mac_64` always appends `iv.to_le_bytes()` to the HMAC input. The path helpers keep `iv = 0` when `chained_name_iv` is false, but still pass that zero to the cipher. Therefore the Rust no-chain MAC input is `data || 8 zero bytes`, not `data`.

This difference does not affect `DIRECT-CHAIN`: the root component has a present parent IV with value zero in both implementations, and subsequent components receive the prior component's MAC64. It does affect `DIRECT-NOCHAIN` and the reverse fixture, where the C++ path layer passes a null pointer.

## Name-Interface Versions

The fixtures are V6 XML configurations, independently of their name-interface versions:

| Fixture | Config format | Cipher interface | Name interface | Chaining |
| --- | --- | --- | --- | --- |
| `direct-nochain` | V6 XML | `ssl/aes` 3.0 | `nameio/block` 3.0 | disabled |
| `direct-chain` | V6 XML | `ssl/aes` 3.0 | `nameio/block` 3.0 | enabled |
| `reverse` | V6 XML | `ssl/aes` 3.0 | `nameio/block` 4.0 | disabled |

C++ documents `nameio/block` 3.0 as adding the full 64-bit IV to filename chaining; prior versions used only the 16-bit MAC output as the block-cipher seed. Its 4.0 block interface adds the separate `nameio/block32` case-insensitive encoding. The standard `nameio/block` 3.0 and 4.0 interfaces both use the Base64 alphabet and the same block transform in the inspected code. The Rust port selects block mode by the interface name `nameio/block` and does not branch on its major/minor version.

The cipher-interface major is a separate axis. Both implementations use HMAC-derived AES IVs for `ssl/aes` major 3.0. Older cipher-interface versions use a legacy seed-mixing IV derivation, which is outside the current TypeScript V6 fixture scope.

## Fixture Results

The C++ semantics now allow the TypeScript implementation to reproduce all three encrypted filename trees, including the `nameio/block` 3.0 direct fixtures and `nameio/block` 4.0 reverse fixture. In particular, the no-chain `file_2` component uses an HMAC without appended zero IV bytes; the chained root `file_2` component uses an HMAC with eight zero bytes appended.

The earlier Rust-based TypeScript behavior instead appended eight zero bytes in both cases. That made `DIRECT-NOCHAIN` and `REVERSE` disagree with the C++ fixtures while `DIRECT-CHAIN` continued to match. The TypeScript codec now represents the parent IV as optional MAC input and uses `chainedNameIV` to select present versus absent semantics.

## Source References

- C++ `encfs/encfs/NameIO.cpp`: nulls the IV pointer when filename IV chaining is disabled.
- C++ `encfs/encfs/BlockNameIO.cpp`: block-name padding, MAC input, version-gated parent-IV seed, and filename serialization.
- C++ `encfs/encfs/Cipher.cpp`: MAC16 folding from MAC64.
- C++ `encfs/encfs/SSL_Cipher.cpp`: HMAC-SHA1 MAC input and AES IV generation.
- Rust `encfs-src/src/encfsctl.rs`: path component IV propagation.
- Rust `encfs-src/src/crypto/ssl.rs`: filename MAC, AES IV, block and stream transforms.
