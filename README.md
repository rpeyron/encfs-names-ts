![AI Generated](https://raw.githubusercontent.com/rpeyron/rpeyron/master/images/badges/badge-ia.svg)

# EncFS Filename Codec

A browser-compatible TypeScript library for encoding and decoding EncFS path components and paths. It does not encrypt file contents or mount a filesystem.

## Supported configurations

- V6 XML with PBKDF2-HMAC-SHA1 and `ssl/aes` (AES-128/192/256)
- `nameio/block` and `nameio/stream`
- Component-level `chainedNameIV`
- Browser Web Crypto; Node.js Web Crypto for tests and server use

Argon2id/V7 key recovery, Blowfish, and cipher interface versions below 3 are not implemented. See [encfs-algo.md](docs/encfs-algo.md) for format details and known fixture compatibility findings.

## Usage

```ts
import { readFile } from "node:fs/promises";
import { EncfsNameCodec } from "encfs-filename-codec";

const xml = await readFile(".encfs6.xml", "utf8");
const codec = await EncfsNameCodec.fromV6Xml(xml, "password");

const encryptedPath = await codec.encodePath("documents/report.txt");
const plaintextPath = await codec.decodePath(encryptedPath);
```

`encryptName` and `decryptName` operate on a single component and expose the returned next-component IV (`{ encodedName, nextIv }` / `{ plaintext, nextIv }`), which is what a caller needs to keep walking a directory's children when `chainedNameIV` is on. `encodePath` and `decodePath` reset the IV at the root and apply the config's `chainedNameIV` setting as they walk components. String inputs/outputs are UTF-8; raw byte names can use the component methods. Failures throw `EncfsCodecError` (bad password, bad config, checksum mismatch, invalid filename).

Consumers that only need path conversion can ignore the IV plumbing and use `fromV6Xml` + `encodePath`/`decodePath`.

## Development

```sh
npm install
npm test
```

The test suite uses the real trees and manifests under `test/fixtures/encfs-tests/`, plus fixed byte-exact vectors from the Rust implementation. The current Rust source agrees with `DIRECT-CHAIN`; the supplied `DIRECT-NOCHAIN` and `REVERSE` names do not authenticate under their adjacent configs. Those differences are captured as explicit tests rather than hidden by changing the codec.

## License

GPL-2.0-or-later (see [LICENSE](LICENSE)) — same family as EncFS itself.
