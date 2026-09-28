import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { EncfsCodecError, EncfsNameCodec } from "../src/index.js";

// Tests run compiled from dist/test/, so fixtures sit two levels up under test/fixtures/.
const fixtureUrl = (name: string): URL => new URL(`../../test/fixtures/encfs-tests/${name}`, import.meta.url);

async function readFixture(name: string): Promise<string> {
  return readFile(fixtureUrl(name), "utf8");
}

async function readManifest(name: string): Promise<string[]> {
  return (await readFixture(name)).split(/\r?\n/).filter((line) => line.length > 0);
}

function canonicalPath(path: string): string {
  const withoutDotPrefix = path.replaceAll("\\", "/").replace(/^\.\//, "");
  return withoutDotPrefix.length === 0 ? "." : withoutDotPrefix;
}

function canonicalSet(paths: string[]): string[] {
  return [...new Set(paths.map(canonicalPath))].sort();
}

async function codecFromConfig(configPath: string): Promise<EncfsNameCodec> {
  return EncfsNameCodec.fromV6Xml(await readFixture(configPath), "test");
}

async function assertFixtureRoundTrip(
  configPath: string,
  encryptedManifestPath: string,
): Promise<void> {
  const codec = await codecFromConfig(configPath);
  const plaintextPaths = await readManifest("ref.lst");
  const encryptedPaths = await readManifest(encryptedManifestPath);

  const encoded = await Promise.all(plaintextPaths.map((path) => codec.encodePath(path)));
  assert.deepEqual(canonicalSet(encoded), canonicalSet(encryptedPaths));

  const decoded = await Promise.all(encryptedPaths.map((path) => codec.decodePath(path)));
  assert.deepEqual(canonicalSet(decoded), canonicalSet(plaintextPaths));
}

test("DIRECT-CHAIN matches the real encrypted tree and decodes back", async () => {
  await assertFixtureRoundTrip("direct-chain/.encfs6.xml", "direct-chain.lst");
});

test("fixture trees match their on-disk path manifests", async () => {
  for (const [treeName, manifestName] of [
    ["ref", "ref.lst"],
    ["direct-nochain", "direct-nochain.lst"],
    ["direct-chain", "direct-chain.lst"],
    ["reverse", "reverse.lst"],
  ] as const) {
    const actualPaths = ["."];
    const rootPath = fileURLToPath(fixtureUrl(treeName));
    const visit = async (directoryPath: string, relativePath: string): Promise<void> => {
      const entries = await readdir(directoryPath, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name === ".encfs6.xml") continue;
        const childRelativePath = relativePath
          ? `${relativePath}/${entry.name}`
          : entry.name;
        actualPaths.push(`./${childRelativePath}`);
        if (entry.isDirectory()) {
          await visit(join(directoryPath, entry.name), childRelativePath);
        }
      }
    };
    await visit(rootPath, "");
    assert.deepEqual(canonicalSet(actualPaths), canonicalSet(await readManifest(manifestName)));
  }
});

test("DIRECT-NOCHAIN matches the real encrypted tree and decodes back", async () => {
  await assertFixtureRoundTrip("direct-nochain/.encfs6.xml", "direct-nochain.lst");

  const noChainCodec = await codecFromConfig("direct-nochain/.encfs6.xml");
  const chainCodec = await codecFromConfig("direct-chain/.encfs6.xml");
  const noChainManifest = await readManifest("direct-nochain.lst");
  const chainManifest = await readManifest("direct-chain.lst");
  const noChainRootName = await noChainCodec.encryptName("file_2");
  const chainRootName = await chainCodec.encryptName("file_2");

  assert.equal(canonicalPath(chainRootName.encodedName), canonicalPath(chainManifest[1]!));
  assert.equal(chainRootName.encodedName, "1QpokPhaq2sP9fqnVyHb63oP");
  assert.equal(canonicalPath(noChainRootName.encodedName), canonicalPath(noChainManifest[1]!));
  assert.equal(noChainRootName.encodedName, "w3kY9smoitBQoQpRpJ,0XN97");
});

test("REVERSE V6 config matches the real encrypted tree and decodes back", async () => {
  await assertFixtureRoundTrip("reverse.encfs6.xml", "reverse.lst");

  const codec = await codecFromConfig("reverse.encfs6.xml");
  const reverseManifest = await readManifest("reverse.lst");
  const encodedFile2 = await codec.encryptName("file_2");

  assert.equal(encodedFile2.encodedName, "JUcVTLvBsEArt6cdvIMtB7mW");
  assert.ok(reverseManifest.some((path) => canonicalPath(path) === encodedFile2.encodedName));
});

test("stream filename matches the Rust fixed vector", async () => {
  const codec = new EncfsNameCodec({
    volumeKey: new Uint8Array(32).fill(0x44),
    volumeIv: new Uint8Array(16).fill(0x55),
    nameEncoding: "stream",
    chainedNameIv: false,
  });

  const encoded = await codec.encryptName("phase0-name.txt", 0x0102030405060708n, true);
  assert.equal(encoded.encodedName, "jXPDn,UNesj7jaXJf3CI3Z6");
  assert.equal(encoded.nextIv, 0xc9c55c89023378c7n);
  assert.equal(
    new TextDecoder().decode(
      (await codec.decryptName(encoded.encodedName, 0x0102030405060708n, true)).plaintext,
    ),
    "phase0-name.txt",
  );
});

test("block filename matches the Rust AES-256 golden vector", async () => {
  const key = Uint8Array.from({ length: 32 }, (_, index) => (index * 0x11) & 0xff);
  const iv = Uint8Array.from({ length: 16 }, (_, index) => (index * 0x22) & 0xff);
  const codec = new EncfsNameCodec({
    volumeKey: key,
    volumeIv: iv,
    nameEncoding: "block",
    chainedNameIv: false,
  });

  const encoded = await codec.encryptName("golden-name.txt", 0x0102030405060708n, true);
  assert.equal(encoded.encodedName, "rjQCKbBNIDTsT3q,ljeJVmlQ");
  assert.equal(encoded.nextIv, 0xddc790c64921f3ebn);
});

test("V6 config rejects an incorrect password", async () => {
  await assert.rejects(
    EncfsNameCodec.fromV6Xml(await readFixture("direct-nochain/.encfs6.xml"), "incorrect"),
    (error: unknown) => error instanceof EncfsCodecError && /checksum mismatch/.test(error.message),
  );
});
