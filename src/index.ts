export type FilenameEncoding = "stream" | "block";

export interface EncfsNameCodecOptions {
  volumeKey: Uint8Array;
  volumeIv: Uint8Array;
  nameEncoding: FilenameEncoding;
  chainedNameIv: boolean;
  cipherMajor?: number;
  cryptoProvider?: Crypto;
}

export interface EncodedName {
  encodedName: string;
  nextIv: bigint;
}

export interface DecodedName {
  plaintext: Uint8Array;
  nextIv: bigint;
}

const AES_BLOCK_SIZE = 16;
const U64_MASK = (1n << 64n) - 1n;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export class EncfsCodecError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EncfsCodecError";
  }
}

export class EncfsNameCodec {
  private readonly cryptoProvider: Crypto;
  private readonly volumeCrypto: LegacyAes;

  constructor(options: EncfsNameCodecOptions) {
    this.cryptoProvider = requireCrypto(options.cryptoProvider ?? globalThis.crypto);
    validateAesKey(options.volumeKey);
    if (options.volumeIv.length !== AES_BLOCK_SIZE) {
      throw new EncfsCodecError("AES volume IV must be 16 bytes");
    }
    const cipherMajor = options.cipherMajor ?? 3;
    if (cipherMajor < 3) {
      throw new EncfsCodecError("Cipher interface versions below 3 are not supported");
    }
    this.nameEncoding = options.nameEncoding;
    this.chainedNameIv = options.chainedNameIv;
    this.volumeCrypto = new LegacyAes(
      options.volumeKey.slice(),
      options.volumeIv.slice(),
      cipherMajor,
      this.cryptoProvider,
    );
  }

  readonly nameEncoding: FilenameEncoding;
  readonly chainedNameIv: boolean;

  static async fromV6Xml(
    xml: string,
    password: string,
    cryptoProvider: Crypto = globalThis.crypto,
  ): Promise<EncfsNameCodec> {
    const provider = requireCrypto(cryptoProvider);
    const config = readV6Config(xml);
    if (config.cipherName !== "ssl/aes") {
      throw new EncfsCodecError(`Unsupported cipher: ${config.cipherName}`);
    }
    if (config.cipherMajor < 3) {
      throw new EncfsCodecError("Cipher interface versions below 3 are not supported");
    }
    if (config.nameName !== "nameio/block" && config.nameName !== "nameio/stream") {
      throw new EncfsCodecError(`Unsupported filename interface: ${config.nameName}`);
    }
    if (config.iterations <= 0) {
      throw new EncfsCodecError("V6 config must use PBKDF2 with positive iterations");
    }

    const keyLength = config.keySize / 8;
    if (![16, 24, 32].includes(keyLength)) {
      throw new EncfsCodecError(`Unsupported AES key size: ${config.keySize}`);
    }
    const ivLength = AES_BLOCK_SIZE;
    const passwordKey = await provider.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"],
    );
    const userKeyBlob = new Uint8Array(
      await provider.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: toArrayBuffer(config.salt),
          iterations: config.iterations,
          hash: "SHA-1",
        },
        passwordKey,
        (keyLength + ivLength) * 8,
      ),
    );
    const userKey = userKeyBlob.slice(0, keyLength);
    const userIv = userKeyBlob.slice(keyLength);
    const wrappedKey = config.encodedKeyData;
    if (wrappedKey.length < 4) {
      throw new EncfsCodecError("Encoded volume key is too short");
    }

    const expectedMac = readU32Be(wrappedKey.subarray(0, 4));
    const userCrypto = new LegacyAes(userKey, userIv, config.cipherMajor, provider);
    const volumeKeyBlob = await userCrypto.streamDecode(
      wrappedKey.slice(4),
      BigInt(expectedMac),
    );
    const calculatedMac = await userCrypto.mac32WithoutIv(volumeKeyBlob);
    if (calculatedMac !== expectedMac) {
      throw new EncfsCodecError("Volume key checksum mismatch (incorrect password or damaged config)");
    }
    if (volumeKeyBlob.length < keyLength + ivLength) {
      throw new EncfsCodecError("Decrypted volume key is too short");
    }

    return new EncfsNameCodec({
      volumeKey: volumeKeyBlob.slice(0, keyLength),
      volumeIv: volumeKeyBlob.slice(keyLength, keyLength + ivLength),
      nameEncoding: config.nameName === "nameio/block" ? "block" : "stream",
      chainedNameIv: config.chainedNameIv,
      cipherMajor: config.cipherMajor,
      cryptoProvider: provider,
    });
  }

  async encryptName(
    plaintext: string | Uint8Array,
    parentIv = 0n,
    includeParentIv = this.chainedNameIv,
  ): Promise<EncodedName> {
    validateU64(parentIv, "parent IV");
    const nameBytes = typeof plaintext === "string" ? encoder.encode(plaintext) : plaintext.slice();

    if (this.nameEncoding === "block") {
      const paddingLength = AES_BLOCK_SIZE - (nameBytes.length % AES_BLOCK_SIZE);
      const paddedName = appendPadding(nameBytes, paddingLength);
      const { checksum, mac64 } = await this.volumeCrypto.mac16(
        paddedName,
        includeParentIv ? parentIv : undefined,
      );
      const nameSeed = BigInt(checksum) ^ (includeParentIv ? parentIv : 0n);
      const ciphertext = await this.volumeCrypto.aesCbcEncryptNoPadding(
        paddedName,
        await this.volumeCrypto.calculateIv(nameSeed),
      );
      const encodedBytes = concatBytes(u16Be(checksum), ciphertext);
      return { encodedName: encodeFilenameBase64(encodedBytes), nextIv: mac64 };
    }

    const { checksum, mac64 } = await this.volumeCrypto.mac16(
      nameBytes,
      includeParentIv ? parentIv : undefined,
    );
    const nameSeed = BigInt(checksum) ^ (includeParentIv ? parentIv : 0n);
    const encrypted = await this.volumeCrypto.streamEncode(nameBytes, nameSeed);
    return {
      encodedName: encodeFilenameBase64(concatBytes(u16Be(checksum), encrypted)),
      nextIv: mac64,
    };
  }

  async decryptName(
    encodedName: string,
    parentIv = 0n,
    includeParentIv = this.chainedNameIv,
  ): Promise<DecodedName> {
    validateU64(parentIv, "parent IV");
    const packed = decodeFilenameBase64(encodedName);
    if (packed.length < 2) {
      throw new EncfsCodecError("Filename is too short");
    }
    const checksum = readU16Be(packed.subarray(0, 2));
    const ciphertext = packed.slice(2);
    const nameSeed = BigInt(checksum) ^ (includeParentIv ? parentIv : 0n);

    if (this.nameEncoding === "block") {
      if (ciphertext.length < AES_BLOCK_SIZE || ciphertext.length % AES_BLOCK_SIZE !== 0) {
        throw new EncfsCodecError("Block filename ciphertext length is invalid");
      }
      const unpaddedName = await this.volumeCrypto.aesCbcDecryptPadded(
        ciphertext,
        await this.volumeCrypto.calculateIv(nameSeed),
      );
      const paddingLength = AES_BLOCK_SIZE - (unpaddedName.length % AES_BLOCK_SIZE);
      const paddedName = appendPadding(unpaddedName, paddingLength);
      const calculated = await this.volumeCrypto.mac16(
        paddedName,
        includeParentIv ? parentIv : undefined,
      );
      if (calculated.checksum !== checksum) {
        throw new EncfsCodecError("Filename checksum mismatch");
      }
      return { plaintext: unpaddedName, nextIv: calculated.mac64 };
    }

    const plaintext = await this.volumeCrypto.streamDecode(ciphertext, nameSeed);
    const calculated = await this.volumeCrypto.mac16(
      plaintext,
      includeParentIv ? parentIv : undefined,
    );
    if (calculated.checksum !== checksum) {
      throw new EncfsCodecError("Filename checksum mismatch");
    }
    return { plaintext, nextIv: calculated.mac64 };
  }

  async encodePath(path: string): Promise<string> {
    const components = splitPath(path);
    const encoded: string[] = [];
    let parentIv = 0n;
    for (const component of components) {
      const result = await this.encryptName(component, parentIv, this.chainedNameIv);
      encoded.push(result.encodedName);
      if (this.chainedNameIv) parentIv = result.nextIv;
    }
    return encoded.join("/");
  }

  async decodePath(path: string): Promise<string> {
    const components = splitPath(path);
    const decoded: string[] = [];
    let parentIv = 0n;
    for (const component of components) {
      const result = await this.decryptName(component, parentIv, this.chainedNameIv);
      decoded.push(decoder.decode(result.plaintext));
      if (this.chainedNameIv) parentIv = result.nextIv;
    }
    return decoded.join("/");
  }
}

class LegacyAes {
  private hmacKeyPromise?: Promise<CryptoKey>;
  private cbcKeyPromise?: Promise<CryptoKey>;
  private ctrKeyPromise?: Promise<CryptoKey>;

  constructor(
    private readonly key: Uint8Array,
    private readonly masterIv: Uint8Array,
    private readonly cipherMajor: number,
    private readonly provider: Crypto,
  ) {}

  async calculateIv(seed: bigint): Promise<Uint8Array> {
    const input = concatBytes(this.masterIv, u64Le(seed));
    const digest = await this.hmacSha1(input);
    return digest.slice(0, this.masterIv.length);
  }

  async mac16(
    data: Uint8Array,
    parentIv?: bigint,
  ): Promise<{ checksum: number; mac64: bigint }> {
    const mac64 = await this.mac64(data, parentIv);
    const high32 = Number((mac64 >> 32n) & 0xffff_ffffn);
    const low32 = Number(mac64 & 0xffff_ffffn);
    const mac32 = (high32 ^ low32) >>> 0;
    const checksum = (((mac32 >>> 16) & 0xffff) ^ (mac32 & 0xffff)) & 0xffff;
    return { checksum, mac64 };
  }

  async mac32WithoutIv(data: Uint8Array): Promise<number> {
    const digest = await this.hmacSha1(data);
    const folded = foldSha1(digest);
    const mac64 = readU64Be(folded);
    return (Number((mac64 >> 32n) & 0xffff_ffffn) ^ Number(mac64 & 0xffff_ffffn)) >>> 0;
  }

  async streamEncode(data: Uint8Array, seed: bigint): Promise<Uint8Array> {
    let transformed = shuffle(data);
    transformed = await this.cfbTransform(transformed, seed, true);
    transformed = flipBytes(transformed);
    transformed = shuffle(transformed);
    return this.cfbTransform(transformed, BigInt.asUintN(64, seed + 1n), true);
  }

  async streamDecode(data: Uint8Array, seed: bigint): Promise<Uint8Array> {
    let transformed = await this.cfbTransform(data, BigInt.asUintN(64, seed + 1n), false);
    transformed = unshuffle(transformed);
    transformed = flipBytes(transformed);
    transformed = await this.cfbTransform(transformed, seed, false);
    return unshuffle(transformed);
  }

  async aesCbcEncryptNoPadding(data: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
    if (data.length === 0 || data.length % AES_BLOCK_SIZE !== 0) {
      throw new EncfsCodecError("AES-CBC input must contain complete blocks");
    }
    const encrypted = new Uint8Array(
      await this.provider.subtle.encrypt(
        { name: "AES-CBC", iv: toArrayBuffer(iv) },
        await this.getCbcKey(),
        toArrayBuffer(data),
      ),
    );
    return encrypted.slice(0, data.length);
  }

  async aesCbcDecryptPadded(ciphertext: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
    try {
      return new Uint8Array(
        await this.provider.subtle.decrypt(
          { name: "AES-CBC", iv: toArrayBuffer(iv) },
          await this.getCbcKey(),
          toArrayBuffer(ciphertext),
        ),
      );
    } catch {
      throw new EncfsCodecError("AES-CBC decryption or padding failed");
    }
  }

  private async mac64(data: Uint8Array, parentIv?: bigint): Promise<bigint> {
    const macInput = parentIv === undefined ? data : concatBytes(data, u64Le(parentIv));
    const digest = await this.hmacSha1(macInput);
    return readU64Be(foldSha1(digest));
  }

  private async hmacSha1(data: Uint8Array): Promise<Uint8Array> {
    this.hmacKeyPromise ??= this.provider.subtle.importKey(
      "raw",
      toArrayBuffer(this.key),
      { name: "HMAC", hash: "SHA-1" },
      false,
      ["sign"],
    );
    return new Uint8Array(
      await this.provider.subtle.sign("HMAC", await this.hmacKeyPromise, toArrayBuffer(data)),
    );
  }

  private async getCbcKey(): Promise<CryptoKey> {
    this.cbcKeyPromise ??= this.provider.subtle.importKey(
      "raw",
      toArrayBuffer(this.key),
      { name: "AES-CBC" },
      false,
      ["encrypt", "decrypt"],
    );
    return this.cbcKeyPromise;
  }

  private async getCtrKey(): Promise<CryptoKey> {
    this.ctrKeyPromise ??= this.provider.subtle.importKey(
      "raw",
      toArrayBuffer(this.key),
      { name: "AES-CTR" },
      false,
      ["encrypt"],
    );
    return this.ctrKeyPromise;
  }

  private async cfbTransform(
    input: Uint8Array,
    seed: bigint,
    encrypting: boolean,
  ): Promise<Uint8Array> {
    const feedback = await this.calculateIv(seed);
    const output = new Uint8Array(input.length);
    const zeroBlock = new Uint8Array(AES_BLOCK_SIZE);

    for (let offset = 0; offset < input.length; offset += AES_BLOCK_SIZE) {
      const blockLength = Math.min(AES_BLOCK_SIZE, input.length - offset);
      const keyStream = new Uint8Array(
        await this.provider.subtle.encrypt(
          { name: "AES-CTR", counter: toArrayBuffer(feedback), length: 128 },
          await this.getCtrKey(),
          toArrayBuffer(zeroBlock),
        ),
      );
      const cipherBlock = input.slice(offset, offset + blockLength);
      for (let byteIndex = 0; byteIndex < blockLength; byteIndex += 1) {
        output[offset + byteIndex] = cipherBlock[byteIndex]! ^ keyStream[byteIndex]!;
      }
      if (blockLength === AES_BLOCK_SIZE) {
        feedback.set(encrypting ? output.subarray(offset, offset + AES_BLOCK_SIZE) : cipherBlock);
      }
    }
    return output;
  }
}

interface V6Config {
  cipherName: string;
  cipherMajor: number;
  nameName: string;
  keySize: number;
  iterations: number;
  salt: Uint8Array;
  encodedKeyData: Uint8Array;
  chainedNameIv: boolean;
}

function readV6Config(xml: string): V6Config {
  const doc = parseXmlDocument(xml);
  if (doc.name !== "boost_serialization") {
    throw new EncfsCodecError("Missing or invalid XML field: boost_serialization");
  }
  const config = requiredChild(doc, "cfg");
  const cipher = requiredChild(config, "cipherAlg");
  const name = requiredChild(config, "nameAlg");

  return {
    cipherName: readString(childText(cipher, "name"), "cipherAlg.name"),
    cipherMajor: readInteger(childText(cipher, "major"), "cipherAlg.major"),
    nameName: readString(childText(name, "name"), "nameAlg.name"),
    keySize: readInteger(childText(config, "keySize"), "keySize"),
    iterations: readInteger(childText(config, "kdfIterations"), "kdfIterations"),
    salt: decodeStandardBase64(readString(childText(config, "saltData"), "saltData")),
    encodedKeyData: decodeStandardBase64(
      readString(childText(config, "encodedKeyData"), "encodedKeyData"),
    ),
    chainedNameIv: readBoolean(childText(config, "chainedNameIV"), "chainedNameIV"),
  };
}

interface XmlElement {
  name: string;
  text: string;
  children: XmlElement[];
}

/**
 * Parse XML without any library: the browser's native DOMParser when present
 * (zero bytes), a small self-contained parser otherwise (Node / test runners).
 * Both produce the same element tree for the boost_serialization schema.
 */
function parseXmlDocument(xml: string): XmlElement {
  try {
    const DomParser = (
      globalThis as {
        DOMParser?: new () => {
          parseFromString(source: string, mimeType: string): DomDocLike;
        };
      }
    ).DOMParser;
    if (DomParser) return parseWithDomParser(xml, DomParser);
  } catch (error) {
    if (error instanceof EncfsCodecError) throw error;
    // Fall through to the internal parser for exotic host environments.
  }
  return parseWithInternalParser(xml);
}

interface DomDocLike {
  documentElement: DomNodeLike | null;
  getElementsByTagName(name: string): ArrayLike<unknown>;
}

interface DomNodeLike {
  nodeType: number;
  nodeName: string;
  textContent: string | null;
  childNodes: ArrayLike<DomNodeLike>;
}

function parseWithDomParser(
  xml: string,
  DomParser: new () => { parseFromString(source: string, mimeType: string): DomDocLike },
): XmlElement {
  const doc = new DomParser().parseFromString(xml, "application/xml");
  if (
    !doc.documentElement ||
    doc.documentElement.nodeName === "parsererror" ||
    doc.getElementsByTagName("parsererror").length > 0
  ) {
    throw new EncfsCodecError("Invalid EncFS XML configuration");
  }
  return domToElement(doc.documentElement);
}

function domToElement(node: DomNodeLike): XmlElement {
  const element: XmlElement = { name: node.nodeName, text: "", children: [] };
  const nodes = node.childNodes;
  for (let i = 0; i < nodes.length; i++) {
    const child = nodes[i]!;
    if (child.nodeType === 1 && child.nodeName) {
      element.children.push(domToElement(child));
    } else if (child.nodeType === 3 || child.nodeType === 4) {
      element.text += decodeXmlEntities(child.textContent ?? "");
    }
  }
  element.text = element.text.trim();
  return element;
}

function parseWithInternalParser(xml: string): XmlElement {
  let index = 0;
  let root: XmlElement | null = null;
  const stack: XmlElement[] = [];
  const invalid: () => never = (): never => {
    throw new EncfsCodecError("Invalid EncFS XML configuration");
  };

  const appendText = (value: string): void => {
    const top = stack[stack.length - 1];
    if (top && value) top.text += decodeXmlEntities(value);
  };

  while (index < xml.length) {
    const lt = xml.indexOf("<", index);
    if (lt < 0) {
      if (stack.length > 0) appendText(xml.slice(index));
      break;
    }
    if (lt > index) appendText(xml.slice(index, lt));

    if (xml.startsWith("<?", lt)) {
      const end = xml.indexOf("?>", lt);
      if (end < 0) invalid();
      index = end + 2;
      continue;
    }
    if (xml.startsWith("<!--", lt)) {
      const end = xml.indexOf("-->", lt + 4);
      if (end < 0) invalid();
      index = end + 3;
      continue;
    }
    if (xml.startsWith("<![CDATA[", lt)) {
      const end = xml.indexOf("]]>", lt + 9);
      if (end < 0) invalid();
      appendText(xml.slice(lt + 9, end));
      index = end + 3;
      continue;
    }
    if (xml.startsWith("<!", lt)) {
      index = skipDoctype(xml, lt);
      continue;
    }
    if (xml.startsWith("</", lt)) {
      const end = xml.indexOf(">", lt);
      if (end < 0) invalid();
      const closing = xml.slice(lt + 2, end).trim();
      const open = stack.pop();
      if (!open || open.name !== closing) invalid();
      index = end + 1;
      continue;
    }

    // Opening tag: name, then attributes skipped until '>' (quotes respected).
    let cursor = lt + 1;
    const nameStart = cursor;
    while (cursor < xml.length && !/[\s/>]/.test(xml[cursor]!)) cursor++;
    const name = xml.slice(nameStart, cursor);
    if (!name) invalid();
    let selfClosing = false;
    while (cursor < xml.length) {
      const character = xml[cursor]!;
      if (character === '"' || character === "'") {
        cursor++;
        while (cursor < xml.length && xml[cursor] !== character) cursor++;
        cursor++;
        continue;
      }
      if (character === ">") {
        cursor++;
        break;
      }
      if (character === "/" && xml[cursor + 1] === ">") {
        selfClosing = true;
        cursor += 2;
        break;
      }
      cursor++;
    }
    const element: XmlElement = { name, text: "", children: [] };
    const parent = stack[stack.length - 1];
    if (parent) parent.children.push(element);
    else if (root) invalid();
    else root = element;
    if (!selfClosing) stack.push(element);
    index = cursor;
  }

  if (stack.length > 0 || !root) invalid();
  return root;
}

function skipDoctype(xml: string, start: number): number {
  let cursor = start + 2;
  let inSubset = false;
  while (cursor < xml.length) {
    const character = xml[cursor]!;
    if (character === "[") inSubset = true;
    else if (character === "]") inSubset = false;
    else if (character === ">" && !inSubset) return cursor + 1;
    cursor++;
  }
  throw new EncfsCodecError("Invalid EncFS XML configuration");
}

function decodeXmlEntities(value: string): string {
  if (!value.includes("&")) return value;
  return value.replace(
    /&(?:#x([0-9a-fA-F]+)|#([0-9]+)|(amp|lt|gt|quot|apos));/g,
    (match, hex: string | undefined, dec: string | undefined, named: string | undefined) => {
      if (named) {
        return named === "amp" ? "&"
          : named === "lt" ? "<"
          : named === "gt" ? ">"
          : named === "quot" ? '"'
          : "'";
      }
      const code = hex !== undefined ? Number.parseInt(hex, 16) : Number.parseInt(dec ?? "", 10);
      return Number.isInteger(code) && code >= 0 && code <= 0x10ffff
        ? String.fromCodePoint(code)
        : match;
    },
  );
}

function childElement(parent: XmlElement, name: string): XmlElement | undefined {
  return parent.children.find((child) => child.name === name);
}

function requiredChild(parent: XmlElement, name: string): XmlElement {
  const child = childElement(parent, name);
  if (!child) throw new EncfsCodecError(`Missing or invalid XML field: ${name}`);
  return child;
}

function childText(parent: XmlElement, name: string): string | undefined {
  const child = childElement(parent, name);
  return child ? child.text.trim() : undefined;
}

function readString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new EncfsCodecError(`Missing or invalid XML field: ${field}`);
  }
  return value;
}

function readInteger(value: unknown, field: string): number {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new EncfsCodecError(`Missing or invalid integer XML field: ${field}`);
  }
  return parsed;
}

function readBoolean(value: unknown, field: string): boolean {
  if (value === true || value === 1 || value === "1" || value === "true") return true;
  if (value === false || value === 0 || value === "0" || value === "false") return false;
  throw new EncfsCodecError(`Missing or invalid boolean XML field: ${field}`);
}

function decodeStandardBase64(value: string): Uint8Array {
  try {
    const binary = atob(value.replace(/\s+/g, ""));
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new EncfsCodecError("Invalid Base64 data in EncFS configuration");
  }
}

function encodeFilenameBase64(data: Uint8Array): string {
  const output: string[] = [];
  let accumulator = 0;
  let bitCount = 0;
  for (const byte of data) {
    accumulator |= byte << bitCount;
    bitCount += 8;
    while (bitCount >= 6) {
      output.push(valueToFilenameChar(accumulator & 0x3f));
      accumulator >>>= 6;
      bitCount -= 6;
    }
  }
  if (bitCount > 0) output.push(valueToFilenameChar(accumulator & 0x3f));
  return output.join("");
}

function decodeFilenameBase64(value: string): Uint8Array {
  const output: number[] = [];
  let accumulator = 0;
  let bitCount = 0;
  for (const character of value) {
    accumulator |= filenameCharToValue(character) << bitCount;
    bitCount += 6;
    while (bitCount >= 8) {
      output.push(accumulator & 0xff);
      accumulator >>>= 8;
      bitCount -= 8;
    }
  }
  return Uint8Array.from(output);
}

function valueToFilenameChar(value: number): string {
  if (value === 0) return ",";
  if (value === 1) return "-";
  if (value <= 11) return String.fromCharCode(48 + value - 2);
  if (value <= 37) return String.fromCharCode(65 + value - 12);
  return String.fromCharCode(97 + value - 38);
}

function filenameCharToValue(character: string): number {
  if (character === ",") return 0;
  if (character === "-") return 1;
  if (character >= "0" && character <= "9") return character.charCodeAt(0) - 48 + 2;
  if (character >= "A" && character <= "Z") return character.charCodeAt(0) - 65 + 12;
  if (character >= "a" && character <= "z") return character.charCodeAt(0) - 97 + 38;
  throw new EncfsCodecError(`Invalid character in EncFS filename: ${character}`);
}

function foldSha1(digest: Uint8Array): Uint8Array {
  const folded = new Uint8Array(8);
  for (let index = 0; index < digest.length - 1; index += 1) {
    const slot = index % folded.length;
    folded[slot] = folded[slot]! ^ digest[index]!;
  }
  return folded;
}

function shuffle(data: Uint8Array): Uint8Array {
  const output = data.slice();
  for (let index = 0; index + 1 < output.length; index += 1) {
    output[index + 1] = output[index + 1]! ^ output[index]!;
  }
  return output;
}

function unshuffle(data: Uint8Array): Uint8Array {
  const output = data.slice();
  for (let index = output.length - 1; index > 0; index -= 1) {
    output[index] = output[index]! ^ output[index - 1]!;
  }
  return output;
}

function flipBytes(data: Uint8Array): Uint8Array {
  const output = data.slice();
  for (let offset = 0; offset < output.length; offset += 64) {
    const end = Math.min(offset + 64, output.length);
    for (let left = offset, right = end - 1; left < right; left += 1, right -= 1) {
      [output[left], output[right]] = [output[right]!, output[left]!];
    }
  }
  return output;
}

function appendPadding(data: Uint8Array, paddingLength: number): Uint8Array {
  const output = new Uint8Array(data.length + paddingLength);
  output.set(data);
  output.fill(paddingLength, data.length);
  return output;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(data.byteLength);
  new Uint8Array(buffer).set(data);
  return buffer;
}

function u16Be(value: number): Uint8Array {
  return Uint8Array.of((value >>> 8) & 0xff, value & 0xff);
}

function readU16Be(data: Uint8Array): number {
  return (data[0]! << 8) | data[1]!;
}

function readU32Be(data: Uint8Array): number {
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(0, false);
}

function u64Le(value: bigint): Uint8Array {
  const output = new Uint8Array(8);
  let remaining = BigInt.asUintN(64, value);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function readU64Be(data: Uint8Array): bigint {
  let value = 0n;
  for (const byte of data) value = (value << 8n) | BigInt(byte);
  return value;
}

function splitPath(path: string): string[] {
  if (path.includes("\0")) throw new EncfsCodecError("Paths cannot contain NUL bytes");
  const components = path.split("/").filter((component) => component !== "" && component !== ".");
  if (components.some((component) => component === "..")) {
    throw new EncfsCodecError("Parent-directory path components are not supported");
  }
  return components;
}

function validateU64(value: bigint, field: string): void {
  if (value < 0n || value > U64_MASK) {
    throw new EncfsCodecError(`${field} must be an unsigned 64-bit integer`);
  }
}

function validateAesKey(key: Uint8Array): void {
  if (![16, 24, 32].includes(key.length)) {
    throw new EncfsCodecError("AES key must be 16, 24, or 32 bytes");
  }
}

function requireCrypto(provider: Crypto | undefined): Crypto {
  if (!provider?.subtle) {
    throw new EncfsCodecError("Web Crypto is unavailable in this environment");
  }
  return provider;
}
