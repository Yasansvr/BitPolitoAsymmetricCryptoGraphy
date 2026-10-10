/**
 * address.js - Bitcoin Address Derivation Engine & Utilities
 * Pure ES Module supporting both browser and Node.js
 */

import { ripemd160 as nobleRipemd160 } from './node_modules/@noble/hashes/legacy.js';
import { sha256 as nobleSha256 } from './node_modules/@noble/hashes/sha2.js';

// Base58 Alphabet (Bitcoin standard)
export const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Convert hex string to Uint8Array
 */
export function hexToBytes(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  if (clean.length % 2 !== 0) {
    throw new Error('Hex string must have an even number of characters');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string (lowercase)
 */
export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert utf-8 string to Uint8Array
 */
export function utf8ToBytes(str) {
  return new TextEncoder().encode(str);
}

/**
 * SHA-256 hash of hex string or Uint8Array, returning lowercase hex string
 */
export function sha256Hex(input) {
  const bytes = typeof input === 'string' ? hexToBytes(input) : input;
  const hashBytes = nobleSha256(bytes);
  return bytesToHex(hashBytes);
}

/**
 * RIPEMD-160 hash of hex string or Uint8Array, returning lowercase hex string
 */
export function ripemd160Hex(input) {
  const bytes = typeof input === 'string' ? hexToBytes(input) : input;
  const hashBytes = nobleRipemd160(bytes);
  return bytesToHex(hashBytes);
}

/**
 * Base58 encode byte array or hex string
 */
export function base58Encode(input) {
  const bytes = typeof input === 'string' ? hexToBytes(input) : input;
  if (!bytes || bytes.length === 0) return '';

  // Count leading zero bytes
  let leadingZeroes = 0;
  while (leadingZeroes < bytes.length && bytes[leadingZeroes] === 0) {
    leadingZeroes++;
  }

  // Convert bytes to BigInt
  const hex = bytesToHex(bytes);
  let num = BigInt('0x' + (hex || '00'));
  let result = '';

  while (num > 0n) {
    const rem = Number(num % 58n);
    result = BASE58_ALPHABET[rem] + result;
    num = num / 58n;
  }

  // Prepend '1' for each leading zero byte
  return '1'.repeat(leadingZeroes) + result;
}

/**
 * Base58 decode string to Uint8Array
 */
export function base58Decode(str) {
  if (!str) return new Uint8Array(0);

  let leadingZeroes = 0;
  while (leadingZeroes < str.length && str[leadingZeroes] === '1') {
    leadingZeroes++;
  }

  let num = 0n;
  for (let i = leadingZeroes; i < str.length; i++) {
    const char = str[i];
    const index = BASE58_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid Base58 character: ${char}`);
    }
    num = num * 58n + BigInt(index);
  }

  let hex = num.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const bodyBytes = hexToBytes(hex);
  const out = new Uint8Array(leadingZeroes + bodyBytes.length);
  out.fill(0, 0, leadingZeroes);
  out.set(bodyBytes, leadingZeroes);
  return out;
}

/**
 * Compute 4-byte checksum via double SHA-256 (returns 8 hex chars)
 */
export function computeChecksum(payloadHex) {
  const bytes = hexToBytes(payloadHex);
  const hash1 = nobleSha256(bytes);
  const hash2 = nobleSha256(hash1);
  return bytesToHex(hash2.slice(0, 4));
}

/**
 * Detailed pipeline runner for deriving a Bitcoin address from a public key
 */
export function deriveAddressPipeline(pubkeyHex) {
  const cleanPub = pubkeyHex.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  const pubBytes = hexToBytes(cleanPub);

  // Step 2: SHA-256
  const sha1Bytes = nobleSha256(pubBytes);
  const sha256Result = bytesToHex(sha1Bytes);

  // Step 3: RIPEMD-160
  const ripeBytes = nobleRipemd160(sha1Bytes);
  const pubKeyHash = bytesToHex(ripeBytes);

  // Step 4: Add Version Byte 0x00 (Mainnet)
  const versionByte = '00';
  const versionedPayload = versionByte + pubKeyHash;
  const versionedBytes = hexToBytes(versionedPayload);

  // Step 5: Double SHA-256 Checksum
  const csHash1 = nobleSha256(versionedBytes);
  const csHash1Hex = bytesToHex(csHash1);
  const csHash2 = nobleSha256(csHash1);
  const csHash2Hex = bytesToHex(csHash2);
  const checksum = bytesToHex(csHash2.slice(0, 4));

  // 25-byte Binary Payload
  const finalPayloadHex = versionedPayload + checksum;
  const finalPayloadBytes = hexToBytes(finalPayloadHex);

  // Step 6: Base58 Encode
  const address = base58Encode(finalPayloadBytes);

  return {
    pubkeyHex: cleanPub,
    pubkeyLengthBytes: pubBytes.length,
    sha256: sha256Result,
    ripemd160: pubKeyHash,
    versionByte,
    versionedPayload,
    csHash1: csHash1Hex,
    csHash2: csHash2Hex,
    checksum,
    finalPayload: finalPayloadHex,
    address
  };
}

/**
 * Check parity of Y coordinate
 */
export function getYParity(yHex) {
  const cleanY = yHex.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (cleanY.length === 0) return { isEven: true, lastDigit: '0', prefix: '02' };
  const lastChar = cleanY[cleanY.length - 1];
  const lastDigit = parseInt(lastChar, 16);
  const isEven = lastDigit % 2 === 0;
  return {
    isEven,
    lastDigit: lastChar,
    prefix: isEven ? '02' : '03'
  };
}

/**
 * Assemble public key from X and Y
 */
export function assemblePublicKey(xHex, yHex, format = 'compressed') {
  const cleanX = xHex.replace(/[^0-9a-fA-F]/g, '').padStart(64, '0').toLowerCase();
  const cleanY = yHex.replace(/[^0-9a-fA-F]/g, '').padStart(64, '0').toLowerCase();

  if (format === 'compressed') {
    const parity = getYParity(cleanY);
    return {
      format: 'compressed',
      prefix: parity.prefix,
      x: cleanX,
      y: cleanY,
      pubkey: parity.prefix + cleanX,
      byteLength: 33
    };
  } else {
    return {
      format: 'uncompressed',
      prefix: '04',
      x: cleanX,
      y: cleanY,
      pubkey: '04' + cleanX + cleanY,
      byteLength: 65
    };
  }
}

/**
 * Standard Predefined Points
 */
export const PREDEFINED_POINTS = [
  {
    id: 'wiki_standard',
    name: 'Bitcoin Standard Test Vector',
    description: 'Official test vector from the Bitcoin Developer Documentation & Wiki',
    x: '50863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352',
    y: '2CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6',
    expectedUncompressedAddress: '16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM',
    expectedCompressedAddress: '1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs'
  },
  {
    id: 'satoshi_genesis',
    name: 'Satoshi Genesis Block (Coinbase)',
    description: 'The public key that received the historical 50 BTC in Block 0 on Jan 3, 2009',
    x: '678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6',
    y: '49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f',
    expectedUncompressedAddress: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
    expectedCompressedAddress: '1FYPDCP1uVnPgEE3gaDMbAApdv9XYX7Si5'
  },
  {
    id: 'generator_g',
    name: 'Base Generator Point G',
    description: 'The fundamental secp256k1 generator point G (private key = 1)',
    x: '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
    y: '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8',
    expectedUncompressedAddress: '1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm',
    expectedCompressedAddress: '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'
  }
];
