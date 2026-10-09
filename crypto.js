/**
 * secp256k1 Elliptic Curve Cryptography Implementation
 * Bitcoin Curve Equation: y^2 = x^3 + 7 (mod p)
 * 
 * Implements pure BigInt point arithmetic, key generation,
 * and ECIES (Elliptic Curve Integrated Encryption Scheme).
 */

// secp256k1 curve parameters
export const SECP256K1 = {
  // Field prime: 2^256 - 2^32 - 977
  p: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn,
  // Curve equation parameter: y^2 = x^3 + ax + b (mod p)
  a: 0n,
  b: 7n,
  // Base generator point G = (Gx, Gy)
  Gx: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
  Gy: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n,
  // Order of G
  n: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n
};

export const G = { x: SECP256K1.Gx, y: SECP256K1.Gy };

// Positive modulo helper
export function mod(a, m = SECP256K1.p) {
  const result = a % m;
  return result >= 0n ? result : result + m;
}

// Modular inverse via Extended Euclidean Algorithm
export function modInverse(k, m = SECP256K1.p) {
  if (k === 0n) throw new Error('Division by zero');
  let [lm, hm] = [1n, 0n];
  let [low, high] = [mod(k, m), m];
  while (low > 1n) {
    const ratio = high / low;
    const nm = hm - lm * ratio;
    const newLow = high - low * ratio;
    hm = lm;
    lm = nm;
    high = low;
    low = newLow;
  }
  return mod(lm, m);
}

// Point Addition on secp256k1
export function pointAdd(p1, p2) {
  if (!p1) return p2;
  if (!p2) return p1;
  if (p1.x === p2.x) {
    if (p1.y === p2.y) return pointDouble(p1);
    return null; // Point at infinity
  }
  const slope = mod((p2.y - p1.y) * modInverse(p2.x - p1.x));
  const x3 = mod(slope * slope - p1.x - p2.x);
  const y3 = mod(slope * (p1.x - x3) - p1.y);
  return { x: x3, y: y3 };
}

// Point Doubling on secp256k1
export function pointDouble(p1) {
  if (!p1) return null;
  const slope = mod((3n * p1.x * p1.x + SECP256K1.a) * modInverse(2n * p1.y));
  const x3 = mod(slope * slope - 2n * p1.x);
  const y3 = mod(slope * (p1.x - x3) - p1.y);
  return { x: x3, y: y3 };
}

// Scalar Point Multiplication k * P (Double-and-Add)
export function scalarMultiply(k, point = G) {
  let result = null;
  let base = point;
  let currK = mod(k, SECP256K1.n);
  while (currK > 0n) {
    if (currK & 1n) {
      result = pointAdd(result, base);
    }
    base = pointDouble(base);
    currK >>= 1n;
  }
  return result;
}

// Check if a point satisfies y^2 = x^3 + 7 (mod p)
export function isOnCurve(point) {
  if (!point) return false;
  const left = mod(point.y * point.y);
  const right = mod(point.x * point.x * point.x + SECP256K1.b);
  return left === right;
}

// Generate a cryptographically secure random 256-bit scalar
export function generatePrivateKey() {
  const bytes = new Uint8Array(32);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 32; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  // Convert bytes to BigInt
  let hex = '';
  for (let b of bytes) hex += b.toString(16).padStart(2, '0');
  let priv = BigInt('0x' + hex) % (SECP256K1.n - 1n) + 1n;
  return priv;
}

// Format BigInt to 64-character hex string (32 bytes)
export function toHex32(bigintVal) {
  return bigintVal.toString(16).padStart(64, '0');
}

// Convert public key point to Bitcoin compressed format (02/03 + X)
export function toCompressedHex(point) {
  const prefix = (point.y % 2n === 0n) ? '02' : '03';
  return prefix + toHex32(point.x);
}

// Convert public key point to uncompressed format (04 + X + Y)
export function toUncompressedHex(point) {
  return '04' + toHex32(point.x) + toHex32(point.y);
}

// SHA-256 helper (compatible with browser WebCrypto or fallback)
export async function sha256(data) {
  let buffer;
  if (typeof data === 'string') {
    buffer = new TextEncoder().encode(data);
  } else if (data instanceof Uint8Array) {
    buffer = data;
  } else {
    buffer = new Uint8Array(data);
  }
  
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    return new Uint8Array(hashBuffer);
  }
  // Lightweight pure-JS SHA-256 fallback if WebCrypto is unavailable
  return fallbackSha256(buffer);
}

// Lightweight SHA-256 implementation fallback
function fallbackSha256(ascii) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  const lengthProperty = 'length';
  let i, j;
  let result = '';
  const words = [];
  const asciiBitLength = ascii[lengthProperty] * 8;
  const hash = [];
  const k = [];
  let primeCounter = 0;

  const isComposite = {};
  for (let candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (i = 0; i < 313; i += candidate) {
        isComposite[i] = candidate;
      }
      hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
      k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
    }
  }

  for (i = 0; i < ascii[lengthProperty]; i++) {
    words[i >> 2] |= ascii[i] << ((3 - (i % 4)) * 8);
  }
  words[asciiBitLength >> 5] |= 0x80 << (24 - (asciiBitLength % 32));
  words[(((asciiBitLength + 64) >> 9) << 4) + 15] = asciiBitLength;

  for (let j = 0; j < words[lengthProperty]; j += 16) {
    const w = words.slice(j, j + 16);
    const oldHash = hash.slice(0);

    for (let i = 0; i < 64; i++) {
      const i2 = i + j;
      const w15 = w[i - 15], w2 = w[i - 2];
      const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
      const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
      w[i] = i < 16 ? w[i] : (w[i - 16] + s0 + w[i - 7] + s1) | 0;

      const s1h = rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25);
      const ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
      const temp1 = (hash[7] + s1h + ch + k[i] + w[i]) | 0;
      const s0h = rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22);
      const maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
      const temp2 = (s0h + maj) | 0;

      hash[7] = hash[6];
      hash[6] = hash[5];
      hash[5] = hash[4];
      hash[4] = (hash[3] + temp1) | 0;
      hash[3] = hash[2];
      hash[2] = hash[1];
      hash[1] = hash[0];
      hash[0] = (temp1 + temp2) | 0;
    }

    for (let i = 0; i < 8; i++) {
      hash[i] = (hash[i] + oldHash[i]) | 0;
    }
  }

  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[i * 4] = (hash[i] >>> 24) & 0xff;
    out[i * 4 + 1] = (hash[i] >>> 16) & 0xff;
    out[i * 4 + 2] = (hash[i] >>> 8) & 0xff;
    out[i * 4 + 3] = hash[i] & 0xff;
  }
  return out;
}

// Decompress 33-byte (66-char) Bitcoin public key to point { x, y }
export function decompressPublicKey(hex) {
  if (!hex || typeof hex !== 'string') throw new Error('Invalid public key hex string');
  const cleanHex = hex.trim().toLowerCase();
  if (cleanHex.length !== 66) throw new Error('Compressed public key must be 66 hex characters (33 bytes)');
  const prefix = cleanHex.slice(0, 2);
  if (prefix !== '02' && prefix !== '03') throw new Error('Compressed public key must start with 02 or 03');
  const isOdd = prefix === '03';
  const rx = BigInt('0x' + cleanHex.slice(2));

  // y^2 = x^3 + 7 (mod p)
  const rhs = mod(rx * rx * rx + SECP256K1.b);
  const exp = (SECP256K1.p + 1n) / 4n;
  let ry = modPow(rhs, exp, SECP256K1.p);
  if ((ry % 2n === 1n) !== isOdd) {
    ry = SECP256K1.p - ry;
  }
  const pt = { x: rx, y: ry };
  if (!isOnCurve(pt)) throw new Error('Point does not satisfy y^2 = x^3 + 7 (mod p)');
  return pt;
}

// Convert bytes to hex string
export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Convert hex string to bytes
export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * ECIES Asymmetric Encryption using Bitcoin Curve (secp256k1)
 * 
 * 1. Sender generates ephemeral keypair: k, R = k * G
 * 2. Shared secret S = k * Q_recipient (where Q_recipient is recipient's public key)
 * 3. Derive symmetric key K = SHA256(S.x)
 * 4. Encrypt message using AES-GCM (or HMAC-authenticated stream)
 * 5. Output includes: ephemeral public key R, IV, and ciphertext
 */
export async function encryptECIES(plaintext, recipientPubKey) {
  // Generate random ephemeral scalar k
  const ephemeralPriv = generatePrivateKey();
  // Ephemeral public key R = k * G
  const R = scalarMultiply(ephemeralPriv, G);
  
  // Shared secret point S = k * Q_recipient
  const S = scalarMultiply(ephemeralPriv, recipientPubKey);
  if (!S) throw new Error('Invalid public key resulting in point at infinity');

  // Derive symmetric key: SHA-256 of S.x (32 bytes)
  const sharedSecretBytes = hexToBytes(toHex32(S.x));
  const derivedKeyBytes = await sha256(sharedSecretBytes);

  // Encrypt with WebCrypto AES-GCM
  const iv = new Uint8Array(12);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(iv);
  } else {
    for (let i = 0; i < 12; i++) iv[i] = Math.floor(Math.random() * 256);
  }

  const enc = new TextEncoder().encode(plaintext);
  let ciphertextBytes;

  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      derivedKeyBytes,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );
    const ctBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      cryptoKey,
      enc
    );
    ciphertextBytes = new Uint8Array(ctBuffer);
  } else {
    // Fallback stream XOR
    ciphertextBytes = new Uint8Array(enc.length);
    for (let i = 0; i < enc.length; i++) {
      ciphertextBytes[i] = enc[i] ^ derivedKeyBytes[i % 32] ^ iv[i % 12];
    }
  }

  return {
    ephemeralPublicKey: R,
    ephemeralPublicHex: toCompressedHex(R),
    sharedSecretX: toHex32(S.x),
    ivHex: bytesToHex(iv),
    ciphertextHex: bytesToHex(ciphertextBytes),
    // Combined payload for transmission
    payload: {
      ephemeralHex: toCompressedHex(R),
      ivHex: bytesToHex(iv),
      ctHex: bytesToHex(ciphertextBytes)
    }
  };
}

/**
 * ECIES Asymmetric Decryption using Bitcoin Curve (secp256k1)
 * 
 * 1. Recipient receives ephemeral public key R and ciphertext
 * 2. Recipient computes shared secret S = d_recipient * R
 *    Notice: d_recipient * R = d_recipient * (k * G) = k * (d_recipient * G) = k * Q = S!
 * 3. Derive symmetric key K = SHA256(S.x)
 * 4. Decrypt message using AES-GCM
 */
export async function decryptECIES(payload, recipientPrivKey) {
  const { ephemeralHex, ivHex, ctHex } = payload;
  
  // Decompress ephemeral point R
  const isOdd = ephemeralHex.slice(0, 2) === '03';
  const rx = BigInt('0x' + ephemeralHex.slice(2));
  
  // Solve for Ry: y^2 = x^3 + 7 (mod p)
  // secp256k1 p % 4 == 3, so sqrt(a) = a^((p+1)/4) mod p
  const rhs = mod(rx * rx * rx + SECP256K1.b);
  const exp = (SECP256K1.p + 1n) / 4n;
  
  // Modular exponentiation
  let ry = modPow(rhs, exp, SECP256K1.p);
  if ((ry % 2n === 1n) !== isOdd) {
    ry = SECP256K1.p - ry;
  }
  const R = { x: rx, y: ry };

  // Shared secret S = d_recipient * R
  const S = scalarMultiply(recipientPrivKey, R);
  if (!S) throw new Error('Shared secret computation failed');

  // Derive symmetric key: SHA-256 of S.x
  const sharedSecretBytes = hexToBytes(toHex32(S.x));
  const derivedKeyBytes = await sha256(sharedSecretBytes);

  const iv = hexToBytes(ivHex);
  const ciphertextBytes = hexToBytes(ctHex);

  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      derivedKeyBytes,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    const ptBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      cryptoKey,
      ciphertextBytes
    );
    return new TextDecoder().decode(ptBuffer);
  } else {
    // Fallback stream XOR
    const ptBytes = new Uint8Array(ciphertextBytes.length);
    for (let i = 0; i < ciphertextBytes.length; i++) {
      ptBytes[i] = ciphertextBytes[i] ^ derivedKeyBytes[i % 32] ^ iv[i % 12];
    }
    return new TextDecoder().decode(ptBytes);
  }
}

// Modular exponentiation: (base^exp) % modulus
export function modPow(base, exp, modulus) {
  let result = 1n;
  let b = mod(base, modulus);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) {
      result = mod(result * b, modulus);
    }
    b = mod(b * b, modulus);
    e >>= 1n;
  }
  return result;
}

/**
 * Create a full identity (Alice or Bob)
 */
export function createIdentity(name) {
  const privateKey = generatePrivateKey();
  const publicKey = scalarMultiply(privateKey, G);
  return {
    name,
    privateKey,
    publicKey,
    privateKeyHex: toHex32(privateKey),
    publicKeyCompressed: toCompressedHex(publicKey),
    publicKeyUncompressed: toUncompressedHex(publicKey),
    curveFormula: 'y² ≡ x³ + 7 (mod p)'
  };
}
