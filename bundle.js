(() => {
  // crypto.js
  var SECP256K1 = {
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
  var G = { x: SECP256K1.Gx, y: SECP256K1.Gy };
  function mod(a, m = SECP256K1.p) {
    const result = a % m;
    return result >= 0n ? result : result + m;
  }
  function modInverse(k, m = SECP256K1.p) {
    if (k === 0n) throw new Error("Division by zero");
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
  function pointAdd(p1, p2) {
    if (!p1) return p2;
    if (!p2) return p1;
    if (p1.x === p2.x) {
      if (p1.y === p2.y) return pointDouble(p1);
      return null;
    }
    const slope = mod((p2.y - p1.y) * modInverse(p2.x - p1.x));
    const x3 = mod(slope * slope - p1.x - p2.x);
    const y3 = mod(slope * (p1.x - x3) - p1.y);
    return { x: x3, y: y3 };
  }
  function pointDouble(p1) {
    if (!p1) return null;
    const slope = mod((3n * p1.x * p1.x + SECP256K1.a) * modInverse(2n * p1.y));
    const x3 = mod(slope * slope - 2n * p1.x);
    const y3 = mod(slope * (p1.x - x3) - p1.y);
    return { x: x3, y: y3 };
  }
  function scalarMultiply(k, point = G) {
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
  function isOnCurve(point) {
    if (!point) return false;
    const left = mod(point.y * point.y);
    const right = mod(point.x * point.x * point.x + SECP256K1.b);
    return left === right;
  }
  function generatePrivateKey() {
    const bytes = new Uint8Array(32);
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
      crypto.getRandomValues(bytes);
    } else {
      for (let i = 0; i < 32; i++) bytes[i] = Math.floor(Math.random() * 256);
    }
    let hex = "";
    for (let b of bytes) hex += b.toString(16).padStart(2, "0");
    let priv = BigInt("0x" + hex) % (SECP256K1.n - 1n) + 1n;
    return priv;
  }
  function toHex32(bigintVal) {
    return bigintVal.toString(16).padStart(64, "0");
  }
  function toCompressedHex(point) {
    const prefix = point.y % 2n === 0n ? "02" : "03";
    return prefix + toHex32(point.x);
  }
  function toUncompressedHex(point) {
    return "04" + toHex32(point.x) + toHex32(point.y);
  }
  async function sha256(data) {
    let buffer;
    if (typeof data === "string") {
      buffer = new TextEncoder().encode(data);
    } else if (data instanceof Uint8Array) {
      buffer = data;
    } else {
      buffer = new Uint8Array(data);
    }
    if (typeof crypto !== "undefined" && crypto.subtle) {
      const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
      return new Uint8Array(hashBuffer);
    }
    return fallbackSha256(buffer);
  }
  function fallbackSha256(ascii) {
    function rightRotate(value, amount) {
      return value >>> amount | value << 32 - amount;
    }
    const mathPow = Math.pow;
    const maxWord = mathPow(2, 32);
    const lengthProperty = "length";
    let i, j;
    let result = "";
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
        hash[primeCounter] = mathPow(candidate, 0.5) * maxWord | 0;
        k[primeCounter++] = mathPow(candidate, 1 / 3) * maxWord | 0;
      }
    }
    for (i = 0; i < ascii[lengthProperty]; i++) {
      words[i >> 2] |= ascii[i] << (3 - i % 4) * 8;
    }
    words[asciiBitLength >> 5] |= 128 << 24 - asciiBitLength % 32;
    words[(asciiBitLength + 64 >> 9 << 4) + 15] = asciiBitLength;
    for (let j2 = 0; j2 < words[lengthProperty]; j2 += 16) {
      const w = words.slice(j2, j2 + 16);
      const oldHash = hash.slice(0);
      for (let i2 = 0; i2 < 64; i2++) {
        const i22 = i2 + j2;
        const w15 = w[i2 - 15], w2 = w[i2 - 2];
        const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ w15 >>> 3;
        const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ w2 >>> 10;
        w[i2] = i2 < 16 ? w[i2] : w[i2 - 16] + s0 + w[i2 - 7] + s1 | 0;
        const s1h = rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25);
        const ch = hash[4] & hash[5] ^ ~hash[4] & hash[6];
        const temp1 = hash[7] + s1h + ch + k[i2] + w[i2] | 0;
        const s0h = rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22);
        const maj = hash[0] & hash[1] ^ hash[0] & hash[2] ^ hash[1] & hash[2];
        const temp2 = s0h + maj | 0;
        hash[7] = hash[6];
        hash[6] = hash[5];
        hash[5] = hash[4];
        hash[4] = hash[3] + temp1 | 0;
        hash[3] = hash[2];
        hash[2] = hash[1];
        hash[1] = hash[0];
        hash[0] = temp1 + temp2 | 0;
      }
      for (let i2 = 0; i2 < 8; i2++) {
        hash[i2] = hash[i2] + oldHash[i2] | 0;
      }
    }
    const out = new Uint8Array(32);
    for (let i2 = 0; i2 < 8; i2++) {
      out[i2 * 4] = hash[i2] >>> 24 & 255;
      out[i2 * 4 + 1] = hash[i2] >>> 16 & 255;
      out[i2 * 4 + 2] = hash[i2] >>> 8 & 255;
      out[i2 * 4 + 3] = hash[i2] & 255;
    }
    return out;
  }
  function decompressPublicKey(hex) {
    if (!hex || typeof hex !== "string") throw new Error("Invalid public key hex string");
    const cleanHex = hex.trim().toLowerCase();
    if (cleanHex.length !== 66) throw new Error("Compressed public key must be 66 hex characters (33 bytes)");
    const prefix = cleanHex.slice(0, 2);
    if (prefix !== "02" && prefix !== "03") throw new Error("Compressed public key must start with 02 or 03");
    const isOdd = prefix === "03";
    const rx = BigInt("0x" + cleanHex.slice(2));
    const rhs = mod(rx * rx * rx + SECP256K1.b);
    const exp = (SECP256K1.p + 1n) / 4n;
    let ry = modPow(rhs, exp, SECP256K1.p);
    if (ry % 2n === 1n !== isOdd) {
      ry = SECP256K1.p - ry;
    }
    const pt = { x: rx, y: ry };
    if (!isOnCurve(pt)) throw new Error("Point does not satisfy y^2 = x^3 + 7 (mod p)");
    return pt;
  }
  function bytesToHex(bytes) {
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }
  async function encryptECIES(plaintext, recipientPubKey) {
    const ephemeralPriv = generatePrivateKey();
    const R = scalarMultiply(ephemeralPriv, G);
    const S = scalarMultiply(ephemeralPriv, recipientPubKey);
    if (!S) throw new Error("Invalid public key resulting in point at infinity");
    const sharedSecretBytes = hexToBytes(toHex32(S.x));
    const derivedKeyBytes = await sha256(sharedSecretBytes);
    const iv = new Uint8Array(12);
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
      crypto.getRandomValues(iv);
    } else {
      for (let i = 0; i < 12; i++) iv[i] = Math.floor(Math.random() * 256);
    }
    const enc = new TextEncoder().encode(plaintext);
    let ciphertextBytes;
    if (typeof crypto !== "undefined" && crypto.subtle) {
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        derivedKeyBytes,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
      );
      const ctBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        enc
      );
      ciphertextBytes = new Uint8Array(ctBuffer);
    } else {
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
  async function decryptECIES(payload, recipientPrivKey) {
    const { ephemeralHex, ivHex, ctHex } = payload;
    const isOdd = ephemeralHex.slice(0, 2) === "03";
    const rx = BigInt("0x" + ephemeralHex.slice(2));
    const rhs = mod(rx * rx * rx + SECP256K1.b);
    const exp = (SECP256K1.p + 1n) / 4n;
    let ry = modPow(rhs, exp, SECP256K1.p);
    if (ry % 2n === 1n !== isOdd) {
      ry = SECP256K1.p - ry;
    }
    const R = { x: rx, y: ry };
    const S = scalarMultiply(recipientPrivKey, R);
    if (!S) throw new Error("Shared secret computation failed");
    const sharedSecretBytes = hexToBytes(toHex32(S.x));
    const derivedKeyBytes = await sha256(sharedSecretBytes);
    const iv = hexToBytes(ivHex);
    const ciphertextBytes = hexToBytes(ctHex);
    if (typeof crypto !== "undefined" && crypto.subtle) {
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        derivedKeyBytes,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );
      const ptBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        ciphertextBytes
      );
      return new TextDecoder().decode(ptBuffer);
    } else {
      const ptBytes = new Uint8Array(ciphertextBytes.length);
      for (let i = 0; i < ciphertextBytes.length; i++) {
        ptBytes[i] = ciphertextBytes[i] ^ derivedKeyBytes[i % 32] ^ iv[i % 12];
      }
      return new TextDecoder().decode(ptBytes);
    }
  }
  function modPow(base, exp, modulus) {
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
  function createIdentity(name) {
    const privateKey = generatePrivateKey();
    const publicKey = scalarMultiply(privateKey, G);
    return {
      name,
      privateKey,
      publicKey,
      privateKeyHex: toHex32(privateKey),
      publicKeyCompressed: toCompressedHex(publicKey),
      publicKeyUncompressed: toUncompressedHex(publicKey),
      curveFormula: "y\xB2 \u2261 x\xB3 + 7 (mod p)"
    };
  }

  // graph.js
  var EllipticGraphEngine = class {
    constructor(canvas, options = {}) {
      this.canvas = canvas;
      this.ctx = canvas.getContext("2d");
      this.domain = options.domain || "real";
      this.p = options.p ?? 23;
      this.a = options.a ?? 0;
      this.b = options.b ?? 7;
      this.centerX = options.centerX ?? 1;
      this.centerY = options.centerY ?? 0.5;
      this.scale = options.scale ?? 36;
      this.xG = options.xG ?? -1.5;
      this.currentStep = 1;
      this.maxStep = options.maxStep ?? 250;
      this.isPlaying = false;
      this.playTimer = null;
      this.isDragging = false;
      this.dragStartX = 0;
      this.dragStartY = 0;
      this.mouseWorldX = 0;
      this.mouseWorldY = 0;
      this.onStateChange = options.onStateChange || null;
      this.initEvents();
      this.resize();
      this.render();
    }
    // Handle high-DPI canvas resizing
    resize() {
      const rect = this.canvas.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      this.width = rect.width;
      this.height = rect.height;
      this.canvas.width = rect.width * dpr;
      this.canvas.height = rect.height * dpr;
      this.ctx.resetTransform?.();
      this.ctx.scale(dpr, dpr);
      this.render();
    }
    // World to Screen coordinates
    toScreenX(x) {
      return this.width / 2 + (x - this.centerX) * this.scale;
    }
    toScreenY(y) {
      return this.height / 2 - (y - this.centerY) * this.scale;
    }
    // Screen to World coordinates
    toWorldX(px) {
      return (px - this.width / 2) / this.scale + this.centerX;
    }
    toWorldY(py) {
      return -(py - this.height / 2) / this.scale + this.centerY;
    }
    // --- Real (R) Curve Math ---
    getBasePointReal() {
      const rhs = this.xG * this.xG * this.xG + this.a * this.xG + this.b;
      if (rhs < 0) {
        const root = this.findFirstValidXReal();
        this.xG = root + 0.5;
        return { x: this.xG, y: Math.sqrt(this.xG * this.xG * this.xG + this.a * this.xG + this.b) };
      }
      return { x: this.xG, y: Math.sqrt(rhs) };
    }
    findFirstValidXReal() {
      for (let x = -10; x <= 10; x += 0.1) {
        if (x * x * x + this.a * x + this.b >= 0) return x;
      }
      return 0;
    }
    addPointsReal(p1, p2) {
      if (!p1) return { ...p2, m: null, isInfinity: false };
      if (!p2) return { ...p1, m: null, isInfinity: false };
      let m;
      const isDouble = Math.abs(p1.x - p2.x) < 1e-7 && Math.abs(p1.y - p2.y) < 1e-7;
      if (isDouble) {
        if (Math.abs(p1.y) < 1e-7) {
          return { isInfinity: true, m: null };
        }
        m = (3 * p1.x * p1.x + this.a) / (2 * p1.y);
      } else {
        if (Math.abs(p1.x - p2.x) < 1e-7) {
          return { isInfinity: true, m: null };
        }
        m = (p2.y - p1.y) / (p2.x - p1.x);
      }
      const x3 = m * m - p1.x - p2.x;
      const y3 = m * (p1.x - x3) - p1.y;
      return {
        x: x3,
        y: y3,
        m,
        xIntersect: x3,
        yIntersect: -y3,
        // 3rd intersection point before reflection
        isInfinity: false,
        isDouble
      };
    }
    // --- Modular (Finite Field F_p) Math ---
    mod(n, m) {
      return (n % m + m) % m;
    }
    modInverse(a, m) {
      let [m0, y, x] = [m, 0n, 1n];
      a = (a % m + m) % m;
      if (m === 1n) return 0n;
      while (a > 1n) {
        let q = a / m;
        let t = m;
        m = a % m;
        a = t;
        t = y;
        y = x - q * y;
        x = t;
      }
      return x < 0n ? x + m0 : x;
    }
    computeCurveModPoints() {
      const pBig = BigInt(this.p);
      const aBig = BigInt(Math.round(this.a));
      const bBig = BigInt(Math.round(this.b));
      let pts = [];
      for (let x = 0n; x < pBig; x++) {
        let rhs = this.mod(x * x * x + aBig * x + bBig, pBig);
        for (let y = 0n; y < pBig; y++) {
          if (this.mod(y * y, pBig) === rhs) {
            pts.push({ x: Number(x), y: Number(y) });
          }
        }
      }
      return pts;
    }
    getBasePointMod() {
      const pts = this.computeCurveModPoints();
      if (pts.length === 0) return { x: 0, y: 0 };
      const found = pts.find((pt) => pt.x === 1 && pt.y > 0) || pts.find((pt) => pt.y > 0) || pts[0];
      return found;
    }
    addPointsMod(p1, p2) {
      if (!p1) return { ...p2, m: null, isInfinity: false };
      if (!p2) return { ...p1, m: null, isInfinity: false };
      const pBig = BigInt(this.p);
      const aBig = BigInt(Math.round(this.a));
      const x1 = BigInt(p1.x), y1 = BigInt(p1.y);
      const x2 = BigInt(p2.x), y2 = BigInt(p2.y);
      let m;
      const isDouble = x1 === x2 && y1 === y2;
      if (isDouble) {
        if (y1 === 0n) return { isInfinity: true, m: null };
        const num = this.mod(3n * x1 * x1 + aBig, pBig);
        const den = this.mod(2n * y1, pBig);
        m = this.mod(num * this.modInverse(den, pBig), pBig);
      } else {
        if (x1 === x2) return { isInfinity: true, m: null };
        const num = this.mod(y2 - y1, pBig);
        const den = this.mod(x2 - x1, pBig);
        m = this.mod(num * this.modInverse(den, pBig), pBig);
      }
      const x3 = this.mod(m * m - x1 - x2, pBig);
      const y3Intersect = this.mod(m * (x3 - x1) + y1, pBig);
      const y3 = this.mod(pBig - y3Intersect, pBig);
      return {
        x: Number(x3),
        y: Number(y3),
        m: Number(m),
        xIntersect: Number(x3),
        yIntersect: Number(y3Intersect),
        isInfinity: false,
        isDouble
      };
    }
    // --- Compute Full Stepper History ---
    computeSteps() {
      if (this.domain === "mod") {
        const G3 = this.getBasePointMod();
        const steps2 = [
          {
            step: 1,
            point: G3,
            prevPoint: null,
            addend: G3,
            m: null,
            intersect: null,
            isDouble: false,
            isInfinity: false
          }
        ];
        let current2 = G3;
        for (let d = 2; d <= this.currentStep; d++) {
          if (!current2) {
            steps2.push({
              step: d,
              point: G3,
              prevPoint: null,
              addend: G3,
              m: null,
              intersect: null,
              isDouble: false,
              isInfinity: false
            });
            current2 = G3;
            continue;
          }
          const res = this.addPointsMod(current2, G3);
          if (res.isInfinity) {
            steps2.push({
              step: d,
              point: null,
              prevPoint: current2,
              addend: G3,
              m: null,
              intersect: null,
              isDouble: false,
              isInfinity: true
            });
            current2 = null;
          } else {
            const newPoint = { x: res.x, y: res.y };
            steps2.push({
              step: d,
              point: newPoint,
              prevPoint: current2,
              addend: G3,
              m: res.m,
              intersect: { x: res.xIntersect, y: res.yIntersect },
              isDouble: res.isDouble,
              isInfinity: false
            });
            current2 = newPoint;
          }
        }
        return steps2;
      }
      const G2 = this.getBasePointReal();
      const steps = [
        {
          step: 1,
          point: G2,
          prevPoint: null,
          addend: G2,
          m: null,
          intersect: null,
          isDouble: false,
          isInfinity: false
        }
      ];
      let current = G2;
      for (let d = 2; d <= this.currentStep; d++) {
        if (!current) {
          steps.push({
            step: d,
            point: G2,
            prevPoint: null,
            addend: G2,
            m: null,
            intersect: null,
            isDouble: false,
            isInfinity: false
          });
          current = G2;
          continue;
        }
        const res = this.addPointsReal(current, G2);
        if (res.isInfinity) {
          steps.push({
            step: d,
            point: null,
            prevPoint: current,
            addend: G2,
            m: null,
            intersect: null,
            isDouble: false,
            isInfinity: true
          });
          current = null;
        } else {
          const newPoint = { x: res.x, y: res.y };
          steps.push({
            step: d,
            point: newPoint,
            prevPoint: current,
            addend: G2,
            m: res.m,
            intersect: { x: res.xIntersect, y: res.yIntersect },
            isDouble: res.isDouble,
            isInfinity: false
          });
          current = newPoint;
        }
      }
      return steps;
    }
    // --- Navigation & Control Methods ---
    nextStep() {
      if (this.currentStep < this.maxStep) {
        this.currentStep++;
        this.render();
        this.notifyState();
      }
    }
    prevStep() {
      if (this.currentStep > 1) {
        this.currentStep--;
        this.render();
        this.notifyState();
      }
    }
    setStep(step) {
      this.currentStep = Math.max(1, Math.min(this.maxStep, step));
      this.render();
      this.notifyState();
    }
    resetStep() {
      this.currentStep = 1;
      this.render();
      this.notifyState();
    }
    togglePlay() {
      if (this.isPlaying) {
        this.stopPlay();
      } else {
        this.startPlay();
      }
    }
    startPlay() {
      this.isPlaying = true;
      if (this.currentStep >= this.maxStep) this.currentStep = 1;
      this.notifyState();
      this.playTimer = setInterval(() => {
        if (this.currentStep < this.maxStep) {
          this.nextStep();
        } else {
          this.stopPlay();
        }
      }, 1400);
    }
    stopPlay() {
      this.isPlaying = false;
      if (this.playTimer) {
        clearInterval(this.playTimer);
        this.playTimer = null;
      }
      this.notifyState();
    }
    setDomain(domain) {
      this.domain = domain;
      if (domain === "mod") {
        this.scale = Math.min(this.width, this.height) / (this.p + 4);
        this.centerX = this.p / 2;
        this.centerY = this.p / 2;
      } else {
        this.resetView();
      }
      this.resetStep();
      this.render();
      this.notifyState();
    }
    setPrime(p) {
      this.p = parseInt(p);
      if (this.domain === "mod") {
        this.scale = Math.min(this.width, this.height) / (this.p + 4);
        this.centerX = this.p / 2;
        this.centerY = this.p / 2;
      }
      this.resetStep();
      this.render();
      this.notifyState();
    }
    setParameters(a, b) {
      this.a = parseFloat(a);
      this.b = parseFloat(b);
      this.resetStep();
      this.render();
      this.notifyState();
    }
    setBasePointX(x) {
      this.xG = parseFloat(x);
      this.resetStep();
      this.render();
      this.notifyState();
    }
    setBitcoinPreset() {
      this.a = 0;
      this.b = 7;
      if (this.domain === "real") {
        this.xG = -1.5;
        this.centerX = 1;
        this.centerY = 0.5;
        this.scale = 36;
      } else {
        this.centerX = this.p / 2;
        this.centerY = this.p / 2;
        this.scale = Math.min(this.width, this.height) / (this.p + 4);
      }
      this.resetStep();
      this.render();
      this.notifyState();
    }
    setTwoComponentPreset() {
      this.a = -3;
      this.b = 1;
      if (this.domain === "real") {
        this.xG = -1.8;
        this.centerX = 0;
        this.centerY = 0;
        this.scale = 55;
      } else {
        this.centerX = this.p / 2;
        this.centerY = this.p / 2;
        this.scale = Math.min(this.width, this.height) / (this.p + 4);
      }
      this.resetStep();
      this.render();
      this.notifyState();
    }
    zoomIn() {
      this.scale = Math.min(this.scale * 1.25, 250);
      this.render();
    }
    zoomOut() {
      this.scale = Math.max(this.scale / 1.25, 12);
      this.render();
    }
    resetView() {
      if (this.domain === "mod") {
        this.scale = Math.min(this.width, this.height) / (this.p + 4);
        this.centerX = this.p / 2;
        this.centerY = this.p / 2;
      } else {
        this.centerX = 1;
        this.centerY = 0.5;
        this.scale = 36;
      }
      this.render();
    }
    notifyState() {
      if (this.onStateChange) {
        const steps = this.computeSteps();
        const current = steps[steps.length - 1];
        this.onStateChange({
          domain: this.domain,
          p: this.p,
          a: this.a,
          b: this.b,
          xG: this.xG,
          currentStep: this.currentStep,
          isPlaying: this.isPlaying,
          currentData: current,
          stepsCount: steps.length,
          discriminant: -16 * (4 * Math.pow(this.a, 3) + 27 * Math.pow(this.b, 2))
        });
      }
    }
    // --- Interactive Events (Pan & Zoom like Desmos) ---
    initEvents() {
      const c = this.canvas;
      c.addEventListener("mousedown", (e) => {
        this.isDragging = true;
        this.dragStartX = e.clientX;
        this.dragStartY = e.clientY;
        c.style.cursor = "grabbing";
      });
      window.addEventListener("mousemove", (e) => {
        const rect = c.getBoundingClientRect();
        this.mouseWorldX = this.toWorldX(e.clientX - rect.left);
        this.mouseWorldY = this.toWorldY(e.clientY - rect.top);
        if (this.isDragging) {
          const dx = e.clientX - this.dragStartX;
          const dy = e.clientY - this.dragStartY;
          this.centerX -= dx / this.scale;
          this.centerY += dy / this.scale;
          this.dragStartX = e.clientX;
          this.dragStartY = e.clientY;
          this.render();
        }
      });
      window.addEventListener("mouseup", () => {
        if (this.isDragging) {
          this.isDragging = false;
          c.style.cursor = "crosshair";
        }
      });
      c.addEventListener("wheel", (e) => {
        e.preventDefault();
        const rect = c.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;
        const worldX = this.toWorldX(mouseX);
        const worldY = this.toWorldY(mouseY);
        const zoomFactor = e.deltaY < 0 ? 1.15 : 0.87;
        const newScale = Math.max(12, Math.min(250, this.scale * zoomFactor));
        this.scale = newScale;
        this.centerX = worldX - (mouseX - this.width / 2) / this.scale;
        this.centerY = worldY + (mouseY - this.height / 2) / this.scale;
        this.render();
      }, { passive: false });
    }
    // --- Main Render Loop ---
    render() {
      const ctx = this.ctx;
      const w = this.width;
      const h = this.height;
      ctx.clearRect(0, 0, w, h);
      if (this.domain === "mod") {
        this.drawModGrid();
        this.drawModCurvePoints();
        this.drawModGeometricConstruction();
      } else {
        this.drawRealGrid();
        this.drawRealCurve();
        this.drawRealGeometricConstruction();
      }
    }
    // ==========================================
    // REAL (R) MODE RENDERING
    // ==========================================
    drawRealGrid() {
      const ctx = this.ctx;
      const w = this.width;
      const h = this.height;
      const minPixelSpacing = 50;
      const roughUnit = minPixelSpacing / this.scale;
      const power = Math.pow(10, Math.floor(Math.log10(roughUnit)));
      let unit = power;
      if (roughUnit / power >= 5) unit = power * 5;
      else if (roughUnit / power >= 2) unit = power * 2;
      const minX = this.toWorldX(0);
      const maxX = this.toWorldX(w);
      const minY = this.toWorldY(h);
      const maxY = this.toWorldY(0);
      const startX = Math.floor(minX / unit) * unit;
      const startY = Math.floor(minY / unit) * unit;
      ctx.strokeStyle = "#EEF1F6";
      ctx.lineWidth = 1;
      ctx.beginPath();
      for (let x = startX; x <= maxX; x += unit / 2) {
        const px = this.toScreenX(x);
        ctx.moveTo(px, 0);
        ctx.lineTo(px, h);
      }
      for (let y = startY; y <= maxY; y += unit / 2) {
        const py = this.toScreenY(y);
        ctx.moveTo(0, py);
        ctx.lineTo(w, py);
      }
      ctx.stroke();
      ctx.strokeStyle = "#E1E6F0";
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      for (let x = startX; x <= maxX; x += unit) {
        const px = this.toScreenX(x);
        ctx.moveTo(px, 0);
        ctx.lineTo(px, h);
      }
      for (let y = startY; y <= maxY; y += unit) {
        const py = this.toScreenY(y);
        ctx.moveTo(0, py);
        ctx.lineTo(w, py);
      }
      ctx.stroke();
      const originPx = this.toScreenX(0);
      const originPy = this.toScreenY(0);
      ctx.strokeStyle = "#8B95A5";
      ctx.lineWidth = 1.8;
      ctx.beginPath();
      ctx.moveTo(0, originPy);
      ctx.lineTo(w, originPy);
      ctx.moveTo(originPx, 0);
      ctx.lineTo(originPx, h);
      ctx.stroke();
      ctx.fillStyle = "#6B7280";
      ctx.font = "10px JetBrains Mono, monospace";
      for (let x = startX; x <= maxX; x += unit) {
        if (Math.abs(x) < 1e-6) continue;
        const px = this.toScreenX(x);
        ctx.fillText(Number(x.toFixed(2)).toString(), px - 8, Math.min(Math.max(originPy + 14, 14), h - 6));
      }
      for (let y = startY; y <= maxY; y += unit) {
        if (Math.abs(y) < 1e-6) continue;
        const py = this.toScreenY(y);
        ctx.fillText(Number(y.toFixed(2)).toString(), Math.min(Math.max(originPx + 6, 6), w - 30), py + 3);
      }
      ctx.fillText("0", originPx + 5, originPy + 12);
    }
    drawRealCurve() {
      const ctx = this.ctx;
      const w = this.width;
      ctx.strokeStyle = "#001CE0";
      ctx.lineWidth = 3;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      const stepPx = 1.5;
      let currentSegmentUpper = [];
      let currentSegmentLower = [];
      const segments = [];
      for (let px = 0; px <= w; px += stepPx) {
        const x = this.toWorldX(px);
        const rhs = x * x * x + this.a * x + this.b;
        if (rhs >= 0) {
          const y = Math.sqrt(rhs);
          currentSegmentUpper.push({ px, py: this.toScreenY(y) });
          currentSegmentLower.push({ px, py: this.toScreenY(-y) });
        } else {
          if (currentSegmentUpper.length > 0) {
            segments.push({ upper: currentSegmentUpper, lower: currentSegmentLower });
            currentSegmentUpper = [];
            currentSegmentLower = [];
          }
        }
      }
      if (currentSegmentUpper.length > 0) {
        segments.push({ upper: currentSegmentUpper, lower: currentSegmentLower });
      }
      for (const seg of segments) {
        ctx.beginPath();
        for (let i = 0; i < seg.upper.length; i++) {
          if (i === 0) ctx.moveTo(seg.upper[i].px, seg.upper[i].py);
          else ctx.lineTo(seg.upper[i].px, seg.upper[i].py);
        }
        ctx.stroke();
        ctx.beginPath();
        for (let i = 0; i < seg.lower.length; i++) {
          if (i === 0) ctx.moveTo(seg.lower[i].px, seg.lower[i].py);
          else ctx.lineTo(seg.lower[i].px, seg.lower[i].py);
        }
        ctx.stroke();
      }
    }
    drawRealGeometricConstruction() {
      const ctx = this.ctx;
      const steps = this.computeSteps();
      const G2 = this.getBasePointReal();
      this.drawPoint(G2.x, G2.y, "#001CE0", "G (Base Point)", 8, true);
      if (this.currentStep === 1) return;
      const currentStepData = steps[steps.length - 1];
      if (currentStepData.isInfinity) {
        ctx.fillStyle = "#D32F2F";
        ctx.font = "bold 14px Inter, sans-serif";
        ctx.fillText("Point at Infinity (Identity Point O)", 30, 40);
        return;
      }
      const P1 = currentStepData.prevPoint;
      const m = currentStepData.m;
      const intersect = currentStepData.intersect;
      const finalQ = currentStepData.point;
      if (this.currentStep > 2 && P1) {
        const prevLabel = `${this.currentStep - 1}\xB7G`;
        this.drawPoint(P1.x, P1.y, "#4B5563", prevLabel, 6);
      }
      if (m !== null && P1) {
        const minX = this.toWorldX(0);
        const maxX = this.toWorldX(this.width);
        const yAtMinX = P1.y + m * (minX - P1.x);
        const yAtMaxX = P1.y + m * (maxX - P1.x);
        ctx.save();
        ctx.strokeStyle = "rgba(0, 28, 224, 0.45)";
        ctx.lineWidth = 2;
        ctx.setLineDash([6, 5]);
        ctx.beginPath();
        ctx.moveTo(this.toScreenX(minX), this.toScreenY(yAtMinX));
        ctx.lineTo(this.toScreenX(maxX), this.toScreenY(yAtMaxX));
        ctx.stroke();
        ctx.restore();
      }
      if (intersect) {
        this.drawPoint(intersect.x, intersect.y, "#DC2626", `-${this.currentStep}\xB7G (3rd Intersection)`, 6);
        ctx.save();
        ctx.strokeStyle = "#DC2626";
        ctx.lineWidth = 1.8;
        ctx.setLineDash([4, 4]);
        ctx.beginPath();
        ctx.moveTo(this.toScreenX(intersect.x), this.toScreenY(intersect.y));
        ctx.lineTo(this.toScreenX(finalQ.x), this.toScreenY(finalQ.y));
        ctx.stroke();
        ctx.restore();
      }
      const label = `Q = ${this.currentStep}\xB7G (Public Key)`;
      this.drawPoint(finalQ.x, finalQ.y, "#10B981", label, 9, true, true);
    }
    // ==========================================
    // MODULAR (MOD p) FINITE FIELD RENDERING
    // ==========================================
    drawModGrid() {
      const ctx = this.ctx;
      const p = this.p;
      const p0x = this.toScreenX(0);
      const p0y = this.toScreenY(0);
      const pX = this.toScreenX(p);
      const pY = this.toScreenY(p);
      ctx.fillStyle = "#FFFFFF";
      ctx.fillRect(p0x, pY, pX - p0x, p0y - pY);
      ctx.strokeStyle = "#EDF1F7";
      ctx.lineWidth = 1;
      ctx.beginPath();
      for (let x = 0; x <= p; x++) {
        const sx = this.toScreenX(x);
        ctx.moveTo(sx, p0y);
        ctx.lineTo(sx, pY);
      }
      for (let y = 0; y <= p; y++) {
        const sy = this.toScreenY(y);
        ctx.moveTo(p0x, sy);
        ctx.lineTo(pX, sy);
      }
      ctx.stroke();
      ctx.save();
      ctx.strokeStyle = "rgba(0, 28, 224, 0.2)";
      ctx.lineWidth = 1.5;
      ctx.setLineDash([4, 4]);
      const symY = this.toScreenY(p / 2);
      ctx.beginPath();
      ctx.moveTo(p0x, symY);
      ctx.lineTo(pX, symY);
      ctx.stroke();
      ctx.restore();
      ctx.strokeStyle = "#8B95A5";
      ctx.lineWidth = 2;
      ctx.strokeRect(p0x, pY, pX - p0x, p0y - pY);
      ctx.fillStyle = "#6B7280";
      ctx.font = "10px JetBrains Mono, monospace";
      const stepUnit = p > 30 ? 5 : 2;
      for (let x = 0; x <= p; x += stepUnit) {
        const sx = this.toScreenX(x);
        ctx.fillText(x.toString(), sx - 4, p0y + 14);
      }
      for (let y = 0; y <= p; y += stepUnit) {
        const sy = this.toScreenY(y);
        ctx.fillText(y.toString(), p0x - 18, sy + 4);
      }
      ctx.fillStyle = "#001CE0";
      ctx.font = "bold 10px Inter, sans-serif";
      ctx.fillText(`Field F_${p} (Symmetry axis y = ${p}/2)`, p0x + 8, pY + 16);
    }
    drawModCurvePoints() {
      const ctx = this.ctx;
      const pts = this.computeCurveModPoints();
      for (const pt of pts) {
        const sx = this.toScreenX(pt.x);
        const sy = this.toScreenY(pt.y);
        ctx.fillStyle = "rgba(0, 28, 224, 0.12)";
        ctx.beginPath();
        ctx.arc(sx, sy, 7, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = "#001CE0";
        ctx.beginPath();
        ctx.arc(sx, sy, 3.5, 0, Math.PI * 2);
        ctx.fill();
      }
    }
    drawModGeometricConstruction() {
      const ctx = this.ctx;
      const steps = this.computeSteps();
      const G2 = this.getBasePointMod();
      const p = this.p;
      this.drawPoint(G2.x, G2.y, "#001CE0", "G (Base Point)", 8, true);
      if (this.currentStep === 1) return;
      const currentStepData = steps[steps.length - 1];
      if (currentStepData.isInfinity) {
        ctx.fillStyle = "#D32F2F";
        ctx.font = "bold 14px Inter, sans-serif";
        ctx.fillText("Point at Infinity (Identity Point O)", 30, 40);
        return;
      }
      const P1 = currentStepData.prevPoint;
      const m = currentStepData.m;
      const intersect = currentStepData.intersect;
      const finalQ = currentStepData.point;
      if (this.currentStep > 2 && P1) {
        const prevLabel = `${this.currentStep - 1}\xB7G`;
        this.drawPoint(P1.x, P1.y, "#4B5563", prevLabel, 6);
      }
      if (m !== null && P1) {
        this.drawWrappedModLines(m, P1.x, P1.y, p);
      }
      if (intersect) {
        this.drawPoint(intersect.x, intersect.y, "#DC2626", `-${this.currentStep}\xB7G (Intersection)`, 6);
        ctx.save();
        ctx.strokeStyle = "#DC2626";
        ctx.lineWidth = 1.8;
        ctx.setLineDash([4, 4]);
        ctx.beginPath();
        ctx.moveTo(this.toScreenX(intersect.x), this.toScreenY(intersect.y));
        ctx.lineTo(this.toScreenX(finalQ.x), this.toScreenY(finalQ.y));
        ctx.stroke();
        ctx.restore();
      }
      const label = `Q = ${this.currentStep}\xB7G (mod ${p})`;
      this.drawPoint(finalQ.x, finalQ.y, "#10B981", label, 9, true, true);
    }
    // Draw modular wrapped line segments y - y1 = m*(x - x1) mod p
    drawWrappedModLines(m, x1, y1, p) {
      const ctx = this.ctx;
      const c = y1 - m * x1;
      const minK = Math.floor(c / p) - 2;
      const maxK = Math.ceil((m * p + c) / p) + 2;
      ctx.save();
      ctx.strokeStyle = "rgba(0, 28, 224, 0.4)";
      ctx.lineWidth = 1.8;
      ctx.setLineDash([5, 4]);
      for (let k = minK; k <= maxK; k++) {
        const offset = c - k * p;
        const pts = [];
        if (offset >= 0 && offset <= p) pts.push({ x: 0, y: offset });
        const yAtP = m * p + offset;
        if (yAtP >= 0 && yAtP <= p) pts.push({ x: p, y: yAtP });
        if (m !== 0) {
          const xAt0 = -offset / m;
          if (xAt0 >= 0 && xAt0 <= p) pts.push({ x: xAt0, y: 0 });
          const xAtP = (p - offset) / m;
          if (xAtP >= 0 && xAtP <= p) pts.push({ x: xAtP, y: p });
        }
        const unique = [];
        for (const pt of pts) {
          if (!unique.some((u) => Math.abs(u.x - pt.x) < 1e-4 && Math.abs(u.y - pt.y) < 1e-4)) {
            unique.push(pt);
          }
        }
        if (unique.length >= 2) {
          ctx.beginPath();
          ctx.moveTo(this.toScreenX(unique[0].x), this.toScreenY(unique[0].y));
          ctx.lineTo(this.toScreenX(unique[1].x), this.toScreenY(unique[1].y));
          ctx.stroke();
        }
      }
      ctx.restore();
    }
    // Draw Point Badge Pill on Canvas
    drawPoint(x, y, color, label, radius = 6, withHalo = false, isPublic = false) {
      const ctx = this.ctx;
      const px = this.toScreenX(x);
      const py = this.toScreenY(y);
      if (px < -50 || px > this.width + 50 || py < -50 || py > this.height + 50) return;
      if (withHalo) {
        ctx.fillStyle = isPublic ? "rgba(16, 185, 129, 0.2)" : "rgba(0, 28, 224, 0.18)";
        ctx.beginPath();
        ctx.arc(px, py, radius * 2.2, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(px, py, radius, 0, Math.PI * 2);
      ctx.fill();
      ctx.strokeStyle = "#FFFFFF";
      ctx.lineWidth = 2;
      ctx.stroke();
      ctx.save();
      ctx.font = "bold 12px Inter, sans-serif";
      const labelMetrics = ctx.measureText(label);
      const coordText = `(${Number(x.toFixed(2))}, ${Number(y.toFixed(2))})`;
      ctx.font = "10px JetBrains Mono, monospace";
      const coordMetrics = ctx.measureText(coordText);
      const boxW = Math.max(labelMetrics.width, coordMetrics.width) + 14;
      const boxH = 34;
      let boxX = px + radius + 6;
      let boxY = py - 17;
      if (boxX + boxW > this.width - 10) {
        boxX = px - radius - boxW - 6;
      }
      ctx.fillStyle = "rgba(255, 255, 255, 0.94)";
      ctx.strokeStyle = isPublic ? "rgba(16, 185, 129, 0.3)" : "rgba(0, 28, 224, 0.15)";
      ctx.lineWidth = 1;
      ctx.shadowColor = "rgba(0, 0, 0, 0.08)";
      ctx.shadowBlur = 8;
      ctx.shadowOffsetY = 2;
      if (ctx.roundRect) {
        ctx.beginPath();
        ctx.roundRect(boxX, boxY, boxW, boxH, 8);
        ctx.fill();
        ctx.stroke();
      } else {
        ctx.fillRect(boxX, boxY, boxW, boxH);
        ctx.strokeRect(boxX, boxY, boxW, boxH);
      }
      ctx.restore();
      ctx.save();
      ctx.fillStyle = "#12141D";
      ctx.font = "bold 12px Inter, sans-serif";
      ctx.fillText(label, boxX + 7, boxY + 14);
      ctx.fillStyle = isPublic ? "#059669" : "#4B5563";
      ctx.font = "10px JetBrains Mono, monospace";
      ctx.fillText(coordText, boxX + 7, boxY + 28);
      ctx.restore();
    }
  };

  // node_modules/@noble/hashes/_u64.js
  var fromNumH = (n) => n / 2 ** 32 | 0;
  var fromNumL = (n) => n >>> 0;
  function setU64FromNum(view, byteOffset, n, isLE) {
    const h = fromNumH(n);
    const l = fromNumL(n);
    view.setUint32(byteOffset, isLE ? l : h, isLE);
    view.setUint32(byteOffset + 4, isLE ? h : l, isLE);
  }

  // node_modules/@noble/hashes/utils.js
  function isBytes(a) {
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
  }
  var atitle = (title) => title ? `"${title}" ` : "";
  function anumber(n, title = "") {
    if (typeof n !== "number")
      throw new TypeError(atitle(title) + "expected number, got " + typeof n);
    if (!Number.isSafeInteger(n) || n < 0)
      throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
    return n;
  }
  function abytes(value, length, title = "") {
    if (isBytes(value) && (length === void 0 || value.length === length))
      return value;
    if (length !== void 0)
      anumber(length, "length");
    const bytes = isBytes(value);
    const ofLen = length !== void 0 ? ` of length ${length}` : "";
    const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
    const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
    if (!bytes)
      throw new TypeError(message);
    throw new RangeError(message);
  }
  var aobject = (value, label) => {
    if (value === null || typeof value !== "object" || Array.isArray(value))
      throw new TypeError((label === "object" ? "" : `"${label}" `) + "expected object, got type=" + typeof value);
  };
  var aopts = (value, label) => {
    aobject(value, label);
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null)
      throw new TypeError(`"${label}" expected plain object`);
    if (Object.hasOwn(value, "__proto__"))
      throw new TypeError(`"${label}.__proto__" is not allowed`);
  };
  function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
      throw new Error("hash was destroyed");
    if (checkFinished && instance.finished)
      throw new Error("digest() was already called");
  }
  function aoutput(out, instance) {
    abytes(out, void 0, "output");
    const min = instance.outputLen;
    if (!(out.length >= min)) {
      throw new RangeError('"output" expected length >= ' + min);
    }
  }
  function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
      arrays[i].fill(0);
    }
  }
  function createView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  }
  function rotr(word, shift) {
    return word << 32 - shift | word >>> shift;
  }
  function rotl(word, shift) {
    return word << shift | word >>> 32 - shift >>> 0;
  }
  function checkOpts(defaults, opts, title = "opts") {
    aopts(defaults, "defaults");
    if (opts !== void 0)
      aopts(opts, title);
    const merged = Object.assign(/* @__PURE__ */ Object.create(null), defaults, opts);
    return merged;
  }
  function createHasher(hashCons, info = {}) {
    if (typeof hashCons !== "function")
      throw new TypeError('"hashCons" expected function, got type=' + typeof hashCons);
    info = checkOpts({}, info, "info");
    const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
    const tmp = hashCons(void 0);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.canXOF = tmp.canXOF;
    hashC.create = (opts) => hashCons(opts);
    Object.assign(hashC, info);
    return Object.freeze(hashC);
  }
  var oidNist = (suffix) => ({
    // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
    // Larger suffix values would need base-128 OID encoding and a different length byte.
    oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
  });

  // node_modules/@noble/hashes/_md.js
  function Chi(a, b, c) {
    return a & b ^ ~a & c;
  }
  function Maj(a, b, c) {
    return a & b ^ a & c ^ b & c;
  }
  var HashMD = class {
    blockLen;
    outputLen;
    canXOF = false;
    padOffset;
    isLE;
    // For partial updates less than block size
    buffer;
    view;
    finished = false;
    length = 0;
    pos = 0;
    destroyed = false;
    constructor(blockLen, outputLen, padOffset, isLE) {
      this.blockLen = blockLen;
      this.outputLen = outputLen;
      this.padOffset = padOffset;
      this.isLE = isLE;
      this.buffer = new Uint8Array(blockLen);
      this.view = createView(this.buffer);
    }
    update(data) {
      aexists(this);
      abytes(data);
      const { view, buffer, blockLen } = this;
      const len = data.length;
      let processed = false;
      for (let pos = 0; pos < len; ) {
        const take = Math.min(blockLen - this.pos, len - pos);
        if (take === blockLen) {
          const dataView = createView(data);
          for (; blockLen <= len - pos; pos += blockLen)
            this.process(dataView, pos);
          processed = true;
          continue;
        }
        buffer.set(pos === 0 && take === len ? data : data.subarray(pos, pos + take), this.pos);
        this.pos += take;
        pos += take;
        if (this.pos === blockLen) {
          this.process(view, 0);
          this.pos = 0;
          processed = true;
        }
      }
      this.length += data.length;
      if (processed)
        this.roundClean();
      return this;
    }
    digestInto(out) {
      aexists(this);
      aoutput(out, this);
      this.finished = true;
      const { buffer, view, blockLen, isLE } = this;
      let { pos } = this;
      buffer[pos++] = 128;
      buffer.fill(0, pos);
      if (this.padOffset > blockLen - pos) {
        this.process(view, 0);
        buffer.fill(0);
      }
      setU64FromNum(view, blockLen - 8, this.length * 8, isLE);
      this.process(view, 0);
      this.roundClean();
      const oview = out === buffer ? view : createView(out);
      const len = this.outputLen;
      const outLen = len / 4;
      const state2 = this.get();
      if (len % 4 || outLen > state2.length)
        throw new Error("invalid outputLen");
      for (let i = 0; i < outLen; i++)
        oview.setUint32(4 * i, state2[i], isLE);
    }
    digest() {
      const { buffer, outputLen } = this;
      this.digestInto(buffer);
      const res = buffer.slice(0, outputLen);
      this.destroy();
      return res;
    }
    _cloneIntoMeta(to) {
      const { buffer, length, finished, destroyed, pos } = this;
      to.destroyed = destroyed;
      to.finished = finished;
      to.length = length;
      to.pos = pos;
      if (pos)
        to.buffer.set(buffer);
      return to;
    }
    clone() {
      return this._cloneInto();
    }
  };
  var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
    1779033703,
    3144134277,
    1013904242,
    2773480762,
    1359893119,
    2600822924,
    528734635,
    1541459225
  ]);

  // node_modules/@noble/hashes/legacy.js
  var Rho160 = /* @__PURE__ */ Uint8Array.from([
    7,
    4,
    13,
    1,
    10,
    6,
    15,
    3,
    12,
    0,
    9,
    5,
    2,
    14,
    11,
    8
  ]);
  var Id160 = /* @__PURE__ */ (() => Uint8Array.from(new Array(16).fill(0).map((_, i) => i)))();
  var Pi160 = /* @__PURE__ */ (() => Id160.map((i) => (9 * i + 5) % 16))();
  var idxLR = /* @__PURE__ */ (() => {
    const L = [Id160];
    const R = [Pi160];
    const res = [L, R];
    for (let i = 0; i < 4; i++)
      for (let j of res)
        j.push(j[i].map((k) => Rho160[k]));
    return res;
  })();
  var idxL = /* @__PURE__ */ (() => idxLR[0])();
  var idxR = /* @__PURE__ */ (() => idxLR[1])();
  var shifts160 = /* @__PURE__ */ [
    [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
    [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
    [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
    [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
    [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5]
  ].map((i) => Uint8Array.from(i));
  var shiftsL160 = /* @__PURE__ */ idxL.map((idx, i) => idx.map((j) => shifts160[i][j]));
  var shiftsR160 = /* @__PURE__ */ idxR.map((idx, i) => idx.map((j) => shifts160[i][j]));
  var Kl160 = /* @__PURE__ */ Uint32Array.from([
    0,
    1518500249,
    1859775393,
    2400959708,
    2840853838
  ]);
  var Kr160 = /* @__PURE__ */ Uint32Array.from([
    1352829926,
    1548603684,
    1836072691,
    2053994217,
    0
  ]);
  function ripemd_f(group, x, y, z) {
    if (group === 0)
      return x ^ y ^ z;
    if (group === 1)
      return x & y | ~x & z;
    if (group === 2)
      return (x | ~y) ^ z;
    if (group === 3)
      return x & z | y & ~z;
    return x ^ (y | ~z);
  }
  var BUF_160 = /* @__PURE__ */ new Uint32Array(16);
  var _RIPEMD160 = class extends HashMD {
    h0 = 1732584193 | 0;
    h1 = 4023233417 | 0;
    h2 = 2562383102 | 0;
    h3 = 271733878 | 0;
    h4 = 3285377520 | 0;
    constructor() {
      super(64, 20, 8, true);
    }
    get() {
      const { h0, h1, h2, h3, h4 } = this;
      return [h0, h1, h2, h3, h4];
    }
    set(h0, h1, h2, h3, h4) {
      this.h0 = h0 | 0;
      this.h1 = h1 | 0;
      this.h2 = h2 | 0;
      this.h3 = h3 | 0;
      this.h4 = h4 | 0;
    }
    _cloneInto(to) {
      (to ||= new this.constructor()).set(...this.get());
      return this._cloneIntoMeta(to);
    }
    process(view, offset) {
      for (let i = 0; i < 16; i++, offset += 4)
        BUF_160[i] = view.getUint32(offset, true);
      let al = this.h0 | 0, ar = al, bl = this.h1 | 0, br = bl, cl = this.h2 | 0, cr = cl, dl = this.h3 | 0, dr = dl, el = this.h4 | 0, er = el;
      for (let group = 0; group < 5; group++) {
        const rGroup = 4 - group;
        const hbl = Kl160[group], hbr = Kr160[group];
        const rl = idxL[group], rr = idxR[group];
        const sl = shiftsL160[group], sr = shiftsR160[group];
        for (let i = 0; i < 16; i++) {
          const tl = rotl(al + ripemd_f(group, bl, cl, dl) + BUF_160[rl[i]] + hbl, sl[i]) + el | 0;
          al = el, el = dl, dl = rotl(cl, 10) | 0, cl = bl, bl = tl;
        }
        for (let i = 0; i < 16; i++) {
          const tr = rotl(ar + ripemd_f(rGroup, br, cr, dr) + BUF_160[rr[i]] + hbr, sr[i]) + er | 0;
          ar = er, er = dr, dr = rotl(cr, 10) | 0, cr = br, br = tr;
        }
      }
      this.set(this.h1 + cl + dr | 0, this.h2 + dl + er | 0, this.h3 + el + ar | 0, this.h4 + al + br | 0, this.h0 + bl + cr | 0);
    }
    roundClean() {
      clean(BUF_160);
    }
    destroy() {
      this.destroyed = true;
      clean(this.buffer);
      this.set(0, 0, 0, 0, 0);
    }
  };
  var ripemd160 = /* @__PURE__ */ createHasher(() => new _RIPEMD160());

  // node_modules/@noble/hashes/sha2.js
  var SHA256_K = /* @__PURE__ */ Uint32Array.from([
    1116352408,
    1899447441,
    3049323471,
    3921009573,
    961987163,
    1508970993,
    2453635748,
    2870763221,
    3624381080,
    310598401,
    607225278,
    1426881987,
    1925078388,
    2162078206,
    2614888103,
    3248222580,
    3835390401,
    4022224774,
    264347078,
    604807628,
    770255983,
    1249150122,
    1555081692,
    1996064986,
    2554220882,
    2821834349,
    2952996808,
    3210313671,
    3336571891,
    3584528711,
    113926993,
    338241895,
    666307205,
    773529912,
    1294757372,
    1396182291,
    1695183700,
    1986661051,
    2177026350,
    2456956037,
    2730485921,
    2820302411,
    3259730800,
    3345764771,
    3516065817,
    3600352804,
    4094571909,
    275423344,
    430227734,
    506948616,
    659060556,
    883997877,
    958139571,
    1322822218,
    1537002063,
    1747873779,
    1955562222,
    2024104815,
    2227730452,
    2361852424,
    2428436474,
    2756734187,
    3204031479,
    3329325298
  ]);
  var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
  var SHA2_32B = class extends HashMD {
    // We cannot use array here since array allows indexing by variable
    // which means optimizer/compiler cannot use registers.
    // Numeric initializers matter: starting the fields as `undefined` changes
    // V8's field representation and makes sha256 3x slower (measured).
    A = 0;
    B = 0;
    C = 0;
    D = 0;
    E = 0;
    F = 0;
    G = 0;
    H = 0;
    constructor(outputLen, IV) {
      super(64, outputLen, 8, false);
      this.A = IV[0] | 0;
      this.B = IV[1] | 0;
      this.C = IV[2] | 0;
      this.D = IV[3] | 0;
      this.E = IV[4] | 0;
      this.F = IV[5] | 0;
      this.G = IV[6] | 0;
      this.H = IV[7] | 0;
    }
    get() {
      const { A, B, C, D, E, F, G: G2, H } = this;
      return [A, B, C, D, E, F, G2, H];
    }
    // prettier-ignore
    set(A, B, C, D, E, F, G2, H) {
      this.A = A | 0;
      this.B = B | 0;
      this.C = C | 0;
      this.D = D | 0;
      this.E = E | 0;
      this.F = F | 0;
      this.G = G2 | 0;
      this.H = H | 0;
    }
    _cloneInto(to) {
      (to ||= new this.constructor()).set(...this.get());
      return this._cloneIntoMeta(to);
    }
    process(view, offset) {
      for (let i = 0; i < 16; i++, offset += 4)
        SHA256_W[i] = view.getUint32(offset, false);
      for (let i = 16; i < 64; i++) {
        const W15 = SHA256_W[i - 15];
        const W2 = SHA256_W[i - 2];
        const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
        const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
        SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
      }
      let { A, B, C, D, E, F, G: G2, H } = this;
      for (let i = 0; i < 64; i++) {
        const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
        const T1 = H + sigma1 + Chi(E, F, G2) + SHA256_K[i] + SHA256_W[i] | 0;
        const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
        const T2 = sigma0 + Maj(A, B, C) | 0;
        H = G2;
        G2 = F;
        F = E;
        E = D + T1 | 0;
        D = C;
        C = B;
        B = A;
        A = T1 + T2 | 0;
      }
      A = A + this.A | 0;
      B = B + this.B | 0;
      C = C + this.C | 0;
      D = D + this.D | 0;
      E = E + this.E | 0;
      F = F + this.F | 0;
      G2 = G2 + this.G | 0;
      H = H + this.H | 0;
      this.set(A, B, C, D, E, F, G2, H);
    }
    roundClean() {
      clean(SHA256_W);
    }
    destroy() {
      this.destroyed = true;
      this.set(0, 0, 0, 0, 0, 0, 0, 0);
      clean(this.buffer);
    }
  };
  var _SHA256 = class extends SHA2_32B {
    constructor() {
      super(32, SHA256_IV);
    }
  };
  var sha2562 = /* @__PURE__ */ createHasher(
    () => new _SHA256(),
    /* @__PURE__ */ oidNist(1)
  );

  // address.js
  var BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  function hexToBytes2(hex) {
    const clean2 = hex.replace(/[^0-9a-fA-F]/g, "");
    if (clean2.length % 2 !== 0) {
      throw new Error("Hex string must have an even number of characters");
    }
    const bytes = new Uint8Array(clean2.length / 2);
    for (let i = 0; i < clean2.length; i += 2) {
      bytes[i / 2] = parseInt(clean2.substring(i, i + 2), 16);
    }
    return bytes;
  }
  function bytesToHex2(bytes) {
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  function utf8ToBytes(str) {
    return new TextEncoder().encode(str);
  }
  function sha256Hex(input) {
    const bytes = typeof input === "string" ? hexToBytes2(input) : input;
    const hashBytes = sha2562(bytes);
    return bytesToHex2(hashBytes);
  }
  function ripemd160Hex(input) {
    const bytes = typeof input === "string" ? hexToBytes2(input) : input;
    const hashBytes = ripemd160(bytes);
    return bytesToHex2(hashBytes);
  }
  function base58Encode(input) {
    const bytes = typeof input === "string" ? hexToBytes2(input) : input;
    if (!bytes || bytes.length === 0) return "";
    let leadingZeroes = 0;
    while (leadingZeroes < bytes.length && bytes[leadingZeroes] === 0) {
      leadingZeroes++;
    }
    const hex = bytesToHex2(bytes);
    let num = BigInt("0x" + (hex || "00"));
    let result = "";
    while (num > 0n) {
      const rem = Number(num % 58n);
      result = BASE58_ALPHABET[rem] + result;
      num = num / 58n;
    }
    return "1".repeat(leadingZeroes) + result;
  }
  function base58Decode(str) {
    if (!str) return new Uint8Array(0);
    let leadingZeroes = 0;
    while (leadingZeroes < str.length && str[leadingZeroes] === "1") {
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
    if (hex.length % 2 !== 0) hex = "0" + hex;
    const bodyBytes = hexToBytes2(hex);
    const out = new Uint8Array(leadingZeroes + bodyBytes.length);
    out.fill(0, 0, leadingZeroes);
    out.set(bodyBytes, leadingZeroes);
    return out;
  }
  function computeChecksum(payloadHex) {
    const bytes = hexToBytes2(payloadHex);
    const hash1 = sha2562(bytes);
    const hash2 = sha2562(hash1);
    return bytesToHex2(hash2.slice(0, 4));
  }
  function getYParity(yHex) {
    const cleanY = yHex.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
    if (cleanY.length === 0) return { isEven: true, lastDigit: "0", prefix: "02" };
    const lastChar = cleanY[cleanY.length - 1];
    const lastDigit = parseInt(lastChar, 16);
    const isEven = lastDigit % 2 === 0;
    return {
      isEven,
      lastDigit: lastChar,
      prefix: isEven ? "02" : "03"
    };
  }
  function assemblePublicKey(xHex, yHex, format = "compressed") {
    const cleanX = xHex.replace(/[^0-9a-fA-F]/g, "").padStart(64, "0").toLowerCase();
    const cleanY = yHex.replace(/[^0-9a-fA-F]/g, "").padStart(64, "0").toLowerCase();
    if (format === "compressed") {
      const parity = getYParity(cleanY);
      return {
        format: "compressed",
        prefix: parity.prefix,
        x: cleanX,
        y: cleanY,
        pubkey: parity.prefix + cleanX,
        byteLength: 33
      };
    } else {
      return {
        format: "uncompressed",
        prefix: "04",
        x: cleanX,
        y: cleanY,
        pubkey: "04" + cleanX + cleanY,
        byteLength: 65
      };
    }
  }
  var PREDEFINED_POINTS = [
    {
      id: "wiki_standard",
      name: "Bitcoin Standard Test Vector",
      description: "Official test vector from the Bitcoin Developer Documentation & Wiki",
      x: "50863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352",
      y: "2CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6",
      expectedUncompressedAddress: "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
      expectedCompressedAddress: "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    },
    {
      id: "satoshi_genesis",
      name: "Satoshi Genesis Block (Coinbase)",
      description: "The public key that received the historical 50 BTC in Block 0 on Jan 3, 2009",
      x: "678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6",
      y: "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
      expectedUncompressedAddress: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
      expectedCompressedAddress: "1FYPDCP1uVnPgEE3gaDMbAApdv9XYX7Si5"
    },
    {
      id: "generator_g",
      name: "Base Generator Point G",
      description: "The fundamental secp256k1 generator point G (private key = 1)",
      x: "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
      y: "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
      expectedUncompressedAddress: "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
      expectedCompressedAddress: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    }
  ];

  // merkle.js
  var DEFAULT_TRANSACTIONS = [
    "Tx 0: Alice -> Bob 1.5 BTC",
    "Tx 1: Charlie -> Dave 0.4 BTC",
    "Tx 2: Eve -> Frank 2.1 BTC",
    "Tx 3: Grace -> Heidi 0.8 BTC"
  ];
  function hashLeaf(txText) {
    const bytes = utf8ToBytes(txText);
    return sha256Hex(bytes);
  }
  function hashPair(leftHex, rightHex) {
    const cleanLeft = leftHex.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
    const cleanRight = rightHex.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
    const combinedBytes = hexToBytes2(cleanLeft + cleanRight);
    return sha256Hex(combinedBytes);
  }
  function formatCompactHash(hashHex) {
    if (!hashHex || hashHex.length < 12) return hashHex || "";
    return hashHex.slice(0, 4) + "..." + hashHex.slice(-4);
  }
  function computeMerkleTreeHierarchy(txTexts) {
    if (!txTexts || txTexts.length === 0) {
      return {
        levels: [],
        root: "",
        leafCount: 0
      };
    }
    const levels = [];
    const level0 = [];
    for (let i = 0; i < txTexts.length; i++) {
      const text = txTexts[i];
      const hash = hashLeaf(text);
      level0.push({
        id: `node-0-${i}`,
        level: 0,
        index: i,
        hash,
        shortHash: formatCompactHash(hash),
        label: `H${i}`,
        txText: text,
        isDuplicated: false,
        isLeaf: true
      });
    }
    levels.push(level0);
    let currentLevel = level0;
    let levelNum = 1;
    while (currentLevel.length > 1) {
      if (currentLevel.length % 2 !== 0) {
        const lastNode = currentLevel[currentLevel.length - 1];
        const dupNode = {
          ...lastNode,
          id: `node-${levelNum - 1}-${currentLevel.length}-dup`,
          index: currentLevel.length,
          isDuplicated: true,
          label: `${lastNode.label}*`
        };
        currentLevel.push(dupNode);
      }
      const workingNodes = currentLevel;
      const nextLevel = [];
      for (let i = 0; i < workingNodes.length; i += 2) {
        const leftNode = workingNodes[i];
        const rightNode = workingNodes[i + 1];
        const parentHash = hashPair(leftNode.hash, rightNode.hash);
        const parentIndex = Math.floor(i / 2);
        const isTopLevel = workingNodes.length <= 2;
        const leftLbl = leftNode.label.replace("H", "").replace("*", "");
        const rightLbl = rightNode.label.replace("H", "").replace("*", "");
        const parentLabel = isTopLevel ? "Merkle Root" : `H${leftLbl}${rightLbl}`;
        const parentNode = {
          id: `node-${levelNum}-${parentIndex}`,
          level: levelNum,
          index: parentIndex,
          hash: parentHash,
          shortHash: formatCompactHash(parentHash),
          label: parentLabel,
          leftChildId: leftNode.id,
          rightChildId: rightNode.id,
          isDuplicated: false,
          isLeaf: false
        };
        leftNode.parentId = parentNode.id;
        rightNode.parentId = parentNode.id;
        nextLevel.push(parentNode);
      }
      levels.push(nextLevel);
      currentLevel = nextLevel;
      levelNum++;
    }
    const root = currentLevel.length > 0 ? currentLevel[0].hash : "";
    if (currentLevel.length > 0) {
      currentLevel[0].label = "Merkle Root";
    }
    return {
      levels,
      root,
      leafCount: txTexts.length
    };
  }
  function computeSpvAuditPath(txTexts, targetIndex) {
    if (targetIndex < 0 || targetIndex >= txTexts.length) {
      targetIndex = 0;
    }
    const { levels, root } = computeMerkleTreeHierarchy(txTexts);
    const auditPath = [];
    let currentIndex = targetIndex;
    for (let lvl = 0; lvl < levels.length - 1; lvl++) {
      const currentNodes = levels[lvl];
      const isLeft = currentIndex % 2 === 0;
      const siblingIndex = isLeft ? currentIndex + 1 : currentIndex - 1;
      const siblingNode = currentNodes[siblingIndex];
      if (!siblingNode) break;
      auditPath.push({
        level: lvl,
        siblingId: siblingNode.id,
        siblingLabel: siblingNode.label,
        siblingHash: siblingNode.hash,
        siblingShortHash: formatCompactHash(siblingNode.hash),
        isSiblingOnRight: isLeft
      });
      currentIndex = Math.floor(currentIndex / 2);
    }
    return {
      targetIndex,
      targetTxText: txTexts[targetIndex],
      targetLeafHash: hashLeaf(txTexts[targetIndex]),
      targetLeafShortHash: formatCompactHash(hashLeaf(txTexts[targetIndex])),
      auditPath,
      expectedRoot: root
    };
  }
  var merkleState = {
    transactions: [...DEFAULT_TRANSACTIONS],
    originalTransactions: [...DEFAULT_TRANSACTIONS],
    storedBlockRoot: "",
    currentRoot: "",
    treeData: null,
    activeMode: "builder",
    // 'builder' | 'tamper' | 'spv'
    stepLevel: 999,
    // 0 = leaves only, 1 = branches, 2 = root, 999 = all
    maxLevels: 0,
    tamperedIndices: /* @__PURE__ */ new Set(),
    tamperedNodeIds: /* @__PURE__ */ new Set(),
    spvTargetIndex: 2,
    // default: Tx 2
    spvCurrentStep: 0,
    spvAuditData: null,
    spvIntermediateHash: ""
  };
  function initMerkleSimulator() {
    if (!merkleState.storedBlockRoot) {
      const initialTree = computeMerkleTreeHierarchy(merkleState.originalTransactions);
      merkleState.storedBlockRoot = initialTree.root;
    }
    recalculateMerkleTree();
    renderMerkleUI();
  }
  function recalculateMerkleTree() {
    merkleState.treeData = computeMerkleTreeHierarchy(merkleState.transactions);
    merkleState.currentRoot = merkleState.treeData.root;
    merkleState.maxLevels = merkleState.treeData.levels.length;
    merkleState.tamperedIndices.clear();
    merkleState.tamperedNodeIds.clear();
    for (let i = 0; i < merkleState.transactions.length; i++) {
      if (i >= merkleState.originalTransactions.length || merkleState.transactions[i] !== merkleState.originalTransactions[i]) {
        merkleState.tamperedIndices.add(i);
        merkleState.tamperedNodeIds.add(`node-0-${i}`);
      }
    }
    if (merkleState.treeData.levels.length > 0) {
      const leafNodes = merkleState.treeData.levels[0];
      for (const node of leafNodes) {
        if (node.isDuplicated) {
          const origNode = leafNodes[node.index - 1];
          if (origNode && merkleState.tamperedNodeIds.has(origNode.id)) {
            merkleState.tamperedNodeIds.add(node.id);
          }
        }
      }
    }
    if (merkleState.tamperedIndices.size > 0 && merkleState.treeData.levels.length > 0) {
      for (let lvl = 0; lvl < merkleState.treeData.levels.length - 1; lvl++) {
        const currentLevelNodes = merkleState.treeData.levels[lvl];
        for (const node of currentLevelNodes) {
          if (merkleState.tamperedNodeIds.has(node.id) && node.parentId) {
            merkleState.tamperedNodeIds.add(node.parentId);
          }
        }
      }
    }
    merkleState.spvAuditData = computeSpvAuditPath(merkleState.transactions, merkleState.spvTargetIndex);
  }
  function renderMerkleUI() {
    renderBlockHeaderStatus();
    renderTransactionsManager();
    renderMerkleTreeDiagram();
    renderSpvAuditCard();
    requestAnimationFrame(() => {
      drawMerkleConnectors();
    });
  }
  function renderBlockHeaderStatus() {
    const rootCompactEl = document.getElementById("merkle-root-compact");
    const rootFullEl = document.getElementById("merkle-root-full");
    const statusBadgeEl = document.getElementById("merkle-status-badge");
    const bannerCard = document.getElementById("merkle-header-status-card");
    const tamperComparisonEl = document.getElementById("merkle-tamper-comparison");
    const storedRootEl = document.getElementById("merkle-stored-root-val");
    const computedRootEl = document.getElementById("merkle-computed-root-val");
    const isTampered = merkleState.currentRoot !== merkleState.storedBlockRoot;
    if (rootCompactEl) {
      rootCompactEl.textContent = formatCompactHash(merkleState.currentRoot);
    }
    if (rootFullEl) {
      rootFullEl.textContent = merkleState.currentRoot;
    }
    if (statusBadgeEl && bannerCard) {
      if (isTampered) {
        statusBadgeEl.className = "merkle-status-badge tampered";
        statusBadgeEl.innerHTML = '<span class="status-dot"></span> TAMPERED BLOCK (Root Mismatch - Block Rejected!)';
        bannerCard.classList.add("tampered");
      } else {
        statusBadgeEl.className = "merkle-status-badge valid";
        statusBadgeEl.innerHTML = '<span class="status-dot"></span> VALID BLOCK HEADER (Merkle Root Matches Consensus)';
        bannerCard.classList.remove("tampered");
      }
    }
    if (tamperComparisonEl) {
      if (isTampered || merkleState.activeMode === "tamper") {
        tamperComparisonEl.style.display = "flex";
        if (storedRootEl) storedRootEl.textContent = merkleState.storedBlockRoot;
        if (computedRootEl) computedRootEl.textContent = merkleState.currentRoot;
      } else {
        tamperComparisonEl.style.display = "none";
      }
    }
  }
  function renderTransactionsManager() {
    const listEl = document.getElementById("merkle-tx-list");
    const oddNoticeEl = document.getElementById("merkle-odd-notice");
    if (!listEl) return;
    const count = merkleState.transactions.length;
    if (oddNoticeEl) {
      if (count % 2 !== 0) {
        oddNoticeEl.style.display = "inline-flex";
        oddNoticeEl.textContent = `Odd Count (${count} Leaves): Duplicating Tx ${count - 1} as per Bitcoin consensus rule`;
      } else {
        oddNoticeEl.style.display = "none";
      }
    }
    let html = "";
    for (let i = 0; i < merkleState.transactions.length; i++) {
      const text = merkleState.transactions[i];
      const isTampered = merkleState.tamperedIndices.has(i);
      const leafHash = hashLeaf(text);
      const isSpvTarget = merkleState.activeMode === "spv" && merkleState.spvTargetIndex === i;
      html += `
      <div class="merkle-tx-item ${isTampered ? "tampered" : ""} ${isSpvTarget ? "spv-target" : ""}">
        <div class="merkle-tx-item-header">
          <span class="merkle-tx-label">Transaction ${i}</span>
          ${isTampered ? '<span class="merkle-badge-tampered">TAMPERED</span>' : ""}
          ${isSpvTarget ? '<span class="merkle-badge-spv">SPV TARGET</span>' : ""}
          <span class="merkle-tx-hash-badge" title="SHA-256(Tx ${i}): ${leafHash}">
            H${i}: <code>${formatCompactHash(leafHash)}</code>
          </span>
        </div>
        <div class="merkle-tx-input-row">
          <input type="text" class="merkle-tx-input ${isTampered ? "tampered" : ""}"
                 value="${escapeHtml(text)}"
                 data-index="${i}"
                 oninput="window.onMerkleTxInputChange(${i}, this.value)"
                 placeholder="e.g. Alice -> Bob 1.0 BTC">
          <button class="p2a-copy-icon-btn" onclick="window.copyMerkleHash('${leafHash}')" title="Copy Leaf Hash">
            \u{1F4CB}
          </button>
        </div>
      </div>
    `;
    }
    listEl.innerHTML = html;
  }
  function renderMerkleTreeDiagram() {
    const treeContainer = document.getElementById("merkle-tree-nodes-container");
    if (!treeContainer || !merkleState.treeData) return;
    const levels = merkleState.treeData.levels;
    if (levels.length === 0) {
      treeContainer.innerHTML = '<div class="merkle-empty-tree">No transactions in tree</div>';
      return;
    }
    const spvSiblingIds = /* @__PURE__ */ new Set();
    if (merkleState.activeMode === "spv" && merkleState.spvAuditData) {
      for (const item of merkleState.spvAuditData.auditPath) {
        spvSiblingIds.add(item.siblingId);
      }
    }
    let html = "";
    for (let lvl = levels.length - 1; lvl >= 0; lvl--) {
      if (lvl > merkleState.stepLevel) {
        continue;
      }
      const levelNodes = levels[lvl];
      const isRootLevel = lvl === levels.length - 1;
      const isLeafLevel = lvl === 0;
      let levelTitle = isRootLevel ? "Merkle Root" : isLeafLevel ? "Level 0: Leaf Hashes" : `Level ${lvl}: Branch Hashes`;
      html += `
      <div class="merkle-tree-level-row" data-level="${lvl}">
        <div class="merkle-level-label-pill">${levelTitle}</div>
        <div class="merkle-level-nodes-group">
    `;
      for (const node of levelNodes) {
        const isTampered = merkleState.tamperedNodeIds.has(node.id);
        const isSpvTargetLeaf = merkleState.activeMode === "spv" && lvl === 0 && node.index === merkleState.spvTargetIndex;
        const isSpvSibling = spvSiblingIds.has(node.id);
        const isSpvDimmed = merkleState.activeMode === "spv" && !isSpvTargetLeaf && !isSpvSibling && !isRootLevel;
        let cardClass = "merkle-node-card";
        if (isRootLevel) cardClass += " root-node";
        if (isLeafLevel) cardClass += " leaf-node";
        if (isTampered) cardClass += " tampered";
        if (isSpvTargetLeaf) cardClass += " spv-target-node";
        if (isSpvSibling) cardClass += " spv-sibling-node";
        if (isSpvDimmed) cardClass += " spv-dimmed";
        if (node.isDuplicated) cardClass += " duplicated-node";
        html += `
        <div class="${cardClass}" id="${node.id}" data-level="${lvl}" data-index="${node.index}">
          <div class="merkle-node-top">
            <span class="merkle-node-tag">${escapeHtml(node.label)}</span>
            ${node.isDuplicated ? '<span class="merkle-node-dup-badge">DUP</span>' : ""}
            ${isTampered ? '<span class="merkle-node-tamper-badge">TAMPERED</span>' : ""}
            ${isSpvTargetLeaf ? '<span class="merkle-node-spv-badge">TARGET</span>' : ""}
            ${isSpvSibling ? '<span class="merkle-node-spv-badge sibling">SPV SIBLING</span>' : ""}
          </div>
          <div class="merkle-node-hash-box" title="Full SHA-256 Hash:
${node.hash}">
            <code class="merkle-node-hash">${node.shortHash}</code>
            <button class="p2a-copy-icon-btn small" onclick="window.copyMerkleHash('${node.hash}')" title="Copy Full Hash">
              \u{1F4CB}
            </button>
          </div>
          ${node.txText ? `<div class="merkle-node-tx-snippet">${escapeHtml(node.txText)}</div>` : ""}
        </div>
      `;
      }
      html += `
        </div>
      </div>
    `;
    }
    treeContainer.innerHTML = html;
  }
  function drawMerkleConnectors() {
    const svg = document.getElementById("merkle-svg-canvas");
    const treeContainer = document.getElementById("merkle-tree-nodes-container");
    if (!svg || !treeContainer || !merkleState.treeData) return;
    const containerRect = treeContainer.getBoundingClientRect();
    svg.setAttribute("width", containerRect.width);
    svg.setAttribute("height", containerRect.height);
    let pathsHtml = "";
    const levels = merkleState.treeData.levels;
    for (let lvl = 0; lvl < levels.length - 1; lvl++) {
      if (lvl + 1 > merkleState.stepLevel) continue;
      const currentNodes = levels[lvl];
      for (const node of currentNodes) {
        if (!node.parentId) continue;
        const childEl = document.getElementById(node.id);
        const parentEl = document.getElementById(node.parentId);
        if (!childEl || !parentEl) continue;
        const childRect = childEl.getBoundingClientRect();
        const parentRect = parentEl.getBoundingClientRect();
        const startX = childRect.left + childRect.width / 2 - containerRect.left;
        const startY = childRect.top - containerRect.top;
        const endX = parentRect.left + parentRect.width / 2 - containerRect.left;
        const endY = parentRect.bottom - containerRect.top;
        const midY = (startY + endY) / 2;
        const pathData = `M ${startX} ${startY} C ${startX} ${midY}, ${endX} ${midY}, ${endX} ${endY}`;
        const isTampered = merkleState.tamperedNodeIds.has(node.id) || merkleState.tamperedNodeIds.has(node.parentId);
        const isSpvActive = merkleState.activeMode === "spv" && (childEl.classList.contains("spv-target-node") || childEl.classList.contains("spv-sibling-node"));
        let strokeColor = "#CBD5E1";
        let strokeWidth = 2;
        let strokeDash = "none";
        if (isTampered) {
          strokeColor = "#EF4444";
          strokeWidth = 2.5;
        } else if (isSpvActive) {
          strokeColor = "#001CE0";
          strokeWidth = 3;
          strokeDash = "4,4";
        }
        pathsHtml += `
        <path d="${pathData}" fill="none" stroke="${strokeColor}" stroke-width="${strokeWidth}" stroke-dasharray="${strokeDash}" stroke-linecap="round" />
      `;
      }
    }
    svg.innerHTML = pathsHtml;
  }
  function renderSpvAuditCard() {
    const spvCard = document.getElementById("merkle-spv-card");
    if (!spvCard) return;
    const targetSelector = document.getElementById("merkle-spv-target-select");
    if (targetSelector) {
      let optionsHtml = "";
      for (let i = 0; i < merkleState.transactions.length; i++) {
        const isSelected = i === merkleState.spvTargetIndex ? "selected" : "";
        optionsHtml += `<option value="${i}" ${isSelected}>Tx ${i}: ${escapeHtml(merkleState.transactions[i].slice(0, 24))}...</option>`;
      }
      targetSelector.innerHTML = optionsHtml;
    }
    const proofStepsContainer = document.getElementById("merkle-spv-steps-container");
    if (!proofStepsContainer || !merkleState.spvAuditData) return;
    const audit = merkleState.spvAuditData;
    const targetHash = audit.targetLeafHash;
    const auditPath = audit.auditPath;
    let stepsHtml = `
    <div class="merkle-spv-step-item completed">
      <span class="merkle-spv-num">1</span>
      <div class="merkle-spv-desc">
        <b>Target Transaction:</b> ${escapeHtml(audit.targetTxText)}<br>
        Leaf Hash: <code>H${audit.targetIndex} = ${formatCompactHash(targetHash)}</code>
      </div>
    </div>
  `;
    let currentHash = targetHash;
    for (let i = 0; i < auditPath.length; i++) {
      const item = auditPath[i];
      const isStepDone = merkleState.spvCurrentStep > i;
      const isStepActive = merkleState.spvCurrentStep === i;
      let combinedHash = "";
      if (item.isSiblingOnRight) {
        combinedHash = hashPair(currentHash, item.siblingHash);
      } else {
        combinedHash = hashPair(item.siblingHash, currentHash);
      }
      stepsHtml += `
      <div class="merkle-spv-step-item ${isStepDone ? "completed" : isStepActive ? "active" : ""}">
        <span class="merkle-spv-num">${i + 2}</span>
        <div class="merkle-spv-desc">
          Combine with Sibling <b>${item.siblingLabel}</b> (${item.isSiblingOnRight ? "on right" : "on left"}):<br>
          <code>${item.isSiblingOnRight ? "Hash(Current + " + item.siblingLabel + ")" : "Hash(" + item.siblingLabel + " + Current)"}</code><br>
          ${isStepDone ? `<span class="spv-result-chip">Result = <code>${formatCompactHash(combinedHash)}</code></span>` : '<span class="spv-pending-chip">Pending</span>'}
        </div>
      </div>
    `;
      currentHash = combinedHash;
    }
    const isAllDone = merkleState.spvCurrentStep >= auditPath.length;
    const rootMatches = currentHash === merkleState.storedBlockRoot;
    stepsHtml += `
    <div class="merkle-spv-step-item ${isAllDone ? rootMatches ? "verified" : "failed" : ""}">
      <span class="merkle-spv-num">${auditPath.length + 2}</span>
      <div class="merkle-spv-desc">
        <b>Final Verification against Block Header:</b><br>
        Computed: <code>${formatCompactHash(currentHash)}</code> | Header: <code>${formatCompactHash(merkleState.storedBlockRoot)}</code><br>
        ${isAllDone ? rootMatches ? '<span class="spv-verified-badge">\u2713 CRYPTOGRAPHICALLY PROVEN INCLUDED!</span>' : '<span class="spv-failed-badge">\u2717 PROOF FAILED (Tampered!)</span>' : ""}
      </div>
    </div>
  `;
    proofStepsContainer.innerHTML = stepsHtml;
    const statBanner = document.getElementById("merkle-spv-stat-banner");
    if (statBanner) {
      const totalTxs = merkleState.transactions.length;
      const hashesNeeded = auditPath.length;
      const percentSaved = Math.round((1 - hashesNeeded / totalTxs) * 100);
      statBanner.innerHTML = `
      <b>SPV Efficiency:</b> Verified Tx in <b>${hashesNeeded} sibling hashes</b> instead of downloading all <b>${totalTxs} transactions</b> (${percentSaved}% bandwidth savings!).
    `;
    }
  }
  window.setMerkleMode = function(mode) {
    merkleState.activeMode = mode;
    const btnBuilder = document.getElementById("merkle-mode-builder");
    const btnTamper = document.getElementById("merkle-mode-tamper");
    const btnSpv = document.getElementById("merkle-mode-spv");
    const spvCard = document.getElementById("merkle-spv-card");
    const builderControls = document.getElementById("merkle-builder-controls");
    if (btnBuilder) btnBuilder.classList.toggle("active", mode === "builder");
    if (btnTamper) btnTamper.classList.toggle("active", mode === "tamper");
    if (btnSpv) btnSpv.classList.toggle("active", mode === "spv");
    if (spvCard) spvCard.style.display = mode === "spv" ? "flex" : "none";
    if (builderControls) builderControls.style.display = mode === "builder" ? "flex" : "none";
    if (mode === "builder") {
      merkleState.stepLevel = 999;
    }
    renderMerkleUI();
  };
  window.onMerkleTxInputChange = function(index, newText) {
    if (index >= 0 && index < merkleState.transactions.length) {
      merkleState.transactions[index] = newText;
      recalculateMerkleTree();
      renderMerkleUI();
    }
  };
  window.addMerkleTx = function() {
    const nextIdx = merkleState.transactions.length;
    merkleState.transactions.push(`Tx ${nextIdx}: User -> Node 1.0 BTC`);
    merkleState.stepLevel = 999;
    recalculateMerkleTree();
    renderMerkleUI();
  };
  window.removeMerkleTx = function() {
    if (merkleState.transactions.length > 2) {
      merkleState.transactions.pop();
      merkleState.stepLevel = 999;
      recalculateMerkleTree();
      renderMerkleUI();
    }
  };
  window.resetMerkleTransactions = function() {
    merkleState.transactions = [...DEFAULT_TRANSACTIONS];
    merkleState.stepLevel = 999;
    recalculateMerkleTree();
    renderMerkleUI();
  };
  window.tamperExampleTx = function(index = 2) {
    if (index >= 0 && index < merkleState.transactions.length) {
      window.setMerkleMode("tamper");
      merkleState.transactions[index] = "Tx 2: Eve -> Frank 999.0 BTC [TAMPERED]";
      recalculateMerkleTree();
      renderMerkleUI();
    }
  };
  window.restoreMerkleOriginal = function() {
    merkleState.transactions = [...merkleState.originalTransactions];
    recalculateMerkleTree();
    renderMerkleUI();
  };
  window.merkleStepNext = function() {
    if (merkleState.stepLevel === 999 || merkleState.stepLevel >= merkleState.maxLevels - 1) {
      merkleState.stepLevel = 0;
    } else {
      merkleState.stepLevel++;
    }
    renderMerkleUI();
  };
  window.merkleBuildFull = function() {
    merkleState.stepLevel = 999;
    renderMerkleUI();
  };
  window.merkleResetSteps = function() {
    merkleState.stepLevel = 0;
    renderMerkleUI();
  };
  window.setSpvTarget = function(targetIndex) {
    merkleState.spvTargetIndex = parseInt(targetIndex, 10) || 0;
    merkleState.spvCurrentStep = 0;
    recalculateMerkleTree();
    renderMerkleUI();
  };
  window.nextSpvStep = function() {
    if (merkleState.spvAuditData) {
      if (merkleState.spvCurrentStep < merkleState.spvAuditData.auditPath.length) {
        merkleState.spvCurrentStep++;
      } else {
        merkleState.spvCurrentStep = 0;
      }
      renderMerkleUI();
    }
  };
  window.resetSpvStep = function() {
    merkleState.spvCurrentStep = 0;
    renderMerkleUI();
  };
  window.copyMerkleHash = function(hashHex) {
    if (window.copyText) {
      window.copyText(hashHex, "Merkle Hash");
    } else if (navigator.clipboard) {
      navigator.clipboard.writeText(hashHex);
    }
  };
  function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }

  // app.js
  var state = {
    alice: null,
    bob: null,
    revealedKeys: {
      alice: false,
      bob: false
    },
    soundEnabled: true,
    activeSender: "ALICE",
    activeRecipient: "BOB",
    currentEncryption: null,
    pendingTransmissions: {
      ALICE: [],
      BOB: []
    },
    history: [],
    contextMenuTarget: null
  };
  var SoundController = class {
    constructor() {
      this.ctx = null;
    }
    init() {
      if (!this.ctx && (window.AudioContext || window.webkitAudioContext)) {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        this.ctx = new AudioCtx();
      }
      if (this.ctx && this.ctx.state === "suspended") {
        this.ctx.resume();
      }
    }
    playClick() {
      if (!state.soundEnabled) return;
      this.init();
      if (!this.ctx) return;
      try {
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = "sine";
        osc.frequency.setValueAtTime(800, this.ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(400, this.ctx.currentTime + 0.04);
        gain.gain.setValueAtTime(0.12, this.ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(1e-3, this.ctx.currentTime + 0.04);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start();
        osc.stop(this.ctx.currentTime + 0.04);
      } catch (e) {
      }
    }
    playLock() {
      if (!state.soundEnabled) return;
      this.init();
      if (!this.ctx) return;
      try {
        const now = this.ctx.currentTime;
        const osc1 = this.ctx.createOscillator();
        const osc2 = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc1.type = "triangle";
        osc2.type = "sine";
        osc1.frequency.setValueAtTime(520, now);
        osc1.frequency.exponentialRampToValueAtTime(780, now + 0.09);
        osc2.frequency.setValueAtTime(1040, now);
        osc2.frequency.exponentialRampToValueAtTime(1560, now + 0.09);
        gain.gain.setValueAtTime(0.15, now);
        gain.gain.exponentialRampToValueAtTime(1e-3, now + 0.12);
        osc1.connect(gain);
        osc2.connect(gain);
        gain.connect(this.ctx.destination);
        osc1.start(now);
        osc2.start(now);
        osc1.stop(now + 0.12);
        osc2.stop(now + 0.12);
      } catch (e) {
      }
    }
    playWhoosh() {
      if (!state.soundEnabled) return;
      this.init();
      if (!this.ctx) return;
      try {
        const now = this.ctx.currentTime;
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = "sine";
        osc.frequency.setValueAtTime(320, now);
        osc.frequency.exponentialRampToValueAtTime(640, now + 0.25);
        gain.gain.setValueAtTime(0.1, now);
        gain.gain.linearRampToValueAtTime(0.18, now + 0.12);
        gain.gain.exponentialRampToValueAtTime(1e-3, now + 0.35);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start(now);
        osc.stop(now + 0.35);
      } catch (e) {
      }
    }
    playSuccessChime() {
      if (!state.soundEnabled) return;
      this.init();
      if (!this.ctx) return;
      try {
        const notes = [523.25, 659.25, 783.99, 1046.5];
        notes.forEach((freq, i) => {
          const osc = this.ctx.createOscillator();
          const gain = this.ctx.createGain();
          const start = this.ctx.currentTime + i * 0.08;
          osc.type = "sine";
          osc.frequency.setValueAtTime(freq, start);
          gain.gain.setValueAtTime(0.12, start);
          gain.gain.exponentialRampToValueAtTime(1e-3, start + 0.35);
          osc.connect(gain);
          gain.connect(this.ctx.destination);
          osc.start(start);
          osc.stop(start + 0.35);
        });
      } catch (e) {
      }
    }
  };
  var sound = new SoundController();
  function initIdentities() {
    state.alice = createIdentity("ALICE");
    state.bob = createIdentity("BOB");
    renderIdentities();
  }
  function renderIdentities() {
    const alicePubEl = document.getElementById("alice-pubkey");
    const alicePrivEl = document.getElementById("alice-privkey");
    if (alicePubEl && state.alice) {
      alicePubEl.textContent = state.alice.publicKeyCompressed;
      alicePubEl.title = `Full Uncompressed:
${state.alice.publicKeyUncompressed}`;
    }
    if (alicePrivEl && state.alice) {
      if (state.revealedKeys.alice) {
        alicePrivEl.textContent = state.alice.privateKeyHex;
        alicePrivEl.classList.remove("masked");
      } else {
        alicePrivEl.textContent = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";
        alicePrivEl.classList.add("masked");
      }
    }
    const bobPubEl = document.getElementById("bob-pubkey");
    const bobPrivEl = document.getElementById("bob-privkey");
    if (bobPubEl && state.bob) {
      bobPubEl.textContent = state.bob.publicKeyCompressed;
      bobPubEl.title = `Full Uncompressed:
${state.bob.publicKeyUncompressed}`;
    }
    if (bobPrivEl && state.bob) {
      if (state.revealedKeys.bob) {
        bobPrivEl.textContent = state.bob.privateKeyHex;
        bobPrivEl.classList.remove("masked");
      } else {
        bobPrivEl.textContent = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";
        bobPrivEl.classList.add("masked");
      }
    }
    updateEyeIcons();
  }
  function updateEyeIcons() {
    const aliceEyeBtn = document.getElementById("alice-eye-btn");
    const bobEyeBtn = document.getElementById("bob-eye-btn");
    const eyeOpenSvg = `<svg class="eye-svg" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
    const eyeSlashedSvg = `<svg class="eye-svg" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`;
    if (aliceEyeBtn) {
      aliceEyeBtn.innerHTML = state.revealedKeys.alice ? eyeOpenSvg : eyeSlashedSvg;
      aliceEyeBtn.title = state.revealedKeys.alice ? "Hide private key" : "Reveal private key";
    }
    if (bobEyeBtn) {
      bobEyeBtn.innerHTML = state.revealedKeys.bob ? eyeOpenSvg : eyeSlashedSvg;
      bobEyeBtn.title = state.revealedKeys.bob ? "Hide private key" : "Reveal private key";
    }
  }
  function togglePrivateKeyReveal(character) {
    const char = character.toLowerCase();
    state.revealedKeys[char] = !state.revealedKeys[char];
    renderIdentities();
    sound.playClick();
  }
  function showAlert(message) {
    const alertEl = document.getElementById("floating-alert");
    const alertText = document.getElementById("alert-text");
    if (!alertEl || !alertText) return;
    alertText.textContent = message;
    alertEl.classList.add("active");
    clearTimeout(alertEl._timeout);
    alertEl._timeout = setTimeout(() => {
      alertEl.classList.remove("active");
    }, 2600);
  }
  window.copyText = function(text, label = "Key") {
    navigator.clipboard.writeText(text).then(() => {
      showAlert(`Copied ${label} to clipboard`);
      sound.playClick();
    }).catch(() => {
      showAlert(`Failed to copy`);
    });
  };
  function setupContextMenu() {
    const menu = document.getElementById("custom-context-menu");
    const aliceUnit = document.getElementById("alice-unit");
    const bobUnit = document.getElementById("bob-unit");
    function handleContextMenu(e, character) {
      e.preventDefault();
      sound.playClick();
      state.contextMenuTarget = character;
      const menuWidth = 220;
      const menuHeight = 140;
      let posX = e.clientX;
      let posY = e.clientY;
      if (posX + menuWidth > window.innerWidth) {
        posX = window.innerWidth - menuWidth - 16;
      }
      if (posY + menuHeight > window.innerHeight) {
        posY = window.innerHeight - menuHeight - 16;
      }
      menu.style.left = `${posX}px`;
      menu.style.top = `${posY}px`;
      menu.style.display = "flex";
      const titleEl = document.getElementById("context-menu-target-name");
      if (titleEl) titleEl.textContent = character;
    }
    if (aliceUnit) {
      aliceUnit.addEventListener("contextmenu", (e) => handleContextMenu(e, "ALICE"));
    }
    if (bobUnit) {
      bobUnit.addEventListener("contextmenu", (e) => handleContextMenu(e, "BOB"));
    }
    window.addEventListener("click", (e) => {
      if (!menu.contains(e.target)) {
        menu.style.display = "none";
      }
    });
    window.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        menu.style.display = "none";
        closeComposeDialog();
        closeMathModal();
      }
    });
  }
  window.onContextMenuSend = function() {
    const menu = document.getElementById("custom-context-menu");
    menu.style.display = "none";
    if (state.contextMenuTarget) {
      openComposeDialog(state.contextMenuTarget);
    }
  };
  window.onContextMenuCopyPub = function() {
    const menu = document.getElementById("custom-context-menu");
    menu.style.display = "none";
    if (state.contextMenuTarget) {
      const ident = state.contextMenuTarget === "ALICE" ? state.alice : state.bob;
      copyText(ident.publicKeyCompressed, `${state.contextMenuTarget} Public Key`);
    }
  };
  window.openComposeDialog = function(senderName) {
    state.activeSender = senderName.toUpperCase();
    state.activeRecipient = state.activeSender === "ALICE" ? "BOB" : "ALICE";
    state.currentEncryption = null;
    const stage = document.getElementById("inline-messaging-stage");
    const senderBadge = document.getElementById("compose-sender-badge");
    const pubkeyInput = document.getElementById("recipient-pubkey-input");
    const statusEl = document.getElementById("recipient-key-status");
    const msgInput = document.getElementById("compose-message-input");
    const encryptResultBox = document.getElementById("encrypted-standalone-box");
    const lockBtn = document.getElementById("lock-encrypt-btn");
    if (senderBadge) {
      senderBadge.innerHTML = `Envelope from <b>${state.activeSender}</b>`;
    }
    if (pubkeyInput) {
      pubkeyInput.value = "";
      pubkeyInput.focus();
    }
    if (statusEl) {
      const targetName = state.activeRecipient;
      statusEl.className = "recipient-key-status";
      statusEl.innerHTML = `Copy ${targetName}'s public key above (click \u{1F4CB}) and paste it here`;
    }
    if (encryptResultBox) encryptResultBox.style.display = "none";
    if (lockBtn) {
      lockBtn.disabled = false;
      lockBtn.innerHTML = `<span>Encrypt Message</span>`;
    }
    if (msgInput && !msgInput.value.trim()) {
      msgInput.value = state.activeSender === "ALICE" ? `Hey Bob! Here is the secret Bitcoin seed: 5 BTC transfer authorized` : `Alice, I received your public key. Confirming transaction hash`;
    }
    if (stage) {
      stage.style.display = "flex";
      stage.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
    sound.playClick();
    startConnectorLineAnimation();
  };
  window.closeComposeDialog = function() {
    const stage = document.getElementById("inline-messaging-stage");
    if (stage) stage.style.display = "none";
    stopConnectorLineAnimation();
    clearConnectorLine();
    sound.playClick();
  };
  window.setQuickMessage = function(text) {
    const msgInput = document.getElementById("compose-message-input");
    if (msgInput) {
      msgInput.value = text;
      sound.playClick();
    }
  };
  window.pasteRecipientKey = async function() {
    const input = document.getElementById("recipient-pubkey-input");
    if (!input) return;
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        input.value = text.trim();
        validateRecipientKeyInput();
        showAlert("Pasted public key from clipboard");
        sound.playClick();
        return;
      }
    } catch (err) {
    }
    const targetObj = state.activeRecipient === "ALICE" ? state.alice : state.bob;
    input.value = targetObj.publicKeyCompressed;
    validateRecipientKeyInput();
    showAlert(`Filled with ${state.activeRecipient}'s public key`);
    sound.playClick();
  };
  function validateRecipientKeyInput() {
    const input = document.getElementById("recipient-pubkey-input");
    const statusEl = document.getElementById("recipient-key-status");
    if (!input || !statusEl) return null;
    const hex = input.value.trim().toLowerCase();
    if (!hex) {
      statusEl.className = "recipient-key-status";
      statusEl.textContent = `Copy the public key from the receiver's card (click \u{1F4CB}) and paste it here`;
      return null;
    }
    if (hex.length !== 66 || !hex.startsWith("02") && !hex.startsWith("03")) {
      statusEl.className = "recipient-key-status error";
      statusEl.textContent = "Invalid format: must be 66 hex characters starting with 02 or 03";
      return null;
    }
    try {
      const pt = decompressPublicKey(hex);
      if (state.bob && hex === state.bob.publicKeyCompressed.toLowerCase()) {
        statusEl.className = "recipient-key-status valid";
        statusEl.textContent = "Verified Receiver: BOB (secp256k1 point verified)";
        state.activeRecipient = "BOB";
      } else if (state.alice && hex === state.alice.publicKeyCompressed.toLowerCase()) {
        statusEl.className = "recipient-key-status valid";
        statusEl.textContent = "Verified Receiver: ALICE (secp256k1 point verified)";
        state.activeRecipient = "ALICE";
      } else {
        statusEl.className = "recipient-key-status valid";
        statusEl.textContent = "Valid external secp256k1 public key";
      }
      return pt;
    } catch (err) {
      statusEl.className = "recipient-key-status error";
      statusEl.textContent = "Invalid curve point: does not lie on y\xB2 \u2261 x\xB3 + 7";
      return null;
    }
  }
  var connectorAnimFrame = null;
  function updateConnectorLine() {
    const stage = document.getElementById("inline-messaging-stage");
    if (!stage || stage.style.display === "none") {
      clearConnectorLine();
      return;
    }
    const senderUnitId = state.activeSender === "ALICE" ? "alice-avatar-frame" : "bob-avatar-frame";
    const senderEl = document.getElementById(senderUnitId);
    const envelopeBadge = document.getElementById("compose-envelope-badge");
    const pathEl = document.getElementById("connector-path");
    const startDot = document.getElementById("connector-start-dot");
    const endDot = document.getElementById("connector-end-dot");
    if (!senderEl || !envelopeBadge || !pathEl) return;
    const senderRect = senderEl.getBoundingClientRect();
    const envRect = envelopeBadge.getBoundingClientRect();
    const x1 = senderRect.left + senderRect.width / 2;
    const y1 = senderRect.top + senderRect.height / 2;
    const x2 = envRect.left + envRect.width / 2;
    const y2 = envRect.top + envRect.height / 2;
    const midX = (x1 + x2) / 2;
    const d = `M ${x1} ${y1} C ${midX} ${y1 - 30}, ${midX} ${y2 - 15}, ${x2} ${y2}`;
    pathEl.setAttribute("d", d);
    if (startDot) {
      startDot.setAttribute("cx", x1);
      startDot.setAttribute("cy", y1);
      startDot.style.display = "block";
    }
    if (endDot) {
      endDot.setAttribute("cx", x2);
      endDot.setAttribute("cy", y2);
      endDot.style.display = "block";
    }
  }
  function startConnectorLineAnimation() {
    function loop() {
      updateConnectorLine();
      connectorAnimFrame = requestAnimationFrame(loop);
    }
    loop();
  }
  function stopConnectorLineAnimation() {
    if (connectorAnimFrame) {
      cancelAnimationFrame(connectorAnimFrame);
      connectorAnimFrame = null;
    }
  }
  function clearConnectorLine() {
    const pathEl = document.getElementById("connector-path");
    const startDot = document.getElementById("connector-start-dot");
    const endDot = document.getElementById("connector-end-dot");
    if (pathEl) pathEl.setAttribute("d", "");
    if (startDot) startDot.style.display = "none";
    if (endDot) endDot.style.display = "none";
  }
  window.handleEncryptClick = async function() {
    const msgInput = document.getElementById("compose-message-input");
    const plaintext = msgInput ? msgInput.value.trim() : "";
    if (!plaintext) {
      showAlert("Please enter a message to encrypt");
      return;
    }
    const recipientPt = validateRecipientKeyInput();
    if (!recipientPt) {
      showAlert("Please paste the receiver public key first");
      const input = document.getElementById("recipient-pubkey-input");
      if (input) input.focus();
      return;
    }
    const lockBtn = document.getElementById("lock-encrypt-btn");
    if (lockBtn) {
      lockBtn.disabled = true;
      lockBtn.innerHTML = `<span>Computing secp256k1 Point...</span>`;
    }
    sound.playLock();
    try {
      const inputHex = document.getElementById("recipient-pubkey-input").value.trim();
      const encryptionResult = await encryptECIES(plaintext, recipientPt);
      state.currentEncryption = {
        ...encryptionResult,
        plaintext,
        recipientPublicKeyHex: inputHex,
        sender: state.activeSender,
        recipient: state.activeRecipient,
        timestamp: (/* @__PURE__ */ new Date()).toLocaleTimeString()
      };
      const encryptResultBox = document.getElementById("encrypted-standalone-box");
      const cipherDisplay = document.getElementById("encrypted-ciphertext-display");
      const ephemeralKeyDisplay = document.getElementById("encrypted-ephemeral-key");
      const sharedSecretDisplay = document.getElementById("encrypted-shared-secret");
      if (cipherDisplay) cipherDisplay.textContent = encryptionResult.ciphertextHex;
      if (ephemeralKeyDisplay) ephemeralKeyDisplay.textContent = encryptionResult.ephemeralPublicHex;
      if (sharedSecretDisplay) sharedSecretDisplay.textContent = encryptionResult.sharedSecretX;
      if (encryptResultBox) {
        encryptResultBox.style.display = "flex";
        encryptResultBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
      if (lockBtn) {
        lockBtn.disabled = false;
        lockBtn.innerHTML = `<span>Re-Encrypt</span>`;
      }
      showAlert("Message encrypted with Bitcoin curve formula");
    } catch (err) {
      console.error("Encryption error:", err);
      showAlert("Encryption failed: " + err.message);
      if (lockBtn) {
        lockBtn.disabled = false;
        lockBtn.innerHTML = `<span>Encrypt Message</span>`;
      }
    }
  };
  window.handleSendClick = function() {
    if (!state.currentEncryption) {
      showAlert("Please encrypt the message first");
      return;
    }
    closeComposeDialog();
    sound.playWhoosh();
    const flyingNode = document.createElement("div");
    flyingNode.className = "flying-envelope-node";
    flyingNode.innerHTML = `<span style="font-weight:800; font-size:12px; color:var(--color-blue);">ENV</span>`;
    document.body.appendChild(flyingNode);
    const senderAvatarId = state.activeSender === "ALICE" ? "alice-avatar-frame" : "bob-avatar-frame";
    const recipientAvatarId = state.activeRecipient === "ALICE" ? "alice-avatar-frame" : "bob-avatar-frame";
    const senderEl = document.getElementById(senderAvatarId);
    const recipientEl = document.getElementById(recipientAvatarId);
    const startRect = senderEl.getBoundingClientRect();
    const endRect = recipientEl.getBoundingClientRect();
    const startX = startRect.left + startRect.width / 2;
    const startY = startRect.top + startRect.height / 2;
    const targetX = endRect.left + endRect.width / 2;
    const targetY = endRect.top + endRect.height / 2;
    flyingNode.style.left = `${startX}px`;
    flyingNode.style.top = `${startY}px`;
    const wireBadge = document.getElementById("wire-transit-badge");
    if (wireBadge) {
      wireBadge.classList.add("active");
      wireBadge.innerHTML = `Ciphertext In Transit: <b style="font-family:monospace; color:var(--color-blue);">${state.currentEncryption.ciphertextHex.slice(0, 16)}...</b>`;
    }
    const duration = 1200;
    const startTime = performance.now();
    function animateFlight(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const ease = progress < 0.5 ? 2 * progress * progress : -1 + (4 - 2 * progress) * progress;
      const currentX = startX + (targetX - startX) * ease;
      const arch = Math.sin(progress * Math.PI) * -70;
      const currentY = startY + (targetY - startY) * ease + arch;
      flyingNode.style.left = `${currentX}px`;
      flyingNode.style.top = `${currentY}px`;
      if (progress < 1) {
        requestAnimationFrame(animateFlight);
      } else {
        flyingNode.remove();
        if (wireBadge) {
          wireBadge.classList.remove("active");
          wireBadge.innerHTML = `Public Wire: Eavesdropper (Eve) only sees scrambled ciphertext`;
        }
        onMessageArrivedAtReceiver();
      }
    }
    requestAnimationFrame(animateFlight);
  };
  function onMessageArrivedAtReceiver() {
    sound.playClick();
    const receiverName = state.activeRecipient;
    const containerId = receiverName === "ALICE" ? "alice-incoming-container" : "bob-incoming-container";
    const container = document.getElementById(containerId);
    if (!container) return;
    const enc = state.currentEncryption;
    const transmissionId = "msg_" + Date.now();
    state.pendingTransmissions[receiverName].push({ id: transmissionId, data: enc });
    const incomingCard = document.createElement("div");
    incomingCard.className = "incoming-encrypted-card";
    incomingCard.id = transmissionId;
    incomingCard.innerHTML = `
    <div class="incoming-card-header">
      <span>Incoming Encrypted Message</span>
      <button class="key-btn" onclick="document.getElementById('${transmissionId}').remove()" title="Dismiss">\u2715</button>
    </div>
    <div class="incoming-card-hint">
      From <b>${enc.sender}</b> \u2022 Encrypted with ${receiverName}'s public key Q
    </div>
    <div class="cipher-mini-box" title="Ciphertext:
${enc.ciphertextHex}">
      ${enc.ciphertextHex}
    </div>
    <div class="incoming-card-hint">
      Only ${receiverName}'s secret private key <b>d</b> can compute <b>S = d \xB7 R</b> to decrypt this ciphertext.
    </div>
    <div style="display:flex; justify-content:flex-end;">
      <button class="photo2-pill-btn primary small" onclick="decryptReceivedMessage('${receiverName}', '${transmissionId}')">
        Decrypt with ${receiverName}'s Private Key (d)
      </button>
    </div>
  `;
    container.prepend(incomingCard);
    showAlert(`Encrypted message arrived at ${receiverName}`);
  }
  window.decryptReceivedMessage = async function(receiverName, transmissionId) {
    const pending = state.pendingTransmissions[receiverName].find((p) => p.id === transmissionId);
    const enc = pending ? pending.data : state.currentEncryption;
    if (!enc) return;
    const receiverIdentity = receiverName === "ALICE" ? state.alice : state.bob;
    let plaintext = "";
    try {
      plaintext = await decryptECIES(enc.payload, receiverIdentity.privateKey);
    } catch (err) {
      console.error("Decryption failed:", err);
      plaintext = "[Decryption failed: signature mismatch]";
    }
    sound.playSuccessChime();
    const card = document.getElementById(transmissionId);
    if (card) {
      card.innerHTML = `
      <div class="incoming-card-header">
        <span>Decrypted by ${receiverName}</span>
        <button class="key-btn" onclick="document.getElementById('${transmissionId}').remove()" title="Dismiss">\u2715</button>
      </div>
      <div class="decrypted-result-view">
        <div class="decrypted-result-text">"${plaintext}"</div>
        <div class="decrypted-math-proof">
          Unlocked: S = d \xB7 R = ${enc.sharedSecretX.slice(0, 16)}...
        </div>
      </div>
      <div style="display:flex; justify-content:space-between; align-items:center; margin-top:2px;">
        <span style="font-size:11px; color:#128743; font-weight:700;">Decryption Verified</span>
        <button class="photo2-pill-btn small primary" onclick="openComposeDialog('${receiverName}')">
          Reply
        </button>
      </div>
    `;
    }
    addHistoryItem({
      sender: enc.sender,
      recipient: receiverName,
      plaintext,
      ciphertext: enc.ciphertextHex,
      time: enc.timestamp
    });
    showAlert(`Message decrypted by ${receiverName} using private key`);
  };
  function addHistoryItem(item) {
    state.history.unshift(item);
    const listEl = document.getElementById("history-list");
    const countEl = document.getElementById("history-count");
    if (!listEl) return;
    if (countEl) countEl.textContent = `${state.history.length} messages`;
    const itemEl = document.createElement("div");
    itemEl.className = "history-item";
    itemEl.innerHTML = `
    <div class="history-sender-badge">
      <span>${item.sender}</span>
      <span style="color:var(--text-dim); font-size:11px;">\u2794</span>
      <span>${item.recipient}</span>
    </div>
    <div class="history-msg-content" title="${item.plaintext}">
      "${item.plaintext}"
    </div>
    <div style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted); max-width:140px; overflow:hidden; text-overflow:ellipsis;" title="Ciphertext:
${item.ciphertext}">
      ${item.ciphertext.slice(0, 14)}...
    </div>
    <div class="history-status-tag">Decrypted</div>
  `;
    listEl.prepend(itemEl);
  }
  window.toggleSound = function() {
    state.soundEnabled = !state.soundEnabled;
    const btn = document.getElementById("sound-toggle-btn");
    if (btn) {
      btn.innerHTML = state.soundEnabled ? "Sound: ON" : "Sound: OFF";
    }
    sound.playClick();
  };
  var graphEngine = null;
  window.switchView = function(viewName) {
    const simView = document.getElementById("view-simulator");
    const graphView = document.getElementById("view-graph");
    const addressView = document.getElementById("view-point-address");
    const merkleView = document.getElementById("view-merkle");
    const tabSim = document.getElementById("tab-nav-sim");
    const tabGuide = document.getElementById("nav-guide-btn");
    const tabAddress = document.getElementById("tab-nav-address");
    const tabMerkle = document.getElementById("tab-nav-merkle");
    if (simView) simView.style.display = "none";
    if (graphView) graphView.style.display = "none";
    if (addressView) addressView.style.display = "none";
    if (merkleView) merkleView.style.display = "none";
    if (tabSim) tabSim.classList.remove("active");
    if (tabGuide) tabGuide.classList.remove("active");
    if (tabAddress) tabAddress.classList.remove("active");
    if (tabMerkle) tabMerkle.classList.remove("active");
    if (viewName === "graph") {
      if (graphView) graphView.style.display = "flex";
      if (tabGuide) tabGuide.classList.add("active");
      initGraphEngine();
      setTimeout(() => {
        if (graphEngine) {
          graphEngine.resize();
          graphEngine.render();
        }
      }, 50);
      window.scrollTo({ top: 0, behavior: "smooth" });
      sound.playClick();
    } else if (viewName === "address") {
      if (addressView) addressView.style.display = "flex";
      if (tabAddress) tabAddress.classList.add("active");
      if (graphEngine && graphEngine.isPlaying) {
        graphEngine.stopPlay();
      }
      initAddressGame();
      window.scrollTo({ top: 0, behavior: "smooth" });
      sound.playClick();
    } else if (viewName === "merkle") {
      if (merkleView) merkleView.style.display = "flex";
      if (tabMerkle) tabMerkle.classList.add("active");
      if (graphEngine && graphEngine.isPlaying) {
        graphEngine.stopPlay();
      }
      initMerkleSimulator();
      setTimeout(() => {
        drawMerkleConnectors();
      }, 60);
      window.scrollTo({ top: 0, behavior: "smooth" });
      sound.playClick();
    } else {
      if (simView) simView.style.display = "flex";
      if (tabSim) tabSim.classList.add("active");
      if (graphEngine && graphEngine.isPlaying) {
        graphEngine.stopPlay();
      }
      window.scrollTo({ top: 0, behavior: "smooth" });
      sound.playClick();
    }
  };
  window.toggleGuideView = function() {
    const graphView = document.getElementById("view-graph");
    const isGraphVisible = graphView && graphView.style.display !== "none";
    if (isGraphVisible) {
      window.switchView("simulator");
    } else {
      window.switchView("graph");
    }
  };
  window.openMathModal = function() {
    window.switchView("graph");
  };
  window.closeMathModal = function() {
    window.switchView("simulator");
  };
  function initGraphEngine() {
    const canvas = document.getElementById("desmos-canvas");
    if (!canvas) return;
    if (!graphEngine) {
      graphEngine = new EllipticGraphEngine(canvas, {
        domain: "real",
        a: 0,
        b: 7,
        p: 23,
        xG: -1.5,
        onStateChange: handleGraphStateChange
      });
      window.graphEngine = graphEngine;
    }
  }
  function handleGraphStateChange(stateData) {
    const { domain, p, a, b, xG, currentStep, isPlaying, currentData, discriminant } = stateData;
    const valA = document.getElementById("param-a-value");
    const valB = document.getElementById("param-b-value");
    const valXg = document.getElementById("param-xg-value");
    const sliderA = document.getElementById("param-a-slider");
    const sliderB = document.getElementById("param-b-slider");
    const sliderXg = document.getElementById("param-xg-slider");
    const formulaText = document.getElementById("graph-formula-text");
    const discTag = document.getElementById("graph-discriminant-tag");
    if (valA) valA.textContent = a.toFixed(1);
    if (valB) valB.textContent = b.toFixed(1);
    if (valXg) valXg.textContent = xG.toFixed(1);
    if (sliderA && parseFloat(sliderA.value) !== a) sliderA.value = a;
    if (sliderB && parseFloat(sliderB.value) !== b) sliderB.value = b;
    if (sliderXg && parseFloat(sliderXg.value) !== xG) sliderXg.value = xG;
    if (formulaText) {
      let eq = "y\xB2 \u2261 x\xB3";
      if (a !== 0) eq += ` ${a > 0 ? "+" : "-"} ${Math.abs(a)}x`;
      if (b !== 0) eq += ` ${b > 0 ? "+" : "-"} ${Math.abs(b)}`;
      if (domain === "mod") {
        eq += ` (mod ${p})`;
      } else {
        if (a === 0 && b === 7) eq += " (Bitcoin)";
      }
      formulaText.textContent = eq;
    }
    if (discTag) {
      if (domain === "mod") {
        discTag.textContent = `Finite Field F_${p} \u2022 Discrete Points on Curve`;
        discTag.style.color = "var(--color-blue)";
      } else {
        if (Math.abs(discriminant) < 1e-4) {
          discTag.textContent = "Singular curve (\u0394 = 0, node or cusp)";
          discTag.style.color = "#DC2626";
        } else {
          discTag.textContent = `Non-singular curve (\u0394 = ${Math.round(discriminant)})`;
          discTag.style.color = "var(--text-muted)";
        }
      }
    }
    const stepperBadge = document.getElementById("stepper-badge");
    const privKeyEl = document.getElementById("stepper-private-key");
    const pubPointEl = document.getElementById("stepper-public-point");
    const playBtn = document.getElementById("step-play-btn");
    if (stepperBadge) {
      if (currentStep === 5) {
        stepperBadge.textContent = "Step d = 5 (5G Step)";
      } else {
        stepperBadge.textContent = `Step d = ${currentStep}`;
      }
    }
    if (privKeyEl) {
      privKeyEl.textContent = `d = ${currentStep} (Scalar)`;
    }
    if (pubPointEl) {
      if (currentData && currentData.point) {
        if (domain === "mod") {
          pubPointEl.textContent = `(${currentData.point.x}, ${currentData.point.y}) mod ${p}`;
        } else {
          pubPointEl.textContent = `(${currentData.point.x.toFixed(2)}, ${currentData.point.y.toFixed(2)})`;
        }
      } else {
        pubPointEl.textContent = "Point at Infinity O";
      }
    }
    if (playBtn) {
      playBtn.textContent = isPlaying ? "Pause" : "Auto Play";
    }
    const stepSlider = document.getElementById("stepper-step-slider");
    const stepSliderVal = document.getElementById("stepper-step-slider-val");
    if (stepSlider && parseInt(stepSlider.value, 10) !== currentStep) {
      stepSlider.value = currentStep;
    }
    if (stepSliderVal) {
      stepSliderVal.textContent = `d = ${currentStep}`;
    }
    const mathBreakdown = document.getElementById("step-math-breakdown");
    if (mathBreakdown && currentData) {
      if (domain === "mod") {
        if (currentData.isInfinity) {
          mathBreakdown.innerHTML = `
          <div class="step-math-box" style="border-left: 3px solid #DC2626;">
            <b>Step ${currentStep} (Identity Element):</b> ${currentStep}\xB7G = \u{1D4AA} (Point at Infinity)<br>
            Group Order Reached: The curve forms a finite cyclic group of order ${currentStep}.
          </div>
          <div class="step-crypto-hint">
            <b>Cyclic Wrap-Around:</b> In finite field cryptography, points generate a cyclic subgroup. Adding G to the identity \u{1D4AA} yields G again! Click <b>Next Step (+G)</b> to see the cycle restart.
          </div>
        `;
        } else if (currentStep === 1) {
          mathBreakdown.innerHTML = `
          <div class="step-math-box">
            Base Point G = (${currentData.point.x}, ${currentData.point.y})<br>
            Public Point Q = 1 \xB7 G = (${currentData.point.x}, ${currentData.point.y}) mod ${p}
          </div>
          <div class="step-crypto-hint">
            <b>Finite Field F_${p}:</b> All coordinates are integers in [0, ${p - 1}]. Click <b>Next Step (+G)</b> to compute scalar multiplication modulo ${p}!
          </div>
        `;
        } else if (currentStep === 5 && currentData.intersect) {
          mathBreakdown.innerHTML = `
          <div class="step-math-box" style="border-left: 3px solid #10B981;">
            <b>Step 5:</b> 5\xB7G = 4\xB7G + G (mod ${p})<br>
            Modular slope m = (y_G - y_4) \xB7 (x_G - x_4)\u207B\xB9 mod ${p} = ${currentData.m}<br>
            Intersection -5G = (${currentData.intersect.x}, ${currentData.intersect.y})<br>
            Reflected to +5G = (${currentData.point.x}, ${currentData.point.y}) [since ${p} - ${currentData.intersect.y} = ${currentData.point.y}]
          </div>
          <div class="step-crypto-hint">
            <b>5G Scalar Generation:</b> With private scalar <b>d = 5</b>, the resulting public key point is <b>Q = (${currentData.point.x}, ${currentData.point.y})</b> wrapped inside field F_${p}. Notice how the modular wrap-around prevents points from blowing up to infinity!
          </div>
        `;
        } else if (currentData.isDouble && currentData.intersect) {
          mathBreakdown.innerHTML = `
          <div class="step-math-box">
            <b>Step 2 (Modular Doubling):</b> 2\xB7G = G + G (mod ${p})<br>
            Modular slope m = (3x\u2081\xB2 + a) \xB7 (2y\u2081)\u207B\xB9 mod ${p} = ${currentData.m}<br>
            Intersection -2G = (${currentData.intersect.x}, ${currentData.intersect.y})<br>
            Reflected to +2G = (${currentData.point.x}, ${currentData.point.y})
          </div>
          <div class="step-crypto-hint">
            <b>Modular Doubling:</b> The tangent line wraps around the borders of the field box [0, ${p}] and hits the curve at -2G, which reflects vertically across y = ${p}/2 to yield <b>Q = 2\xB7G</b>.
          </div>
        `;
        } else if (currentData.point) {
          const intDesc = currentData.intersect ? `Intersection -${currentStep}\xB7G = (${currentData.intersect.x}, ${currentData.intersect.y})<br>` : "";
          const slopeDesc = currentData.m !== null ? `Modular slope m = ${currentData.m}<br>` : "";
          mathBreakdown.innerHTML = `
          <div class="step-math-box">
            <b>Step ${currentStep} (Modular Addition):</b> ${currentStep}\xB7G (mod ${p})<br>
            ${slopeDesc}
            ${intDesc}
            Result Public Point Q = (${currentData.point.x}, ${currentData.point.y})
          </div>
          <div class="step-crypto-hint">
            <b>Modular Pseudo-Random Leap:</b> The discrete points jump across the grid in a pseudo-random fashion. This is why deducing scalar <b>d = ${currentStep}</b> from point <b>Q</b> is intractable (ECDLP)!
          </div>
        `;
        }
      } else {
        if (currentData.isInfinity) {
          mathBreakdown.innerHTML = `
          <div class="step-math-box" style="border-left: 3px solid #DC2626;">
            <b>Step ${currentStep}:</b> Point at Infinity \u{1D4AA} (Identity Element)
          </div>
        `;
        } else if (currentStep === 1) {
          mathBreakdown.innerHTML = `
          <div class="step-math-box">
            Base Generator Point G = (${currentData.point.x.toFixed(2)}, ${currentData.point.y.toFixed(2)})<br>
            Public Point Q = 1 \xB7 G = (${currentData.point.x.toFixed(2)}, ${currentData.point.y.toFixed(2)})
          </div>
          <div class="step-crypto-hint">
            <b>How it starts:</b> The private key is scalar <b>d = 1</b>. The public key is point <b>Q = 1\xB7G</b> on the curve. Click <b>Next Step (+G)</b> or <b>5G Step</b>!
          </div>
        `;
        } else if (currentStep === 5) {
          mathBreakdown.innerHTML = `
          <div class="step-math-box" style="border-left: 3px solid #10B981;">
            <b>Step 5 (5G Step):</b> 5\xB7G = 4\xB7G + G<br>
            Secant slope m = (y\u2081 - y\u2084) / (x\u2081 - x\u2084) = ${currentData.m.toFixed(3)}<br>
            Intersection -5G = (${currentData.intersect.x.toFixed(2)}, ${currentData.intersect.y.toFixed(2)})<br>
            Reflected to +5G = (${currentData.point.x.toFixed(2)}, ${currentData.point.y.toFixed(2)})
          </div>
          <div class="step-crypto-hint">
            <b>5G Public Point:</b> The private key scalar <b>d = 5</b> produces the public key point <b>Q = 5\xB7G = (${currentData.point.x.toFixed(2)}, ${currentData.point.y.toFixed(2)})</b> through 4 successive point addition & reflection steps.
          </div>
        `;
        } else if (currentData.isDouble) {
          mathBreakdown.innerHTML = `
          <div class="step-math-box">
            <b>Step 2 (Point Doubling):</b> 2\xB7G = G + G<br>
            Tangent slope m = (3x\u2081\xB2 + a) / (2y\u2081) = ${currentData.m.toFixed(3)}<br>
            Intersection -2G = (${currentData.intersect.x.toFixed(2)}, ${currentData.intersect.y.toFixed(2)})<br>
            Reflected to +2G = (${currentData.point.x.toFixed(2)}, ${currentData.point.y.toFixed(2)})
          </div>
          <div class="step-crypto-hint">
            <b>Tangent Doubling:</b> Adding a point to itself draws a tangent line touching the curve at G. The line hits the curve at -2G, which reflects across the X-axis to yield <b>Q = 2\xB7G</b>.
          </div>
        `;
        } else if (currentData.point) {
          mathBreakdown.innerHTML = `
          <div class="step-math-box">
            <b>Step ${currentStep} (Point Addition):</b> ${currentStep}\xB7G = ${currentStep - 1}\xB7G + G<br>
            Secant slope m = (y\u2082 - y\u2081) / (x\u2082 - x\u2081) = ${currentData.m.toFixed(3)}<br>
            Intersection -${currentStep}\xB7G = (${currentData.intersect.x.toFixed(2)}, ${currentData.intersect.y.toFixed(2)})<br>
            Reflected to +${currentStep}\xB7G = (${currentData.point.x.toFixed(2)}, ${currentData.point.y.toFixed(2)})
          </div>
          <div class="step-crypto-hint">
            <b>Asymmetric One-Way Property:</b> Notice how the point jumps across the curve! Knowing <b>d = ${currentStep}</b> easily gives point <b>Q</b>. But looking at <b>Q</b> on the curve, it is computationally impossible to guess how many additions were performed. This is the <b>Discrete Logarithm Problem (ECDLP)</b>!
          </div>
        `;
        } else {
          mathBreakdown.innerHTML = `
          <div class="step-math-box" style="color:#DC2626;">
            Vertical line hit Point at Infinity (Identity element O).
          </div>
        `;
        }
      }
    }
  }
  window.setGraphDomain = function(domain) {
    if (!graphEngine) return;
    graphEngine.setDomain(domain);
    const tabReal = document.getElementById("tab-domain-real");
    const tabMod = document.getElementById("tab-domain-mod");
    const groupXg = document.getElementById("group-param-xg");
    const groupMod = document.getElementById("group-param-mod");
    if (domain === "mod") {
      tabMod?.classList.add("active");
      tabReal?.classList.remove("active");
      if (groupXg) groupXg.style.display = "none";
      if (groupMod) groupMod.style.display = "flex";
    } else {
      tabReal?.classList.add("active");
      tabMod?.classList.remove("active");
      if (groupXg) groupXg.style.display = "flex";
      if (groupMod) groupMod.style.display = "none";
    }
    sound.playClick();
  };
  window.setPrimeMod = function(p) {
    if (!graphEngine) return;
    graphEngine.setPrime(p);
    [17, 23, 43, 67].forEach((prime) => {
      const btn = document.getElementById(`prime-btn-${prime}`);
      if (btn) {
        if (prime === p) btn.classList.add("primary");
        else btn.classList.remove("primary");
      }
    });
    const valEl = document.getElementById("param-mod-value");
    if (valEl) valEl.textContent = `p = ${p}`;
    sound.playClick();
  };
  window.setStepperStep = function(val) {
    if (!graphEngine) return;
    graphEngine.setStep(parseInt(val, 10));
    sound?.playClick();
  };
  window.updateParamA = function(val) {
    if (graphEngine) {
      graphEngine.setParameters(val, graphEngine.b);
    }
  };
  window.updateParamB = function(val) {
    if (graphEngine) {
      graphEngine.setParameters(graphEngine.a, val);
    }
  };
  window.updateBasePointX = function(val) {
    if (graphEngine) {
      graphEngine.setBasePointX(val);
    }
  };
  window.setPresetBitcoin = function() {
    if (graphEngine) {
      graphEngine.setBitcoinPreset();
      sound.playClick();
    }
  };
  window.setPresetTwoComponents = function() {
    if (graphEngine) {
      graphEngine.setTwoComponentPreset();
      sound.playClick();
    }
  };
  window.stepNext = function() {
    if (graphEngine) {
      graphEngine.nextStep();
      sound.playClick();
    }
  };
  window.stepPrevious = function() {
    if (graphEngine) {
      graphEngine.prevStep();
      sound.playClick();
    }
  };
  window.resetSteps = function() {
    if (graphEngine) {
      graphEngine.resetStep();
      sound.playClick();
    }
  };
  window.togglePlaySteps = function() {
    if (graphEngine) {
      graphEngine.togglePlay();
      sound.playClick();
    }
  };
  window.addEventListener("DOMContentLoaded", () => {
    initIdentities();
    setupContextMenu();
    const aliceEye = document.getElementById("alice-eye-btn");
    const bobEye = document.getElementById("bob-eye-btn");
    if (aliceEye) aliceEye.addEventListener("click", () => togglePrivateKeyReveal("alice"));
    if (bobEye) bobEye.addEventListener("click", () => togglePrivateKeyReveal("bob"));
    const pubkeyInput = document.getElementById("recipient-pubkey-input");
    if (pubkeyInput) {
      pubkeyInput.addEventListener("input", () => validateRecipientKeyInput());
    }
    window.addEventListener("resize", () => {
      updateConnectorLine();
      if (graphEngine) graphEngine.resize();
      drawMerkleConnectors();
    });
    const addrStage = document.getElementById("view-point-address");
    if (addrStage) {
      initAddressGame();
    }
    const merkleStage = document.getElementById("view-merkle");
    if (merkleStage) {
      initMerkleSimulator();
    }
  });
  var addressGameState = {
    currentPresetId: "wiki_standard",
    xHex: "50863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352",
    yHex: "2CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6",
    format: "compressed",
    // 'compressed' | 'uncompressed'
    currentStep: 1,
    step1Completed: false,
    step2Completed: false,
    step3Completed: false,
    step4Completed: false,
    step5Completed: false,
    step6Completed: false,
    assembledPubkey: "",
    sha256Digest: "",
    ripemd160Digest: "",
    versionByte: "00",
    versionedPayload: "",
    csHash1: "",
    csHash2: "",
    checksum: "",
    finalPayload: "",
    finalAddress: "",
    tools: {
      shaMode: "hex",
      ripeMode: "hex",
      b58Mode: "encode"
    }
  };
  window.initAddressGame = function() {
    const xEl = document.getElementById("p2a-x-val");
    const yEl = document.getElementById("p2a-y-val");
    if (xEl) xEl.textContent = addressGameState.xHex.toUpperCase();
    if (yEl) yEl.textContent = addressGameState.yHex.toUpperCase();
    const parity = getYParity(addressGameState.yHex);
    const parityBadge = document.getElementById("p2a-parity-badge");
    const parityDetails = document.getElementById("p2a-parity-details");
    const challengeYChar = document.getElementById("p2a-challenge-y-char");
    if (parityBadge) {
      parityBadge.className = `p2a-parity-badge ${parity.isEven ? "even" : "odd"}`;
      parityBadge.textContent = parity.isEven ? "Y is EVEN" : "Y is ODD";
    }
    if (parityDetails) {
      parityDetails.innerHTML = `Last hex digit of Y is <b>'${parity.lastDigit.toUpperCase()}'</b> (${parity.isEven ? "even" : "odd"}). Compressed prefix = <code>${parity.prefix}</code>.`;
    }
    if (challengeYChar) {
      challengeYChar.textContent = parity.lastDigit.toUpperCase();
    }
    const cardComp = document.getElementById("format-card-comp");
    const cardUncomp = document.getElementById("format-card-uncomp");
    const radioComp = document.getElementById("radio-comp");
    const radioUncomp = document.getElementById("radio-uncomp");
    const parityChallengeBox = document.getElementById("p2a-parity-challenge-box");
    if (addressGameState.format === "compressed") {
      if (cardComp) cardComp.classList.add("selected");
      if (cardUncomp) cardUncomp.classList.remove("selected");
      if (radioComp) radioComp.checked = true;
      if (parityChallengeBox) parityChallengeBox.style.display = "flex";
    } else {
      if (cardUncomp) cardUncomp.classList.add("selected");
      if (cardComp) cardComp.classList.remove("selected");
      if (radioUncomp) radioUncomp.checked = true;
      if (parityChallengeBox) parityChallengeBox.style.display = "none";
    }
    renderStep1Assembly();
    window.jumpToAddressStep(addressGameState.currentStep || 1);
  };
  window.selectPointPreset = function(presetId) {
    addressGameState.currentPresetId = presetId;
    const presetButtons = document.querySelectorAll(".p2a-preset-btn");
    presetButtons.forEach((btn) => btn.classList.remove("active"));
    const activeBtn = document.getElementById(`btn-preset-${presetId.replace("_", "-")}`) || document.getElementById(`btn-preset-${presetId}`);
    if (activeBtn) activeBtn.classList.add("active");
    const customDrawer = document.getElementById("p2a-custom-drawer");
    if (presetId === "custom") {
      if (customDrawer) customDrawer.style.display = "block";
      const inX = document.getElementById("p2a-input-custom-x");
      const inY = document.getElementById("p2a-input-custom-y");
      if (inX) inX.value = addressGameState.xHex;
      if (inY) inY.value = addressGameState.yHex;
      return;
    } else {
      if (customDrawer) customDrawer.style.display = "none";
    }
    if (presetId === "alice") {
      if (state.alice && state.alice.keyPair) {
        addressGameState.xHex = toHex32(state.alice.keyPair.publicPoint.x);
        addressGameState.yHex = toHex32(state.alice.keyPair.publicPoint.y);
      } else {
        showAlert("Alice identity initializing...");
        return;
      }
    } else if (presetId === "bob") {
      if (state.bob && state.bob.keyPair) {
        addressGameState.xHex = toHex32(state.bob.keyPair.publicPoint.x);
        addressGameState.yHex = toHex32(state.bob.keyPair.publicPoint.y);
      } else {
        showAlert("Bob identity initializing...");
        return;
      }
    } else {
      const preset = PREDEFINED_POINTS.find((p) => p.id === presetId);
      if (preset) {
        addressGameState.xHex = preset.x;
        addressGameState.yHex = preset.y;
      }
    }
    window.resetAddressGame(false);
    window.initAddressGame();
    showAlert(`Loaded Point: ${presetId.replace("_", " ").toUpperCase()}`);
    sound.playClick();
  };
  window.applyCustomCoordinates = function() {
    const inX = document.getElementById("p2a-input-custom-x");
    const inY = document.getElementById("p2a-input-custom-y");
    if (!inX || !inY) return;
    const rawX = inX.value.trim().replace(/[^0-9a-fA-F]/g, "");
    const rawY = inY.value.trim().replace(/[^0-9a-fA-F]/g, "");
    if (rawX.length !== 64 || rawY.length !== 64) {
      showAlert("Error: X and Y must each be 64 hexadecimal characters (32 bytes).");
      return;
    }
    addressGameState.xHex = rawX;
    addressGameState.yHex = rawY;
    const customDrawer = document.getElementById("p2a-custom-drawer");
    if (customDrawer) customDrawer.style.display = "none";
    window.resetAddressGame(false);
    window.initAddressGame();
    showAlert("Custom coordinates loaded successfully");
    sound.playLock();
  };
  window.setKeyFormat = function(format) {
    addressGameState.format = format;
    const parityChallengeBox = document.getElementById("p2a-parity-challenge-box");
    const cardComp = document.getElementById("format-card-comp");
    const cardUncomp = document.getElementById("format-card-uncomp");
    if (format === "compressed") {
      if (cardComp) cardComp.classList.add("selected");
      if (cardUncomp) cardUncomp.classList.remove("selected");
      if (parityChallengeBox) parityChallengeBox.style.display = "flex";
    } else {
      if (cardUncomp) cardUncomp.classList.add("selected");
      if (cardComp) cardComp.classList.remove("selected");
      if (parityChallengeBox) parityChallengeBox.style.display = "none";
    }
    addressGameState.step2Completed = false;
    addressGameState.step3Completed = false;
    addressGameState.step4Completed = false;
    addressGameState.step5Completed = false;
    addressGameState.step6Completed = false;
    const navPills = document.querySelectorAll(".p2a-nav-pill");
    navPills.forEach((p, idx) => {
      if (idx > 0) p.classList.remove("completed");
    });
    const btnNext2 = document.getElementById("p2a-btn-next-step2");
    const btnNext3 = document.getElementById("p2a-btn-next-step3");
    const btnNext4 = document.getElementById("p2a-btn-next-step4");
    const btnNext5 = document.getElementById("p2a-btn-next-step5");
    if (btnNext2) btnNext2.disabled = true;
    if (btnNext3) btnNext3.disabled = true;
    if (btnNext4) btnNext4.disabled = true;
    if (btnNext5) btnNext5.disabled = true;
    renderStep1Assembly();
    sound.playClick();
  };
  window.handlePrefixGuess = function(guessedPrefix) {
    const parity = getYParity(addressGameState.yHex);
    const btn02 = document.getElementById("btn-prefix-02");
    const btn03 = document.getElementById("btn-prefix-03");
    const feedback = document.getElementById("p2a-prefix-feedback");
    if (btn02) btn02.classList.remove("correct", "incorrect");
    if (btn03) btn03.classList.remove("correct", "incorrect");
    const chosenBtn = guessedPrefix === "02" ? btn02 : btn03;
    const isCorrect = guessedPrefix === parity.prefix;
    if (chosenBtn) {
      chosenBtn.classList.add(isCorrect ? "correct" : "incorrect");
    }
    if (feedback) {
      feedback.style.display = "block";
      feedback.className = `p2a-challenge-feedback ${isCorrect ? "success" : "error"}`;
      if (isCorrect) {
        feedback.innerHTML = `Correct! Y ends in '${parity.lastDigit.toUpperCase()}' (${parity.isEven ? "even" : "odd"}), so prefix <code>${parity.prefix}</code> is required.`;
        sound.playLock();
      } else {
        feedback.innerHTML = `Incorrect. Y ends in '${parity.lastDigit.toUpperCase()}' (${parity.isEven ? "even" : "odd"}), so prefix <code>${parity.prefix}</code> must be used instead.`;
        sound.playClick();
      }
    }
  };
  function renderStep1Assembly() {
    const res = assemblePublicKey(addressGameState.xHex, addressGameState.yHex, addressGameState.format);
    addressGameState.assembledPubkey = res.pubkey;
    const displayEl = document.getElementById("p2a-assembled-pubkey");
    const bytesBadge = document.getElementById("p2a-pubkey-bytes-badge");
    if (bytesBadge) {
      bytesBadge.textContent = `${res.byteLength} Bytes (${res.pubkey.length} hex)`;
    }
    if (displayEl) {
      if (res.format === "compressed") {
        displayEl.innerHTML = `
        <span class="hex-chip prefix" title="Parity Prefix (02=even, 03=odd)">${res.prefix}</span>
        <span class="hex-chip x-coord" title="X Coordinate (32 bytes)">${res.x.toUpperCase()}</span>
      `;
      } else {
        displayEl.innerHTML = `
        <span class="hex-chip prefix" title="Uncompressed Prefix (04)">04</span>
        <span class="hex-chip x-coord" title="X Coordinate (32 bytes)">${res.x.toUpperCase()}</span>
        <span class="hex-chip y-coord" title="Y Coordinate (32 bytes)">${res.y.toUpperCase()}</span>
      `;
      }
    }
    const step2In = document.getElementById("p2a-step2-input");
    if (step2In) step2In.value = res.pubkey.toUpperCase();
  }
  window.completeStep1AndAdvance = function() {
    addressGameState.step1Completed = true;
    const pill1 = document.getElementById("p2a-nav-step-1");
    if (pill1) pill1.classList.add("completed");
    const step2In = document.getElementById("p2a-step2-input");
    if (step2In) step2In.value = addressGameState.assembledPubkey.toUpperCase();
    window.jumpToAddressStep(2);
    sound.playClick();
  };
  window.runStep2Sha256 = function() {
    const inEl = document.getElementById("p2a-step2-input");
    const val = inEl ? inEl.value.trim().toLowerCase() : addressGameState.assembledPubkey;
    try {
      const hashHex = sha256Hex(val);
      addressGameState.sha256Digest = hashHex;
      const outEl = document.getElementById("p2a-step2-output");
      if (outEl) outEl.textContent = hashHex.toUpperCase();
      const btnNext = document.getElementById("p2a-btn-next-step2");
      if (btnNext) btnNext.disabled = false;
      const step3In = document.getElementById("p2a-step3-input");
      if (step3In) step3In.value = hashHex.toUpperCase();
      sound.playLock();
    } catch (err) {
      showAlert("Error computing SHA-256: " + err.message);
    }
  };
  window.completeStep2AndAdvance = function() {
    addressGameState.step2Completed = true;
    const pill2 = document.getElementById("p2a-nav-step-2");
    if (pill2) pill2.classList.add("completed");
    const step3In = document.getElementById("p2a-step3-input");
    if (step3In) step3In.value = addressGameState.sha256Digest.toUpperCase();
    window.jumpToAddressStep(3);
    sound.playClick();
  };
  window.runStep3Ripemd160 = function() {
    const inEl = document.getElementById("p2a-step3-input");
    const val = inEl ? inEl.value.trim().toLowerCase() : addressGameState.sha256Digest;
    try {
      const hashHex = ripemd160Hex(val);
      addressGameState.ripemd160Digest = hashHex;
      const outEl = document.getElementById("p2a-step3-output");
      if (outEl) outEl.textContent = hashHex.toUpperCase();
      const btnNext = document.getElementById("p2a-btn-next-step3");
      if (btnNext) btnNext.disabled = false;
      sound.playLock();
    } catch (err) {
      showAlert("Error computing RIPEMD-160: " + err.message);
    }
  };
  window.completeStep3AndAdvance = function() {
    addressGameState.step3Completed = true;
    const pill3 = document.getElementById("p2a-nav-step-3");
    if (pill3) pill3.classList.add("completed");
    window.jumpToAddressStep(4);
    sound.playClick();
  };
  window.runStep4AddVersion = function() {
    if (!addressGameState.ripemd160Digest) {
      showAlert("Please complete Step 3 (RIPEMD-160) first!");
      return;
    }
    addressGameState.versionByte = "00";
    addressGameState.versionedPayload = "00" + addressGameState.ripemd160Digest;
    const outEl = document.getElementById("p2a-step4-output");
    const rawEl = document.getElementById("p2a-step4-output-raw");
    if (outEl) {
      outEl.innerHTML = `
      <span class="hex-chip version" title="Bitcoin Mainnet Version Byte (00)">00</span>
      <span class="hex-chip hash160" title="PubKeyHash (20 bytes)">${addressGameState.ripemd160Digest.toUpperCase()}</span>
    `;
    }
    if (rawEl) {
      rawEl.textContent = addressGameState.versionedPayload.toUpperCase();
    }
    const btnNext = document.getElementById("p2a-btn-next-step4");
    if (btnNext) btnNext.disabled = false;
    sound.playLock();
  };
  window.completeStep4AndAdvance = function() {
    addressGameState.step4Completed = true;
    const pill4 = document.getElementById("p2a-nav-step-4");
    if (pill4) pill4.classList.add("completed");
    window.jumpToAddressStep(5);
    sound.playClick();
  };
  window.runStep5Checksum = function() {
    if (!addressGameState.versionedPayload) {
      showAlert("Please complete Step 4 first!");
      return;
    }
    try {
      const payloadBytes = hexToBytes2(addressGameState.versionedPayload);
      const csHash1 = sha256Hex(payloadBytes);
      const csHash2 = sha256Hex(hexToBytes2(csHash1));
      const checksum = csHash2.substring(0, 8);
      const finalPayload = addressGameState.versionedPayload + checksum;
      addressGameState.csHash1 = csHash1;
      addressGameState.csHash2 = csHash2;
      addressGameState.checksum = checksum;
      addressGameState.finalPayload = finalPayload;
      const breakdown = document.getElementById("p2a-checksum-breakdown");
      const h1El = document.getElementById("p2a-cs-hash1");
      const h2El = document.getElementById("p2a-cs-hash2");
      const csExtractedEl = document.getElementById("p2a-cs-extracted");
      if (breakdown) breakdown.style.display = "flex";
      if (h1El) h1El.textContent = csHash1.toUpperCase();
      if (h2El) h2El.textContent = csHash2.toUpperCase();
      if (csExtractedEl) csExtractedEl.textContent = checksum.toUpperCase();
      const outEl = document.getElementById("p2a-step5-output");
      const rawEl = document.getElementById("p2a-step5-output-raw");
      if (outEl) {
        outEl.innerHTML = `
        <span class="hex-chip version">00</span>
        <span class="hex-chip hash160">${addressGameState.ripemd160Digest.toUpperCase()}</span>
        <span class="hex-chip checksum" title="4-Byte Checksum">${checksum.toUpperCase()}</span>
      `;
      }
      if (rawEl) {
        rawEl.textContent = finalPayload.toUpperCase();
      }
      const step6In = document.getElementById("p2a-step6-input");
      if (step6In) step6In.value = finalPayload.toUpperCase();
      const btnNext = document.getElementById("p2a-btn-next-step5");
      if (btnNext) btnNext.disabled = false;
      sound.playLock();
    } catch (err) {
      showAlert("Error calculating checksum: " + err.message);
    }
  };
  window.completeStep5AndAdvance = function() {
    addressGameState.step5Completed = true;
    const pill5 = document.getElementById("p2a-nav-step-5");
    if (pill5) pill5.classList.add("completed");
    const step6In = document.getElementById("p2a-step6-input");
    if (step6In) step6In.value = addressGameState.finalPayload.toUpperCase();
    window.jumpToAddressStep(6);
    sound.playClick();
  };
  window.runStep6Base58 = function() {
    const inEl = document.getElementById("p2a-step6-input");
    const val = inEl ? inEl.value.trim().toLowerCase() : addressGameState.finalPayload;
    try {
      const payloadBytes = hexToBytes2(val);
      const address = base58Encode(payloadBytes);
      addressGameState.finalAddress = address;
      const addrCard = document.getElementById("p2a-final-address-card");
      const addrVal = document.getElementById("p2a-final-address-val");
      const formatTag = document.getElementById("p2a-meta-format-tag");
      if (addrCard) addrCard.style.display = "flex";
      if (addrVal) addrVal.textContent = address;
      if (formatTag) {
        formatTag.textContent = addressGameState.format === "compressed" ? "Compressed Public Key" : "Uncompressed Public Key";
      }
      const victoryCard = document.getElementById("p2a-victory-card");
      const sumPoint = document.getElementById("p2a-sum-point");
      const sumPubkey = document.getElementById("p2a-sum-pubkey");
      const sumHash160 = document.getElementById("p2a-sum-hash160");
      const sumAddress = document.getElementById("p2a-sum-address");
      if (victoryCard) victoryCard.style.display = "flex";
      if (sumPoint) sumPoint.textContent = `(${addressGameState.xHex.slice(0, 10)}..., ${addressGameState.yHex.slice(0, 10)}...)`;
      if (sumPubkey) sumPubkey.textContent = `${addressGameState.assembledPubkey.slice(0, 14)}... (${addressGameState.format})`;
      if (sumHash160) sumHash160.textContent = addressGameState.ripemd160Digest.toUpperCase();
      if (sumAddress) sumAddress.textContent = address;
      addressGameState.step6Completed = true;
      const pill6 = document.getElementById("p2a-nav-step-6");
      if (pill6) pill6.classList.add("completed");
      sound.playLock();
      setTimeout(() => sound.playWhoosh(), 120);
      showAlert("Bitcoin Address Derived Successfully!");
    } catch (err) {
      showAlert("Error encoding Base58: " + err.message);
    }
  };
  window.jumpToAddressStep = function(stepNum) {
    addressGameState.currentStep = stepNum;
    for (let i = 1; i <= 6; i++) {
      const pill = document.getElementById(`p2a-nav-step-${i}`);
      const card = document.getElementById(`p2a-card-step-${i}`);
      if (pill) {
        if (i === stepNum) pill.classList.add("active");
        else pill.classList.remove("active");
      }
      if (card) {
        if (i === stepNum) card.classList.add("active");
        else card.classList.remove("active");
      }
    }
    sound.playClick();
  };
  window.resetAddressGame = function(showToast = true) {
    addressGameState.currentStep = 1;
    addressGameState.step1Completed = false;
    addressGameState.step2Completed = false;
    addressGameState.step3Completed = false;
    addressGameState.step4Completed = false;
    addressGameState.step5Completed = false;
    addressGameState.step6Completed = false;
    addressGameState.assembledPubkey = "";
    addressGameState.sha256Digest = "";
    addressGameState.ripemd160Digest = "";
    addressGameState.versionedPayload = "";
    addressGameState.finalPayload = "";
    addressGameState.finalAddress = "";
    const out2 = document.getElementById("p2a-step2-output");
    const out3 = document.getElementById("p2a-step3-output");
    const out4 = document.getElementById("p2a-step4-output");
    const out5 = document.getElementById("p2a-step5-output");
    const bd5 = document.getElementById("p2a-checksum-breakdown");
    const addrCard = document.getElementById("p2a-final-address-card");
    const victoryCard = document.getElementById("p2a-victory-card");
    if (out2) out2.textContent = "(Click Compute SHA-256)";
    if (out3) out3.textContent = "(Click Compute RIPEMD-160)";
    if (out4) out4.textContent = "(Click Prepend Mainnet Byte)";
    if (out5) out5.textContent = "(Click Calculate Checksum)";
    if (bd5) bd5.style.display = "none";
    if (addrCard) addrCard.style.display = "none";
    if (victoryCard) victoryCard.style.display = "none";
    const btnNext2 = document.getElementById("p2a-btn-next-step2");
    const btnNext3 = document.getElementById("p2a-btn-next-step3");
    const btnNext4 = document.getElementById("p2a-btn-next-step4");
    const btnNext5 = document.getElementById("p2a-btn-next-step5");
    if (btnNext2) btnNext2.disabled = true;
    if (btnNext3) btnNext3.disabled = true;
    if (btnNext4) btnNext4.disabled = true;
    if (btnNext5) btnNext5.disabled = true;
    for (let i = 1; i <= 6; i++) {
      const pill = document.getElementById(`p2a-nav-step-${i}`);
      if (pill) pill.classList.remove("completed");
    }
    const btn02 = document.getElementById("btn-prefix-02");
    const btn03 = document.getElementById("btn-prefix-03");
    const feedback = document.getElementById("p2a-prefix-feedback");
    if (btn02) btn02.classList.remove("correct", "incorrect");
    if (btn03) btn03.classList.remove("correct", "incorrect");
    if (feedback) feedback.style.display = "none";
    window.jumpToAddressStep(1);
    renderStep1Assembly();
    if (showToast) {
      showAlert("Game Reset to Step 1");
      sound.playClick();
    }
  };
  window.solveAllAddressSteps = function() {
    renderStep1Assembly();
    window.completeStep1AndAdvance();
    window.runStep2Sha256();
    window.completeStep2AndAdvance();
    window.runStep3Ripemd160();
    window.completeStep3AndAdvance();
    window.runStep4AddVersion();
    window.completeStep4AndAdvance();
    window.runStep5Checksum();
    window.completeStep5AndAdvance();
    window.runStep6Base58();
    showAlert("All 6 Cryptographic Steps Solved!");
  };
  window.copyTextById = function(elemId) {
    const el = document.getElementById(elemId);
    if (!el) return;
    const val = (el.value !== void 0 ? el.value : el.textContent).trim();
    window.copyText(val, "Value");
  };
  window.setToolMode = function(tool, mode) {
    addressGameState.tools[`${tool}Mode`] = mode;
    if (tool === "sha") {
      const btnHex = document.getElementById("tool-sha-mode-hex");
      const btnText = document.getElementById("tool-sha-mode-text");
      const inArea = document.getElementById("tool-sha-input");
      if (mode === "hex") {
        if (btnHex) btnHex.classList.add("active");
        if (btnText) btnText.classList.remove("active");
        if (inArea) inArea.placeholder = "Enter hexadecimal string to hash...";
      } else {
        if (btnText) btnText.classList.add("active");
        if (btnHex) btnHex.classList.remove("active");
        if (inArea) inArea.placeholder = "Enter plain text to hash...";
      }
    } else if (tool === "ripe") {
      const btnHex = document.getElementById("tool-ripe-mode-hex");
      const btnText = document.getElementById("tool-ripe-mode-text");
      const inArea = document.getElementById("tool-ripe-input");
      if (mode === "hex") {
        if (btnHex) btnHex.classList.add("active");
        if (btnText) btnText.classList.remove("active");
        if (inArea) inArea.placeholder = "Enter hexadecimal string to hash...";
      } else {
        if (btnText) btnText.classList.add("active");
        if (btnHex) btnHex.classList.remove("active");
        if (inArea) inArea.placeholder = "Enter plain text to hash...";
      }
    } else if (tool === "b58") {
      const btnEnc = document.getElementById("tool-b58-mode-enc");
      const btnDec = document.getElementById("tool-b58-mode-dec");
      const inArea = document.getElementById("tool-b58-input");
      const actionBtn = document.getElementById("tool-b58-btn");
      const outLabel = document.getElementById("tool-b58-output-label");
      if (mode === "encode") {
        if (btnEnc) btnEnc.classList.add("active");
        if (btnDec) btnDec.classList.remove("active");
        if (inArea) inArea.placeholder = "Enter hex payload to encode to Base58...";
        if (actionBtn) actionBtn.querySelector("span").textContent = "Encode to Base58";
        if (outLabel) outLabel.textContent = "Base58 Result:";
      } else {
        if (btnDec) btnDec.classList.add("active");
        if (btnEnc) btnEnc.classList.remove("active");
        if (inArea) inArea.placeholder = "Enter Base58 string (e.g. 16UwLL9...) to decode...";
        if (actionBtn) actionBtn.querySelector("span").textContent = "Decode from Base58";
        if (outLabel) outLabel.textContent = "Decoded Hex:";
      }
    }
    sound.playClick();
  };
  window.runStandaloneSha256 = function() {
    const inArea = document.getElementById("tool-sha-input");
    const outVal = document.getElementById("tool-sha-output");
    if (!inArea || !outVal) return;
    const val = inArea.value.trim();
    if (!val) {
      showAlert("Please enter input for SHA-256");
      return;
    }
    try {
      let inputBytes;
      if (addressGameState.tools.shaMode === "hex") {
        inputBytes = hexToBytes2(val);
      } else {
        inputBytes = utf8ToBytes(val);
      }
      const hash = sha256Hex(inputBytes);
      outVal.textContent = hash.toUpperCase();
      sound.playLock();
    } catch (err) {
      outVal.textContent = "Error: " + err.message;
      showAlert("Error: " + err.message);
    }
  };
  window.runStandaloneRipemd160 = function() {
    const inArea = document.getElementById("tool-ripe-input");
    const outVal = document.getElementById("tool-ripe-output");
    if (!inArea || !outVal) return;
    const val = inArea.value.trim();
    if (!val) {
      showAlert("Please enter input for RIPEMD-160");
      return;
    }
    try {
      let inputBytes;
      if (addressGameState.tools.ripeMode === "hex") {
        inputBytes = hexToBytes2(val);
      } else {
        inputBytes = utf8ToBytes(val);
      }
      const hash = ripemd160Hex(inputBytes);
      outVal.textContent = hash.toUpperCase();
      sound.playLock();
    } catch (err) {
      outVal.textContent = "Error: " + err.message;
      showAlert("Error: " + err.message);
    }
  };
  window.runStandaloneBase58 = function() {
    const inArea = document.getElementById("tool-b58-input");
    const outVal = document.getElementById("tool-b58-output");
    if (!inArea || !outVal) return;
    const val = inArea.value.trim();
    if (!val) {
      showAlert("Please enter input for Base58 tool");
      return;
    }
    try {
      if (addressGameState.tools.b58Mode === "encode") {
        const bytes = hexToBytes2(val);
        const encoded = base58Encode(bytes);
        outVal.textContent = encoded;
        sound.playLock();
      } else {
        const bytes = base58Decode(val);
        const hex = bytesToHex2(bytes);
        let checksumNote = "";
        if (bytes.length === 25) {
          const payload = bytes.slice(0, 21);
          const expectedCs = bytesToHex2(bytes.slice(21, 25));
          const actualCs = computeChecksum(bytesToHex2(payload));
          if (expectedCs === actualCs) {
            checksumNote = " [Valid Address Checksum \u2713]";
          } else {
            checksumNote = " [Checksum Mismatch \u2717]";
          }
        }
        outVal.textContent = hex.toUpperCase() + checksumNote;
        sound.playLock();
      }
    } catch (err) {
      outVal.textContent = "Error: " + err.message;
      showAlert("Error: " + err.message);
    }
  };
})();
