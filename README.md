# Bitpolito Cryptography Simulator

An interactive Bitcoin **secp256k1** elliptic curve asymmetric cryptography simulator designed with pixel-art avatars, soft neumorphic floating aesthetics, and an interactive 2D Desmos-style graph with finite field modulo ($p$) and continuous ($\mathbb{R}$) point stepping.

---

## 🎨 Visual Palette & UI Updates

- **Web Title:** `Bitpolito Cryptography Simulator`
- **Background:** `#F9F9F9` (Clean minimalist studio backdrop — zero background blur)
- **Primary Brand / Text:** `#001CE0` (Royal electric blue)
- **Cards & Pills:** Pure white `#FFFFFF` with soft diffused float shadows:
  ```css
  box-shadow: 0 16px 36px -6px rgba(0, 0, 0, 0.08),
              0 6px 16px -2px rgba(0, 0, 0, 0.03),
              0 0 0 1px rgba(0, 0, 0, 0.025);
  border-radius: 9999px; /* Pill buttons */
  ```
- **Characters:**
  - **ALICE:** Female pixel art avatar in royal blue (10×10 grid)
  - **BOB:** Male pixel art avatar in royal blue (10×10 grid)
- **Navigation:** Single **"Cryptography Guide"** button in header to toggle seamlessly between the Alice/Bob simulator and the 2D curve graph.
- **Zero Emojis:** Replaced with clean vector SVG icons and typography (only `📋` copy/paste icons retained).
- **Inline Messaging:** No popup overlays and no background blur. The messaging interface unfolds directly in the center of the page between Alice and Bob.

---

## 📐 Mathematical Foundation (Bitcoin secp256k1)

Authentic, zero-dependency BigInt point arithmetic on the Bitcoin curve:

$$y^2 \equiv x^3 + 7 \pmod p$$

Where:
- **Field Prime ($p$):** $2^{256} - 2^{32} - 977 = \text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F}$
- **Generator Point ($G$):**
  - $G_x = \text{0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798}$
  - $G_y = \text{0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8}$
- **Curve Order ($n$):** $\text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141}$

### Key Generation
1. **Private Key ($d$):** Random 256-bit scalar ($1 \le d < n$).
2. **Public Key ($Q$):** Point scalar multiplication $Q = d \cdot G$.

### Asymmetric Encryption (ECIES)
1. **Ephemeral Keypair:** Sender chooses ephemeral scalar $k$, computes ephemeral public point $R = k \cdot G$.
2. **Shared Secret Point:** Sender computes $S = k \cdot Q_{\text{receiver}}$ using the receiver's public key pasted into the input field.
3. **Key Derivation:** $K = \text{SHA-256}(S_x)$.
4. **Symmetric Encryption:** Plaintext encrypted using AES-256-GCM.
5. **Decryption at Receiver:** Receiver uses their secret private key $d_{\text{receiver}}$ to calculate:
   $$S = d_{\text{receiver}} \cdot R = d_{\text{receiver}} \cdot (k \cdot G) = k \cdot (d_{\text{receiver}} \cdot G) = k \cdot Q_{\text{receiver}} = S$$
   The receiver unlocks and reveals the original message without revealing their private key.

---

## 🚀 Interactive Flow

1. **Inline Workflow:** Clicking **"Send Encrypted Message"** on Alice opens Box 1 directly between Alice and Bob without obscuring or blurring the page.
2. **Manual Receiver Key Entry:** In Part 2, copy Bob's public key by clicking `📋` on Bob's card, then paste it into the receiver input field.
3. **Encrypt Message:** Click **"Encrypt Message"** to generate the shared secret point $S$ and display Box 2 with the ciphertext payload.
4. **Transmission:** Click **"Send Message"** to animate the envelope node along the wire.
5. **Receiver Decryption:** An incoming encrypted card appears under Bob's card showing the raw ciphertext. Clicking **"Decrypt with Bob's Private Key (d)"** unlocks the plaintext and records the exchange in the transmission log.
6. **SVG Eye Toggle:** Toggle visibility of the private key scalars using the vector eye icons.

---

## 📈 Interactive 2D Curve Graph (Desmos-Style) with Finite Field (mod p)

Clicking the **"Cryptography Guide"** button in the header or the formula banner transitions into an interactive Desmos-style 2D graph workspace:

1. **Dual Domains:**
   - **Continuous Curve (ℝ):** Smooth plotting of $y^2 = x^3 + ax + b$ with full pan and zoom.
   - **Finite Field (mod p):** Discrete field grid $[0, p-1] \times [0, p-1]$ plotting all integer solutions to $y^2 \equiv x^3 + ax + b \pmod p$ with axis of symmetry at $y = p/2$ for selectable primes ($p = 17, 23, 43, 67$).

2. **Changeable Parameters:**
   - Sliders for parameter $a$, parameter $b$, base generator point $x_G$, and prime modulus $p$.
   - Live discriminant calculation $\Delta = -(4a^3 + 27b^2)$ with singularity indicator.
   - Shortcut preset buttons:
     - **Bitcoin Curve ($a=0, b=7$)**: The standard secp256k1 curve.
     - **Two-Component ($a=-3, b=1$)**: Visualizes an isolated oval component and open branch.

3. **Public Key Generation Stepper & 5G Step ($5\cdot G = 4\cdot G + G$):**
   - Click **"Next Step (+G)"** or the dedicated **"5G Step"** button.
   - **5G Step:** Directly demonstrates private key scalar $d = 5$, drawing secant / wrapped modular lines connecting $4G$ and $G$, 3rd intersection point $-5G$, and reflection across the axis of symmetry to yield public key point $Q = 5\cdot G$.
   - Real-time display of private key scalar $d$, public point coordinates $Q$, slope equations, and an educational breakdown of the Discrete Logarithm Problem (ECDLP).

---

## 💻 Local Execution

```bash
# Serve locally via Python
python3 -m http.server 8080

# Open in browser
http://localhost:8080
```

# BitPolitoAsymmetricCryptoGraphy
