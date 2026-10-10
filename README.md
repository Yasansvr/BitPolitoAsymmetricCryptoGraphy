# Bitpolito Cryptography Simulator

An interactive Bitcoin **secp256k1** elliptic curve asymmetric cryptography simulator designed with soft neumorphic floating aesthetics, and an interactive 2D graph with finite field modulo ($p$) and continuous ($\mathbb{R}$) point stepping.


## 📐 Mathematical Foundation (Bitcoin secp256k1)

Authentic, zero-dependency BigInt point arithmetic on the Bitcoin curve:

$$y^2 \equiv x^3 + 7 \pmod p$$

Where:
- **Field Prime ($p$):** $2^{256} - 2^{32} - 977 = \text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F}$
- **Generator Point ($G$):**
  - $G_x = \text{0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798}$
  - $G_y = \text{0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8}$

### Key Generation
1. **Private Key ($d$):** Random 256-bit scalar ($1 \le d < n$).
2. **Public Key ($Q$):** Point scalar multiplication $Q = d \cdot G$.

## 💻 Local Execution

```bash
# Serve locally via Python
python3 -m http.server 8080

# Open in browser
http://localhost:8080
```

# BitPolitoAsymmetricCryptoGraphy
