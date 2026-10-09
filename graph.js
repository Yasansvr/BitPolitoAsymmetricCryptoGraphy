/**
 * Desmos-Style 2D Elliptic Curve Graph Engine & Point Addition Stepper
 * Equation: y^2 = x^3 + ax + b (Real Curve)
 * Modular Equation: y^2 = x^3 + ax + b (mod p) (Finite Field F_p)
 * Bitcoin secp256k1 Default: a = 0, b = 7
 */

export class EllipticGraphEngine {
  constructor(canvas, options = {}) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    
    // Domain: 'real' (continuous R) or 'mod' (finite field F_p)
    this.domain = options.domain || 'real';
    this.p = options.p ?? 23; // Modulus prime for 'mod' mode
    
    // Curve parameters (Default: Bitcoin secp256k1)
    this.a = options.a ?? 0;
    this.b = options.b ?? 7;
    
    // Viewport / Coordinate Window (World coordinates)
    this.centerX = options.centerX ?? 1.0;
    this.centerY = options.centerY ?? 0.5;
    this.scale = options.scale ?? 36; // pixels per unit (ensures 1G-5G comfortably visible)
    
    // Base generator point G (Default xG = -1.5 in real mode so 1G-5G all fit nicely on screen)
    this.xG = options.xG ?? -1.5;
    this.currentStep = 1; // d = 1 (1*G), 2 (2*G), ...
    this.maxStep = options.maxStep ?? 250; // Unlimited / high ceiling stepping up to 250+
    this.isPlaying = false;
    this.playTimer = null;
    
    // Interaction state
    this.isDragging = false;
    this.dragStartX = 0;
    this.dragStartY = 0;
    this.mouseWorldX = 0;
    this.mouseWorldY = 0;
    
    // Callbacks
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
      m: m,
      xIntersect: x3,
      yIntersect: -y3, // 3rd intersection point before reflection
      isInfinity: false,
      isDouble
    };
  }

  // --- Modular (Finite Field F_p) Math ---
  mod(n, m) {
    return ((n % m) + m) % m;
  }

  modInverse(a, m) {
    let [m0, y, x] = [m, 0n, 1n];
    a = ((a % m) + m) % m;
    if (m === 1n) return 0n;
    while (a > 1n) {
      let q = a / m;
      let t = m;
      m = a % m; a = t;
      t = y;
      y = x - q * y; x = t;
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
    // Prefer point with x=1 and y>0, else first positive y
    const found = pts.find(pt => pt.x === 1 && pt.y > 0) || pts.find(pt => pt.y > 0) || pts[0];
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
    const y3 = this.mod(pBig - y3Intersect, pBig); // Reflected point

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
    if (this.domain === 'mod') {
      const G = this.getBasePointMod();
      const steps = [
        {
          step: 1,
          point: G,
          prevPoint: null,
          addend: G,
          m: null,
          intersect: null,
          isDouble: false,
          isInfinity: false
        }
      ];

      let current = G;
      for (let d = 2; d <= this.currentStep; d++) {
        if (!current) {
          // Point at infinity + G = G (Group cyclic wrap-around)
          steps.push({
            step: d,
            point: G,
            prevPoint: null,
            addend: G,
            m: null,
            intersect: null,
            isDouble: false,
            isInfinity: false
          });
          current = G;
          continue;
        }

        const res = this.addPointsMod(current, G);
        if (res.isInfinity) {
          steps.push({
            step: d,
            point: null,
            prevPoint: current,
            addend: G,
            m: null,
            intersect: null,
            isDouble: false,
            isInfinity: true
          });
          current = null; // Next step will cycle back to G
        } else {
          const newPoint = { x: res.x, y: res.y };
          steps.push({
            step: d,
            point: newPoint,
            prevPoint: current,
            addend: G,
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

    // Real Mode
    const G = this.getBasePointReal();
    const steps = [
      {
        step: 1,
        point: G,
        prevPoint: null,
        addend: G,
        m: null,
        intersect: null,
        isDouble: false,
        isInfinity: false
      }
    ];

    let current = G;
    for (let d = 2; d <= this.currentStep; d++) {
      if (!current) {
        steps.push({
          step: d,
          point: G,
          prevPoint: null,
          addend: G,
          m: null,
          intersect: null,
          isDouble: false,
          isInfinity: false
        });
        current = G;
        continue;
      }

      const res = this.addPointsReal(current, G);
      if (res.isInfinity) {
        steps.push({
          step: d,
          point: null,
          prevPoint: current,
          addend: G,
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
          addend: G,
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
    if (domain === 'mod') {
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
    if (this.domain === 'mod') {
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
    if (this.domain === 'real') {
      this.xG = -1.5;
      this.centerX = 1.0;
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
    if (this.domain === 'real') {
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
    if (this.domain === 'mod') {
      this.scale = Math.min(this.width, this.height) / (this.p + 4);
      this.centerX = this.p / 2;
      this.centerY = this.p / 2;
    } else {
      this.centerX = 1.0;
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

    c.addEventListener('mousedown', (e) => {
      this.isDragging = true;
      this.dragStartX = e.clientX;
      this.dragStartY = e.clientY;
      c.style.cursor = 'grabbing';
    });

    window.addEventListener('mousemove', (e) => {
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

    window.addEventListener('mouseup', () => {
      if (this.isDragging) {
        this.isDragging = false;
        c.style.cursor = 'crosshair';
      }
    });

    c.addEventListener('wheel', (e) => {
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

    if (this.domain === 'mod') {
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

    // Minor Grid
    ctx.strokeStyle = '#EEF1F6';
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

    // Major Grid
    ctx.strokeStyle = '#E1E6F0';
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

    // Axes
    const originPx = this.toScreenX(0);
    const originPy = this.toScreenY(0);

    ctx.strokeStyle = '#8B95A5';
    ctx.lineWidth = 1.8;
    ctx.beginPath();
    ctx.moveTo(0, originPy);
    ctx.lineTo(w, originPy);
    ctx.moveTo(originPx, 0);
    ctx.lineTo(originPx, h);
    ctx.stroke();

    // Numbers along X
    ctx.fillStyle = '#6B7280';
    ctx.font = '10px JetBrains Mono, monospace';
    for (let x = startX; x <= maxX; x += unit) {
      if (Math.abs(x) < 1e-6) continue;
      const px = this.toScreenX(x);
      ctx.fillText(Number(x.toFixed(2)).toString(), px - 8, Math.min(Math.max(originPy + 14, 14), h - 6));
    }

    // Numbers along Y
    for (let y = startY; y <= maxY; y += unit) {
      if (Math.abs(y) < 1e-6) continue;
      const py = this.toScreenY(y);
      ctx.fillText(Number(y.toFixed(2)).toString(), Math.min(Math.max(originPx + 6, 6), w - 30), py + 3);
    }

    ctx.fillText('0', originPx + 5, originPy + 12);
  }

  drawRealCurve() {
    const ctx = this.ctx;
    const w = this.width;

    ctx.strokeStyle = '#001CE0';
    ctx.lineWidth = 3;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';

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
    const G = this.getBasePointReal();

    this.drawPoint(G.x, G.y, '#001CE0', 'G (Base Point)', 8, true);

    if (this.currentStep === 1) return;

    const currentStepData = steps[steps.length - 1];
    if (currentStepData.isInfinity) {
      ctx.fillStyle = '#D32F2F';
      ctx.font = 'bold 14px Inter, sans-serif';
      ctx.fillText('Point at Infinity (Identity Point O)', 30, 40);
      return;
    }

    const P1 = currentStepData.prevPoint;
    const m = currentStepData.m;
    const intersect = currentStepData.intersect;
    const finalQ = currentStepData.point;

    // Previous point label
    if (this.currentStep > 2 && P1) {
      const prevLabel = `${this.currentStep - 1}·G`;
      this.drawPoint(P1.x, P1.y, '#4B5563', prevLabel, 6);
    }

    // Tangent or Secant Line
    if (m !== null && P1) {
      const minX = this.toWorldX(0);
      const maxX = this.toWorldX(this.width);
      const yAtMinX = P1.y + m * (minX - P1.x);
      const yAtMaxX = P1.y + m * (maxX - P1.x);

      ctx.save();
      ctx.strokeStyle = 'rgba(0, 28, 224, 0.45)';
      ctx.lineWidth = 2;
      ctx.setLineDash([6, 5]);
      ctx.beginPath();
      ctx.moveTo(this.toScreenX(minX), this.toScreenY(yAtMinX));
      ctx.lineTo(this.toScreenX(maxX), this.toScreenY(yAtMaxX));
      ctx.stroke();
      ctx.restore();
    }

    // 3rd Intersection Point
    if (intersect) {
      this.drawPoint(intersect.x, intersect.y, '#DC2626', `-${this.currentStep}·G (3rd Intersection)`, 6);

      // Reflection Line to +d·G
      ctx.save();
      ctx.strokeStyle = '#DC2626';
      ctx.lineWidth = 1.8;
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(this.toScreenX(intersect.x), this.toScreenY(intersect.y));
      ctx.lineTo(this.toScreenX(finalQ.x), this.toScreenY(finalQ.y));
      ctx.stroke();
      ctx.restore();
    }

    // Final Public Key Point Q = d·G
    const label = `Q = ${this.currentStep}·G (Public Key)`;
    this.drawPoint(finalQ.x, finalQ.y, '#10B981', label, 9, true, true);
  }

  // ==========================================
  // MODULAR (MOD p) FINITE FIELD RENDERING
  // ==========================================
  drawModGrid() {
    const ctx = this.ctx;
    const p = this.p;

    // Grid box [0, p] x [0, p]
    const p0x = this.toScreenX(0);
    const p0y = this.toScreenY(0);
    const pX = this.toScreenX(p);
    const pY = this.toScreenY(p);

    // Background fill for field box
    ctx.fillStyle = '#FFFFFF';
    ctx.fillRect(p0x, pY, pX - p0x, p0y - pY);

    // Minor grid lines for discrete integers
    ctx.strokeStyle = '#EDF1F7';
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

    // Symmetry axis at y = p / 2
    ctx.save();
    ctx.strokeStyle = 'rgba(0, 28, 224, 0.2)';
    ctx.lineWidth = 1.5;
    ctx.setLineDash([4, 4]);
    const symY = this.toScreenY(p / 2);
    ctx.beginPath();
    ctx.moveTo(p0x, symY);
    ctx.lineTo(pX, symY);
    ctx.stroke();
    ctx.restore();

    // Field boundary box
    ctx.strokeStyle = '#8B95A5';
    ctx.lineWidth = 2;
    ctx.strokeRect(p0x, pY, pX - p0x, p0y - pY);

    // Axis Labels
    ctx.fillStyle = '#6B7280';
    ctx.font = '10px JetBrains Mono, monospace';
    const stepUnit = p > 30 ? 5 : 2;
    for (let x = 0; x <= p; x += stepUnit) {
      const sx = this.toScreenX(x);
      ctx.fillText(x.toString(), sx - 4, p0y + 14);
    }
    for (let y = 0; y <= p; y += stepUnit) {
      const sy = this.toScreenY(y);
      ctx.fillText(y.toString(), p0x - 18, sy + 4);
    }

    // Symmetry annotation
    ctx.fillStyle = '#001CE0';
    ctx.font = 'bold 10px Inter, sans-serif';
    ctx.fillText(`Field F_${p} (Symmetry axis y = ${p}/2)`, p0x + 8, pY + 16);
  }

  drawModCurvePoints() {
    const ctx = this.ctx;
    const pts = this.computeCurveModPoints();

    // Render all points on the modular curve
    for (const pt of pts) {
      const sx = this.toScreenX(pt.x);
      const sy = this.toScreenY(pt.y);

      // Subtle halo
      ctx.fillStyle = 'rgba(0, 28, 224, 0.12)';
      ctx.beginPath();
      ctx.arc(sx, sy, 7, 0, Math.PI * 2);
      ctx.fill();

      // Dot
      ctx.fillStyle = '#001CE0';
      ctx.beginPath();
      ctx.arc(sx, sy, 3.5, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  drawModGeometricConstruction() {
    const ctx = this.ctx;
    const steps = this.computeSteps();
    const G = this.getBasePointMod();
    const p = this.p;

    // Plot Base Point G
    this.drawPoint(G.x, G.y, '#001CE0', 'G (Base Point)', 8, true);

    if (this.currentStep === 1) return;

    const currentStepData = steps[steps.length - 1];
    if (currentStepData.isInfinity) {
      ctx.fillStyle = '#D32F2F';
      ctx.font = 'bold 14px Inter, sans-serif';
      ctx.fillText('Point at Infinity (Identity Point O)', 30, 40);
      return;
    }

    const P1 = currentStepData.prevPoint;
    const m = currentStepData.m;
    const intersect = currentStepData.intersect;
    const finalQ = currentStepData.point;

    // Previous point
    if (this.currentStep > 2 && P1) {
      const prevLabel = `${this.currentStep - 1}·G`;
      this.drawPoint(P1.x, P1.y, '#4B5563', prevLabel, 6);
    }

    // Draw wrapped lines across [0, p] x [0, p]
    if (m !== null && P1) {
      this.drawWrappedModLines(m, P1.x, P1.y, p);
    }

    // 3rd Intersection Point (before reflection)
    if (intersect) {
      this.drawPoint(intersect.x, intersect.y, '#DC2626', `-${this.currentStep}·G (Intersection)`, 6);

      // Vertical reflection across y = p/2
      ctx.save();
      ctx.strokeStyle = '#DC2626';
      ctx.lineWidth = 1.8;
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(this.toScreenX(intersect.x), this.toScreenY(intersect.y));
      ctx.lineTo(this.toScreenX(finalQ.x), this.toScreenY(finalQ.y));
      ctx.stroke();
      ctx.restore();
    }

    // Final Public Key Point Q = d·G (mod p)
    const label = `Q = ${this.currentStep}·G (mod ${p})`;
    this.drawPoint(finalQ.x, finalQ.y, '#10B981', label, 9, true, true);
  }

  // Draw modular wrapped line segments y - y1 = m*(x - x1) mod p
  drawWrappedModLines(m, x1, y1, p) {
    const ctx = this.ctx;
    const c = y1 - m * x1;
    const minK = Math.floor(c / p) - 2;
    const maxK = Math.ceil((m * p + c) / p) + 2;

    ctx.save();
    ctx.strokeStyle = 'rgba(0, 28, 224, 0.4)';
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

      // Deduplicate
      const unique = [];
      for (const pt of pts) {
        if (!unique.some(u => Math.abs(u.x - pt.x) < 1e-4 && Math.abs(u.y - pt.y) < 1e-4)) {
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
      ctx.fillStyle = isPublic ? 'rgba(16, 185, 129, 0.2)' : 'rgba(0, 28, 224, 0.18)';
      ctx.beginPath();
      ctx.arc(px, py, radius * 2.2, 0, Math.PI * 2);
      ctx.fill();
    }

    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(px, py, radius, 0, Math.PI * 2);
    ctx.fill();

    ctx.strokeStyle = '#FFFFFF';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Measure label text
    ctx.save();
    ctx.font = 'bold 12px Inter, sans-serif';
    const labelMetrics = ctx.measureText(label);
    const coordText = `(${Number(x.toFixed(2))}, ${Number(y.toFixed(2))})`;
    ctx.font = '10px JetBrains Mono, monospace';
    const coordMetrics = ctx.measureText(coordText);
    const boxW = Math.max(labelMetrics.width, coordMetrics.width) + 14;
    const boxH = 34;
    let boxX = px + radius + 6;
    let boxY = py - 17;

    // Flip to left if too close to right edge
    if (boxX + boxW > this.width - 10) {
      boxX = px - radius - boxW - 6;
    }

    // Pill background
    ctx.fillStyle = 'rgba(255, 255, 255, 0.94)';
    ctx.strokeStyle = isPublic ? 'rgba(16, 185, 129, 0.3)' : 'rgba(0, 28, 224, 0.15)';
    ctx.lineWidth = 1;
    ctx.shadowColor = 'rgba(0, 0, 0, 0.08)';
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

    // Label Text
    ctx.save();
    ctx.fillStyle = '#12141D';
    ctx.font = 'bold 12px Inter, sans-serif';
    ctx.fillText(label, boxX + 7, boxY + 14);

    // Coordinate tag
    ctx.fillStyle = isPublic ? '#059669' : '#4B5563';
    ctx.font = '10px JetBrains Mono, monospace';
    ctx.fillText(coordText, boxX + 7, boxY + 28);
    ctx.restore();
  }
}
