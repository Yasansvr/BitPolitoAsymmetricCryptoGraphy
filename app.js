/**
 * Asymmetric Cryptography Simulator - Application Logic
 * Bitcoin secp256k1 Curve: y^2 = x^3 + 7 (mod p)
 */

import {
  createIdentity,
  encryptECIES,
  decryptECIES,
  decompressPublicKey,
  toHex32,
  toCompressedHex,
  scalarMultiply,
  G
} from './crypto.js';

import { EllipticGraphEngine } from './graph.js';
import {
  PREDEFINED_POINTS,
  assemblePublicKey,
  deriveAddressPipeline,
  getYParity,
  sha256Hex,
  ripemd160Hex,
  base58Encode,
  base58Decode,
  computeChecksum,
  hexToBytes,
  bytesToHex,
  utf8ToBytes
} from './address.js';

// Application State
const state = {
  alice: null,
  bob: null,
  revealedKeys: {
    alice: false,
    bob: false
  },
  soundEnabled: true,
  activeSender: 'ALICE',
  activeRecipient: 'BOB',
  currentEncryption: null,
  pendingTransmissions: {
    ALICE: [],
    BOB: []
  },
  history: [],
  contextMenuTarget: null
};

// Web Audio API Sound Synthesizer
class SoundController {
  constructor() {
    this.ctx = null;
  }

  init() {
    if (!this.ctx && (window.AudioContext || window.webkitAudioContext)) {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      this.ctx = new AudioCtx();
    }
    if (this.ctx && this.ctx.state === 'suspended') {
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
      osc.type = 'sine';
      osc.frequency.setValueAtTime(800, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(400, this.ctx.currentTime + 0.04);
      gain.gain.setValueAtTime(0.12, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + 0.04);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start();
      osc.stop(this.ctx.currentTime + 0.04);
    } catch (e) {}
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

      osc1.type = 'triangle';
      osc2.type = 'sine';
      osc1.frequency.setValueAtTime(520, now);
      osc1.frequency.exponentialRampToValueAtTime(780, now + 0.09);
      osc2.frequency.setValueAtTime(1040, now);
      osc2.frequency.exponentialRampToValueAtTime(1560, now + 0.09);

      gain.gain.setValueAtTime(0.15, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.12);

      osc1.connect(gain);
      osc2.connect(gain);
      gain.connect(this.ctx.destination);

      osc1.start(now);
      osc2.start(now);
      osc1.stop(now + 0.12);
      osc2.stop(now + 0.12);
    } catch (e) {}
  }

  playWhoosh() {
    if (!state.soundEnabled) return;
    this.init();
    if (!this.ctx) return;
    try {
      const now = this.ctx.currentTime;
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(320, now);
      osc.frequency.exponentialRampToValueAtTime(640, now + 0.25);
      gain.gain.setValueAtTime(0.1, now);
      gain.gain.linearRampToValueAtTime(0.18, now + 0.12);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start(now);
      osc.stop(now + 0.35);
    } catch (e) {}
  }

  playSuccessChime() {
    if (!state.soundEnabled) return;
    this.init();
    if (!this.ctx) return;
    try {
      const notes = [523.25, 659.25, 783.99, 1046.50]; // C5, E5, G5, C6
      notes.forEach((freq, i) => {
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        const start = this.ctx.currentTime + i * 0.08;
        osc.type = 'sine';
        osc.frequency.setValueAtTime(freq, start);
        gain.gain.setValueAtTime(0.12, start);
        gain.gain.exponentialRampToValueAtTime(0.001, start + 0.35);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start(start);
        osc.stop(start + 0.35);
      });
    } catch (e) {}
  }
}

const sound = new SoundController();

// Initialize Identies
function initIdentities() {
  state.alice = createIdentity('ALICE');
  state.bob = createIdentity('BOB');
  renderIdentities();
}

// Render identity information onto cards
function renderIdentities() {
  // Alice
  const alicePubEl = document.getElementById('alice-pubkey');
  const alicePrivEl = document.getElementById('alice-privkey');
  if (alicePubEl && state.alice) {
    alicePubEl.textContent = state.alice.publicKeyCompressed;
    alicePubEl.title = `Full Uncompressed:\n${state.alice.publicKeyUncompressed}`;
  }
  if (alicePrivEl && state.alice) {
    if (state.revealedKeys.alice) {
      alicePrivEl.textContent = state.alice.privateKeyHex;
      alicePrivEl.classList.remove('masked');
    } else {
      alicePrivEl.textContent = '••••••••••••••••••••••••••••••••••••••••••••••••';
      alicePrivEl.classList.add('masked');
    }
  }

  // Bob
  const bobPubEl = document.getElementById('bob-pubkey');
  const bobPrivEl = document.getElementById('bob-privkey');
  if (bobPubEl && state.bob) {
    bobPubEl.textContent = state.bob.publicKeyCompressed;
    bobPubEl.title = `Full Uncompressed:\n${state.bob.publicKeyUncompressed}`;
  }
  if (bobPrivEl && state.bob) {
    if (state.revealedKeys.bob) {
      bobPrivEl.textContent = state.bob.privateKeyHex;
      bobPrivEl.classList.remove('masked');
    } else {
      bobPrivEl.textContent = '••••••••••••••••••••••••••••••••••••••••••••••••';
      bobPrivEl.classList.add('masked');
    }
  }

  updateEyeIcons();
}

// Update SVG eye icons based on reveal state
function updateEyeIcons() {
  const aliceEyeBtn = document.getElementById('alice-eye-btn');
  const bobEyeBtn = document.getElementById('bob-eye-btn');

  const eyeOpenSvg = `<svg class="eye-svg" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
  const eyeSlashedSvg = `<svg class="eye-svg" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`;

  if (aliceEyeBtn) {
    aliceEyeBtn.innerHTML = state.revealedKeys.alice ? eyeOpenSvg : eyeSlashedSvg;
    aliceEyeBtn.title = state.revealedKeys.alice ? 'Hide private key' : 'Reveal private key';
  }
  if (bobEyeBtn) {
    bobEyeBtn.innerHTML = state.revealedKeys.bob ? eyeOpenSvg : eyeSlashedSvg;
    bobEyeBtn.title = state.revealedKeys.bob ? 'Hide private key' : 'Reveal private key';
  }
}

// Toggle Private Key Visibility
function togglePrivateKeyReveal(character) {
  const char = character.toLowerCase();
  state.revealedKeys[char] = !state.revealedKeys[char];
  renderIdentities();
  sound.playClick();
}

// Floating Toast Alert (No Emojis)
function showAlert(message) {
  const alertEl = document.getElementById('floating-alert');
  const alertText = document.getElementById('alert-text');
  if (!alertEl || !alertText) return;
  alertText.textContent = message;
  alertEl.classList.add('active');
  clearTimeout(alertEl._timeout);
  alertEl._timeout = setTimeout(() => {
    alertEl.classList.remove('active');
  }, 2600);
}

// Copy to Clipboard (Keeps 📋 copy feedback)
window.copyText = function(text, label = 'Key') {
  navigator.clipboard.writeText(text).then(() => {
    showAlert(`Copied ${label} to clipboard`);
    sound.playClick();
  }).catch(() => {
    showAlert(`Failed to copy`);
  });
};

// Open Custom Context Menu on Right Click
function setupContextMenu() {
  const menu = document.getElementById('custom-context-menu');
  const aliceUnit = document.getElementById('alice-unit');
  const bobUnit = document.getElementById('bob-unit');

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
    menu.style.display = 'flex';

    const titleEl = document.getElementById('context-menu-target-name');
    if (titleEl) titleEl.textContent = character;
  }

  if (aliceUnit) {
    aliceUnit.addEventListener('contextmenu', (e) => handleContextMenu(e, 'ALICE'));
  }
  if (bobUnit) {
    bobUnit.addEventListener('contextmenu', (e) => handleContextMenu(e, 'BOB'));
  }

  window.addEventListener('click', (e) => {
    if (!menu.contains(e.target)) {
      menu.style.display = 'none';
    }
  });

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      menu.style.display = 'none';
      closeComposeDialog();
      closeMathModal();
    }
  });
}

// Context Menu Action Handlers
window.onContextMenuSend = function() {
  const menu = document.getElementById('custom-context-menu');
  menu.style.display = 'none';
  if (state.contextMenuTarget) {
    openComposeDialog(state.contextMenuTarget);
  }
};

window.onContextMenuCopyPub = function() {
  const menu = document.getElementById('custom-context-menu');
  menu.style.display = 'none';
  if (state.contextMenuTarget) {
    const ident = state.contextMenuTarget === 'ALICE' ? state.alice : state.bob;
    copyText(ident.publicKeyCompressed, `${state.contextMenuTarget} Public Key`);
  }
};

// Open Compose Box INLINE (NO modal popup, NO blurred background!)
window.openComposeDialog = function(senderName) {
  state.activeSender = senderName.toUpperCase();
  state.activeRecipient = state.activeSender === 'ALICE' ? 'BOB' : 'ALICE';
  state.currentEncryption = null;

  const stage = document.getElementById('inline-messaging-stage');
  const senderBadge = document.getElementById('compose-sender-badge');
  const pubkeyInput = document.getElementById('recipient-pubkey-input');
  const statusEl = document.getElementById('recipient-key-status');
  const msgInput = document.getElementById('compose-message-input');
  const encryptResultBox = document.getElementById('encrypted-standalone-box');
  const lockBtn = document.getElementById('lock-encrypt-btn');

  if (senderBadge) {
    senderBadge.innerHTML = `Envelope from <b>${state.activeSender}</b>`;
  }

  // Clear or prepare the receiver public key hand-input
  if (pubkeyInput) {
    pubkeyInput.value = '';
    pubkeyInput.focus();
  }
  if (statusEl) {
    const targetName = state.activeRecipient;
    statusEl.className = 'recipient-key-status';
    statusEl.innerHTML = `Copy ${targetName}'s public key above (click 📋) and paste it here`;
  }

  // Hide encrypted result box initially
  if (encryptResultBox) encryptResultBox.style.display = 'none';
  if (lockBtn) {
    lockBtn.disabled = false;
    lockBtn.innerHTML = `<span>Encrypt Message</span>`;
  }

  // Default demonstration message
  if (msgInput && !msgInput.value.trim()) {
    msgInput.value = state.activeSender === 'ALICE' 
      ? `Hey Bob! Here is the secret Bitcoin seed: 5 BTC transfer authorized`
      : `Alice, I received your public key. Confirming transaction hash`;
  }

  // Open inline messaging stage without blurring anything
  if (stage) {
    stage.style.display = 'flex';
    stage.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  sound.playClick();
  startConnectorLineAnimation();
};

window.closeComposeDialog = function() {
  const stage = document.getElementById('inline-messaging-stage');
  if (stage) stage.style.display = 'none';
  stopConnectorLineAnimation();
  clearConnectorLine();
  sound.playClick();
};

// Quick chips message setter
window.setQuickMessage = function(text) {
  const msgInput = document.getElementById('compose-message-input');
  if (msgInput) {
    msgInput.value = text;
    sound.playClick();
  }
};

// Paste Receiver Public Key from Clipboard
window.pasteRecipientKey = async function() {
  const input = document.getElementById('recipient-pubkey-input');
  if (!input) return;

  try {
    const text = await navigator.clipboard.readText();
    if (text) {
      input.value = text.trim();
      validateRecipientKeyInput();
      showAlert('Pasted public key from clipboard');
      sound.playClick();
      return;
    }
  } catch (err) {
    // If browser blocks clipboard API, fallback to auto-filling target receiver key
  }

  // Smart fallback: autofill the target receiver key if clipboard blocked
  const targetObj = state.activeRecipient === 'ALICE' ? state.alice : state.bob;
  input.value = targetObj.publicKeyCompressed;
  validateRecipientKeyInput();
  showAlert(`Filled with ${state.activeRecipient}'s public key`);
  sound.playClick();
};

// Validate Receiver Public Key Input
function validateRecipientKeyInput() {
  const input = document.getElementById('recipient-pubkey-input');
  const statusEl = document.getElementById('recipient-key-status');
  if (!input || !statusEl) return null;

  const hex = input.value.trim().toLowerCase();
  if (!hex) {
    statusEl.className = 'recipient-key-status';
    statusEl.textContent = `Copy the public key from the receiver's card (click 📋) and paste it here`;
    return null;
  }

  if (hex.length !== 66 || (!hex.startsWith('02') && !hex.startsWith('03'))) {
    statusEl.className = 'recipient-key-status error';
    statusEl.textContent = 'Invalid format: must be 66 hex characters starting with 02 or 03';
    return null;
  }

  try {
    const pt = decompressPublicKey(hex);
    if (state.bob && hex === state.bob.publicKeyCompressed.toLowerCase()) {
      statusEl.className = 'recipient-key-status valid';
      statusEl.textContent = 'Verified Receiver: BOB (secp256k1 point verified)';
      state.activeRecipient = 'BOB';
    } else if (state.alice && hex === state.alice.publicKeyCompressed.toLowerCase()) {
      statusEl.className = 'recipient-key-status valid';
      statusEl.textContent = 'Verified Receiver: ALICE (secp256k1 point verified)';
      state.activeRecipient = 'ALICE';
    } else {
      statusEl.className = 'recipient-key-status valid';
      statusEl.textContent = 'Valid external secp256k1 public key';
    }
    return pt;
  } catch (err) {
    statusEl.className = 'recipient-key-status error';
    statusEl.textContent = 'Invalid curve point: does not lie on y² ≡ x³ + 7';
    return null;
  }
}

// Dynamic SVG Connector Line from Sender to Envelope Badge
let connectorAnimFrame = null;

function updateConnectorLine() {
  const stage = document.getElementById('inline-messaging-stage');
  if (!stage || stage.style.display === 'none') {
    clearConnectorLine();
    return;
  }

  const senderUnitId = state.activeSender === 'ALICE' ? 'alice-avatar-frame' : 'bob-avatar-frame';
  const senderEl = document.getElementById(senderUnitId);
  const envelopeBadge = document.getElementById('compose-envelope-badge');
  const pathEl = document.getElementById('connector-path');
  const startDot = document.getElementById('connector-start-dot');
  const endDot = document.getElementById('connector-end-dot');

  if (!senderEl || !envelopeBadge || !pathEl) return;

  const senderRect = senderEl.getBoundingClientRect();
  const envRect = envelopeBadge.getBoundingClientRect();

  const x1 = senderRect.left + senderRect.width / 2;
  const y1 = senderRect.top + senderRect.height / 2;

  const x2 = envRect.left + envRect.width / 2;
  const y2 = envRect.top + envRect.height / 2;

  const midX = (x1 + x2) / 2;
  const d = `M ${x1} ${y1} C ${midX} ${y1 - 30}, ${midX} ${y2 - 15}, ${x2} ${y2}`;

  pathEl.setAttribute('d', d);
  if (startDot) {
    startDot.setAttribute('cx', x1);
    startDot.setAttribute('cy', y1);
    startDot.style.display = 'block';
  }
  if (endDot) {
    endDot.setAttribute('cx', x2);
    endDot.setAttribute('cy', y2);
    endDot.style.display = 'block';
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
  const pathEl = document.getElementById('connector-path');
  const startDot = document.getElementById('connector-start-dot');
  const endDot = document.getElementById('connector-end-dot');
  if (pathEl) pathEl.setAttribute('d', '');
  if (startDot) startDot.style.display = 'none';
  if (endDot) endDot.style.display = 'none';
}

// Encrypt Message (Clicking Lock Button)
window.handleEncryptClick = async function() {
  const msgInput = document.getElementById('compose-message-input');
  const plaintext = msgInput ? msgInput.value.trim() : '';

  if (!plaintext) {
    showAlert('Please enter a message to encrypt');
    return;
  }

  // Validate the entered receiver public key
  const recipientPt = validateRecipientKeyInput();
  if (!recipientPt) {
    showAlert('Please paste the receiver public key first');
    const input = document.getElementById('recipient-pubkey-input');
    if (input) input.focus();
    return;
  }

  const lockBtn = document.getElementById('lock-encrypt-btn');
  if (lockBtn) {
    lockBtn.disabled = true;
    lockBtn.innerHTML = `<span>Computing secp256k1 Point...</span>`;
  }

  sound.playLock();

  try {
    const inputHex = document.getElementById('recipient-pubkey-input').value.trim();
    const encryptionResult = await encryptECIES(plaintext, recipientPt);
    state.currentEncryption = {
      ...encryptionResult,
      plaintext,
      recipientPublicKeyHex: inputHex,
      sender: state.activeSender,
      recipient: state.activeRecipient,
      timestamp: new Date().toLocaleTimeString()
    };

    // Show Box 2 (Encrypted Payload Box)
    const encryptResultBox = document.getElementById('encrypted-standalone-box');
    const cipherDisplay = document.getElementById('encrypted-ciphertext-display');
    const ephemeralKeyDisplay = document.getElementById('encrypted-ephemeral-key');
    const sharedSecretDisplay = document.getElementById('encrypted-shared-secret');

    if (cipherDisplay) cipherDisplay.textContent = encryptionResult.ciphertextHex;
    if (ephemeralKeyDisplay) ephemeralKeyDisplay.textContent = encryptionResult.ephemeralPublicHex;
    if (sharedSecretDisplay) sharedSecretDisplay.textContent = encryptionResult.sharedSecretX;

    if (encryptResultBox) {
      encryptResultBox.style.display = 'flex';
      encryptResultBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    if (lockBtn) {
      lockBtn.disabled = false;
      lockBtn.innerHTML = `<span>Re-Encrypt</span>`;
    }

    showAlert('Message encrypted with Bitcoin curve formula');
  } catch (err) {
    console.error('Encryption error:', err);
    showAlert('Encryption failed: ' + err.message);
    if (lockBtn) {
      lockBtn.disabled = false;
      lockBtn.innerHTML = `<span>Encrypt Message</span>`;
    }
  }
};

// Send Encrypted Message & Launch Flying Envelope
window.handleSendClick = function() {
  if (!state.currentEncryption) {
    showAlert('Please encrypt the message first');
    return;
  }

  // Close compose stage and begin wire transmission
  closeComposeDialog();
  sound.playWhoosh();

  // Create flying envelope element (clean circle badge, no emoji)
  const flyingNode = document.createElement('div');
  flyingNode.className = 'flying-envelope-node';
  flyingNode.innerHTML = `<span style="font-weight:800; font-size:12px; color:var(--color-blue);">ENV</span>`;
  document.body.appendChild(flyingNode);

  // Sender and Receiver bounding coordinates
  const senderAvatarId = state.activeSender === 'ALICE' ? 'alice-avatar-frame' : 'bob-avatar-frame';
  const recipientAvatarId = state.activeRecipient === 'ALICE' ? 'alice-avatar-frame' : 'bob-avatar-frame';

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

  // Update wire status
  const wireBadge = document.getElementById('wire-transit-badge');
  if (wireBadge) {
    wireBadge.classList.add('active');
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
        wireBadge.classList.remove('active');
        wireBadge.innerHTML = `Public Wire: Eavesdropper (Eve) only sees scrambled ciphertext`;
      }
      onMessageArrivedAtReceiver();
    }
  }

  requestAnimationFrame(animateFlight);
};

// Message Arrived at Receiver: Show Encrypted Message Box on Receiver Card
function onMessageArrivedAtReceiver() {
  sound.playClick();
  const receiverName = state.activeRecipient;
  const containerId = receiverName === 'ALICE' ? 'alice-incoming-container' : 'bob-incoming-container';
  const container = document.getElementById(containerId);
  if (!container) return;

  const enc = state.currentEncryption;
  const transmissionId = 'msg_' + Date.now();
  state.pendingTransmissions[receiverName].push({ id: transmissionId, data: enc });

  const incomingCard = document.createElement('div');
  incomingCard.className = 'incoming-encrypted-card';
  incomingCard.id = transmissionId;
  incomingCard.innerHTML = `
    <div class="incoming-card-header">
      <span>Incoming Encrypted Message</span>
      <button class="key-btn" onclick="document.getElementById('${transmissionId}').remove()" title="Dismiss">✕</button>
    </div>
    <div class="incoming-card-hint">
      From <b>${enc.sender}</b> • Encrypted with ${receiverName}'s public key Q
    </div>
    <div class="cipher-mini-box" title="Ciphertext:\n${enc.ciphertextHex}">
      ${enc.ciphertextHex}
    </div>
    <div class="incoming-card-hint">
      Only ${receiverName}'s secret private key <b>d</b> can compute <b>S = d · R</b> to decrypt this ciphertext.
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

// Receiver Decrypts Message with Private Key (d)
window.decryptReceivedMessage = async function(receiverName, transmissionId) {
  const pending = state.pendingTransmissions[receiverName].find(p => p.id === transmissionId);
  const enc = pending ? pending.data : state.currentEncryption;
  if (!enc) return;

  const receiverIdentity = receiverName === 'ALICE' ? state.alice : state.bob;

  let plaintext = '';
  try {
    plaintext = await decryptECIES(enc.payload, receiverIdentity.privateKey);
  } catch (err) {
    console.error('Decryption failed:', err);
    plaintext = '[Decryption failed: signature mismatch]';
  }

  sound.playSuccessChime();

  const card = document.getElementById(transmissionId);
  if (card) {
    card.innerHTML = `
      <div class="incoming-card-header">
        <span>Decrypted by ${receiverName}</span>
        <button class="key-btn" onclick="document.getElementById('${transmissionId}').remove()" title="Dismiss">✕</button>
      </div>
      <div class="decrypted-result-view">
        <div class="decrypted-result-text">"${plaintext}"</div>
        <div class="decrypted-math-proof">
          Unlocked: S = d · R = ${enc.sharedSecretX.slice(0, 16)}...
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

  // Add to History Log
  addHistoryItem({
    sender: enc.sender,
    recipient: receiverName,
    plaintext: plaintext,
    ciphertext: enc.ciphertextHex,
    time: enc.timestamp
  });

  showAlert(`Message decrypted by ${receiverName} using private key`);
};

// Add Item to History Section
function addHistoryItem(item) {
  state.history.unshift(item);
  const listEl = document.getElementById('history-list');
  const countEl = document.getElementById('history-count');
  if (!listEl) return;

  if (countEl) countEl.textContent = `${state.history.length} messages`;

  const itemEl = document.createElement('div');
  itemEl.className = 'history-item';
  itemEl.innerHTML = `
    <div class="history-sender-badge">
      <span>${item.sender}</span>
      <span style="color:var(--text-dim); font-size:11px;">➔</span>
      <span>${item.recipient}</span>
    </div>
    <div class="history-msg-content" title="${item.plaintext}">
      "${item.plaintext}"
    </div>
    <div style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted); max-width:140px; overflow:hidden; text-overflow:ellipsis;" title="Ciphertext:\n${item.ciphertext}">
      ${item.ciphertext.slice(0, 14)}...
    </div>
    <div class="history-status-tag">Decrypted</div>
  `;

  listEl.prepend(itemEl);
}

// Toggle Sound
window.toggleSound = function() {
  state.soundEnabled = !state.soundEnabled;
  const btn = document.getElementById('sound-toggle-btn');
  if (btn) {
    btn.innerHTML = state.soundEnabled ? 'Sound: ON' : 'Sound: OFF';
  }
  sound.playClick();
};

// ==========================================================================
// Desmos-Style 2D Elliptic Curve Graph Explorer & Stepper
// ==========================================================================

let graphEngine = null;

// Switch between Simulator View, Desmos 2D Graph Guide View, and Point to Address View
window.switchView = function(viewName) {
  const simView = document.getElementById('view-simulator');
  const graphView = document.getElementById('view-graph');
  const addressView = document.getElementById('view-point-address');

  const tabSim = document.getElementById('tab-nav-sim');
  const tabGuide = document.getElementById('nav-guide-btn');
  const tabAddress = document.getElementById('tab-nav-address');

  // Hide all views first
  if (simView) simView.style.display = 'none';
  if (graphView) graphView.style.display = 'none';
  if (addressView) addressView.style.display = 'none';

  // Clear active tab button styling
  if (tabSim) tabSim.classList.remove('active');
  if (tabGuide) tabGuide.classList.remove('active');
  if (tabAddress) tabAddress.classList.remove('active');

  if (viewName === 'graph') {
    if (graphView) graphView.style.display = 'flex';
    if (tabGuide) tabGuide.classList.add('active');
    
    // Initialize or resize graph engine
    initGraphEngine();
    setTimeout(() => {
      if (graphEngine) {
        graphEngine.resize();
        graphEngine.render();
      }
    }, 50);

    window.scrollTo({ top: 0, behavior: 'smooth' });
    sound.playClick();
  } else if (viewName === 'address') {
    if (addressView) addressView.style.display = 'flex';
    if (tabAddress) tabAddress.classList.add('active');
    if (graphEngine && graphEngine.isPlaying) {
      graphEngine.stopPlay();
    }
    initAddressGame();
    window.scrollTo({ top: 0, behavior: 'smooth' });
    sound.playClick();
  } else {
    // Default: simulator view
    if (simView) simView.style.display = 'flex';
    if (tabSim) tabSim.classList.add('active');
    if (graphEngine && graphEngine.isPlaying) {
      graphEngine.stopPlay();
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
    sound.playClick();
  }
};

// Toggle Cryptography Guide View from single header button
window.toggleGuideView = function() {
  const graphView = document.getElementById('view-graph');
  const isGraphVisible = graphView && graphView.style.display !== 'none';
  if (isGraphVisible) {
    window.switchView('simulator');
  } else {
    window.switchView('graph');
  }
};

window.openMathModal = function() {
  window.switchView('graph');
};

window.closeMathModal = function() {
  window.switchView('simulator');
};

// Initialize Desmos Graph Engine
function initGraphEngine() {
  const canvas = document.getElementById('desmos-canvas');
  if (!canvas) return;

  if (!graphEngine) {
    graphEngine = new EllipticGraphEngine(canvas, {
      domain: 'real',
      a: 0,
      b: 7,
      p: 23,
      xG: -1.5,
      onStateChange: handleGraphStateChange
    });
    window.graphEngine = graphEngine;
  }
}

// Handle State Change from Graph Engine
function handleGraphStateChange(stateData) {
  const { domain, p, a, b, xG, currentStep, isPlaying, currentData, discriminant } = stateData;

  // 1. Update Parameters & Formula Badge
  const valA = document.getElementById('param-a-value');
  const valB = document.getElementById('param-b-value');
  const valXg = document.getElementById('param-xg-value');
  const sliderA = document.getElementById('param-a-slider');
  const sliderB = document.getElementById('param-b-slider');
  const sliderXg = document.getElementById('param-xg-slider');
  const formulaText = document.getElementById('graph-formula-text');
  const discTag = document.getElementById('graph-discriminant-tag');

  if (valA) valA.textContent = a.toFixed(1);
  if (valB) valB.textContent = b.toFixed(1);
  if (valXg) valXg.textContent = xG.toFixed(1);

  if (sliderA && parseFloat(sliderA.value) !== a) sliderA.value = a;
  if (sliderB && parseFloat(sliderB.value) !== b) sliderB.value = b;
  if (sliderXg && parseFloat(sliderXg.value) !== xG) sliderXg.value = xG;

  if (formulaText) {
    let eq = 'y² ≡ x³';
    if (a !== 0) eq += ` ${a > 0 ? '+' : '-'} ${Math.abs(a)}x`;
    if (b !== 0) eq += ` ${b > 0 ? '+' : '-'} ${Math.abs(b)}`;
    if (domain === 'mod') {
      eq += ` (mod ${p})`;
    } else {
      if (a === 0 && b === 7) eq += ' (Bitcoin)';
    }
    formulaText.textContent = eq;
  }

  if (discTag) {
    if (domain === 'mod') {
      discTag.textContent = `Finite Field F_${p} • Discrete Points on Curve`;
      discTag.style.color = 'var(--color-blue)';
    } else {
      if (Math.abs(discriminant) < 1e-4) {
        discTag.textContent = 'Singular curve (Δ = 0, node or cusp)';
        discTag.style.color = '#DC2626';
      } else {
        discTag.textContent = `Non-singular curve (Δ = ${Math.round(discriminant)})`;
        discTag.style.color = 'var(--text-muted)';
      }
    }
  }

  // 2. Update Stepper Card
  const stepperBadge = document.getElementById('stepper-badge');
  const privKeyEl = document.getElementById('stepper-private-key');
  const pubPointEl = document.getElementById('stepper-public-point');
  const playBtn = document.getElementById('step-play-btn');

  if (stepperBadge) {
    if (currentStep === 5) {
      stepperBadge.textContent = 'Step d = 5 (5G Step)';
    } else {
      stepperBadge.textContent = `Step d = ${currentStep}`;
    }
  }

  if (privKeyEl) {
    privKeyEl.textContent = `d = ${currentStep} (Scalar)`;
  }

  if (pubPointEl) {
    if (currentData && currentData.point) {
      if (domain === 'mod') {
        pubPointEl.textContent = `(${currentData.point.x}, ${currentData.point.y}) mod ${p}`;
      } else {
        pubPointEl.textContent = `(${currentData.point.x.toFixed(2)}, ${currentData.point.y.toFixed(2)})`;
      }
    } else {
      pubPointEl.textContent = 'Point at Infinity O';
    }
  }

  if (playBtn) {
    playBtn.textContent = isPlaying ? 'Pause' : 'Auto Play';
  }

  // Sync direct scalar slider
  const stepSlider = document.getElementById('stepper-step-slider');
  const stepSliderVal = document.getElementById('stepper-step-slider-val');
  if (stepSlider && parseInt(stepSlider.value, 10) !== currentStep) {
    stepSlider.value = currentStep;
  }
  if (stepSliderVal) {
    stepSliderVal.textContent = `d = ${currentStep}`;
  }

  // 3. Update Step Math Breakdown
  const mathBreakdown = document.getElementById('step-math-breakdown');
  if (mathBreakdown && currentData) {
    if (domain === 'mod') {
      // Modular Math Explanations
      if (currentData.isInfinity) {
        mathBreakdown.innerHTML = `
          <div class="step-math-box" style="border-left: 3px solid #DC2626;">
            <b>Step ${currentStep} (Identity Element):</b> ${currentStep}·G = 𝒪 (Point at Infinity)<br>
            Group Order Reached: The curve forms a finite cyclic group of order ${currentStep}.
          </div>
          <div class="step-crypto-hint">
            <b>Cyclic Wrap-Around:</b> In finite field cryptography, points generate a cyclic subgroup. Adding G to the identity 𝒪 yields G again! Click <b>Next Step (+G)</b> to see the cycle restart.
          </div>
        `;
      } else if (currentStep === 1) {
        mathBreakdown.innerHTML = `
          <div class="step-math-box">
            Base Point G = (${currentData.point.x}, ${currentData.point.y})<br>
            Public Point Q = 1 · G = (${currentData.point.x}, ${currentData.point.y}) mod ${p}
          </div>
          <div class="step-crypto-hint">
            <b>Finite Field F_${p}:</b> All coordinates are integers in [0, ${p - 1}]. Click <b>Next Step (+G)</b> to compute scalar multiplication modulo ${p}!
          </div>
        `;
      } else if (currentStep === 5 && currentData.intersect) {
        mathBreakdown.innerHTML = `
          <div class="step-math-box" style="border-left: 3px solid #10B981;">
            <b>Step 5:</b> 5·G = 4·G + G (mod ${p})<br>
            Modular slope m = (y_G - y_4) · (x_G - x_4)⁻¹ mod ${p} = ${currentData.m}<br>
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
            <b>Step 2 (Modular Doubling):</b> 2·G = G + G (mod ${p})<br>
            Modular slope m = (3x₁² + a) · (2y₁)⁻¹ mod ${p} = ${currentData.m}<br>
            Intersection -2G = (${currentData.intersect.x}, ${currentData.intersect.y})<br>
            Reflected to +2G = (${currentData.point.x}, ${currentData.point.y})
          </div>
          <div class="step-crypto-hint">
            <b>Modular Doubling:</b> The tangent line wraps around the borders of the field box [0, ${p}] and hits the curve at -2G, which reflects vertically across y = ${p}/2 to yield <b>Q = 2·G</b>.
          </div>
        `;
      } else if (currentData.point) {
        const intDesc = currentData.intersect
          ? `Intersection -${currentStep}·G = (${currentData.intersect.x}, ${currentData.intersect.y})<br>`
          : '';
        const slopeDesc = currentData.m !== null ? `Modular slope m = ${currentData.m}<br>` : '';
        mathBreakdown.innerHTML = `
          <div class="step-math-box">
            <b>Step ${currentStep} (Modular Addition):</b> ${currentStep}·G (mod ${p})<br>
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
      // Real (Continuous R) Math Explanations
      if (currentData.isInfinity) {
        mathBreakdown.innerHTML = `
          <div class="step-math-box" style="border-left: 3px solid #DC2626;">
            <b>Step ${currentStep}:</b> Point at Infinity 𝒪 (Identity Element)
          </div>
        `;
      } else if (currentStep === 1) {
        mathBreakdown.innerHTML = `
          <div class="step-math-box">
            Base Generator Point G = (${currentData.point.x.toFixed(2)}, ${currentData.point.y.toFixed(2)})<br>
            Public Point Q = 1 · G = (${currentData.point.x.toFixed(2)}, ${currentData.point.y.toFixed(2)})
          </div>
          <div class="step-crypto-hint">
            <b>How it starts:</b> The private key is scalar <b>d = 1</b>. The public key is point <b>Q = 1·G</b> on the curve. Click <b>Next Step (+G)</b> or <b>5G Step</b>!
          </div>
        `;
      } else if (currentStep === 5) {
        mathBreakdown.innerHTML = `
          <div class="step-math-box" style="border-left: 3px solid #10B981;">
            <b>Step 5 (5G Step):</b> 5·G = 4·G + G<br>
            Secant slope m = (y₁ - y₄) / (x₁ - x₄) = ${currentData.m.toFixed(3)}<br>
            Intersection -5G = (${currentData.intersect.x.toFixed(2)}, ${currentData.intersect.y.toFixed(2)})<br>
            Reflected to +5G = (${currentData.point.x.toFixed(2)}, ${currentData.point.y.toFixed(2)})
          </div>
          <div class="step-crypto-hint">
            <b>5G Public Point:</b> The private key scalar <b>d = 5</b> produces the public key point <b>Q = 5·G = (${currentData.point.x.toFixed(2)}, ${currentData.point.y.toFixed(2)})</b> through 4 successive point addition & reflection steps.
          </div>
        `;
      } else if (currentData.isDouble) {
        mathBreakdown.innerHTML = `
          <div class="step-math-box">
            <b>Step 2 (Point Doubling):</b> 2·G = G + G<br>
            Tangent slope m = (3x₁² + a) / (2y₁) = ${currentData.m.toFixed(3)}<br>
            Intersection -2G = (${currentData.intersect.x.toFixed(2)}, ${currentData.intersect.y.toFixed(2)})<br>
            Reflected to +2G = (${currentData.point.x.toFixed(2)}, ${currentData.point.y.toFixed(2)})
          </div>
          <div class="step-crypto-hint">
            <b>Tangent Doubling:</b> Adding a point to itself draws a tangent line touching the curve at G. The line hits the curve at -2G, which reflects across the X-axis to yield <b>Q = 2·G</b>.
          </div>
        `;
      } else if (currentData.point) {
        mathBreakdown.innerHTML = `
          <div class="step-math-box">
            <b>Step ${currentStep} (Point Addition):</b> ${currentStep}·G = ${currentStep - 1}·G + G<br>
            Secant slope m = (y₂ - y₁) / (x₂ - x₁) = ${currentData.m.toFixed(3)}<br>
            Intersection -${currentStep}·G = (${currentData.intersect.x.toFixed(2)}, ${currentData.intersect.y.toFixed(2)})<br>
            Reflected to +${currentStep}·G = (${currentData.point.x.toFixed(2)}, ${currentData.point.y.toFixed(2)})
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

// Domain Switcher (Continuous Real vs Modulo Field)
window.setGraphDomain = function(domain) {
  if (!graphEngine) return;
  graphEngine.setDomain(domain);

  const tabReal = document.getElementById('tab-domain-real');
  const tabMod = document.getElementById('tab-domain-mod');
  const groupXg = document.getElementById('group-param-xg');
  const groupMod = document.getElementById('group-param-mod');

  if (domain === 'mod') {
    tabMod?.classList.add('active');
    tabReal?.classList.remove('active');
    if (groupXg) groupXg.style.display = 'none';
    if (groupMod) groupMod.style.display = 'flex';
  } else {
    tabReal?.classList.add('active');
    tabMod?.classList.remove('active');
    if (groupXg) groupXg.style.display = 'flex';
    if (groupMod) groupMod.style.display = 'none';
  }
  sound.playClick();
};

// Set Modulo Prime p
window.setPrimeMod = function(p) {
  if (!graphEngine) return;
  graphEngine.setPrime(p);

  [17, 23, 43, 67].forEach(prime => {
    const btn = document.getElementById(`prime-btn-${prime}`);
    if (btn) {
      if (prime === p) btn.classList.add('primary');
      else btn.classList.remove('primary');
    }
  });

  const valEl = document.getElementById('param-mod-value');
  if (valEl) valEl.textContent = `p = ${p}`;
  sound.playClick();
};

// Jump directly to 5G Step
window.setStepperStep = function(val) {
  if (!graphEngine) return;
  graphEngine.setStep(parseInt(val, 10));
  sound?.playClick();
};

// Sliders and Stepper Global Handlers
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

// Global initialization
window.addEventListener('DOMContentLoaded', () => {
  initIdentities();
  setupContextMenu();

  // Eye buttons
  const aliceEye = document.getElementById('alice-eye-btn');
  const bobEye = document.getElementById('bob-eye-btn');
  if (aliceEye) aliceEye.addEventListener('click', () => togglePrivateKeyReveal('alice'));
  if (bobEye) bobEye.addEventListener('click', () => togglePrivateKeyReveal('bob'));

  // Recipient input listener for live validation
  const pubkeyInput = document.getElementById('recipient-pubkey-input');
  if (pubkeyInput) {
    pubkeyInput.addEventListener('input', () => validateRecipientKeyInput());
  }

  // Window resize listener
  window.addEventListener('resize', () => {
    updateConnectorLine();
    if (graphEngine) graphEngine.resize();
  });

  // Initialize Point to Address Game if element exists
  const addrStage = document.getElementById('view-point-address');
  if (addrStage) {
    initAddressGame();
  }
});

// ==========================================================================
// Point to Address Game Controller & Standalone Cryptography Tools
// ==========================================================================

const addressGameState = {
  currentPresetId: 'wiki_standard',
  xHex: '50863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352',
  yHex: '2CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6',
  format: 'compressed', // 'compressed' | 'uncompressed'
  currentStep: 1,
  step1Completed: false,
  step2Completed: false,
  step3Completed: false,
  step4Completed: false,
  step5Completed: false,
  step6Completed: false,
  assembledPubkey: '',
  sha256Digest: '',
  ripemd160Digest: '',
  versionByte: '00',
  versionedPayload: '',
  csHash1: '',
  csHash2: '',
  checksum: '',
  finalPayload: '',
  finalAddress: '',
  tools: {
    shaMode: 'hex',
    ripeMode: 'hex',
    b58Mode: 'encode'
  }
};

// Initialize Point to Address Game
window.initAddressGame = function() {
  // Update Coordinates Display
  const xEl = document.getElementById('p2a-x-val');
  const yEl = document.getElementById('p2a-y-val');
  if (xEl) xEl.textContent = addressGameState.xHex.toUpperCase();
  if (yEl) yEl.textContent = addressGameState.yHex.toUpperCase();

  // Parity Analysis of Y
  const parity = getYParity(addressGameState.yHex);
  const parityBadge = document.getElementById('p2a-parity-badge');
  const parityDetails = document.getElementById('p2a-parity-details');
  const challengeYChar = document.getElementById('p2a-challenge-y-char');

  if (parityBadge) {
    parityBadge.className = `p2a-parity-badge ${parity.isEven ? 'even' : 'odd'}`;
    parityBadge.textContent = parity.isEven ? 'Y is EVEN' : 'Y is ODD';
  }

  if (parityDetails) {
    parityDetails.innerHTML = `Last hex digit of Y is <b>'${parity.lastDigit.toUpperCase()}'</b> (${parity.isEven ? 'even' : 'odd'}). Compressed prefix = <code>${parity.prefix}</code>.`;
  }

  if (challengeYChar) {
    challengeYChar.textContent = parity.lastDigit.toUpperCase();
  }

  // Update Format Selection cards
  const cardComp = document.getElementById('format-card-comp');
  const cardUncomp = document.getElementById('format-card-uncomp');
  const radioComp = document.getElementById('radio-comp');
  const radioUncomp = document.getElementById('radio-uncomp');
  const parityChallengeBox = document.getElementById('p2a-parity-challenge-box');

  if (addressGameState.format === 'compressed') {
    if (cardComp) cardComp.classList.add('selected');
    if (cardUncomp) cardUncomp.classList.remove('selected');
    if (radioComp) radioComp.checked = true;
    if (parityChallengeBox) parityChallengeBox.style.display = 'flex';
  } else {
    if (cardUncomp) cardUncomp.classList.add('selected');
    if (cardComp) cardComp.classList.remove('selected');
    if (radioUncomp) radioUncomp.checked = true;
    if (parityChallengeBox) parityChallengeBox.style.display = 'none';
  }

  // Assemble Step 1 Public Key
  renderStep1Assembly();

  // Highlight active step
  window.jumpToAddressStep(addressGameState.currentStep || 1);
};

// Select Point Preset
window.selectPointPreset = function(presetId) {
  addressGameState.currentPresetId = presetId;

  // Update Preset Button Active Styles
  const presetButtons = document.querySelectorAll('.p2a-preset-btn');
  presetButtons.forEach(btn => btn.classList.remove('active'));
  const activeBtn = document.getElementById(`btn-preset-${presetId.replace('_', '-')}`) ||
                    document.getElementById(`btn-preset-${presetId}`);
  if (activeBtn) activeBtn.classList.add('active');

  const customDrawer = document.getElementById('p2a-custom-drawer');

  if (presetId === 'custom') {
    if (customDrawer) customDrawer.style.display = 'block';
    const inX = document.getElementById('p2a-input-custom-x');
    const inY = document.getElementById('p2a-input-custom-y');
    if (inX) inX.value = addressGameState.xHex;
    if (inY) inY.value = addressGameState.yHex;
    return;
  } else {
    if (customDrawer) customDrawer.style.display = 'none';
  }

  if (presetId === 'alice') {
    if (state.alice && state.alice.keyPair) {
      addressGameState.xHex = toHex32(state.alice.keyPair.publicPoint.x);
      addressGameState.yHex = toHex32(state.alice.keyPair.publicPoint.y);
    } else {
      showAlert('Alice identity initializing...');
      return;
    }
  } else if (presetId === 'bob') {
    if (state.bob && state.bob.keyPair) {
      addressGameState.xHex = toHex32(state.bob.keyPair.publicPoint.x);
      addressGameState.yHex = toHex32(state.bob.keyPair.publicPoint.y);
    } else {
      showAlert('Bob identity initializing...');
      return;
    }
  } else {
    const preset = PREDEFINED_POINTS.find(p => p.id === presetId);
    if (preset) {
      addressGameState.xHex = preset.x;
      addressGameState.yHex = preset.y;
    }
  }

  // Reset steps state for new coordinates
  window.resetAddressGame(false);
  window.initAddressGame();
  showAlert(`Loaded Point: ${presetId.replace('_', ' ').toUpperCase()}`);
  sound.playClick();
};

// Apply Custom (X, Y) Coordinates
window.applyCustomCoordinates = function() {
  const inX = document.getElementById('p2a-input-custom-x');
  const inY = document.getElementById('p2a-input-custom-y');
  if (!inX || !inY) return;

  const rawX = inX.value.trim().replace(/[^0-9a-fA-F]/g, '');
  const rawY = inY.value.trim().replace(/[^0-9a-fA-F]/g, '');

  if (rawX.length !== 64 || rawY.length !== 64) {
    showAlert('Error: X and Y must each be 64 hexadecimal characters (32 bytes).');
    return;
  }

  addressGameState.xHex = rawX;
  addressGameState.yHex = rawY;

  const customDrawer = document.getElementById('p2a-custom-drawer');
  if (customDrawer) customDrawer.style.display = 'none';

  window.resetAddressGame(false);
  window.initAddressGame();
  showAlert('Custom coordinates loaded successfully');
  sound.playLock();
};

// Set Public Key Format (Compressed vs Uncompressed)
window.setKeyFormat = function(format) {
  addressGameState.format = format;
  const parityChallengeBox = document.getElementById('p2a-parity-challenge-box');
  const cardComp = document.getElementById('format-card-comp');
  const cardUncomp = document.getElementById('format-card-uncomp');

  if (format === 'compressed') {
    if (cardComp) cardComp.classList.add('selected');
    if (cardUncomp) cardUncomp.classList.remove('selected');
    if (parityChallengeBox) parityChallengeBox.style.display = 'flex';
  } else {
    if (cardUncomp) cardUncomp.classList.add('selected');
    if (cardComp) cardComp.classList.remove('selected');
    if (parityChallengeBox) parityChallengeBox.style.display = 'none';
  }

  // Invalidate subsequent completed steps since format changed
  addressGameState.step2Completed = false;
  addressGameState.step3Completed = false;
  addressGameState.step4Completed = false;
  addressGameState.step5Completed = false;
  addressGameState.step6Completed = false;

  const navPills = document.querySelectorAll('.p2a-nav-pill');
  navPills.forEach((p, idx) => {
    if (idx > 0) p.classList.remove('completed');
  });

  const btnNext2 = document.getElementById('p2a-btn-next-step2');
  const btnNext3 = document.getElementById('p2a-btn-next-step3');
  const btnNext4 = document.getElementById('p2a-btn-next-step4');
  const btnNext5 = document.getElementById('p2a-btn-next-step5');
  if (btnNext2) btnNext2.disabled = true;
  if (btnNext3) btnNext3.disabled = true;
  if (btnNext4) btnNext4.disabled = true;
  if (btnNext5) btnNext5.disabled = true;

  renderStep1Assembly();
  sound.playClick();
};

// Parity Prefix Guess
window.handlePrefixGuess = function(guessedPrefix) {
  const parity = getYParity(addressGameState.yHex);
  const btn02 = document.getElementById('btn-prefix-02');
  const btn03 = document.getElementById('btn-prefix-03');
  const feedback = document.getElementById('p2a-prefix-feedback');

  if (btn02) btn02.classList.remove('correct', 'incorrect');
  if (btn03) btn03.classList.remove('correct', 'incorrect');

  const chosenBtn = guessedPrefix === '02' ? btn02 : btn03;
  const isCorrect = guessedPrefix === parity.prefix;

  if (chosenBtn) {
    chosenBtn.classList.add(isCorrect ? 'correct' : 'incorrect');
  }

  if (feedback) {
    feedback.style.display = 'block';
    feedback.className = `p2a-challenge-feedback ${isCorrect ? 'success' : 'error'}`;
    if (isCorrect) {
      feedback.innerHTML = `Correct! Y ends in '${parity.lastDigit.toUpperCase()}' (${parity.isEven ? 'even' : 'odd'}), so prefix <code>${parity.prefix}</code> is required.`;
      sound.playLock();
    } else {
      feedback.innerHTML = `Incorrect. Y ends in '${parity.lastDigit.toUpperCase()}' (${parity.isEven ? 'even' : 'odd'}), so prefix <code>${parity.prefix}</code> must be used instead.`;
      sound.playClick();
    }
  }
};

// Render Step 1 Public Key Assembly
function renderStep1Assembly() {
  const res = assemblePublicKey(addressGameState.xHex, addressGameState.yHex, addressGameState.format);
  addressGameState.assembledPubkey = res.pubkey;

  const displayEl = document.getElementById('p2a-assembled-pubkey');
  const bytesBadge = document.getElementById('p2a-pubkey-bytes-badge');

  if (bytesBadge) {
    bytesBadge.textContent = `${res.byteLength} Bytes (${res.pubkey.length} hex)`;
  }

  if (displayEl) {
    if (res.format === 'compressed') {
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

  // Pre-fill Step 2 input
  const step2In = document.getElementById('p2a-step2-input');
  if (step2In) step2In.value = res.pubkey.toUpperCase();
}

// Complete Step 1 and Advance
window.completeStep1AndAdvance = function() {
  addressGameState.step1Completed = true;
  const pill1 = document.getElementById('p2a-nav-step-1');
  if (pill1) pill1.classList.add('completed');

  const step2In = document.getElementById('p2a-step2-input');
  if (step2In) step2In.value = addressGameState.assembledPubkey.toUpperCase();

  window.jumpToAddressStep(2);
  sound.playClick();
};

// Step 2: SHA-256
window.runStep2Sha256 = function() {
  const inEl = document.getElementById('p2a-step2-input');
  const val = inEl ? inEl.value.trim().toLowerCase() : addressGameState.assembledPubkey;

  try {
    const hashHex = sha256Hex(val);
    addressGameState.sha256Digest = hashHex;

    const outEl = document.getElementById('p2a-step2-output');
    if (outEl) outEl.textContent = hashHex.toUpperCase();

    const btnNext = document.getElementById('p2a-btn-next-step2');
    if (btnNext) btnNext.disabled = false;

    // Pre-fill Step 3 input
    const step3In = document.getElementById('p2a-step3-input');
    if (step3In) step3In.value = hashHex.toUpperCase();

    sound.playLock();
  } catch (err) {
    showAlert('Error computing SHA-256: ' + err.message);
  }
};

window.completeStep2AndAdvance = function() {
  addressGameState.step2Completed = true;
  const pill2 = document.getElementById('p2a-nav-step-2');
  if (pill2) pill2.classList.add('completed');

  const step3In = document.getElementById('p2a-step3-input');
  if (step3In) step3In.value = addressGameState.sha256Digest.toUpperCase();

  window.jumpToAddressStep(3);
  sound.playClick();
};

// Step 3: RIPEMD-160 (PubKeyHash)
window.runStep3Ripemd160 = function() {
  const inEl = document.getElementById('p2a-step3-input');
  const val = inEl ? inEl.value.trim().toLowerCase() : addressGameState.sha256Digest;

  try {
    const hashHex = ripemd160Hex(val);
    addressGameState.ripemd160Digest = hashHex;

    const outEl = document.getElementById('p2a-step3-output');
    if (outEl) outEl.textContent = hashHex.toUpperCase();

    const btnNext = document.getElementById('p2a-btn-next-step3');
    if (btnNext) btnNext.disabled = false;

    sound.playLock();
  } catch (err) {
    showAlert('Error computing RIPEMD-160: ' + err.message);
  }
};

window.completeStep3AndAdvance = function() {
  addressGameState.step3Completed = true;
  const pill3 = document.getElementById('p2a-nav-step-3');
  if (pill3) pill3.classList.add('completed');

  window.jumpToAddressStep(4);
  sound.playClick();
};

// Step 4: Network Version Byte 0x00
window.runStep4AddVersion = function() {
  if (!addressGameState.ripemd160Digest) {
    showAlert('Please complete Step 3 (RIPEMD-160) first!');
    return;
  }

  addressGameState.versionByte = '00';
  addressGameState.versionedPayload = '00' + addressGameState.ripemd160Digest;

  const outEl = document.getElementById('p2a-step4-output');
  const rawEl = document.getElementById('p2a-step4-output-raw');

  if (outEl) {
    outEl.innerHTML = `
      <span class="hex-chip version" title="Bitcoin Mainnet Version Byte (00)">00</span>
      <span class="hex-chip hash160" title="PubKeyHash (20 bytes)">${addressGameState.ripemd160Digest.toUpperCase()}</span>
    `;
  }
  if (rawEl) {
    rawEl.textContent = addressGameState.versionedPayload.toUpperCase();
  }

  const btnNext = document.getElementById('p2a-btn-next-step4');
  if (btnNext) btnNext.disabled = false;

  sound.playLock();
};

window.completeStep4AndAdvance = function() {
  addressGameState.step4Completed = true;
  const pill4 = document.getElementById('p2a-nav-step-4');
  if (pill4) pill4.classList.add('completed');

  window.jumpToAddressStep(5);
  sound.playClick();
};

// Step 5: Double SHA-256 Checksum
window.runStep5Checksum = function() {
  if (!addressGameState.versionedPayload) {
    showAlert('Please complete Step 4 first!');
    return;
  }

  try {
    const payloadBytes = hexToBytes(addressGameState.versionedPayload);
    const csHash1 = sha256Hex(payloadBytes);
    const csHash2 = sha256Hex(hexToBytes(csHash1));
    const checksum = csHash2.substring(0, 8);
    const finalPayload = addressGameState.versionedPayload + checksum;

    addressGameState.csHash1 = csHash1;
    addressGameState.csHash2 = csHash2;
    addressGameState.checksum = checksum;
    addressGameState.finalPayload = finalPayload;

    // Show breakdown
    const breakdown = document.getElementById('p2a-checksum-breakdown');
    const h1El = document.getElementById('p2a-cs-hash1');
    const h2El = document.getElementById('p2a-cs-hash2');
    const csExtractedEl = document.getElementById('p2a-cs-extracted');

    if (breakdown) breakdown.style.display = 'flex';
    if (h1El) h1El.textContent = csHash1.toUpperCase();
    if (h2El) h2El.textContent = csHash2.toUpperCase();
    if (csExtractedEl) csExtractedEl.textContent = checksum.toUpperCase();

    // Show 25-byte payload
    const outEl = document.getElementById('p2a-step5-output');
    const rawEl = document.getElementById('p2a-step5-output-raw');

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

    // Pre-fill Step 6 input
    const step6In = document.getElementById('p2a-step6-input');
    if (step6In) step6In.value = finalPayload.toUpperCase();

    const btnNext = document.getElementById('p2a-btn-next-step5');
    if (btnNext) btnNext.disabled = false;

    sound.playLock();
  } catch (err) {
    showAlert('Error calculating checksum: ' + err.message);
  }
};

window.completeStep5AndAdvance = function() {
  addressGameState.step5Completed = true;
  const pill5 = document.getElementById('p2a-nav-step-5');
  if (pill5) pill5.classList.add('completed');

  const step6In = document.getElementById('p2a-step6-input');
  if (step6In) step6In.value = addressGameState.finalPayload.toUpperCase();

  window.jumpToAddressStep(6);
  sound.playClick();
};

// Step 6: Base58 Encoding
window.runStep6Base58 = function() {
  const inEl = document.getElementById('p2a-step6-input');
  const val = inEl ? inEl.value.trim().toLowerCase() : addressGameState.finalPayload;

  try {
    const payloadBytes = hexToBytes(val);
    const address = base58Encode(payloadBytes);
    addressGameState.finalAddress = address;

    // Show Address Banner
    const addrCard = document.getElementById('p2a-final-address-card');
    const addrVal = document.getElementById('p2a-final-address-val');
    const formatTag = document.getElementById('p2a-meta-format-tag');

    if (addrCard) addrCard.style.display = 'flex';
    if (addrVal) addrVal.textContent = address;
    if (formatTag) {
      formatTag.textContent = addressGameState.format === 'compressed' ? 'Compressed Public Key' : 'Uncompressed Public Key';
    }

    // Show Victory Summary
    const victoryCard = document.getElementById('p2a-victory-card');
    const sumPoint = document.getElementById('p2a-sum-point');
    const sumPubkey = document.getElementById('p2a-sum-pubkey');
    const sumHash160 = document.getElementById('p2a-sum-hash160');
    const sumAddress = document.getElementById('p2a-sum-address');

    if (victoryCard) victoryCard.style.display = 'flex';
    if (sumPoint) sumPoint.textContent = `(${addressGameState.xHex.slice(0, 10)}..., ${addressGameState.yHex.slice(0, 10)}...)`;
    if (sumPubkey) sumPubkey.textContent = `${addressGameState.assembledPubkey.slice(0, 14)}... (${addressGameState.format})`;
    if (sumHash160) sumHash160.textContent = addressGameState.ripemd160Digest.toUpperCase();
    if (sumAddress) sumAddress.textContent = address;

    addressGameState.step6Completed = true;
    const pill6 = document.getElementById('p2a-nav-step-6');
    if (pill6) pill6.classList.add('completed');

    sound.playLock();
    setTimeout(() => sound.playWhoosh(), 120);
    showAlert('Bitcoin Address Derived Successfully!');
  } catch (err) {
    showAlert('Error encoding Base58: ' + err.message);
  }
};

// Step Navigation Jump
window.jumpToAddressStep = function(stepNum) {
  addressGameState.currentStep = stepNum;

  // Toggle Nav Pills Active
  for (let i = 1; i <= 6; i++) {
    const pill = document.getElementById(`p2a-nav-step-${i}`);
    const card = document.getElementById(`p2a-card-step-${i}`);
    if (pill) {
      if (i === stepNum) pill.classList.add('active');
      else pill.classList.remove('active');
    }
    if (card) {
      if (i === stepNum) card.classList.add('active');
      else card.classList.remove('active');
    }
  }

  sound.playClick();
};

// Reset Game
window.resetAddressGame = function(showToast = true) {
  addressGameState.currentStep = 1;
  addressGameState.step1Completed = false;
  addressGameState.step2Completed = false;
  addressGameState.step3Completed = false;
  addressGameState.step4Completed = false;
  addressGameState.step5Completed = false;
  addressGameState.step6Completed = false;
  addressGameState.assembledPubkey = '';
  addressGameState.sha256Digest = '';
  addressGameState.ripemd160Digest = '';
  addressGameState.versionedPayload = '';
  addressGameState.finalPayload = '';
  addressGameState.finalAddress = '';

  // Reset outputs in UI
  const out2 = document.getElementById('p2a-step2-output');
  const out3 = document.getElementById('p2a-step3-output');
  const out4 = document.getElementById('p2a-step4-output');
  const out5 = document.getElementById('p2a-step5-output');
  const bd5 = document.getElementById('p2a-checksum-breakdown');
  const addrCard = document.getElementById('p2a-final-address-card');
  const victoryCard = document.getElementById('p2a-victory-card');

  if (out2) out2.textContent = '(Click Compute SHA-256)';
  if (out3) out3.textContent = '(Click Compute RIPEMD-160)';
  if (out4) out4.textContent = '(Click Prepend Mainnet Byte)';
  if (out5) out5.textContent = '(Click Calculate Checksum)';
  if (bd5) bd5.style.display = 'none';
  if (addrCard) addrCard.style.display = 'none';
  if (victoryCard) victoryCard.style.display = 'none';

  // Disable next buttons
  const btnNext2 = document.getElementById('p2a-btn-next-step2');
  const btnNext3 = document.getElementById('p2a-btn-next-step3');
  const btnNext4 = document.getElementById('p2a-btn-next-step4');
  const btnNext5 = document.getElementById('p2a-btn-next-step5');
  if (btnNext2) btnNext2.disabled = true;
  if (btnNext3) btnNext3.disabled = true;
  if (btnNext4) btnNext4.disabled = true;
  if (btnNext5) btnNext5.disabled = true;

  // Clear completed on nav pills
  for (let i = 1; i <= 6; i++) {
    const pill = document.getElementById(`p2a-nav-step-${i}`);
    if (pill) pill.classList.remove('completed');
  }

  // Clear challenge buttons
  const btn02 = document.getElementById('btn-prefix-02');
  const btn03 = document.getElementById('btn-prefix-03');
  const feedback = document.getElementById('p2a-prefix-feedback');
  if (btn02) btn02.classList.remove('correct', 'incorrect');
  if (btn03) btn03.classList.remove('correct', 'incorrect');
  if (feedback) feedback.style.display = 'none';

  window.jumpToAddressStep(1);
  renderStep1Assembly();

  if (showToast) {
    showAlert('Game Reset to Step 1');
    sound.playClick();
  }
};

// Solve All Steps
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

  showAlert('All 6 Cryptographic Steps Solved!');
};

// Copy Text Helper by Element ID
window.copyTextById = function(elemId) {
  const el = document.getElementById(elemId);
  if (!el) return;
  const val = (el.value !== undefined ? el.value : el.textContent).trim();
  window.copyText(val, 'Value');
};

// ==========================================================================
// Standalone Cryptographic Toolbox
// ==========================================================================

window.setToolMode = function(tool, mode) {
  addressGameState.tools[`${tool}Mode`] = mode;

  if (tool === 'sha') {
    const btnHex = document.getElementById('tool-sha-mode-hex');
    const btnText = document.getElementById('tool-sha-mode-text');
    const inArea = document.getElementById('tool-sha-input');
    if (mode === 'hex') {
      if (btnHex) btnHex.classList.add('active');
      if (btnText) btnText.classList.remove('active');
      if (inArea) inArea.placeholder = 'Enter hexadecimal string to hash...';
    } else {
      if (btnText) btnText.classList.add('active');
      if (btnHex) btnHex.classList.remove('active');
      if (inArea) inArea.placeholder = 'Enter plain text to hash...';
    }
  } else if (tool === 'ripe') {
    const btnHex = document.getElementById('tool-ripe-mode-hex');
    const btnText = document.getElementById('tool-ripe-mode-text');
    const inArea = document.getElementById('tool-ripe-input');
    if (mode === 'hex') {
      if (btnHex) btnHex.classList.add('active');
      if (btnText) btnText.classList.remove('active');
      if (inArea) inArea.placeholder = 'Enter hexadecimal string to hash...';
    } else {
      if (btnText) btnText.classList.add('active');
      if (btnHex) btnHex.classList.remove('active');
      if (inArea) inArea.placeholder = 'Enter plain text to hash...';
    }
  } else if (tool === 'b58') {
    const btnEnc = document.getElementById('tool-b58-mode-enc');
    const btnDec = document.getElementById('tool-b58-mode-dec');
    const inArea = document.getElementById('tool-b58-input');
    const actionBtn = document.getElementById('tool-b58-btn');
    const outLabel = document.getElementById('tool-b58-output-label');
    if (mode === 'encode') {
      if (btnEnc) btnEnc.classList.add('active');
      if (btnDec) btnDec.classList.remove('active');
      if (inArea) inArea.placeholder = 'Enter hex payload to encode to Base58...';
      if (actionBtn) actionBtn.querySelector('span').textContent = 'Encode to Base58';
      if (outLabel) outLabel.textContent = 'Base58 Result:';
    } else {
      if (btnDec) btnDec.classList.add('active');
      if (btnEnc) btnEnc.classList.remove('active');
      if (inArea) inArea.placeholder = 'Enter Base58 string (e.g. 16UwLL9...) to decode...';
      if (actionBtn) actionBtn.querySelector('span').textContent = 'Decode from Base58';
      if (outLabel) outLabel.textContent = 'Decoded Hex:';
    }
  }

  sound.playClick();
};

window.runStandaloneSha256 = function() {
  const inArea = document.getElementById('tool-sha-input');
  const outVal = document.getElementById('tool-sha-output');
  if (!inArea || !outVal) return;

  const val = inArea.value.trim();
  if (!val) {
    showAlert('Please enter input for SHA-256');
    return;
  }

  try {
    let inputBytes;
    if (addressGameState.tools.shaMode === 'hex') {
      inputBytes = hexToBytes(val);
    } else {
      inputBytes = utf8ToBytes(val);
    }
    const hash = sha256Hex(inputBytes);
    outVal.textContent = hash.toUpperCase();
    sound.playLock();
  } catch (err) {
    outVal.textContent = 'Error: ' + err.message;
    showAlert('Error: ' + err.message);
  }
};

window.runStandaloneRipemd160 = function() {
  const inArea = document.getElementById('tool-ripe-input');
  const outVal = document.getElementById('tool-ripe-output');
  if (!inArea || !outVal) return;

  const val = inArea.value.trim();
  if (!val) {
    showAlert('Please enter input for RIPEMD-160');
    return;
  }

  try {
    let inputBytes;
    if (addressGameState.tools.ripeMode === 'hex') {
      inputBytes = hexToBytes(val);
    } else {
      inputBytes = utf8ToBytes(val);
    }
    const hash = ripemd160Hex(inputBytes);
    outVal.textContent = hash.toUpperCase();
    sound.playLock();
  } catch (err) {
    outVal.textContent = 'Error: ' + err.message;
    showAlert('Error: ' + err.message);
  }
};

window.runStandaloneBase58 = function() {
  const inArea = document.getElementById('tool-b58-input');
  const outVal = document.getElementById('tool-b58-output');
  if (!inArea || !outVal) return;

  const val = inArea.value.trim();
  if (!val) {
    showAlert('Please enter input for Base58 tool');
    return;
  }

  try {
    if (addressGameState.tools.b58Mode === 'encode') {
      const bytes = hexToBytes(val);
      const encoded = base58Encode(bytes);
      outVal.textContent = encoded;
      sound.playLock();
    } else {
      // Decode
      const bytes = base58Decode(val);
      const hex = bytesToHex(bytes);

      // Verify checksum if 25 bytes (standard Bitcoin address payload)
      let checksumNote = '';
      if (bytes.length === 25) {
        const payload = bytes.slice(0, 21);
        const expectedCs = bytesToHex(bytes.slice(21, 25));
        const actualCs = computeChecksum(bytesToHex(payload));
        if (expectedCs === actualCs) {
          checksumNote = ' [Valid Address Checksum ✓]';
        } else {
          checksumNote = ' [Checksum Mismatch ✗]';
        }
      }

      outVal.textContent = hex.toUpperCase() + checksumNote;
      sound.playLock();
    }
  } catch (err) {
    outVal.textContent = 'Error: ' + err.message;
    showAlert('Error: ' + err.message);
  }
};


