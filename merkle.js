/**
 * merkle.js - Blockchain Merkle Tree Simulator Engine & Interactive Controllers
 * Pure ES Module supporting dynamic hashing, avalanche tamper detection, and SPV proofs
 */

import { sha256Hex, utf8ToBytes, hexToBytes } from './address.js';

// Default mock transactions from user specification
export const DEFAULT_TRANSACTIONS = [
  'Tx 0: Alice -> Bob 1.5 BTC',
  'Tx 1: Charlie -> Dave 0.4 BTC',
  'Tx 2: Eve -> Frank 2.1 BTC',
  'Tx 3: Grace -> Heidi 0.8 BTC'
];

/**
 * Hash a leaf transaction text using SHA-256
 */
export function hashLeaf(txText) {
  const bytes = utf8ToBytes(txText);
  return sha256Hex(bytes);
}

/**
 * Hash a pair of hex hashes using SHA-256 on concatenated binary bytes
 */
export function hashPair(leftHex, rightHex) {
  const cleanLeft = leftHex.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  const cleanRight = rightHex.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  const combinedBytes = hexToBytes(cleanLeft + cleanRight);
  return sha256Hex(combinedBytes);
}

/**
 * Format a 64-char hex hash into compact format (e.g., "a1b2...c3d4")
 */
export function formatCompactHash(hashHex) {
  if (!hashHex || hashHex.length < 12) return hashHex || '';
  return hashHex.slice(0, 4) + '...' + hashHex.slice(-4);
}

/**
 * Compute the complete Merkle Tree hierarchy for an array of transaction texts
 * Handles odd node counts by duplicating the last node (standard Bitcoin rule)
 */
export function computeMerkleTreeHierarchy(txTexts) {
  if (!txTexts || txTexts.length === 0) {
    return {
      levels: [],
      root: '',
      leafCount: 0
    };
  }

  const levels = [];

  // Level 0: Leaf nodes
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

  // Successive levels upwards
  let currentLevel = level0;
  let levelNum = 1;

  while (currentLevel.length > 1) {
    // If odd number of nodes at this level, duplicate the last node (Bitcoin consensus rule)
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
      const leftLbl = leftNode.label.replace('H', '').replace('*', '');
      const rightLbl = rightNode.label.replace('H', '').replace('*', '');
      const parentLabel = isTopLevel ? 'Merkle Root' : `H${leftLbl}${rightLbl}`;

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

      // Set parent references
      leftNode.parentId = parentNode.id;
      rightNode.parentId = parentNode.id;

      nextLevel.push(parentNode);
    }

    levels.push(nextLevel);
    currentLevel = nextLevel;
    levelNum++;
  }

  const root = currentLevel.length > 0 ? currentLevel[0].hash : '';
  if (currentLevel.length > 0) {
    currentLevel[0].label = 'Merkle Root';
  }

  return {
    levels,
    root,
    leafCount: txTexts.length
  };
}

/**
 * Compute SPV Audit Proof Path for a specific leaf transaction index
 */
export function computeSpvAuditPath(txTexts, targetIndex) {
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

/**
 * Verify an SPV Proof
 */
export function verifySpvProof(targetLeafHash, auditPath) {
  let currentHash = targetLeafHash;
  const steps = [];

  for (let i = 0; i < auditPath.length; i++) {
    const item = auditPath[i];
    let stepCombinedHash;

    if (item.isSiblingOnRight) {
      stepCombinedHash = hashPair(currentHash, item.siblingHash);
      steps.push({
        stepIndex: i + 1,
        leftLabel: i === 0 ? 'Target Hash' : `Step ${i}`,
        leftHash: currentHash,
        rightLabel: item.siblingLabel,
        rightHash: item.siblingHash,
        resultHash: stepCombinedHash
      });
    } else {
      stepCombinedHash = hashPair(item.siblingHash, currentHash);
      steps.push({
        stepIndex: i + 1,
        leftLabel: item.siblingLabel,
        leftHash: item.siblingHash,
        rightLabel: i === 0 ? 'Target Hash' : `Step ${i}`,
        rightHash: currentHash,
        resultHash: stepCombinedHash
      });
    }

    currentHash = stepCombinedHash;
  }

  return {
    computedRoot: currentHash,
    steps
  };
}

// ==========================================================================
// Merkle Simulator State & UI Controller
// ==========================================================================

export const merkleState = {
  transactions: [...DEFAULT_TRANSACTIONS],
  originalTransactions: [...DEFAULT_TRANSACTIONS],
  storedBlockRoot: '',
  currentRoot: '',
  treeData: null,
  activeMode: 'builder', // 'builder' | 'tamper' | 'spv'
  stepLevel: 999, // 0 = leaves only, 1 = branches, 2 = root, 999 = all
  maxLevels: 0,
  tamperedIndices: new Set(),
  tamperedNodeIds: new Set(),
  spvTargetIndex: 2, // default: Tx 2
  spvCurrentStep: 0,
  spvAuditData: null,
  spvIntermediateHash: ''
};

// Initialize Merkle Simulator
export function initMerkleSimulator() {
  if (!merkleState.storedBlockRoot) {
    const initialTree = computeMerkleTreeHierarchy(merkleState.originalTransactions);
    merkleState.storedBlockRoot = initialTree.root;
  }

  recalculateMerkleTree();
  renderMerkleUI();
}

/**
 * Recalculate Tree and identify tampered nodes
 */
export function recalculateMerkleTree() {
  merkleState.treeData = computeMerkleTreeHierarchy(merkleState.transactions);
  merkleState.currentRoot = merkleState.treeData.root;
  merkleState.maxLevels = merkleState.treeData.levels.length;

  // Detect tampered transactions
  merkleState.tamperedIndices.clear();
  merkleState.tamperedNodeIds.clear();

  for (let i = 0; i < merkleState.transactions.length; i++) {
    if (i >= merkleState.originalTransactions.length || merkleState.transactions[i] !== merkleState.originalTransactions[i]) {
      merkleState.tamperedIndices.add(i);
      // Mark leaf node as tampered
      merkleState.tamperedNodeIds.add(`node-0-${i}`);
    }
  }

  // If a leaf is tampered, mark any duplicated node of it as tampered too
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

  // Avalanche effect: propagate tampered status upwards to parent nodes
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

  // Update SPV audit path data
  merkleState.spvAuditData = computeSpvAuditPath(merkleState.transactions, merkleState.spvTargetIndex);
}

/**
 * Main UI Render function
 */
export function renderMerkleUI() {
  renderBlockHeaderStatus();
  renderTransactionsManager();
  renderMerkleTreeDiagram();
  renderSpvAuditCard();

  // Draw connector lines after DOM settles
  requestAnimationFrame(() => {
    drawMerkleConnectors();
  });
}

/**
 * Render Block Header & Merkle Root Status Banner
 */
function renderBlockHeaderStatus() {
  const rootCompactEl = document.getElementById('merkle-root-compact');
  const rootFullEl = document.getElementById('merkle-root-full');
  const statusBadgeEl = document.getElementById('merkle-status-badge');
  const bannerCard = document.getElementById('merkle-header-status-card');
  const tamperComparisonEl = document.getElementById('merkle-tamper-comparison');
  const storedRootEl = document.getElementById('merkle-stored-root-val');
  const computedRootEl = document.getElementById('merkle-computed-root-val');

  const isTampered = merkleState.currentRoot !== merkleState.storedBlockRoot;

  if (rootCompactEl) {
    rootCompactEl.textContent = formatCompactHash(merkleState.currentRoot);
  }
  if (rootFullEl) {
    rootFullEl.textContent = merkleState.currentRoot;
  }

  if (statusBadgeEl && bannerCard) {
    if (isTampered) {
      statusBadgeEl.className = 'merkle-status-badge tampered';
      statusBadgeEl.innerHTML = '<span class="status-dot"></span> TAMPERED BLOCK (Root Mismatch - Block Rejected!)';
      bannerCard.classList.add('tampered');
    } else {
      statusBadgeEl.className = 'merkle-status-badge valid';
      statusBadgeEl.innerHTML = '<span class="status-dot"></span> VALID BLOCK HEADER (Merkle Root Matches Consensus)';
      bannerCard.classList.remove('tampered');
    }
  }

  if (tamperComparisonEl) {
    if (isTampered || merkleState.activeMode === 'tamper') {
      tamperComparisonEl.style.display = 'flex';
      if (storedRootEl) storedRootEl.textContent = merkleState.storedBlockRoot;
      if (computedRootEl) computedRootEl.textContent = merkleState.currentRoot;
    } else {
      tamperComparisonEl.style.display = 'none';
    }
  }
}

/**
 * Render Transactions Inputs & Controls
 */
function renderTransactionsManager() {
  const listEl = document.getElementById('merkle-tx-list');
  const oddNoticeEl = document.getElementById('merkle-odd-notice');
  if (!listEl) return;

  const count = merkleState.transactions.length;
  if (oddNoticeEl) {
    if (count % 2 !== 0) {
      oddNoticeEl.style.display = 'inline-flex';
      oddNoticeEl.textContent = `Odd Count (${count} Leaves): Duplicating Tx ${count - 1} as per Bitcoin consensus rule`;
    } else {
      oddNoticeEl.style.display = 'none';
    }
  }

  let html = '';
  for (let i = 0; i < merkleState.transactions.length; i++) {
    const text = merkleState.transactions[i];
    const isTampered = merkleState.tamperedIndices.has(i);
    const leafHash = hashLeaf(text);
    const isSpvTarget = merkleState.activeMode === 'spv' && merkleState.spvTargetIndex === i;

    html += `
      <div class="merkle-tx-item ${isTampered ? 'tampered' : ''} ${isSpvTarget ? 'spv-target' : ''}">
        <div class="merkle-tx-item-header">
          <span class="merkle-tx-label">Transaction ${i}</span>
          ${isTampered ? '<span class="merkle-badge-tampered">TAMPERED</span>' : ''}
          ${isSpvTarget ? '<span class="merkle-badge-spv">SPV TARGET</span>' : ''}
          <span class="merkle-tx-hash-badge" title="SHA-256(Tx ${i}): ${leafHash}">
            H${i}: <code>${formatCompactHash(leafHash)}</code>
          </span>
        </div>
        <div class="merkle-tx-input-row">
          <input type="text" class="merkle-tx-input ${isTampered ? 'tampered' : ''}"
                 value="${escapeHtml(text)}"
                 data-index="${i}"
                 oninput="window.onMerkleTxInputChange(${i}, this.value)"
                 placeholder="e.g. Alice -> Bob 1.0 BTC">
          <button class="p2a-copy-icon-btn" onclick="window.copyMerkleHash('${leafHash}')" title="Copy Leaf Hash">
            📋
          </button>
        </div>
      </div>
    `;
  }

  listEl.innerHTML = html;
}

/**
 * Render Visual Tree Diagram
 */
function renderMerkleTreeDiagram() {
  const treeContainer = document.getElementById('merkle-tree-nodes-container');
  if (!treeContainer || !merkleState.treeData) return;

  const levels = merkleState.treeData.levels;
  if (levels.length === 0) {
    treeContainer.innerHTML = '<div class="merkle-empty-tree">No transactions in tree</div>';
    return;
  }

  // Determine active SPV sibling node IDs
  const spvSiblingIds = new Set();
  if (merkleState.activeMode === 'spv' && merkleState.spvAuditData) {
    for (const item of merkleState.spvAuditData.auditPath) {
      spvSiblingIds.add(item.siblingId);
    }
  }

  let html = '';

  // Render from Top (Root) down to Bottom (Leaves)
  for (let lvl = levels.length - 1; lvl >= 0; lvl--) {
    // If in step mode, hide levels above stepLevel
    if (lvl > merkleState.stepLevel) {
      continue;
    }

    const levelNodes = levels[lvl];
    const isRootLevel = lvl === levels.length - 1;
    const isLeafLevel = lvl === 0;

    let levelTitle = isRootLevel ? 'Merkle Root' : isLeafLevel ? 'Level 0: Leaf Hashes' : `Level ${lvl}: Branch Hashes`;

    html += `
      <div class="merkle-tree-level-row" data-level="${lvl}">
        <div class="merkle-level-label-pill">${levelTitle}</div>
        <div class="merkle-level-nodes-group">
    `;

    for (const node of levelNodes) {
      const isTampered = merkleState.tamperedNodeIds.has(node.id);
      const isSpvTargetLeaf = merkleState.activeMode === 'spv' && lvl === 0 && node.index === merkleState.spvTargetIndex;
      const isSpvSibling = spvSiblingIds.has(node.id);
      const isSpvDimmed = merkleState.activeMode === 'spv' && !isSpvTargetLeaf && !isSpvSibling && !isRootLevel;

      let cardClass = 'merkle-node-card';
      if (isRootLevel) cardClass += ' root-node';
      if (isLeafLevel) cardClass += ' leaf-node';
      if (isTampered) cardClass += ' tampered';
      if (isSpvTargetLeaf) cardClass += ' spv-target-node';
      if (isSpvSibling) cardClass += ' spv-sibling-node';
      if (isSpvDimmed) cardClass += ' spv-dimmed';
      if (node.isDuplicated) cardClass += ' duplicated-node';

      html += `
        <div class="${cardClass}" id="${node.id}" data-level="${lvl}" data-index="${node.index}">
          <div class="merkle-node-top">
            <span class="merkle-node-tag">${escapeHtml(node.label)}</span>
            ${node.isDuplicated ? '<span class="merkle-node-dup-badge">DUP</span>' : ''}
            ${isTampered ? '<span class="merkle-node-tamper-badge">TAMPERED</span>' : ''}
            ${isSpvTargetLeaf ? '<span class="merkle-node-spv-badge">TARGET</span>' : ''}
            ${isSpvSibling ? '<span class="merkle-node-spv-badge sibling">SPV SIBLING</span>' : ''}
          </div>
          <div class="merkle-node-hash-box" title="Full SHA-256 Hash:\n${node.hash}">
            <code class="merkle-node-hash">${node.shortHash}</code>
            <button class="p2a-copy-icon-btn small" onclick="window.copyMerkleHash('${node.hash}')" title="Copy Full Hash">
              📋
            </button>
          </div>
          ${node.txText ? `<div class="merkle-node-tx-snippet">${escapeHtml(node.txText)}</div>` : ''}
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

/**
 * Draw dynamic SVG connecting lines between children and parents
 */
export function drawMerkleConnectors() {
  const svg = document.getElementById('merkle-svg-canvas');
  const treeContainer = document.getElementById('merkle-tree-nodes-container');
  if (!svg || !treeContainer || !merkleState.treeData) return;

  const containerRect = treeContainer.getBoundingClientRect();
  svg.setAttribute('width', containerRect.width);
  svg.setAttribute('height', containerRect.height);

  let pathsHtml = '';
  const levels = merkleState.treeData.levels;

  for (let lvl = 0; lvl < levels.length - 1; lvl++) {
    // If parent level is not visible in step mode, skip lines
    if (lvl + 1 > merkleState.stepLevel) continue;

    const currentNodes = levels[lvl];
    for (const node of currentNodes) {
      if (!node.parentId) continue;

      const childEl = document.getElementById(node.id);
      const parentEl = document.getElementById(node.parentId);

      if (!childEl || !parentEl) continue;

      const childRect = childEl.getBoundingClientRect();
      const parentRect = parentEl.getBoundingClientRect();

      // Child top center -> Parent bottom center
      const startX = childRect.left + childRect.width / 2 - containerRect.left;
      const startY = childRect.top - containerRect.top;
      const endX = parentRect.left + parentRect.width / 2 - containerRect.left;
      const endY = parentRect.bottom - containerRect.top;

      const midY = (startY + endY) / 2;
      const pathData = `M ${startX} ${startY} C ${startX} ${midY}, ${endX} ${midY}, ${endX} ${endY}`;

      const isTampered = merkleState.tamperedNodeIds.has(node.id) || merkleState.tamperedNodeIds.has(node.parentId);
      const isSpvActive = merkleState.activeMode === 'spv' && (childEl.classList.contains('spv-target-node') || childEl.classList.contains('spv-sibling-node'));

      let strokeColor = '#CBD5E1';
      let strokeWidth = 2;
      let strokeDash = 'none';

      if (isTampered) {
        strokeColor = '#EF4444';
        strokeWidth = 2.5;
      } else if (isSpvActive) {
        strokeColor = '#001CE0';
        strokeWidth = 3;
        strokeDash = '4,4';
      }

      pathsHtml += `
        <path d="${pathData}" fill="none" stroke="${strokeColor}" stroke-width="${strokeWidth}" stroke-dasharray="${strokeDash}" stroke-linecap="round" />
      `;
    }
  }

  svg.innerHTML = pathsHtml;
}

/**
 * Render SPV Audit Quiz Card
 */
function renderSpvAuditCard() {
  const spvCard = document.getElementById('merkle-spv-card');
  if (!spvCard) return;

  const targetSelector = document.getElementById('merkle-spv-target-select');
  if (targetSelector) {
    let optionsHtml = '';
    for (let i = 0; i < merkleState.transactions.length; i++) {
      const isSelected = i === merkleState.spvTargetIndex ? 'selected' : '';
      optionsHtml += `<option value="${i}" ${isSelected}>Tx ${i}: ${escapeHtml(merkleState.transactions[i].slice(0, 24))}...</option>`;
    }
    targetSelector.innerHTML = optionsHtml;
  }

  const proofStepsContainer = document.getElementById('merkle-spv-steps-container');
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

    let combinedHash = '';
    if (item.isSiblingOnRight) {
      combinedHash = hashPair(currentHash, item.siblingHash);
    } else {
      combinedHash = hashPair(item.siblingHash, currentHash);
    }

    stepsHtml += `
      <div class="merkle-spv-step-item ${isStepDone ? 'completed' : isStepActive ? 'active' : ''}">
        <span class="merkle-spv-num">${i + 2}</span>
        <div class="merkle-spv-desc">
          Combine with Sibling <b>${item.siblingLabel}</b> (${item.isSiblingOnRight ? 'on right' : 'on left'}):<br>
          <code>${item.isSiblingOnRight ? 'Hash(Current + ' + item.siblingLabel + ')' : 'Hash(' + item.siblingLabel + ' + Current)'}</code><br>
          ${isStepDone ? `<span class="spv-result-chip">Result = <code>${formatCompactHash(combinedHash)}</code></span>` : '<span class="spv-pending-chip">Pending</span>'}
        </div>
      </div>
    `;

    currentHash = combinedHash;
  }

  // Final Root match
  const isAllDone = merkleState.spvCurrentStep >= auditPath.length;
  const rootMatches = currentHash === merkleState.storedBlockRoot;

  stepsHtml += `
    <div class="merkle-spv-step-item ${isAllDone ? (rootMatches ? 'verified' : 'failed') : ''}">
      <span class="merkle-spv-num">${auditPath.length + 2}</span>
      <div class="merkle-spv-desc">
        <b>Final Verification against Block Header:</b><br>
        Computed: <code>${formatCompactHash(currentHash)}</code> | Header: <code>${formatCompactHash(merkleState.storedBlockRoot)}</code><br>
        ${isAllDone ? (rootMatches ? '<span class="spv-verified-badge">✓ CRYPTOGRAPHICALLY PROVEN INCLUDED!</span>' : '<span class="spv-failed-badge">✗ PROOF FAILED (Tampered!)</span>') : ''}
      </div>
    </div>
  `;

  proofStepsContainer.innerHTML = stepsHtml;

  // Efficiency statistics banner
  const statBanner = document.getElementById('merkle-spv-stat-banner');
  if (statBanner) {
    const totalTxs = merkleState.transactions.length;
    const hashesNeeded = auditPath.length;
    const percentSaved = Math.round((1 - hashesNeeded / totalTxs) * 100);
    statBanner.innerHTML = `
      <b>SPV Efficiency:</b> Verified Tx in <b>${hashesNeeded} sibling hashes</b> instead of downloading all <b>${totalTxs} transactions</b> (${percentSaved}% bandwidth savings!).
    `;
  }
}

// ==========================================================================
// Window Handlers for User Interactions
// ==========================================================================

window.setMerkleMode = function(mode) {
  merkleState.activeMode = mode;

  const btnBuilder = document.getElementById('merkle-mode-builder');
  const btnTamper = document.getElementById('merkle-mode-tamper');
  const btnSpv = document.getElementById('merkle-mode-spv');
  const spvCard = document.getElementById('merkle-spv-card');
  const builderControls = document.getElementById('merkle-builder-controls');

  if (btnBuilder) btnBuilder.classList.toggle('active', mode === 'builder');
  if (btnTamper) btnTamper.classList.toggle('active', mode === 'tamper');
  if (btnSpv) btnSpv.classList.toggle('active', mode === 'spv');

  if (spvCard) spvCard.style.display = mode === 'spv' ? 'flex' : 'none';
  if (builderControls) builderControls.style.display = mode === 'builder' ? 'flex' : 'none';

  if (mode === 'builder') {
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
    window.setMerkleMode('tamper');
    merkleState.transactions[index] = 'Tx 2: Eve -> Frank 999.0 BTC [TAMPERED]';
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
    window.copyText(hashHex, 'Merkle Hash');
  } else if (navigator.clipboard) {
    navigator.clipboard.writeText(hashHex);
  }
};

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
}
