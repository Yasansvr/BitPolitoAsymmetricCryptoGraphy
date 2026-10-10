import puppeteer from 'puppeteer';

async function runMerkleTest() {
  console.log('Starting Merkle Tree Simulator E2E Test...');
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 1100 });

  page.on('console', msg => {
    if (msg.type() === 'error') {
      console.error('BROWSER ERROR:', msg.text());
    }
  });

  page.on('pageerror', err => {
    console.error('PAGE ERROR:', err.message);
  });

  await page.goto('http://localhost:8080/index.html', { waitUntil: 'networkidle0' });
  console.log('Loaded http://localhost:8080/index.html');

  // Test 1: Navigation to Merkle Tree Tab
  console.log('\n--- Test 1: Navigation to Merkle Tree Tab ---');
  const headerTabs = await page.$$eval('.header-actions button', btns => btns.map(b => b.textContent.trim()));
  console.log('Header Tabs:', headerTabs);

  if (!headerTabs.includes('Merkle Tree')) {
    throw new Error('Merkle Tree tab button missing from header');
  }

  await page.click('#tab-nav-merkle');
  await new Promise(r => setTimeout(r, 400));

  const isMerkleVisible = await page.$eval('#view-merkle', el => el.style.display !== 'none');
  const isSimHidden = await page.$eval('#view-simulator', el => el.style.display === 'none');
  const isAddressHidden = await page.$eval('#view-point-address', el => el.style.display === 'none');
  const isMerkleTabActive = await page.$eval('#tab-nav-merkle', el => el.classList.contains('active'));

  console.log('Merkle visible:', isMerkleVisible, '| Sim hidden:', isSimHidden, '| Addr hidden:', isAddressHidden, '| Tab active:', isMerkleTabActive);
  if (!isMerkleVisible || !isMerkleTabActive) {
    throw new Error('Failed to switch to Merkle Tree tab');
  }

  // Test 2: Initial Tree State & Block Header Status
  console.log('\n--- Test 2: Initial Tree State ---');
  const initialRoot = await page.$eval('#merkle-root-full', el => el.textContent.trim());
  const initialStatus = await page.$eval('#merkle-status-badge', el => el.textContent.trim());
  console.log('Merkle Root:', initialRoot);
  console.log('Status Badge:', initialStatus);

  if (initialRoot !== '8876ddfb245f0dd2b82d29dea8887a71436fbfff2b3bb6501b48f32d1e11d9bd') {
    throw new Error(`Unexpected initial Merkle root: ${initialRoot}`);
  }
  if (!initialStatus.includes('VALID BLOCK HEADER')) {
    throw new Error('Initial block header should be VALID');
  }

  // Count nodes in tree
  const nodeCount = await page.$$eval('.merkle-node-card', nodes => nodes.length);
  const svgPaths = await page.$$eval('#merkle-svg-canvas path', paths => paths.length);
  console.log('Total tree node cards rendered:', nodeCount, '| SVG connector paths:', svgPaths);
  if (nodeCount < 7) {
    throw new Error(`Expected at least 7 nodes (4 leaves + 2 branches + 1 root), found ${nodeCount}`);
  }
  if (svgPaths < 6) {
    throw new Error(`Expected at least 6 connecting paths, found ${svgPaths}`);
  }


  // Test 3: Stepper Progression (Step Next Level)
  console.log('\n--- Test 3: Stepper Mode ---');
  await page.click('#merkle-builder-controls button:nth-child(1)'); // Reset to leaves
  await new Promise(r => setTimeout(r, 200));
  let levelRows = await page.$$eval('.merkle-tree-level-row', rows => rows.length);
  console.log('After Reset (Leaves only), visible level rows:', levelRows);
  if (levelRows !== 1) {
    throw new Error(`Expected 1 level row (leaves only), got ${levelRows}`);
  }

  await page.click('#merkle-builder-controls button:nth-child(2)'); // Step Next (Branches)
  await new Promise(r => setTimeout(r, 200));
  levelRows = await page.$$eval('.merkle-tree-level-row', rows => rows.length);
  console.log('After Step Next, visible level rows:', levelRows);
  if (levelRows !== 2) {
    throw new Error(`Expected 2 level rows, got ${levelRows}`);
  }

  await page.click('#merkle-builder-controls button:nth-child(3)'); // Full Tree
  await new Promise(r => setTimeout(r, 200));
  levelRows = await page.$$eval('.merkle-tree-level-row', rows => rows.length);
  console.log('After Full Tree, visible level rows:', levelRows);
  if (levelRows !== 3) {
    throw new Error(`Expected 3 level rows (Root, Branches, Leaves), got ${levelRows}`);
  }

  // Test 4: Tampering & Avalanche Effect Attack Game
  console.log('\n--- Test 4: Tampering & Avalanche Effect ---');
  // Trigger Attack Demo: Tamper Tx 2
  await page.click('#merkle-tx-manager-card .merkle-tx-actions button:nth-child(4)');
  await new Promise(r => setTimeout(r, 300));

  const tamperedRoot = await page.$eval('#merkle-root-full', el => el.textContent.trim());
  const tamperedStatus = await page.$eval('#merkle-status-badge', el => el.textContent.trim());
  const tamperedCardsCount = await page.$$eval('.merkle-node-card.tampered', nodes => nodes.length);

  console.log('Tampered Root:', tamperedRoot);
  console.log('Status Badge:', tamperedStatus);
  console.log('Red Tampered Cards in Tree (Avalanche):', tamperedCardsCount);

  if (tamperedRoot === initialRoot) {
    throw new Error('Tampered root should differ from initial root');
  }
  if (!tamperedStatus.includes('TAMPERED BLOCK')) {
    throw new Error('Status should show TAMPERED BLOCK');
  }
  if (tamperedCardsCount < 3) {
    // Leaf H2, Branch H23, and Root must turn red!
    throw new Error(`Expected at least 3 nodes in avalanche red cascade, got ${tamperedCardsCount}`);
  }


  // Test Restore Original
  console.log('Clicking Restore Original Transactions...');
  await page.click('#merkle-tamper-comparison button');
  await new Promise(r => setTimeout(r, 300));

  const restoredRoot = await page.$eval('#merkle-root-full', el => el.textContent.trim());
  const restoredStatus = await page.$eval('#merkle-status-badge', el => el.textContent.trim());
  console.log('Restored Root:', restoredRoot);
  console.log('Restored Status:', restoredStatus);
  if (restoredRoot !== initialRoot || !restoredStatus.includes('VALID BLOCK HEADER')) {
    throw new Error('Failed to restore original valid state');
  }

  // Test 5: Odd Node Duplication Rule
  console.log('\n--- Test 5: Odd Node Count Duplication Rule ---');
  await page.click('#merkle-tx-manager-card .merkle-tx-actions button:nth-child(2)'); // Remove last Tx -> 3 Txs
  await new Promise(r => setTimeout(r, 300));

  const oddNoticeVisible = await page.$eval('#merkle-odd-notice', el => el.style.display !== 'none');
  const oddNoticeText = await page.$eval('#merkle-odd-notice', el => el.textContent.trim());
  const dupBadgeCount = await page.$$eval('.merkle-node-card.duplicated-node', nodes => nodes.length);
  console.log('Odd notice visible:', oddNoticeVisible, '| Text:', oddNoticeText);
  console.log('Duplicated nodes in tree:', dupBadgeCount);

  if (!oddNoticeVisible || dupBadgeCount < 1) {
    throw new Error('Odd count notice and duplicated node should be present');
  }

  // Restore 4 transactions
  await page.click('#merkle-tx-manager-card .merkle-tx-actions button:nth-child(3)'); // Reset
  await new Promise(r => setTimeout(r, 300));

  // Test 6: SPV Proof Mini-Challenge Audit Game
  console.log('\n--- Test 6: SPV Proof Audit Quiz ---');
  await page.click('#merkle-mode-spv');
  await new Promise(r => setTimeout(r, 300));

  const isSpvCardVisible = await page.$eval('#merkle-spv-card', el => el.style.display !== 'none');
  const spvTargetNodes = await page.$$eval('.merkle-node-card.spv-target-node', nodes => nodes.length);
  const spvSiblingNodes = await page.$$eval('.merkle-node-card.spv-sibling-node', nodes => nodes.length);
  const spvDimmedNodes = await page.$$eval('.merkle-node-card.spv-dimmed', nodes => nodes.length);

  console.log('SPV Card Visible:', isSpvCardVisible);
  console.log('SPV Target Node count:', spvTargetNodes);
  console.log('SPV Sibling Nodes count:', spvSiblingNodes);
  console.log('SPV Dimmed Nodes count:', spvDimmedNodes);

  if (!isSpvCardVisible || spvTargetNodes !== 1 || spvSiblingNodes < 1) {
    throw new Error('SPV visual mode elements not set up correctly');
  }

  // Step through SPV Audit Quiz
  console.log('Advancing SPV Step 1...');
  await page.click('#merkle-spv-card .merkle-spv-footer-actions button:nth-child(1)');
  await new Promise(r => setTimeout(r, 300));

  console.log('Advancing SPV Step 2...');
  await page.click('#merkle-spv-card .merkle-spv-footer-actions button:nth-child(1)');
  await new Promise(r => setTimeout(r, 300));

  const isVerifiedBadgePresent = await page.$eval('#merkle-spv-steps-container', el => el.textContent.includes('CRYPTOGRAPHICALLY PROVEN INCLUDED'));
  console.log('SPV Verification Badge Present:', isVerifiedBadgePresent);
  if (!isVerifiedBadgePresent) {
    throw new Error('SPV Proof Verification should succeed');
  }


  console.log('\n===========================================');
  console.log('ALL MERKLE TREE TESTS PASSED WITH 100% SUCCESS!');
  console.log('===========================================');

  await browser.close();
}

runMerkleTest().catch(err => {
  console.error('TEST FAILED:', err);
  process.exit(1);
});
