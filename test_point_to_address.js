import puppeteer from 'puppeteer';

async function runTest() {
  console.log('Starting Point to Address E2E Test...');
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900 });

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

  // Test 1: Navigation to Point to Address Tab
  console.log('\n--- Test 1: Navigation ---');
  await page.click('#tab-nav-address');
  await new Promise(r => setTimeout(r, 400));

  const isAddressVisible = await page.$eval('#view-point-address', el => el.style.display !== 'none');
  const isSimHidden = await page.$eval('#view-simulator', el => el.style.display === 'none');
  const isTabActive = await page.$eval('#tab-nav-address', el => el.classList.contains('active'));
  console.log('Point to Address visible:', isAddressVisible, '| Sim hidden:', isSimHidden, '| Tab active:', isTabActive);

  if (!isAddressVisible || !isTabActive) {
    throw new Error('Failed to navigate to Point to Address tab');
  }

  // Test 2: Coordinates and Parity Verification
  console.log('\n--- Test 2: Coordinates & Parity Analysis ---');
  const xVal = await page.$eval('#p2a-x-val', el => el.textContent.trim());
  const yVal = await page.$eval('#p2a-y-val', el => el.textContent.trim());
  const parityText = await page.$eval('#p2a-parity-badge', el => el.textContent.trim());
  console.log('X Coordinate (length ' + xVal.length + '):', xVal.slice(0, 16) + '...');
  console.log('Y Coordinate (length ' + yVal.length + '):', yVal.slice(0, 16) + '...');
  console.log('Parity Badge:', parityText);

  if (xVal.length !== 64 || yVal.length !== 64) {
    throw new Error('Coordinates must be 64 hex characters each');
  }

  // Test 3: Uncompressed vs Compressed Format Toggle
  console.log('\n--- Test 3: Format Selection Toggle ---');
  // Click uncompressed
  await page.click('#format-card-uncomp');
  await new Promise(r => setTimeout(r, 200));
  const uncompKey = await page.$eval('#p2a-assembled-pubkey', el => el.textContent.replace(/\s+/g, ''));
  console.log('Uncompressed PubKey (length ' + uncompKey.length + '):', uncompKey.slice(0, 20) + '...');
  if (!uncompKey.startsWith('04') || uncompKey.length !== 130) {
    throw new Error('Uncompressed public key should start with 04 and have 130 hex characters');
  }

  // Click compressed
  await page.click('#format-card-comp');
  await new Promise(r => setTimeout(r, 200));
  const compKey = await page.$eval('#p2a-assembled-pubkey', el => el.textContent.replace(/\s+/g, ''));
  console.log('Compressed PubKey (length ' + compKey.length + '):', compKey.slice(0, 20) + '...');
  if (!compKey.startsWith('02') && !compKey.startsWith('03') || compKey.length !== 66) {
    throw new Error('Compressed public key should start with 02/03 and have 66 hex characters');
  }

  // Test 4: Parity Interactive Challenge
  console.log('\n--- Test 4: Parity Interactive Challenge ---');
  // Guess '02' (which is correct for wiki_standard since y ends in 6)
  await page.click('#btn-prefix-02');
  await new Promise(r => setTimeout(r, 200));
  const feedbackClass = await page.$eval('#p2a-prefix-feedback', el => el.className);
  const feedbackText = await page.$eval('#p2a-prefix-feedback', el => el.textContent);
  console.log('Prefix 02 feedback:', feedbackText, '| Class:', feedbackClass);
  if (!feedbackClass.includes('success')) {
    throw new Error('Expected success feedback for prefix 02');
  }

  // Test 5: Step-by-Step Derivation Execution
  console.log('\n--- Test 5: Step-by-Step Derivation Pipeline ---');
  // Step 1 -> Advance
  await page.click('#p2a-card-step-1 .p2a-card-footer button');
  await new Promise(r => setTimeout(r, 300));
  const isStep2Active = await page.$eval('#p2a-card-step-2', el => el.classList.contains('active'));
  console.log('Advanced to Step 2:', isStep2Active);

  // Step 2: Compute SHA-256
  await page.click('#p2a-card-step-2 .p2a-generator-actions button');
  await new Promise(r => setTimeout(r, 300));
  const sha256Out = await page.$eval('#p2a-step2-output', el => el.textContent.trim());
  console.log('Step 2 SHA-256 output:', sha256Out);
  if (sha256Out.length !== 64) throw new Error('Invalid SHA-256 output length');

  // Step 2 -> Advance
  await page.click('#p2a-btn-next-step2');
  await new Promise(r => setTimeout(r, 300));
  const isStep3Active = await page.$eval('#p2a-card-step-3', el => el.classList.contains('active'));
  console.log('Advanced to Step 3:', isStep3Active);

  // Step 3: Compute RIPEMD-160
  await page.click('#p2a-card-step-3 .p2a-generator-actions button');
  await new Promise(r => setTimeout(r, 300));
  const ripeOut = await page.$eval('#p2a-step3-output', el => el.textContent.trim());
  console.log('Step 3 RIPEMD-160 output:', ripeOut);
  if (ripeOut.length !== 40) throw new Error('Invalid RIPEMD-160 output length');

  // Step 3 -> Advance
  await page.click('#p2a-btn-next-step3');
  await new Promise(r => setTimeout(r, 300));

  // Step 4: Prepend Mainnet Byte 00
  await page.click('#p2a-card-step-4 .p2a-generator-actions button');
  await new Promise(r => setTimeout(r, 300));
  const verOut = await page.$eval('#p2a-step4-output-raw', el => el.textContent.trim());
  console.log('Step 4 Versioned payload (42 hex):', verOut);
  if (!verOut.startsWith('00') || verOut.length !== 42) throw new Error('Invalid versioned payload');

  // Step 4 -> Advance
  await page.click('#p2a-btn-next-step4');
  await new Promise(r => setTimeout(r, 300));

  // Step 5: Checksum
  await page.click('#p2a-card-step-5 .p2a-generator-actions button');
  await new Promise(r => setTimeout(r, 300));
  const csExtracted = await page.$eval('#p2a-cs-extracted', el => el.textContent.trim());
  const finalPayload = await page.$eval('#p2a-step5-output-raw', el => el.textContent.trim());
  console.log('Step 5 Extracted Checksum (8 hex):', csExtracted);
  console.log('Step 5 Complete 25-byte Payload (50 hex):', finalPayload);
  if (csExtracted.length !== 8 || finalPayload.length !== 50) throw new Error('Invalid checksum payload');

  // Step 5 -> Advance
  await page.click('#p2a-btn-next-step5');
  await new Promise(r => setTimeout(r, 300));

  // Step 6: Base58
  await page.click('#p2a-card-step-6 .p2a-generator-actions button');
  await new Promise(r => setTimeout(r, 300));
  const finalAddress = await page.$eval('#p2a-final-address-val', el => el.textContent.trim());
  const isVictoryVisible = await page.$eval('#p2a-victory-card', el => el.style.display !== 'none');
  console.log('Step 6 Final Bitcoin Address:', finalAddress);
  console.log('Victory Card Visible:', isVictoryVisible);

  if (!finalAddress.startsWith('1') || !isVictoryVisible) {
    throw new Error('Final Bitcoin address should start with 1');
  }

  // Take screenshot of Step 6 completed
  await page.screenshot({ path: 'test_p2a_step6_complete.png' });
  console.log('Saved screenshot: test_p2a_step6_complete.png');

  // Test 6: Auto-Solve Pipeline
  console.log('\n--- Test 6: Auto-Solve All Steps ---');
  await page.click('#p2a-btn-reset');
  await new Promise(r => setTimeout(r, 300));
  await page.click('#p2a-btn-solve-all');
  await new Promise(r => setTimeout(r, 500));
  const autoAddress = await page.$eval('#p2a-final-address-val', el => el.textContent.trim());
  console.log('Auto-solved address:', autoAddress);
  if (autoAddress !== finalAddress) {
    throw new Error('Auto-solved address mismatch');
  }

  // Test 7: Standalone Crypto Tools
  console.log('\n--- Test 7: Standalone Crypto Toolbox ---');
  // Standalone SHA-256 with hex
  await page.type('#tool-sha-input', 'hello');
  await page.click('#tool-sha-mode-text');
  await page.click('#p2a-tools-sandbox .p2a-tool-card:nth-child(1) button.photo2-pill-btn');
  await new Promise(r => setTimeout(r, 300));
  const toolShaOut = await page.$eval('#tool-sha-output', el => el.textContent.trim());
  console.log('SHA-256("hello"):', toolShaOut);
  // Expected sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
  if (toolShaOut.toLowerCase() !== '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824') {
    throw new Error('Standalone SHA-256 output mismatch for "hello"');
  }

  // Standalone RIPEMD-160 with text "hello"
  await page.type('#tool-ripe-input', 'hello');
  await page.click('#tool-ripe-mode-text');
  await page.click('#p2a-tools-sandbox .p2a-tool-card:nth-child(2) button.photo2-pill-btn');
  await new Promise(r => setTimeout(r, 300));
  const toolRipeOut = await page.$eval('#tool-ripe-output', el => el.textContent.trim());
  console.log('RIPEMD-160("hello"):', toolRipeOut);
  // Expected ripemd160("hello") = 108f07b8382412612c048d07d13f814118445acd
  if (toolRipeOut.toLowerCase() !== '108f07b8382412612c048d07d13f814118445acd') {
    throw new Error('Standalone RIPEMD-160 output mismatch for "hello"');
  }

  // Standalone Base58 Decode with checksum verification
  await page.click('#tool-b58-mode-dec');
  await page.type('#tool-b58-input', '16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM');
  await page.click('#tool-b58-btn');
  await new Promise(r => setTimeout(r, 300));
  const toolB58Out = await page.$eval('#tool-b58-output', el => el.textContent.trim());
  console.log('Base58 decode("16UwLL9..."):', toolB58Out);
  if (!toolB58Out.includes('Valid Address Checksum')) {
    throw new Error('Expected Valid Address Checksum on standard Bitcoin address');
  }

  // Test 8: Satoshi Genesis Preset Check
  console.log('\n--- Test 8: Satoshi Genesis Preset Check ---');
  await page.click('#btn-preset-satoshi');
  await new Promise(r => setTimeout(r, 300));
  // Switch to uncompressed (as Satoshi's coinbase was uncompressed)
  await page.click('#format-card-uncomp');
  await new Promise(r => setTimeout(r, 300));
  await page.click('#p2a-btn-solve-all');
  await new Promise(r => setTimeout(r, 500));
  const genesisAddr = await page.$eval('#p2a-final-address-val', el => el.textContent.trim());
  console.log('Genesis Block Uncompressed Address:', genesisAddr);
  if (genesisAddr !== '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa') {
    throw new Error(`Expected Genesis Address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa, got ${genesisAddr}`);
  }

  // Take final screenshot of Genesis Address
  await page.screenshot({ path: 'test_p2a_genesis_complete.png' });
  console.log('Saved screenshot: test_p2a_genesis_complete.png');

  console.log('\n===========================================');
  console.log('ALL TESTS COMPLETED SUCCESSFULLY! 100% PASS');
  console.log('===========================================');

  await browser.close();
}

runTest().catch(err => {
  console.error('TEST FAILED:', err);
  process.exit(1);
});
