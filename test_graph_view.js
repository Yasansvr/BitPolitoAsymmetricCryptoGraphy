const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 960 });

  const errors = [];
  page.on('console', msg => {
    if (msg.type() === 'error') {
      errors.push(`Console Error: ${msg.text()}`);
    }
  });
  page.on('pageerror', err => {
    errors.push(`Page Error: ${err.message}`);
  });

  console.log('Navigating to http://localhost:8080/ ...');
  await page.goto('http://localhost:8080/', { waitUntil: 'networkidle0' });

  // 1. Check Initial Simulator Page
  const simTitle = await page.$eval('.header-title-group h1', el => el.textContent.trim());
  console.log('Simulator Title:', simTitle);

  // 2. Click "2D Curve Graph" button
  console.log('Clicking "2D Curve Graph" nav button...');
  await page.click('#nav-graph-btn');
  await new Promise(r => setTimeout(r, 600));

  // Verify Graph view is active
  const isGraphVisible = await page.$eval('#view-graph', el => getComputedStyle(el).display !== 'none');
  console.log('Is Graph View Visible:', isGraphVisible);

  await page.screenshot({ path: 'preview_desmos_initial.png', fullPage: false });
  console.log('Saved preview_desmos_initial.png');

  // 3. Step forward: Click "Next Step (+G)" to reach d = 2
  console.log('Clicking Next Step (+G) for d = 2...');
  await page.click('#step-next-btn');
  await new Promise(r => setTimeout(r, 300));

  let badgeText = await page.$eval('#stepper-badge', el => el.textContent.trim());
  let mathDesc = await page.$eval('#step-math-breakdown', el => el.textContent.trim());
  console.log('Step 2 Badge:', badgeText);
  console.log('Step 2 Breakdown snippet:', mathDesc.substring(0, 100));

  await page.screenshot({ path: 'preview_desmos_step2.png', fullPage: false });
  console.log('Saved preview_desmos_step2.png');

  // 4. Click Next Step again for d = 3
  console.log('Clicking Next Step (+G) for d = 3...');
  await page.click('#step-next-btn');
  await new Promise(r => setTimeout(r, 300));

  badgeText = await page.$eval('#stepper-badge', el => el.textContent.trim());
  console.log('Step 3 Badge:', badgeText);

  await page.screenshot({ path: 'preview_desmos_step3.png', fullPage: false });
  console.log('Saved preview_desmos_step3.png');

  // 5. Test Two-Component Preset (a=-3, b=1)
  console.log('Testing Two-Component Preset...');
  const presetBtns = await page.$$('.presets-row button');
  if (presetBtns.length >= 2) {
    await presetBtns[1].click(); // Click two-component
    await new Promise(r => setTimeout(r, 300));
  }
  const formulaText = await page.$eval('#graph-formula-text', el => el.textContent.trim());
  console.log('Preset formula text:', formulaText);
  await page.screenshot({ path: 'preview_desmos_twocomponent.png', fullPage: false });
  console.log('Saved preview_desmos_twocomponent.png');

  // 6. Test Bitcoin Preset Shortcut (a=0, b=7)
  console.log('Testing Bitcoin Shortcut button...');
  if (presetBtns.length >= 1) {
    await presetBtns[0].click(); // Click bitcoin preset
    await new Promise(r => setTimeout(r, 300));
  }
  const btcFormula = await page.$eval('#graph-formula-text', el => el.textContent.trim());
  console.log('Bitcoin formula text:', btcFormula);
  await page.screenshot({ path: 'preview_desmos_bitcoin_preset.png', fullPage: false });
  console.log('Saved preview_desmos_bitcoin_preset.png');

  // 7. Check errors
  if (errors.length > 0) {
    console.error('Errors encountered:', errors);
  } else {
    console.log('SUCCESS: Zero errors detected!');
  }

  await browser.close();
})();
