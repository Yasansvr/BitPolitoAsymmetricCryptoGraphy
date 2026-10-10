import puppeteer from 'puppeteer';

(async () => {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 1100 });

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

  // 1. Verify Page Title and Header Title
  const title = await page.title();
  const headerH1 = await page.$eval('.header-title-group h1', el => el.textContent.trim());
  console.log('Document Title:', title);
  console.log('Header H1:', headerH1);

  if (title !== 'Bitpolito Cryptography Simulator') {
    throw new Error(`Expected title 'Bitpolito Cryptography Simulator', got '${title}'`);
  }
  if (headerH1 !== 'Bitpolito Cryptography Simulator') {
    throw new Error(`Expected header 'Bitpolito Cryptography Simulator', got '${headerH1}'`);
  }

  // 2. Verify Header Tabs: Cryptography Guide and Point to Address tabs exist
  const headerBtns = await page.$$eval('.header-actions button', btns => btns.map(b => b.textContent.trim()));
  console.log('Header Action Buttons:', headerBtns);
  if (!headerBtns.includes('Cryptography Guide')) {
    throw new Error('Cryptography Guide button missing from header');
  }
  if (!headerBtns.includes('Point to Address')) {
    throw new Error('Point to Address tab button missing from header');
  }

  await page.screenshot({ path: 'preview_bitpolito_home.png', fullPage: false });
  console.log('Saved preview_bitpolito_home.png');

  // 3. Click Cryptography Guide to open 2D Graph View
  console.log('Clicking "Cryptography Guide"...');
  await page.click('#nav-guide-btn');
  await new Promise(r => setTimeout(r, 500));

  const isGraphVisible = await page.$eval('#view-graph', el => getComputedStyle(el).display !== 'none');
  console.log('Is Graph View Visible:', isGraphVisible);

  // 4. Test 5G Step in Real Curve Mode (Continuous R)
  console.log('Testing 5G Step in Real mode...');
  await page.click('#step-5g-btn');
  await new Promise(r => setTimeout(r, 400));

  let badgeText = await page.$eval('#stepper-badge', el => el.textContent.trim());
  let pubPoint = await page.$eval('#stepper-public-point', el => el.textContent.trim());
  let mathDesc = await page.$eval('#step-math-breakdown', el => el.textContent.trim());
  console.log('Real Mode 5G Badge:', badgeText);
  console.log('Real Mode 5G Public Point:', pubPoint);
  console.log('Real Mode 5G Breakdown snippet:', mathDesc.substring(0, 140));

  await page.screenshot({ path: 'preview_real_5g_step.png', fullPage: false });
  console.log('Saved preview_real_5g_step.png');

  // 5. Test Switching Domain to Finite Field (mod p)
  console.log('Switching domain to Finite Field (mod p)...');
  await page.click('#tab-domain-mod');
  await new Promise(r => setTimeout(r, 400));

  let modFormula = await page.$eval('#graph-formula-text', el => el.textContent.trim());
  let discTag = await page.$eval('#graph-discriminant-tag', el => el.textContent.trim());
  console.log('Mod Formula:', modFormula);
  console.log('Mod Tag:', discTag);

  await page.screenshot({ path: 'preview_mod_step1.png', fullPage: false });
  console.log('Saved preview_mod_step1.png');

  // 6. Test 5G Step in Modulo Mode (mod p)
  console.log('Testing 5G Step in Modulo mode...');
  await page.click('#step-5g-btn');
  await new Promise(r => setTimeout(r, 400));

  badgeText = await page.$eval('#stepper-badge', el => el.textContent.trim());
  pubPoint = await page.$eval('#stepper-public-point', el => el.textContent.trim());
  mathDesc = await page.$eval('#step-math-breakdown', el => el.textContent.trim());
  console.log('Mod Mode 5G Badge:', badgeText);
  console.log('Mod Mode 5G Public Point:', pubPoint);
  console.log('Mod Mode 5G Breakdown snippet:', mathDesc.substring(0, 140));

  await page.screenshot({ path: 'preview_mod_5g_step.png', fullPage: false });
  console.log('Saved preview_mod_5g_step.png');

  // 7. Test Prime Switching (p = 43)
  console.log('Testing Prime switching to p=43...');
  await page.click('#prime-btn-43');
  await new Promise(r => setTimeout(r, 300));
  await page.click('#step-5g-btn');
  await new Promise(r => setTimeout(r, 300));

  pubPoint = await page.$eval('#stepper-public-point', el => el.textContent.trim());
  console.log('Prime 43, 5G Public Point:', pubPoint);
  await page.screenshot({ path: 'preview_mod43_5g_step.png', fullPage: false });
  console.log('Saved preview_mod43_5g_step.png');

  // 8. Return to Simulator View using Back to Simulator button
  console.log('Clicking "← Back to Simulator"...');
  await page.click('.graph-title-group button');
  await new Promise(r => setTimeout(r, 400));

  const isSimVisible = await page.$eval('#view-simulator', el => getComputedStyle(el).display !== 'none');
  console.log('Is Simulator View Visible again:', isSimVisible);

  if (errors.length > 0) {
    console.error('Errors encountered:', errors);
  } else {
    console.log('SUCCESS: All checks passed with 0 errors!');
  }

  await browser.close();
})();
