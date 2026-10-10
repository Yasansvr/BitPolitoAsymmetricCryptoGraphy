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
    if (msg.type() === 'error') errors.push(`Console Error: ${msg.text()}`);
  });
  page.on('pageerror', err => {
    errors.push(`Page Error: ${err.message}`);
  });

  console.log('Navigating to http://localhost:8080/ ...');
  await page.goto('http://localhost:8080/', { waitUntil: 'networkidle0' });

  // 1. Click Cryptography Guide to open graph
  console.log('Opening Cryptography Guide...');
  await page.click('#nav-guide-btn');
  await new Promise(r => setTimeout(r, 400));

  // 2. Verify 5G button is REMOVED
  const btn5g = await page.$('#step-5g-btn');
  console.log('Is 5G Step button present:', btn5g !== null);
  if (btn5g !== null) {
    throw new Error('5G step button was NOT removed!');
  }

  // 3. Test stepping PAST 12 steps using "Next Step (+G)"
  console.log('Stepping sequentially from 1 to 15...');
  for (let s = 1; s <= 14; s++) {
    await page.click('#step-next-btn');
    await new Promise(r => setTimeout(r, 50));
  }

  let badgeText = await page.$eval('#stepper-badge', el => el.textContent.trim());
  let privKey = await page.$eval('#stepper-private-key', el => el.textContent.trim());
  let pubPoint = await page.$eval('#stepper-public-point', el => el.textContent.trim());
  console.log('Step 15 Badge:', badgeText);
  console.log('Step 15 Private Key:', privKey);
  console.log('Step 15 Public Point:', pubPoint);

  if (!badgeText.includes('15')) {
    throw new Error(`Failed to exceed 12 steps! Badge shows: ${badgeText}`);
  }

  await page.screenshot({ path: 'preview_step15_exceed12.png', fullPage: false });
  console.log('Saved preview_step15_exceed12.png');

  // 4. Test Direct Scalar Slider Jump to Step 24
  console.log('Testing direct slider jump to Step d = 24...');
  await page.$eval('#stepper-step-slider', el => {
    el.value = 24;
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await new Promise(r => setTimeout(r, 300));

  badgeText = await page.$eval('#stepper-badge', el => el.textContent.trim());
  privKey = await page.$eval('#stepper-private-key', el => el.textContent.trim());
  pubPoint = await page.$eval('#stepper-public-point', el => el.textContent.trim());
  console.log('Step 24 Badge:', badgeText);
  console.log('Step 24 Private Key:', privKey);
  console.log('Step 24 Public Point:', pubPoint);

  if (!badgeText.includes('24')) {
    throw new Error(`Failed to jump to step 24! Badge shows: ${badgeText}`);
  }

  await page.screenshot({ path: 'preview_step24_jump.png', fullPage: false });
  console.log('Saved preview_step24_jump.png');

  // 5. Test Finite Field mode stepping past 12 (up to full cycle in mod 23)
  console.log('Switching to Finite Field (mod p)...');
  await page.click('#tab-domain-mod');
  await new Promise(r => setTimeout(r, 300));

  await page.$eval('#stepper-step-slider', el => {
    el.value = 23;
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await new Promise(r => setTimeout(r, 300));

  badgeText = await page.$eval('#stepper-badge', el => el.textContent.trim());
  pubPoint = await page.$eval('#stepper-public-point', el => el.textContent.trim());
  console.log('Mod 23 Step 23 Point:', pubPoint);

  // Step 24 (Group order = 24, Point at infinity O)
  await page.click('#step-next-btn');
  await new Promise(r => setTimeout(r, 300));
  badgeText = await page.$eval('#stepper-badge', el => el.textContent.trim());
  pubPoint = await page.$eval('#stepper-public-point', el => el.textContent.trim());
  console.log('Mod 23 Step 24 (Identity O):', badgeText, pubPoint);

  // Step 25 (Cycles back to G!)
  await page.click('#step-next-btn');
  await new Promise(r => setTimeout(r, 300));
  badgeText = await page.$eval('#stepper-badge', el => el.textContent.trim());
  pubPoint = await page.$eval('#stepper-public-point', el => el.textContent.trim());
  console.log('Mod 23 Step 25 (Cyclic wrap to G):', badgeText, pubPoint);

  await page.screenshot({ path: 'preview_mod23_cyclic_wrap.png', fullPage: false });
  console.log('Saved preview_mod23_cyclic_wrap.png');

  if (errors.length > 0) {
    console.error('Errors encountered:', errors);
  } else {
    console.log('SUCCESS: Exceeding 12 steps and removal of 5G button completely verified!');
  }

  await browser.close();
})();
