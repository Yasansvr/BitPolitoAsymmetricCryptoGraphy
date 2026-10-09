import puppeteer from 'puppeteer';

async function run() {
  console.log('Launching browser for inline workflow test...');
  const browser = await puppeteer.launch({
    headless: true,
    executablePath: '/usr/bin/google-chrome',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  page.on('console', msg => console.log('PAGE LOG:', msg.text()));
  page.on('pageerror', err => console.error('PAGE ERROR:', err.toString()));

  await page.setViewport({ width: 1400, height: 900 });
  await page.goto('http://localhost:8080', { waitUntil: 'networkidle0' });

  // 1. Initial State
  console.log('1. Page loaded, capturing initial state...');
  await page.screenshot({ path: 'preview_1_initial.png' });

  // 2. Open inline compose box for Alice
  console.log('2. Opening inline compose box for Alice...');
  await page.evaluate(() => window.openComposeDialog('ALICE'));
  await new Promise(r => setTimeout(r, 600));
  await page.screenshot({ path: 'preview_2_inline_compose.png' });

  // 3. Player enters Bob public key by hand (copy-paste simulation)
  console.log('3. Copying Bob public key and pasting into recipient input...');
  const bobPub = await page.$eval('#bob-pubkey', el => el.textContent.trim());
  console.log('Bob public key:', bobPub);
  await page.$eval('#recipient-pubkey-input', (el, val) => {
    el.value = val;
    el.dispatchEvent(new Event('input'));
  }, bobPub);
  await new Promise(r => setTimeout(r, 300));

  // 4. Click Encrypt Message
  console.log('4. Clicking Encrypt Message...');
  await page.evaluate(() => window.handleEncryptClick());
  await new Promise(r => setTimeout(r, 600));
  await page.screenshot({ path: 'preview_3_inline_encrypted.png' });

  // 5. Click Send Message
  console.log('5. Clicking Send Message...');
  await page.evaluate(() => window.handleSendClick());
  // Wait for flying flight animation (1.5s)
  await new Promise(r => setTimeout(r, 1800));
  await page.screenshot({ path: 'preview_4_bob_received_encrypted.png' });

  // 6. Bob uses private key to decrypt
  console.log('6. Bob clicking Decrypt with Private Key (d)...');
  const decryptBtn = await page.$('#bob-incoming-container button.photo2-pill-btn');
  if (decryptBtn) {
    await decryptBtn.click();
    await new Promise(r => setTimeout(r, 600));
  }
  await page.screenshot({ path: 'preview_5_bob_decrypted.png' });

  // 7. Test eye reveal on Alice & Bob
  console.log('7. Testing eye reveal on Bob...');
  await page.evaluate(() => document.getElementById('bob-eye-btn').click());
  await new Promise(r => setTimeout(r, 300));
  await page.screenshot({ path: 'preview_6_eye_revealed.png' });

  await browser.close();
  console.log('All inline workflow tests completed successfully!');
}

run().catch(console.error);
