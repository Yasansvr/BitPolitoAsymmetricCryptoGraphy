import puppeteer from 'puppeteer';

async function run() {
  const browser = await puppeteer.launch({
    headless: true,
    executablePath: '/usr/bin/google-chrome',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  page.on('console', msg => console.log('BROWSER CONSOLE:', msg.type(), msg.text()));
  page.on('pageerror', err => console.error('BROWSER PAGE ERROR:', err.toString()));

  await page.setViewport({ width: 1366, height: 850 });
  await page.goto('http://localhost:8080', { waitUntil: 'networkidle0' });

  // Wait 1 second for module to initialize
  await new Promise(r => setTimeout(r, 1000));

  const hasFn = await page.evaluate(() => typeof window.onContextMenuSend);
  console.log('typeof window.onContextMenuSend:', hasFn);

  await browser.close();
}

run().catch(console.error);
