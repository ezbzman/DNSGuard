// Renders assets/wallpaper.html to assets/wallpaper.jpg (3840x2160) with Playwright.
// The JPEG is committed, so this is only needed after editing the HTML.
//   node tools/render_wallpaper.js
const path = require('path');
const { chromium } = require('playwright');

(async () => {
  const assets = path.resolve(__dirname, '..', 'assets');
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 2 });
  await page.goto('file://' + path.join(assets, 'wallpaper.html'));
  await page.screenshot({ path: path.join(assets, 'wallpaper.jpg'), type: 'jpeg', quality: 92 });
  await browser.close();
})();
