const fs = require('node:fs');
const path = require('node:path');
const {chromium, webkit} = require('playwright');

const chromeChannel = process.env.PLAYWRIGHT_CHANNEL ?? 'chrome';
const webkitExecutable = process.env.PLAYWRIGHT_WEBKIT_EXECUTABLE || undefined;

function launchChrome() {
  return chromium.launch({headless: true, ...(chromeChannel ? {channel: chromeChannel} : {})});
}

function launchWebKit() {
  return webkit.launch({headless: true, executablePath: webkitExecutable});
}

async function checkBrowsers(checkWebKit) {
  console.log(`Checking Playwright ${chromeChannel || 'Chromium (bundled)'}`);
  const chrome = await launchChrome();
  await chrome.close();
  if (checkWebKit) {
    console.log(`Checking Playwright WebKit at ${webkitExecutable || webkit.executablePath()}`);
    const safari = await launchWebKit();
    await safari.close();
  } else {
    console.log('WebKit skipped for this entry');
  }
}

async function capture(target, options) {
  const directory = process.env.U60_TEST_ARTIFACTS;
  if (!directory) return;
  fs.mkdirSync(directory, {recursive: true});
  await target.screenshot({...options, path: path.join(directory, path.basename(options.path))});
}

module.exports = {launchChrome, launchWebKit, checkBrowsers, capture};
