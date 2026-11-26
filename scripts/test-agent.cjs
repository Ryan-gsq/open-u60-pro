const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {signals} = require('node:os').constants;

const root = path.resolve(__dirname, '..');
const uiTests = 'zte-agent/ui/tests';
const pureNames = [
  'actions', 'advanced', 'battery-model', 'cellular', 'clients-model',
  'data-usage-model', 'dns-model', 'esim-model', 'mihomo-model', 'relay-model',
  'routing-model', 'tailscale-model', 'wireguard-model',
];
const browserNames = [
  'battery', 'clients', 'controls', 'dashboard', 'data-usage', 'dns', 'dns-cache',
  'esim', 'https', 'mihomo', 'navigation', 'network-session', 'numbers', 'proxies',
  'relay', 'routing', 'session', 'tailscale', 'update', 'wireguard', 'workspaces',
];
const uiSuite = name => ({name, command: process.execPath, args: [`${uiTests}/${name}.cjs`]});
const pure = pureNames.map(uiSuite);
const browser = browserNames.map(uiSuite);
const screenshots = uiSuite('screenshots');
const single = [
  {name: 'mihomo-dashboard', command: process.execPath, args: ['--test', 'zte-agent/tests/mihomo-dashboard.cjs']},
  {name: 'install-agent', command: 'python3', args: ['-m', 'unittest', 'scripts/test_install_agent.py']},
];
const suites = [...pure, ...browser, screenshots, ...single];
const groups = new Map([['pure', pure], ['browser', browser]]);
const helpers = ['browser.cjs', 'fixture.cjs'];

function validateRegistration() {
  const names = [...groups.keys(), ...suites.map(suite => suite.name)];
  const files = [...suites.map(suite => suite.args.at(-1)), ...helpers.map(file => `${uiTests}/${file}`)];
  for (const entries of [names, files]) {
    const duplicates = entries.filter((entry, index) => entries.indexOf(entry) !== index);
    if (duplicates.length) throw new Error(`Duplicate test registration: ${duplicates.join(', ')}`);
  }
  const missing = files.filter(file => !fs.statSync(path.join(root, file), {throwIfNoEntry: false})?.isFile());
  if (missing.length) throw new Error(`Missing test files: ${missing.join(', ')}`);
  const registered = new Set(files);
  const unregistered = fs.readdirSync(path.join(root, uiTests))
    .filter(file => file.endsWith('.cjs') && !registered.has(`${uiTests}/${file}`));
  if (unregistered.length) throw new Error(`Unregistered test files: ${unregistered.join(', ')}`);
}

async function main() {
  validateRegistration();
  const [entry, ...rest] = process.argv.slice(2);
  const suite = suites.find(suite => suite.name === entry);
  const selected = groups.get(entry) ?? (suite && [suite]);
  if (!selected || rest.length) throw new Error(`Usage: node scripts/test-agent.cjs ${[...groups.keys(), ...suites.map(suite => suite.name)].join(' | ')}`);

  if (selected.some(suite => browser.includes(suite) || suite === screenshots)) {
    const {checkBrowsers} = require(path.join(root, uiTests, 'browser.cjs'));
    await checkBrowsers(selected.some(suite => suite.name === 'navigation'));
  }

  let firstFailure = 0;
  for (const {name, command, args} of selected) {
    console.log(`Running ${name}`);
    const result = spawnSync(command, args, {cwd: root, stdio: 'inherit'});
    if (result.error) console.error(result.error);
    const code = result.status ?? (result.signal ? 128 + signals[result.signal] : 1);
    console.log(`${name} exited ${code}${result.signal ? ` (${result.signal})` : ''}`);
    if (!firstFailure) firstFailure = code;
  }
  process.exitCode = firstFailure;
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
