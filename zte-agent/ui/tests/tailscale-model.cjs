const assert = require('node:assert/strict');
const M = require('../tailscale-model.js');

// Lifecycle states and action eligibility mirror tailscale/mod.rs guards.
assert.deepEqual(
  [M.view(null).tone, M.view(null).chip, M.view(null).canEnable, M.view(null).canUpdate],
  ['off', 'WAITING', false, false]
);

let v = M.view({installed: false, enabled: false, enrolled: false, state: 'not_installed'});
assert.deepEqual(
  [v.tone, v.chip, v.canEnable, v.canDisable, v.canLogout, v.canLoginUrl, v.canAuthKey, v.canConfig, v.canUpdate],
  ['off', 'NOT INSTALLED', false, false, false, false, false, true, true]
);
assert.match(v.authReason, /Install Tailscale/);

v = M.view({installed: true, enabled: false, enrolled: false, state: 'updating', updating: true});
assert.deepEqual(
  [v.tone, v.chip, v.canEnable, v.canDisable, v.canLogout, v.canLoginUrl, v.canAuthKey, v.canConfig, v.canUpdate],
  ['busy', 'UPDATING', false, false, false, false, false, false, false]
);

v = M.view({installed: true, enabled: false, enrolled: true, state: 'disabled'});
assert.deepEqual(
  [v.tone, v.chip, v.canEnable, v.canDisable, v.canLogout, v.canLoginUrl, v.canAuthKey],
  ['off', 'DISABLED', true, false, true, false, true],
  'enrolled+disabled allows enable, logout and auth-key setup, while login-url requires enabling first'
);
assert.match(v.authReason, /Enable Tailscale above/);

v = M.view({installed: true, enabled: false, enrolled: false, state: 'disabled'});
assert.deepEqual(
  [v.tone, v.chip, v.canEnable, v.canLoginUrl, v.canAuthKey],
  ['off', 'NOT ENROLLED', true, true, true]
);

v = M.view({
  installed: true, enabled: true, enrolled: true, daemon_running: true,
  state: 'healthy', backend_state: 'Running', dns_name: 'u60-pro.tail1234.ts.net.',
  hostname: 'u60-pro', login_url: 'https://login.tailscale.com/a/stale'
});
assert.deepEqual(
  [v.tone, v.chip, v.title, v.canEnable, v.canDisable, v.canLogout, v.canLoginUrl, v.canAuthKey],
  ['active', 'CONNECTED', 'u60-pro.tail1234.ts.net', false, true, true, false, false]
);
assert.match(v.authReason, /Already enrolled/);

for (const [state, tone, chip] of [
  ['respawning', 'busy', 'STARTING'],
  ['starting', 'busy', 'STARTING'],
  ['connecting', 'busy', 'CONNECTING'],
  ['awaiting_setup', 'warn', 'AWAITING SETUP'],
  ['needs_login', 'warn', 'NEEDS LOGIN'],
  ['pending_approval', 'warn', 'PENDING APPROVAL'],
  ['paused', 'off', 'PAUSED'],
  ['degraded', 'warn', 'OFFLINE'],
  ['mystery', 'off', 'UNKNOWN']
]) {
  const result = M.view({installed: true, enabled: true, daemon_running: true, state});
  assert.deepEqual([result.tone, result.chip], [tone, chip], state);
}

// Safe HTTPS login URL filtering rejects unsafe schemes.
assert.equal(M.safeLoginUrl('https://login.tailscale.com/a/abc123'), 'https://login.tailscale.com/a/abc123');
for (const bad of ['', 'http://login.tailscale.com/a/1', 'javascript:alert(1)', 'data:text/html,x', 'not-a-url']) {
  assert.equal(M.safeLoginUrl(bad), '', bad);
}

// Facts, key expiry (including Go zero time), connection labels and alerts.
const nowMs = Date.parse('2026-11-23T00:00:00Z');
assert.equal(M.formatExpiry('0001-01-01T00:00:00Z', false, nowMs), 'Never expires');
assert.equal(M.formatExpiry('2027-05-19T12:00:00Z', false, nowMs), '2027-05-19');
assert.equal(M.formatExpiry('2026-01-01T00:00:00Z', false, nowMs), 'Expired');
assert.equal(M.formatExpiry('2027-05-19T12:00:00Z', true, nowMs), 'Expired');
assert.equal(M.formatExpiry(null, false, nowMs), '—');

const facts = Object.fromEntries(M.facts({
  installed: true,
  backend_state: 'Running',
  tailscale_ips: ['100.64.0.10', 'fd7a:115c:a1e0::10'],
  dns_name: 'u60-pro.tail.ts.net.',
  direct: true,
  relay: 'hkg',
  client_version: '1.86.2',
  key_expiry: '0001-01-01T00:00:00Z',
  expired: false,
  wakelock_held: true,
  hold_wakelock: true,
  advertise_routes: ['192.168.0.0/24'],
  tailscale_ssh: true
}, nowMs).map(([label, value]) => [label, value]));
assert.deepEqual(facts, {
  'Tailscale IP': '100.64.0.10 · fd7a:115c:a1e0::10',
  'MagicDNS': 'u60-pro.tail.ts.net',
  'Connection': 'Direct · DERP hkg',
  'Version': '1.86.2',
  'Key expiry': 'Never expires',
  'Wakelock': 'Held',
  'Advertised routes': '192.168.0.0/24',
  'Tailscale SSH': 'Enabled'
});

assert.equal(
  M.facts({installed: true, backend_state: 'Running', direct: false, relay: 'sin'}).find(item => item[0] === 'Connection')[1],
  'Relayed · DERP sin'
);

const alerts = M.alerts({
  state: 'pending_approval',
  error: 'socket starting',
  expired: true,
  health: ['DERP warning', 'DERP warning', '']
});
assert.equal(alerts.length, 4);
assert.match(alerts[0], /socket starting/);
assert.match(alerts[1], /expired/);
assert.match(alerts[2], /Approve this machine/);
assert.equal(alerts[3], 'DERP warning');

// Validation & config diff mirror tailscale/config.rs and tailscale/mod.rs.
for (const [host, ok] of [['u60-pro', true], ['Router-01', true], ['a'.repeat(63), true], ['', false], ['a'.repeat(64), false], ['bad host', false], ['bad.host', false]]) {
  assert.equal(M.hostnameProblem(host) === '', ok, host);
}
for (const [cidr, ok] of [['192.168.0.0/24', true], ['10.0.0.0/8', true], ['0.0.0.0/0', true], ['192.168.0.1/32', true], ['192.168.0.0/33', false], ['256.0.0.0/24', false], ['192.168.0/24', false], ['fd00::/64', false], ['not-cidr', false]]) {
  assert.equal(M.validCidr(cidr), ok, cidr);
}
assert.deepEqual(M.parseRoutes(' 192.168.0.0/24,\n10.0.0.0/24  192.168.0.0/24 '), ['192.168.0.0/24', '10.0.0.0/24']);
assert.match(M.routesProblem('192.168.0.0/24, bad/route'), /bad\/route/);
assert.equal(M.routesProblem(''), '');

const base = M.configBaseline({hostname: 'u60-pro', advertise_routes: ['192.168.0.0/24'], tailscale_ssh: false, hold_wakelock: true});
assert.deepEqual(M.configDiff(base, {hostname: 'u60-pro', routesText: '192.168.0.0/24', tailscale_ssh: false, hold_wakelock: true}), {});
const diff = M.configDiff(base, {hostname: 'u60-home', routesText: '192.168.0.0/24, 10.10.0.0/24', tailscale_ssh: true, hold_wakelock: false});
assert.deepEqual(diff, {
  hostname: 'u60-home',
  advertise_routes: ['192.168.0.0/24', '10.10.0.0/24'],
  tailscale_ssh: true,
  hold_wakelock: false
});
assert.match(M.configConfirmation(diff, true), /MagicDNS/);
assert.match(M.configConfirmation(diff, true), /Tailscale SSH will be enabled/);
assert.match(M.configConfirmation(diff, true), /wakelock will be released/);

// Auth key, version and SHA-256 validation.
assert.equal(M.authKeyProblem('tskey-auth-k12345'), '');
assert.match(M.authKeyProblem(''), /Enter a Tailscale auth key/);
assert.match(M.authKeyProblem('tskey auth'), /spaces/);

const goodSha = 'A'.repeat(64);
assert.equal(M.packageUrl('1.86.2'), 'https://pkgs.tailscale.com/stable/tailscale_1.86.2_arm64.tgz');
assert.equal(M.packageUrl('v1.86.2'), '');
assert.match(M.versionProblem('v1.86.2'), /without a leading/);
assert.match(M.versionProblem('1..2'), /digits and dots/);
assert.equal(M.sha256Problem(''), '');
assert.match(M.sha256Problem('1234'), /64 hexadecimal/);
assert.equal(M.updateProblem({version: '1.104.7', sha256: ''}), '');
assert.deepEqual(M.updateRequest({version: ' 1.104.7 ', sha256: ''}), {version: '1.104.7'});
assert.equal(M.updateProblem({version: '1.86.2', sha256: goodSha}), '');
assert.deepEqual(M.updateRequest({version: ' 1.86.2 ', sha256: ` ${goodSha} `}), {version: '1.86.2', sha256: 'a'.repeat(64)});

// Release catalog normalization, version comparison, option labels, and install intent.
assert.equal(M.cleanVersion('v1.104.7-t8491b4291-g123456'), '1.104.7');
assert.equal(M.installedVersion({installed: true, client_version: '1.102.5-tabcdef'}), '1.102.5');
assert.equal(M.installedVersion({installed: true, client_version: null, pinned_version: '1.98.9'}), '1.98.9');
assert.equal(M.installedVersion({installed: false, pinned_version: '1.98.9'}), '');
assert.equal(M.compareVersions('1.104.7', '1.98.10'), 1);
assert.equal(M.compareVersions('1.98.10', '1.104.7'), -1);
assert.equal(M.compareVersions('1.104.7', '1.104.7'), 0);
assert.equal(M.compareVersions('bad', '1.104.7'), null);
assert.equal(M.formatReleaseDate('2026-11-12T22:56:51Z'), '2026-11-12');
assert.equal(M.formatReleaseDate(''), '');

const catalog = M.normalizeVersions({
  latest: '1.104.7',
  versions: [
    {version: '1.104.7', published_at: '2026-11-12T22:56:51Z'},
    {version: '1.104.6', published_at: '2026-11-11T00:29:49Z'},
    {version: 'bad-ver', published_at: '2026-11-10T00:00:00Z'},
    {version: '1.104.6', published_at: '2026-11-11T00:29:49Z'}
  ],
  source: 'github+pkgs',
  warning: null,
  fetched_at: 1_800_000_000
});
assert.equal(catalog.latest, '1.104.7');
assert.deepEqual(catalog.versions.map(item => item.version), ['1.104.7', '1.104.6']);
assert.equal(
  M.versionOptionLabel(catalog.versions[0], {latest: '1.104.7', installed: '1.104.7'}),
  'v1.104.7 — Latest · Installed · 2026-11-12'
);
assert.equal(
  M.versionOptionLabel(catalog.versions[1], {latest: '1.104.7', installed: '1.104.7'}),
  'v1.104.6 — 2026-11-11'
);
assert.equal(M.updateIntent('1.104.7', {installed: false}), 'install');
assert.equal(M.updateIntent('1.104.7', {installed: true, client_version: '1.104.6'}), 'upgrade');
assert.equal(M.updateIntent('1.104.6', {installed: true, client_version: '1.104.7'}), 'downgrade');
assert.equal(M.updateIntent('1.104.7', {installed: true, client_version: '1.104.7-t1234'}), 'reinstall');

// Last update summary formatting.
const nowSec = 1_800_000_000;
assert.deepEqual(M.lastUpdateSummary({version: '1.86.2', ok: true, error: null, finished_at: nowSec - 120}, nowSec), {
  ok: true,
  text: 'Installed v1.86.2 · 2 min ago.'
});
assert.deepEqual(M.lastUpdateSummary({version: '1.86.2', ok: false, error: 'sha256 mismatch', finished_at: nowSec - 10}, nowSec), {
  ok: false,
  text: 'Update to v1.86.2 failed · just now: sha256 mismatch'
});

console.log('Passed: tailscale-model.js states, eligibility, URL safety, CIDR/version/SHA-256 validation, diffs and formatting.');
