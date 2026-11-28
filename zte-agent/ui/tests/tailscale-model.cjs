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
const base = M.configBaseline({hostname: 'u60-pro', advertise_routes: ['192.168.0.0/24'], tailscale_ssh: false, hold_wakelock: true});
assert.deepEqual(M.configDiff(base, {...base, advertise_routes: ['10.10.0.0/24']}), {});
const diff = M.configDiff(base, {hostname: 'u60-home', tailscale_ssh: true, hold_wakelock: false});
assert.deepEqual(diff, {
  hostname: 'u60-home',
  tailscale_ssh: true,
  hold_wakelock: false
});
assert.match(M.configConfirmation(diff, true), /MagicDNS/);
assert.match(M.configConfirmation(diff, true), /Tailscale SSH will be enabled/);
assert.match(M.configConfirmation(diff, true), /wakelock will be released/);

for (const [raw, prefix, hasHostBits] of [
  [' 192.168.0.1/24 ', '192.168.0.0/24', true],
  ['10.14.193.2/17', '10.14.128.0/17', true],
  ['192.168.0.1/32', '192.168.0.1/32', false],
  ['2001:DB8:0:0:0:0:0:1/64', '2001:db8::/64', true],
  ['2001:db8:abcd:0:8abc::1/73', '2001:db8:abcd:0:8a80::/73', true],
  ['FD01:0:0:1:0:0:2:3/128', 'fd01::1:0:0:2:3/128', false],
  ['::ffff:192.0.2.89/120', '::ffff:192.0.2.0/120', true]
]) {
  assert.deepEqual(M.normalizeRoute(raw), {prefix, hasHostBits}, raw);
}
for (const raw of ['0.0.0.0/0', '192.168.1.1/0', '::/0', '2001:db8::/0']) {
  assert.match(M.normalizeRoute(raw).error, /Advertise Exit Node/, raw);
}
for (const raw of [
  '192.168.0.0/33', '192.168.00.1/24', '256.0.0.0/24', '192.168.0/24',
  '2001:db8::/129', '2001::db8::/64', '2001:db8::\n/64', 'fe80::1%wlan0/128', '1:2:3:4:5:6:7/128', 'fd00::/-1', 'fd00::/1/2', 'not-cidr'
]) {
  assert.match(M.normalizeRoute(raw).error, /valid IPv4 or IPv6 CIDR/, raw);
}
for (const raw of ['100.64.1.0/24', '100.0.0.0/8', '127.0.0.1/32', '224.1.1.0/24', 'fd7a:115c::/32', '::1/128', 'ff02::/64']) {
  assert.match(M.normalizeRoute(raw).error, /overlaps the reserved range/, raw);
}
assert.match(M.routeCandidate('192.168.0.123/24', ['192.168.0.0/24']).error, /already in the list/);
assert.match(M.routeCandidate('fd00:0:0::1/64', ['fd00::/64']).error, /already in the list/);
const fullRoutes = Array.from({length: 16}, (_, index) => `10.0.${index}.0/24`);
assert.match(M.routeCandidate('192.168.0.0/24', fullRoutes).error, /up to 16/);
assert.equal(M.routeCandidate('192.168.0.0/24', fullRoutes.slice(1)).prefix, '192.168.0.0/24');
assert.deepEqual(
  M.lanRouteSuggestions(['192.168.0.0/24', 'fd01::1/64', 'fd01:0::/64', '127.0.0.0/8'], ['192.168.0.0/24']),
  ['fd01::/64']
);

const routes = ['10.1.0.0/24', '10.2.0.0/24', '10.3.0.0/24', '10.4.0.0/24'];
const live = {routes: [
  {prefix: routes[0], state: 'approved'}, {prefix: routes[1], state: 'standby'}, {prefix: routes[2], state: 'pending'}
]};
assert.deepEqual([...routes, '10.5.0.0/24'].map(prefix => M.ROUTE_STATES[M.routeState(prefix, routes, live.routes)]),
  ['Approved', 'Standby', 'Pending', 'Unknown', 'New']);
for (const [sync, syncLabel] of [['applied', 'Applied'], ['pending_daemon', 'Pending daemon'], ['drift', 'Drift'], ['unknown', 'Unknown']]) {
  assert.deepEqual(M.routingStatus({tun: {mode: 'kernel'}, sync}), {modeLabel: 'Kernel TUN', sync, syncLabel});
}
assert.equal(M.routingStatus({tun: {mode: 'userspace'}}).modeLabel, 'Userspace networking');
assert.deepEqual(M.routingStatus(), {modeLabel: 'Unknown', sync: 'unknown', syncLabel: 'Unknown'});
assert.deepEqual(M.exitApproval('pending'), {state: 'pending', label: 'Pending'});
assert.deepEqual(M.exitApproval('off'), {state: 'off', label: 'Off'});
const routerDoh = {running: true, config: {enabled: true, transport: 'doh'}};
assert.deepEqual(M.exitContext({running: true}, routerDoh), {
  mihomoLabel: 'Running', dnsLabel: 'Unknown'
});
assert.equal(M.exitContext({}, {...routerDoh, clean_dns: {running: false}}).dnsLabel, 'Inactive');
assert.equal(M.exitContext({}, {clean_dns: {enabled: false}}).dnsLabel, 'Off');
assert.equal(M.exitContext({}, {clean_dns: {state: 'active'}}).dnsLabel, 'Active');
assert.equal(M.exitContext({}, {exit: {clean_dns: 'degraded'}}).dnsLabel, 'Degraded');
assert.equal(M.exitContext({}, {clean_dns: {status: 'error', running: true}}).dnsLabel, 'Degraded');

const saved = M.routingBaseline({advertise_routes: routes, advertise_exit_node: false, exit_via_mihomo: true});
assert.deepEqual(M.routingDiff(saved, {...saved, advertise_exit_node: true}), {advertise_exit_node: true});
assert.deepEqual(M.routingDiff(saved, {...saved, advertise_routes: [], exit_via_mihomo: false}), {
  advertise_routes: [], exit_via_mihomo: false
});
assert.deepEqual(M.routingDiff(saved, {...saved, advertise_routes: routes.toReversed()}), {});
assert.equal(M.routingBaselineChanged(saved, M.routingBaseline({...saved, routing: live, hostname: 'router-home'})), false);
assert.equal(M.routingBaselineChanged(saved, {...saved, advertise_routes: routes.slice(1)}), true);
assert.equal(M.routingBaselineChanged(saved, {...saved, exit_via_mihomo: false}), true);

const [originalRoute, localRoute, remoteRoute] = routes;
const original = M.routingBaseline({advertise_routes: [originalRoute]});
const latest = M.routingBaseline({advertise_routes: [originalRoute, remoteRoute]});
const adding = M.rebaseRouting(original, {edits: {addedRoutes: [localRoute, localRoute]}});
const merged = M.rebaseRouting(latest, adding);
assert.deepEqual(merged.draft.advertise_routes, [originalRoute, remoteRoute, localRoute]);
assert.deepEqual(M.routingDiff(latest, merged.draft), {advertise_routes: [originalRoute, remoteRoute, localRoute]});
assert.equal(merged.dirty, true);
assert.equal(merged.reviewBaseline, original);
assert.equal(M.rebaseRouting(original, merged).reviewBaseline, latest);
assert.equal(M.rebaseRouting(M.routingBaseline({advertise_routes: fullRoutes}), adding).overLimit, true);

const removing = M.rebaseRouting(original, {edits: {removedRoutes: [originalRoute]}});
const withoutOriginal = M.rebaseRouting(latest, removing);
assert.deepEqual(withoutOriginal.draft.advertise_routes, [remoteRoute]);
assert.deepEqual(withoutOriginal.edits.removedRoutes, [originalRoute]);

const empty = M.routingBaseline();
const addingOriginal = M.rebaseRouting(empty, {edits: {addedRoutes: [originalRoute]}});
const reviewed = M.rebaseRouting(M.routingBaseline({advertise_exit_node: true}), addingOriginal);
assert.equal(reviewed.reviewBaseline, empty);
const satisfied = M.rebaseRouting({...original, advertise_exit_node: true}, reviewed);
assert.deepEqual(satisfied.edits.addedRoutes, []);
assert.equal(satisfied.dirty, false);
assert.equal(satisfied.reviewBaseline, null);

const remoteExit = {...original, advertise_exit_node: true, exit_via_mihomo: true};
const mergedExit = M.rebaseRouting(remoteExit, adding);
assert.deepEqual(mergedExit.draft, {...remoteExit, advertise_routes: [originalRoute, localRoute]});
assert.deepEqual(M.routingDiff(remoteExit, mergedExit.draft), {advertise_routes: [originalRoute, localRoute]});
const disabling = M.rebaseRouting(remoteExit, {edits: {advertiseExitNode: false, exitViaMihomo: false}});
assert.equal(disabling.draft.advertise_exit_node, false);
assert.deepEqual(M.rebaseRouting(original, disabling).edits, {
  addedRoutes: [], removedRoutes: [], advertiseExitNode: null, exitViaMihomo: null
});
const exitOff = M.rebaseRouting(remoteExit, {edits: {advertiseExitNode: false}});
assert.equal(exitOff.draft.exit_via_mihomo, true);
assert.deepEqual(M.routingDiff(remoteExit, exitOff.draft), {advertise_exit_node: false});

assert.match(M.exitEnableConfirmation(false, true), /Peer traffic may consume your router’s cellular data/);
assert.equal(M.exitEnableConfirmation(true, true), '');
assert.equal(M.exitEnableConfirmation(true, false), '');

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

// Tailscale Services (svc:*) validation, normalization, picker, and hints.
assert.deepEqual(M.normalizeServiceName('t3code'), {name: 't3code', service: 'svc:t3code'});
assert.deepEqual(M.normalizeServiceName('svc:my-app-1'), {name: 'my-app-1', service: 'svc:my-app-1'});
assert.equal(M.serviceAdminUrl('t3code'), 'https://console.tailscale.com/admin/services/svc:t3code');
assert.equal(M.serviceAdminUrl('t3code', false), 'https://console.tailscale.com/admin/services');
assert.equal(M.serviceAdminUrl('Bad_Name'), '');
assert.match(M.servicePendingNotice({name: 't3code', service: 'svc:t3code', defined_in_tailnet: false, vips: [], configured_ports: [443, 3773]}), /Define Service.*name: t3code, ports: tcp:443, tcp:3773.*Re-advertise/);
assert.match(M.servicePendingNotice({name: 't3code', service: 'svc:t3code', defined_in_tailnet: true, vips: ['100.75.1.1']}), /Defined in Tailscale Admin, waiting for host approval.*Re-advertise/);
for (const bad of ['', 'svc:', 'Upper', '-lead', 'trail-', 'a.b', 'a/b', 'a'.repeat(64)]) {
  assert.ok(M.serviceNameProblem(bad), `expected error for ${bad}`);
}

assert.deepEqual(M.normalizeServicePath('', false), {path: '/', dedupKey: '/'});
assert.deepEqual(M.normalizeServicePath('/api/', false), {path: '/api', dedupKey: '/api'});
assert.deepEqual(M.normalizeServicePath('/files/', true), {path: '/files/', dedupKey: '/files'});
assert.ok(M.normalizeServicePath('relative', false).error);
assert.ok(M.normalizeServicePath('/a?b=1', false).error);
assert.ok(M.normalizeServicePath('/a//b', false).error);

const validRules = M.validateServiceRules([
  {protocol: 'https', port: 443, path: '/', target: 'http://192.168.0.124:3773'},
  {protocol: 'https', port: 443, path: '/api/', target: 'https+insecure://192.168.0.1:9443'},
  {protocol: 'https', port: 443, path: '/lo', target: 'http://127.0.0.1:9090'},
  {protocol: 'https', port: 443, path: '/ts', target: 'http://100.64.1.5:8080'},
  {protocol: 'https', port: 443, path: '/pub', target: 'https://1.1.1.1:443'},
  {protocol: 'https', port: 443, path: '/sock', target: 'unix:/tmp/app.sock'},
  {protocol: 'https', port: 443, path: '/files/', target: 'file:///data/share'},
  {protocol: 'tcp', port: 3773, target: 'tcp://192.168.0.124:3773'},
  {protocol: 'tcp', port: 2222, target: '[::1]:2222'},
  {protocol: 'tcp', port: 9001, target: 'unix:///tmp/raw.sock'}
]);
assert.equal(validRules.error, undefined);
assert.equal(validRules.rules.length, 10);
assert.equal(validRules.rules[1].path, '/api');
assert.equal(validRules.rules[6].path, '/files/');
assert.equal(validRules.rules[7].target, '192.168.0.124:3773');
assert.equal(validRules.rules[9].target, 'unix:/tmp/raw.sock');

// Conflicts and malformed targets.
assert.ok(M.validateServiceRules([]).error);
assert.match(M.validateServiceRules([
  {protocol: 'https', port: 443, path: '/', target: 'http://192.168.0.2:80'},
  {protocol: 'tcp', port: 443, target: '192.168.0.2:443'}
]).error, /both HTTPS and TCP/);
assert.match(M.validateServiceRules([
  {protocol: 'https', port: 443, path: '/api', target: 'http://192.168.0.2:80'},
  {protocol: 'https', port: 443, path: '/api/', target: 'http://192.168.0.3:80'}
]).error, /Duplicate HTTPS path/);
assert.match(M.validateServiceRules([
  {protocol: 'tcp', port: 22, target: '192.168.0.2:22'},
  {protocol: 'tcp', port: 22, target: '192.168.0.3:22'}
]).error, /Duplicate TCP rule/);
assert.match(M.validateServiceRules([
  {protocol: 'tcp', port: 80, target: 'file:///etc/hosts'}
]).error, /HTTPS rules/);
assert.match(M.validateServiceRules([
  {protocol: 'tcp', port: 80, target: '192.168.0.2'}
]).error, /include a port/);

// MAC masking and device picker (never leaks full MAC).
assert.equal(M.maskMac('AA:BB:CC:DD:EE:01'), '••:••:••:••:ee:01');
assert.equal(M.maskMac('invalid'), '');
const picker = M.buildTargetPickerOptions(
  {
    hosts: {'aa:bb:cc:dd:ee:01': {name: 'Workstation', ipaddrs: ['192.168.0.124'], ip6addrs: ['fe80::1', 'fd00:12::10']}},
    dhcp_leases: [{macaddr: 'aa:bb:cc:dd:ee:02', hostname: '', ipaddr: '192.168.0.150'}]
  },
  {entries: [{mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.0.124', name: 'Workstation'}]}
);
assert.equal(picker[0].ip, '192.168.0.124');
assert.equal(picker[0].isStatic, true);
assert.doesNotMatch(picker.map(item => item.label).join('\n'), /aa:bb:cc:dd/i);
assert.match(picker.find(item => item.ip === '192.168.0.150').label, /••:••:••:••:ee:02/);

assert.equal(M.applyPickedIpToTarget('https', 'https+insecure://192.168.0.10:8443/app', '192.168.0.124'), 'https+insecure://192.168.0.124:8443/app');
assert.equal(M.applyPickedIpToTarget('https', '', 'fd00:12::10'), 'http://[fd00:12::10]');
assert.equal(M.applyPickedIpToTarget('tcp', '192.168.0.10:3773', '192.168.0.124'), '192.168.0.124:3773');

// Dynamic DHCP IP hint & Subnet Route coverage hint (non-blocking).
const hints = M.serviceTargetHints(
  [
    {protocol: 'https', port: 443, path: '/', target: 'http://192.168.0.124:3773'},
    {protocol: 'https', port: 443, path: '/b', target: 'http://192.168.0.150:8080'},
    {protocol: 'tcp', port: 9000, target: '10.20.0.5:9000'},
    {protocol: 'tcp', port: 9001, target: '10.99.0.5:9001'},
    {protocol: 'https', port: 443, path: '/self', target: 'http://192.168.0.1:9090'},
    {protocol: 'https', port: 443, path: '/lo', target: 'http://127.0.0.1:9090'},
    {protocol: 'https', port: 443, path: '/ts', target: 'http://100.64.1.2:80'},
    {protocol: 'https', port: 443, path: '/pub', target: 'https://1.1.1.1:443'}
  ],
  {
    reservations: [{ip: '192.168.0.124'}],
    advertisedRoutes: ['192.168.0.0/24', '10.20.0.0/24'],
    approvedRoutes: ['192.168.0.0/24'],
    routerIps: ['192.168.0.1'],
    httpsEnabled: false
  }
);
assert.deepEqual(hints.unreservedIps, ['192.168.0.150', '10.20.0.5', '10.99.0.5']);
assert.deepEqual(hints.pendingSubnetIps, ['10.20.0.5']);
assert.deepEqual(hints.unadvertisedSubnetIps, ['10.99.0.5']);
assert.equal(hints.httpsDisabledWarning, true);

assert.deepEqual(M.serviceStateMeta('active'), {state: 'active', label: 'Active', chipState: 'approved'});
assert.deepEqual(M.serviceStateMeta('port_mismatch'), {state: 'port_mismatch', label: 'Port mismatch', chipState: 'pending'});
assert.deepEqual(M.serviceStateMeta('drained'), {state: 'drained', label: 'Drained', chipState: 'unknown'});
assert.match(M.formatServicePortDiff({unallowed_ports: [8443], tailnet_ports: ['tcp:443']}), /8443.*tcp:443/);
assert.equal(M.formatServicePortDiff({unallowed_ports: [], tailnet_ports: ['tcp:443']}), '');

console.log('Passed: tailscale-model.js states, eligibility, URL safety, CIDR/version/SHA-256/Services validation, diffs, hints and formatting.');
