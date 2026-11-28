// Tailscale console page end-to-end checks against a local fake router.
const assert = require('node:assert/strict');
const {launchChrome}=require('./browser.cjs');
const {start, envelope, watchApiResponses, releaseResponse, refreshOn} = require('./fixture.cjs');

(async () => {
  const sha = 'a1b2c3d4'.repeat(8);
  let status = {
    installed: false,
    enabled: false,
    enrolled: false,
    daemon_running: false,
    state: 'not_installed',
    backend_state: null,
    healthy: false,
    health: [],
    tailscale_ips: [],
    dns_name: null,
    relay: null,
    direct: false,
    key_expiry: null,
    expired: false,
    client_version: null,
    login_url: null,
    wakelock_held: false,
    updating: false,
    last_update: null,
    hostname: 'u60-pro',
    advertise_routes: [],
    advertise_exit_node: false,
    exit_via_mihomo: false,
    tailscale_ssh: false,
    hold_wakelock: true,
    pinned_version: ''
  };
  let loginUrlMode = 'pending';
  let setupMode = 'ok';
  let versionsCatalog = {
    latest: '1.104.7',
    versions: [
      {version: '1.104.7', published_at: '2026-11-12T22:56:51Z'},
      {version: '1.104.6', published_at: '2026-11-11T00:29:49Z'},
      {version: '1.102.5', published_at: '2026-09-29T18:47:23Z'}
    ],
    source: 'github+pkgs',
    warning: null,
    fetched_at: Math.floor(Date.now() / 1000)
  };
  let versionsFail = false;
  let configError = null;
  let mihomo = {running: true};
  const dns = {running: true, config: {enabled: true, transport: 'doh'}};
  const lanClients = {
    hosts: {
      'aa:bb:cc:dd:ee:01': {name: 'DevBox', ipaddrs: ['192.168.0.124'], ip6addrs: ['fe80::1']},
      'aa:bb:cc:dd:ee:02': {name: 'DynamicLaptop', ipaddrs: ['192.168.0.150'], ip6addrs: []}
    },
    dhcp_leases: [{macaddr: 'aa:bb:cc:dd:ee:02', hostname: 'DynamicLaptop', ipaddr: '192.168.0.150'}]
  };
  const dhcpReservations = {
    entries: [{id: 'res-1', mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.0.124', name: 'DevBox'}]
  };
  let servicesStore = [
    {
      name: 't3code',
      service: 'svc:t3code',
      fqdn: 't3code.tail1234.ts.net',
      admin_url: 'https://console.tailscale.com/admin/services/svc:t3code',
      state: 'active',
      configured: true,
      advertised: true,
      drained: false,
      approved: true,
      editable: true,
      unsupported_reasons: [],
      vips: ['100.75.136.27'],
      primary_vips: ['100.75.136.27'],
      allowed_vips: ['100.75.136.27'],
      tailnet_ports: ['tcp:443', 'tcp:3773'],
      configured_ports: [443, 3773],
      unallowed_ports: [],
      access_urls: ['https://t3code.tail1234.ts.net', 'tcp://t3code.tail1234.ts.net:3773'],
      rules: [
        {protocol: 'https', port: 443, path: '/', target: 'http://192.168.0.124:3773', access_url: 'https://t3code.tail1234.ts.net', port_allowed: true, target_ip: '192.168.0.124', target_kind: 'lan_private', subnet_route_state: 'approved'},
        {protocol: 'tcp', port: 3773, target: '192.168.0.124:3773', access_url: 'tcp://t3code.tail1234.ts.net:3773', port_allowed: true, target_ip: '192.168.0.124', target_kind: 'lan_private', subnet_route_state: 'approved'}
      ]
    },
    {
      name: 'mismatch',
      service: 'svc:mismatch',
      fqdn: 'mismatch.tail1234.ts.net',
      admin_url: 'https://console.tailscale.com/admin/services/svc:mismatch',
      state: 'port_mismatch',
      configured: true,
      advertised: true,
      drained: false,
      approved: true,
      editable: true,
      unsupported_reasons: [],
      vips: ['100.75.136.28'],
      primary_vips: ['100.75.136.28'],
      allowed_vips: ['100.75.136.28'],
      tailnet_ports: ['tcp:443'],
      configured_ports: [443, 8443],
      unallowed_ports: [8443],
      access_urls: ['https://mismatch.tail1234.ts.net', 'tcp://mismatch.tail1234.ts.net:8443'],
      rules: [
        {protocol: 'https', port: 443, path: '/', target: 'http://192.168.0.124:8080', access_url: 'https://mismatch.tail1234.ts.net', port_allowed: true, target_ip: '192.168.0.124', target_kind: 'lan_private', subnet_route_state: 'approved'},
        {protocol: 'tcp', port: 8443, target: '192.168.0.124:8443', access_url: 'tcp://mismatch.tail1234.ts.net:8443', port_allowed: false, target_ip: '192.168.0.124', target_kind: 'lan_private', subnet_route_state: 'approved'}
      ]
    },
    {
      name: 'cli-only',
      service: 'svc:cli-only',
      fqdn: 'cli-only.tail1234.ts.net',
      admin_url: 'https://console.tailscale.com/admin/services/svc:cli-only',
      state: 'active',
      configured: true,
      advertised: true,
      drained: false,
      approved: true,
      editable: false,
      unsupported_reasons: ['plain text handler on port 443 / is CLI-only'],
      vips: ['100.75.136.29'],
      primary_vips: ['100.75.136.29'],
      allowed_vips: ['100.75.136.29'],
      tailnet_ports: ['tcp:443'],
      configured_ports: [443],
      unallowed_ports: [],
      access_urls: [],
      rules: []
    },
    {
      name: 'assigned-only',
      service: 'svc:assigned-only',
      fqdn: 'assigned-only.tail1234.ts.net',
      admin_url: 'https://console.tailscale.com/admin/services/svc:assigned-only',
      state: 'unconfigured',
      configured: false,
      advertised: false,
      drained: false,
      approved: false,
      editable: true,
      unsupported_reasons: [],
      vips: ['100.75.136.30'],
      primary_vips: [],
      allowed_vips: [],
      tailnet_ports: ['tcp:443'],
      configured_ports: [],
      unallowed_ports: [],
      access_urls: [],
      rules: []
    }
  ];
  function servicesPayload() {
    const running = status.backend_state === 'Running';
    if (!running) {
      return {available: false, reason: 'Enable and sign in to Tailscale.', backend_state: status.backend_state, magic_dns_suffix: null, https_enabled: false, tags: [], advertised_routes: [], approved_routes: [], lan_subnets: [], router_ips: [], services: []};
    }
    return {
      available: true,
      reason: null,
      backend_state: 'Running',
      magic_dns_suffix: 'tail1234.ts.net',
      https_enabled: true,
      tags: ['tag:t3'],
      advertised_routes: status.advertise_routes,
      approved_routes: (status.routing?.routes || []).filter(r => r.state === 'approved').map(r => r.prefix),
      lan_subnets: ['192.168.0.0/24'],
      router_ips: ['192.168.0.1'],
      services: servicesStore
    };
  }

  function updateRouting() {
    const running = status.backend_state === 'Running';
    const prior = status.routing?.routes ?? [];
    const approval = status.advertise_exit_node ? (running ? 'pending' : 'unknown') : 'off';
    status.routing = {
      sync: running ? 'applied' : 'pending_daemon',
      tun: {mode: running ? 'kernel' : 'unknown', active: running, netfilter_mode: running ? 'off' : 'unknown'},
      lan_subnets: ['192.168.0.0/24', 'fd00:12::/64'],
      routes: status.advertise_routes.map(prefix => ({
        prefix,
        state: running ? (prior.find(route => route.prefix === prefix)?.state ?? 'pending') : 'unknown'
      })),
      exit: {
        advertised: status.advertise_exit_node,
        via_mihomo: status.exit_via_mihomo,
        state: approval,
        state_v4: approval,
        state_v6: approval
      }
    };
  }
  updateRouting();

  const fixture = await start(({method, url, body}, reply, fail) => {
    if (method === 'POST' && url === '/api/auth/login') {
      reply({token: 'fixture-session-2'});
      return true;
    }
    if (method === 'GET' && url === '/api/tailscale/status') {
      reply(status);
      return true;
    }
    if (method === 'GET' && url === '/api/mihomo/status') {
      reply(mihomo);
      return true;
    }
    if (method === 'GET' && url === '/api/doh/status') {
      reply(dns);
      return true;
    }
    if (method === 'GET' && url === '/api/tailscale/versions') {
      if (versionsFail) { fail('GitHub and pkgs unavailable', 502); return true; }
      reply(versionsCatalog);
      return true;
    }
    if (method === 'POST' && url === '/api/tailscale/versions/refresh') {
      if (versionsFail) { fail('upstream timeout', 502); return true; }
      versionsCatalog = {
        ...versionsCatalog,
        latest: '1.104.8',
        versions: [
          {version: '1.104.8', published_at: '2026-11-20T12:00:00Z'},
          ...versionsCatalog.versions
        ]
      };
      reply(versionsCatalog);
      return true;
    }
    if (method === 'POST' && url === '/api/tailscale/update') {
      status = {...status, updating: true, state: 'updating'};
      reply({status: 'updating'});
      return true;
    }
    if (method === 'POST' && url === '/api/tailscale/enable') {
      status = {...status, enabled: true, daemon_running: true, state: 'awaiting_setup', backend_state: 'NeedsLogin', wakelock_held: status.hold_wakelock};
      reply({status: 'enabling'});
      return true;
    }
    if (method === 'POST' && url === '/api/tailscale/login-url') {
      if (loginUrlMode === 'pending') {
        reply({login_url: null, pending: true});
      } else if (loginUrlMode === 'unsafe') {
        reply({login_url: 'javascript:alert(1)', pending: false});
      } else {
        status = {...status, login_url: 'https://login.tailscale.com/a/fixture123'};
        reply({login_url: status.login_url, pending: false});
      }
      return true;
    }
    if (method === 'POST' && url === '/api/tailscale/setup') {
      if (!body?.auth_key) { fail('missing auth_key', 400); return true; }
      if (setupMode === 'fail') { fail('tailscale up: invalid auth key', 502); return true; }
      status = {
        ...status,
        enabled: true,
        enrolled: true,
        daemon_running: true,
        state: 'healthy',
        backend_state: 'Running',
        healthy: true,
        tailscale_ips: ['100.64.0.10', 'fd7a:115c:a1e0::10'],
        dns_name: `${status.hostname}.tail1234.ts.net.`,
        relay: 'hkg',
        direct: true,
        key_expiry: '0001-01-01T00:00:00Z',
        expired: false,
        login_url: null,
        wakelock_held: status.hold_wakelock
      };
      updateRouting();
      reply(status);
      return true;
    }
    if (method === 'PUT' && url === '/api/tailscale/config') {
      if (configError) {
        fail(configError.message, configError.status);
        return true;
      }
      if (Object.hasOwn(body, 'hostname')) status.hostname = body.hostname;
      if (Object.hasOwn(body, 'advertise_routes')) status.advertise_routes = body.advertise_routes;
      if (Object.hasOwn(body, 'advertise_exit_node')) status.advertise_exit_node = body.advertise_exit_node;
      if (Object.hasOwn(body, 'exit_via_mihomo')) status.exit_via_mihomo = body.exit_via_mihomo;
      if (Object.hasOwn(body, 'tailscale_ssh')) status.tailscale_ssh = body.tailscale_ssh;
      if (Object.hasOwn(body, 'hold_wakelock')) {
        status.hold_wakelock = body.hold_wakelock;
        status.wakelock_held = status.enabled && body.hold_wakelock;
      }
      if (status.backend_state === 'Running') {
        status.dns_name = `${status.hostname}.tail1234.ts.net.`;
      }
      updateRouting();
      reply(status);
      return true;
    }
    if (method === 'POST' && url === '/api/tailscale/disable') {
      status = {
        ...status,
        enabled: false,
        daemon_running: false,
        state: 'disabled',
        backend_state: null,
        healthy: false,
        wakelock_held: false
      };
      updateRouting();
      reply({status: 'disabled'});
      return true;
    }
    if (method === 'POST' && url === '/api/tailscale/logout') {
      status = {
        ...status,
        enabled: false,
        enrolled: false,
        daemon_running: false,
        state: 'disabled',
        backend_state: null,
        healthy: false,
        tailscale_ips: [],
        dns_name: null,
        relay: null,
        direct: false,
        login_url: null,
        wakelock_held: false
      };
      updateRouting();
      reply({status: 'logged_out', warning: 'daemon unavailable — remove this machine in the admin console'});
      return true;
    }
    if (method === 'GET' && url === '/api/tailscale/services') {
      reply(servicesPayload());
      return true;
    }
    if (method === 'GET' && url === '/api/network/clients') {
      reply(lanClients);
      return true;
    }
    if (method === 'GET' && url === '/api/router/reservations') {
      reply(dhcpReservations);
      return true;
    }
    if (method === 'PUT' && url.startsWith('/api/tailscale/services/')) {
      const name = decodeURIComponent(url.slice('/api/tailscale/services/'.length));
      const existing = servicesStore.find(s => s.name === name);
      if (existing && existing.editable === false) {
        fail(`svc:${name} contains CLI-only handlers`, 409);
        return true;
      }
      const rules = (body?.rules || []).map(r => ({
        ...r,
        access_url: r.protocol === 'https'
          ? `https://${name}.tail1234.ts.net${r.port === 443 ? '' : `:${r.port}`}${r.path && r.path !== '/' ? r.path : ''}`
          : `tcp://${name}.tail1234.ts.net:${r.port}`,
        port_allowed: null,
        target_ip: null,
        target_kind: 'lan_private',
        subnet_route_state: 'not_advertised'
      }));
      const next = {
        name,
        service: `svc:${name}`,
        fqdn: `${name}.tail1234.ts.net`,
        admin_url: `https://console.tailscale.com/admin/services/svc:${name}`,
        state: existing?.approved ? 'active' : 'pending',
        configured: true,
        advertised: existing ? existing.advertised || !existing.configured : true,
        drained: existing?.drained === true,
        approved: existing?.approved === true,
        editable: true,
        unsupported_reasons: [],
        vips: existing?.vips || [],
        primary_vips: existing?.primary_vips || [],
        allowed_vips: existing?.allowed_vips || [],
        tailnet_ports: existing?.tailnet_ports || [],
        configured_ports: [...new Set(rules.map(r => r.port))],
        unallowed_ports: [],
        access_urls: rules.map(r => r.access_url),
        rules
      };
      if (existing) Object.assign(existing, next);
      else servicesStore.push(next);
      reply(servicesPayload());
      return true;
    }
    if (method === 'POST' && url.startsWith('/api/tailscale/services/') && url.endsWith('/drain')) {
      const name = decodeURIComponent(url.slice('/api/tailscale/services/'.length, -'/drain'.length));
      const svc = servicesStore.find(s => s.name === name);
      if (!svc) { fail('not found', 404); return true; }
      svc.advertised = false;
      svc.drained = true;
      svc.state = 'drained';
      reply(servicesPayload());
      return true;
    }
    if (method === 'POST' && url.startsWith('/api/tailscale/services/') && url.endsWith('/advertise')) {
      const name = decodeURIComponent(url.slice('/api/tailscale/services/'.length, -'/advertise'.length));
      const svc = servicesStore.find(s => s.name === name);
      if (!svc) { fail('not found', 404); return true; }
      svc.advertised = true;
      svc.drained = false;
      svc.state = svc.approved ? 'active' : 'pending';
      reply(servicesPayload());
      return true;
    }
    if (method === 'DELETE' && url.startsWith('/api/tailscale/services/')) {
      const name = decodeURIComponent(url.slice('/api/tailscale/services/'.length));
      servicesStore = servicesStore.filter(s => s.name !== name);
      reply(servicesPayload());
      return true;
    }
    return false;
  });

  const browser = await launchChrome();
  const page = await browser.newPage({viewport: {width: 1440, height: 1200}});
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await watchApiResponses(page);
  await page.clock.install();
  await page.addInitScript(() => sessionStorage.setItem('openu60.session', 'fixture-session'));

  const text = selector => page.locator(selector).textContent();
  const button = name => page.getByRole('button', {name, exact: true});
  const confirm = label => page.locator('.confirm-dialog').getByRole('button', {name: label, exact: true}).click();
  const said = (selector, needle) => page.waitForFunction(
    ([sel, wanted]) => document.querySelector(sel)?.textContent.includes(wanted),
    [selector, needle]
  );
  const lastConfig = () => fixture.requests.filter(item => item.method === 'PUT' && item.url === '/api/tailscale/config').at(-1).body;
  const routing = page.locator('#tailscale-routing');
  const routeInput = routing.getByRole('textbox', {name: 'IPv4 or IPv6 CIDR'});
  const routeRow = prefix => routing.getByRole('listitem').filter({has: page.getByText(prefix, {exact: true})});
  const exit = routing.getByRole('switch', {name: /Advertise Exit Node/});
  const viaMihomo = routing.getByRole('switch', {name: /Route Exit Node via Mihomo/});

  try {
    // 1. Not installed: enrollment & enable are unavailable; install form validates inputs first.
    await page.goto(`${fixture.url}/#network/tailscale`);
    await said('#tailscale-status .tailscale-state', 'NOT INSTALLED');
    assert.equal(await button('Enable Tailscale').isHidden(), true);
    assert.equal(await button('Get login link').isDisabled(), true);
    assert.equal(await button('Enroll with auth key').isDisabled(), true);

    // Release list auto-loads into the dropdown with latest pre-selected (without marking panel dirty).
    await page.waitForFunction(() => document.querySelector('#tailscale-version-select')?.value === '1.104.7');
    assert.equal(await page.locator('#tailscale-update').getAttribute('data-dirty'), 'false');
    assert.match(await text('#tailscale-version-select'), /v1\.104\.7 — Latest · 2026-11-12/);
    assert.equal(await page.locator('#tailscale-manual').evaluate(node => node.open), false);

    // Picking an older release from the dropdown installs with auto-SHA256 (omits sha256 field).
    await page.locator('#tailscale-version-select').selectOption('1.102.5');
    await button('Install v1.102.5').click();
    assert.match(await text('.confirm-dialog'), /official \.sha256 checksum from pkgs\.tailscale\.com/);
    await confirm('Install v1.102.5');
    await said('#tailscale-status .tailscale-state', 'UPDATING');
    assert.deepEqual(
      fixture.requests.find(item => item.method === 'POST' && item.url === '/api/tailscale/update').body,
      {version: '1.102.5'}
    );

    status = {
      ...status,
      installed: true,
      updating: false,
      state: 'disabled',
      client_version: '1.102.5',
      pinned_version: '1.102.5',
      last_update: {version: '1.102.5', ok: true, error: null, finished_at: Math.floor(Date.now() / 1000)}
    };
    fixture.patch({tailscale_status: envelope(status)});
    await said('#tailscale-status .tailscale-state', 'NOT ENROLLED');
    assert.match(await text('#tailscale-update .tailscale-update-banner'), /Installed v1\.102\.5/);
    assert.match(await text('#tailscale-version-select'), /v1\.102\.5 — Installed · 2026-09-29/);

    // Refreshing versions updates the dropdown and selecting latest offers Upgrade.
    await button('Refresh versions').click();
    await page.waitForFunction(() => document.querySelector('#tailscale-version-select')?.textContent.includes('v1.104.8'));
    await page.locator('#tailscale-version-select').selectOption('1.104.8');
    assert.equal(await button('Upgrade to v1.104.8').isVisible(), true);

    // 2. Manual override validates inputs and sends custom version + SHA-256 when provided.
    await page.locator('#tailscale-manual summary').click();
    await page.locator('#tailscale-version').fill('v1.86.2');
    await page.locator('#tailscale-sha256').fill('short');
    await button('Download & upgrade').click();
    await said('#tailscale-update .action-status', 'without a leading');
    assert.equal(fixture.count('POST', '/api/tailscale/update'), 1);

    await page.locator('#tailscale-version').fill('1.86.2');
    await page.locator('#tailscale-sha256').fill(sha.toUpperCase());
    assert.match(await text('#tailscale-version-help'), /tailscale_1\.86\.2_arm64\.tgz/);
    await button('Downgrade to v1.86.2').click();
    assert.match(await text('.confirm-dialog'), /older release/);
    await confirm('Downgrade to v1.86.2');
    await said('#tailscale-status .tailscale-state', 'UPDATING');
    assert.deepEqual(
      fixture.requests.filter(item => item.method === 'POST' && item.url === '/api/tailscale/update').at(-1).body,
      {version: '1.86.2', sha256: sha}
    );
    assert.equal(await page.locator('#tailscale-version').inputValue(), '');
    assert.equal(await page.locator('#tailscale-sha256').inputValue(), '');

    status = {
      ...status,
      installed: true,
      updating: false,
      state: 'disabled',
      client_version: '1.86.2',
      pinned_version: '1.86.2',
      last_update: {version: '1.86.2', ok: true, error: null, finished_at: Math.floor(Date.now() / 1000)}
    };
    fixture.patch({tailscale_status: envelope(status)});
    await said('#tailscale-status .tailscale-state', 'NOT ENROLLED');
    assert.match(await text('#tailscale-update .tailscale-update-banner'), /Installed v1\.86\.2/);

    // 3. Enable transitions to awaiting_setup; interactive login URL rejects unsafe URLs and renders safe HTTPS links via SSE.
    await button('Enable Tailscale').click();
    await confirm('Enable Tailscale');
    await said('#tailscale-status .tailscale-state', 'AWAITING SETUP');

    loginUrlMode = 'unsafe';
    await button('Get login link').click();
    await said('#tailscale-auth .action-status', 'did not return an HTTPS login URL');
    assert.equal(await page.locator('.tailscale-login-box').isHidden(), true);

    loginUrlMode = 'pending';
    await button('Get login link').click();
    await said('#tailscale-auth .action-status', 'Waiting for Tailscale');

    status = {...status, login_url: 'https://login.tailscale.com/a/sse-login-99'};
    fixture.patch({tailscale_status: envelope(status)});
    await page.locator('.tailscale-login-box').waitFor({state: 'visible'});
    assert.equal(await page.locator('.tailscale-login-box a').getAttribute('href'), 'https://login.tailscale.com/a/sse-login-99');
    assert.equal(await page.locator('.tailscale-login-box a').getAttribute('rel'), 'noopener noreferrer');

    // 3b. Daemon exit / respawning or withdrawn login_url must clear the displayed login link.
    status = {...status, daemon_running: false, state: 'respawning', backend_state: null, login_url: null};
    fixture.patch({tailscale_status: envelope(status)});
    await page.locator('.tailscale-login-box').waitFor({state: 'hidden'});
    assert.equal(await page.locator('.tailscale-login-box a').getAttribute('href'), null);

    status = {...status, daemon_running: true, state: 'starting', backend_state: null, login_url: null};
    fixture.patch({tailscale_status: envelope(status)});
    await said('#tailscale-status .tailscale-state', 'STARTING');
    assert.equal(await page.locator('.tailscale-login-box').isHidden(), true);

    status = {...status, daemon_running: true, state: 'awaiting_setup', backend_state: 'NeedsLogin', login_url: null};
    fixture.patch({tailscale_status: envelope(status)});
    await said('#tailscale-status .tailscale-state', 'AWAITING SETUP');
    assert.equal(await page.locator('.tailscale-login-box').isHidden(), true);

    loginUrlMode = 'direct';
    await button('Get login link').click();
    await page.locator('.tailscale-login-box').waitFor({state: 'visible'});
    assert.equal(await page.locator('.tailscale-login-box a').getAttribute('href'), 'https://login.tailscale.com/a/fixture123');

    status = {...status, daemon_running: true, state: 'awaiting_setup', backend_state: 'NeedsLogin', login_url: null};
    fixture.patch({tailscale_status: envelope(status)});
    await page.locator('.tailscale-login-box').waitFor({state: 'hidden'});
    assert.equal(await page.locator('.tailscale-login-box a').getAttribute('href'), null);

    // 3c. Manual status refresh notice clears when SSE preempts the in-flight GET.
    const [preempted] = await Promise.all([
      fixture.holdRequest('GET','/api/tailscale/status'),
      button('Read current status').click(),
    ]);
    await said('#tailscale-status .action-status', 'Reading Tailscale status…');
    fixture.patch({tailscale_status: envelope({...status})});
    await page.waitForFunction(() => document.querySelector('#tailscale-status .action-status')?.textContent === '');
    await releaseResponse(page,preempted,{...status});
    assert.equal(await text('#tailscale-status .action-status'), '');

    // 3d. Auth key clears immediately on confirmed submit, including failure and timeout paths.
    const failedKey = 'tskey-auth-failed-secret-must-clear';
    setupMode = 'fail';
    await page.locator('#tailscale-auth-key').fill(failedKey);
    await button('Enroll with auth key').click();
    await confirm('Enroll router');
    await said('#tailscale-auth .action-status', 'invalid auth key');
    assert.equal(await page.locator('#tailscale-auth-key').inputValue(), '', 'auth key clears on enrollment failure');
    assert.doesNotMatch(await page.content(), new RegExp(failedKey), 'failed auth key never lingers in DOM');

    const timedOutKey = 'tskey-auth-timeout-secret-must-clear';
    await page.locator('#tailscale-auth-key').fill(timedOutKey);
    await button('Enroll with auth key').click();
    const [setup] = await Promise.all([
      fixture.holdRequest('POST','/api/tailscale/setup'),
      confirm('Enroll router'),
    ]);
    assert.equal(setup.body.auth_key,timedOutKey);
    assert.equal(await page.locator('#tailscale-auth-key').inputValue(), '', 'auth key clears immediately while setup is in flight');
    await releaseResponse(page,setup,'tailscale up: timed out after 90s',504);
    await said('#tailscale-auth .action-status', 'timed out after 90s');
    assert.equal(await page.locator('#tailscale-auth-key').inputValue(), '', 'auth key stays cleared after timeout');
    assert.doesNotMatch(await page.content(), new RegExp(timedOutKey), 'timed-out auth key never lingers in DOM');
    setupMode = 'ok';

    // 4. Auth key enrollment sends key, clears input immediately, and transitions to CONNECTED with facts.
    const secretKey = 'tskey-auth-fixture-secret-must-clear';
    await page.locator('#tailscale-auth-key').fill(secretKey);
    await button('Enroll with auth key').click();
    await confirm('Enroll router');
    await said('#tailscale-status .tailscale-state', 'CONNECTED');
    assert.deepEqual(
      fixture.requests.filter(item => item.method === 'POST' && item.url === '/api/tailscale/setup').at(-1).body,
      {auth_key: secretKey}
    );
    assert.equal(await page.locator('#tailscale-auth-key').inputValue(), '', 'auth key clears after enrollment');
    assert.doesNotMatch(await page.content(), new RegExp(secretKey), 'auth key never appears in DOM');
    assert.equal(await page.locator('.tailscale-login-box').isHidden(), true, 'login URL hides after enrollment');
    assert.match(await text('#tailscale-status .tailscale-facts'), /100\.64\.0\.10/);
    assert.match(await text('#tailscale-status .tailscale-facts'), /u60-pro\.tail1234\.ts\.net/);
    assert.match(await text('#tailscale-status .tailscale-facts'), /Direct · DERP hkg/);
    assert.match(await text('#tailscale-status .tailscale-facts'), /Never expires/);

    // 5. Basic preferences remain independent of routing.
    assert.equal(await page.locator('#tailscale-config').getByRole('textbox', {name: /CIDR|subnet/i}).count(), 0);
    await page.locator('#tailscale-hostname').fill('u60-home');
    await page.locator('#tailscale-ssh').check();
    await page.locator('#tailscale-wakelock').uncheck();
    // Live SSE update must preserve unsaved config edits.
    fixture.patch({tailscale_status: envelope({...status, relay: 'sin'})});
    await said('#tailscale-status .tailscale-facts', 'DERP sin');
    assert.equal(await page.locator('#tailscale-hostname').inputValue(), 'u60-home');

    await page.clock.runFor(1200);
    status = {...status, relay: 'fra'};
    await refreshOn(page,fixture,'focus','/api/tailscale/status');
    await said('#tailscale-status .tailscale-facts', 'DERP fra');
    assert.equal(await page.locator('#tailscale-hostname').inputValue(), 'u60-home');

    await button('Save preferences').click();
    assert.match(await text('.confirm-dialog'), /Tailscale SSH will be enabled/);
    await confirm('Save preferences');
    await said('#tailscale-config .action-status', 'Tailscale preferences saved');
    assert.deepEqual(lastConfig(), {hostname: 'u60-home', tailscale_ssh: true, hold_wakelock: false});
    assert.match(await text('#tailscale-status .tailscale-facts'), /u60-home\.tail1234\.ts\.net/);
    assert.match(await text('#tailscale-status .tailscale-facts'), /Enabled/);

    // 5a. Validate and normalize manual input and add a LAN subnet.
    const savedPrefix = '10.10.0.0/24';
    const longPrefix = '2001:db8:abcd:1234:5678:9abc:def0:1234/128';
    status.advertise_routes = [savedPrefix];
    updateRouting();
    fixture.patch({tailscale_status: envelope(status)});
    await routeRow(savedPrefix).getByText('Pending').waitFor();
    const admin = routing.getByRole('link', {name: /Approve in Tailscale/});
    assert.equal(await admin.getAttribute('href'), 'https://login.tailscale.com/admin/machines');
    assert.equal(await admin.getAttribute('target'), '_blank');
    assert.equal(await admin.getAttribute('rel'), 'noopener noreferrer');
    await said('#tailscale-routing .tailscale-routing-bar', 'Kernel TUN');
    await said('#tailscale-routing .tailscale-routing-bar', 'Applied');
    await said('#tailscale-routing .tailscale-exit-context', 'Exit Node Clean DNS · Unknown');
    status.routing.clean_dns = {running: false};
    fixture.patch({tailscale_status: envelope(status)});
    await said('#tailscale-routing .tailscale-exit-context', 'Exit Node Clean DNS · Inactive');
    status.routing.clean_dns = {state: 'active'};
    fixture.patch({tailscale_status: envelope(status)});
    await said('#tailscale-routing .tailscale-exit-context', 'Exit Node Clean DNS · Active');
    assert.equal(fixture.requests.some(request => request.url === '/api/doh/status'), false);

    await routeInput.fill('192.168.0.0/33');
    await said('#tailscale-route-hint', 'Enter a valid IPv4 or IPv6 CIDR');
    assert.equal(await button('Add route').isDisabled(), true);
    await routeInput.fill('::/0');
    await said('#tailscale-route-hint', 'Use the Advertise Exit Node switch');
    await routeInput.fill('10.10.0.42/24');
    await said('#tailscale-route-hint', '10.10.0.0/24 is already in the list');
    assert.equal(await button('Add route').isDisabled(), true);
    await routeInput.fill('2001:DB8::1/64');
    await said('#tailscale-route-hint', 'Will normalize to 2001:db8::/64');
    await routeInput.press('Enter');
    await routeRow('2001:db8::/64').getByText('New').waitFor();
    await button('+ Add LAN 192.168.0.0/24').click();
    await routeRow('192.168.0.0/24').getByText('New').waitFor();
    assert.equal(await button('+ Add LAN 192.168.0.0/24').count(), 0);
    assert.equal(await button('+ Add LAN fd00:12::/64').isVisible(), true);
    await routeInput.fill(longPrefix);
    await button('Add route').click();

    // 5b. Approval status changes through SSE and focus refresh while route drafts persist.
    status.routing.routes[0].state = 'approved';
    fixture.patch({tailscale_status: envelope(status)});
    await routeRow(savedPrefix).getByText('Approved').waitFor();
    await routeRow('2001:db8::/64').getByText('New').waitFor();
    assert.equal(await routing.getAttribute('data-dirty'), 'true');
    assert.equal(await routing.locator('.tailscale-routing-conflict').isHidden(), true);
    status.routing.routes[0].state = 'standby';
    status.routing.sync = 'drift';
    await page.clock.runFor(1200);
    await refreshOn(page, fixture, 'focus', '/api/tailscale/status');
    await routeRow(savedPrefix).getByText('Standby').waitFor();
    await said('#tailscale-routing .tailscale-routing-bar', 'Drift');
    await routeRow('192.168.0.0/24').getByText('New').waitFor();
    mihomo = {running: false};
    status.routing.clean_dns = {state: 'disabled'};
    fixture.patch({tailscale_status: envelope(status)});
    await page.clock.runFor(5500);
    await said('#tailscale-routing .tailscale-exit-context', 'Mihomo · Stopped');
    await said('#tailscale-routing .tailscale-exit-context', 'Exit Node Clean DNS · Off');

    // 5c. Validation, contention and daemon errors retain changes for retry.
    const routesPatch = {advertise_routes: [savedPrefix, '2001:db8::/64', '192.168.0.0/24', longPrefix]};
    for (const [errorStatus, message] of [[400, 'invalid routing settings'], [409, 'preferences are busy'], [502, 'tailscale set failed']]) {
      configError = {status: errorStatus, message};
      await button('Save routing').click();
      await said('#tailscale-routing .action-status', message);
      await said('#tailscale-routing .action-status', 'Your draft is kept');
      assert.deepEqual(lastConfig(), routesPatch);
      assert.equal(await routing.getAttribute('data-dirty'), 'true');
      await routeRow(longPrefix).getByText('New').waitFor();
    }
    configError = null;
    await button('Save routing').click();
    await said('#tailscale-routing .action-status', 'Tailscale routing saved');
    assert.deepEqual(lastConfig(), routesPatch);
    await routeRow(longPrefix).getByText('Pending').waitFor();

    // 5d. Discard after a remote change loads the latest configuration.
    await button(`Remove ${savedPrefix}`).click();
    status.advertise_routes = [...status.advertise_routes, '10.11.0.0/24'];
    updateRouting();
    fixture.patch({tailscale_status: envelope(status)});
    await routing.locator('.tailscale-routing-conflict').waitFor({state: 'visible'});
    assert.match(await text('.tailscale-routing-conflict'), /Review your draft before saving/);
    assert.equal(await routeRow(savedPrefix).count(), 0);
    await routeRow('10.11.0.0/24').getByText('Pending').waitFor();
    await button('Discard routing edits').click();
    await routeRow(savedPrefix).waitFor();
    await routeRow('10.11.0.0/24').waitFor();
    assert.equal(await routing.locator('.tailscale-routing-conflict').isHidden(), true);

    // 5e. Exit Node confirmation, linked Mihomo control and dual-stack status.
    assert.equal(await viaMihomo.isDisabled(), true);
    await exit.click();
    assert.match(await text('.confirm-dialog'), /Peer traffic may consume your router’s cellular data/);
    await confirm('Cancel');
    await page.locator('.confirm-dialog').waitFor({state: 'hidden'});
    assert.equal(await exit.isChecked(), false);
    await exit.click();
    await confirm('Advertise Exit Node');
    await page.waitForFunction(() => document.querySelector('#tailscale-advertise-exit-node').checked);
    assert.equal(await viaMihomo.isEnabled(), true);
    await viaMihomo.check();
    await button('Save routing').click();
    await said('#tailscale-routing .action-status', 'Tailscale routing saved');
    assert.deepEqual(lastConfig(), {advertise_exit_node: true, exit_via_mihomo: true});
    status.routing.exit.state = status.routing.exit.state_v4 = 'approved';
    fixture.patch({tailscale_status: envelope(status)});
    await said('#tailscale-routing [data-family=state]', 'Approved');
    await said('#tailscale-routing [data-family=state_v4]', 'Approved');
    await said('#tailscale-routing [data-family=state_v6]', 'Pending');
    await exit.uncheck();
    assert.equal(await viaMihomo.isDisabled(), true);
    await button('Save routing').click();
    await said('#tailscale-routing .action-status', 'Tailscale routing saved');
    assert.deepEqual(lastConfig(), {advertise_exit_node: false});

    const earlierRoutes = status.advertise_routes;
    const localPrefix = '10.12.0.0/24', remotePrefix = '10.13.0.0/24';
    status.advertise_routes = [savedPrefix];
    updateRouting();
    fixture.patch({tailscale_status: envelope(status)});
    await routeRow(longPrefix).waitFor({state: 'detached'});
    await routeInput.fill(localPrefix);
    await button('Add route').click();
    status.advertise_routes = [savedPrefix, remotePrefix];
    updateRouting();
    status.routing.routes[1].state = 'approved';
    fixture.patch({tailscale_status: envelope(status)});
    await routeRow(remotePrefix).getByText('Approved').waitFor();
    await routeRow(localPrefix).getByText('New').waitFor();
    assert.deepEqual(await routing.locator('.tailscale-route-row code').allTextContents(), [savedPrefix, remotePrefix, localPrefix]);
    await said('.tailscale-routing-conflict', '1 saved subnet route was added.');
    assert.equal(await routing.locator('.tailscale-routing-conflict').isVisible(), true);
    await button('Save routing').click();
    await said('#tailscale-routing .action-status', 'Tailscale routing saved');
    assert.deepEqual(lastConfig(), {advertise_routes: [savedPrefix, remotePrefix, localPrefix]});

    // 5f. A 409 during Save rebases SSE updates received while busy before enabling retry.
    const retryLocal = '10.14.0.0/24', retryRemote = '10.15.0.0/24', retryRemoteDuringGet = '10.18.0.0/24';
    status.advertise_routes = [savedPrefix];
    updateRouting();
    fixture.patch({tailscale_status: envelope(status)});
    await routeRow(localPrefix).waitFor({state: 'detached'});
    await routeInput.fill(retryLocal);
    await button('Add route').click();
    const [heldPut] = await Promise.all([
      fixture.holdRequest('PUT', '/api/tailscale/config'),
      button('Save routing').click(),
    ]);
    assert.deepEqual(heldPut.body, {advertise_routes: [savedPrefix, retryLocal]});
    status.advertise_routes = [savedPrefix, retryRemote];
    updateRouting();
    status.routing.routes[1].state = 'approved';
    fixture.patch({tailscale_status: envelope(status)});
    // Give EventSource a turn to deliver the SSE update while PUT is still in flight.
    await page.waitForTimeout(100);
    // Hold the recovery GET so a second SSE arrives while the GET is in flight, then fail the GET.
    const [heldRecoveryGet] = await Promise.all([
      fixture.holdRequest('GET', '/api/tailscale/status'),
      releaseResponse(page, heldPut, 'preferences are busy', 409),
    ]);
    await routeRow(retryRemote).getByText('Approved').waitFor();
    status.advertise_routes = [savedPrefix, retryRemote, retryRemoteDuringGet];
    updateRouting();
    status.routing.routes[1].state = 'approved';
    status.routing.routes[2].state = 'approved';
    fixture.patch({tailscale_status: envelope(status)});
    await page.waitForTimeout(100);
    await releaseResponse(page, heldRecoveryGet, 'status unavailable', 503);
    await said('#tailscale-routing .action-status', 'preferences are busy');
    await said('#tailscale-routing .action-status', 'Your draft is kept');
    await routeRow(retryRemote).getByText('Approved').waitFor();
    await routeRow(retryRemoteDuringGet).getByText('Approved').waitFor();
    await routeRow(retryLocal).getByText('New').waitFor();
    assert.deepEqual(
      await routing.locator('.tailscale-route-row code').allTextContents(),
      [savedPrefix, retryRemote, retryRemoteDuringGet, retryLocal]
    );
    await said('.tailscale-routing-conflict', '1 saved subnet route was added.');
    await button('Save routing').click();
    await said('#tailscale-routing .action-status', 'Tailscale routing saved');
    assert.deepEqual(lastConfig(), {advertise_routes: [savedPrefix, retryRemote, retryRemoteDuringGet, retryLocal]});

    // Also verify 409 without SSE refreshes latest status before retry.
    const retryLocal2 = '10.16.0.0/24', retryRemote2 = '10.17.0.0/24';
    status.advertise_routes = [savedPrefix];
    updateRouting();
    fixture.patch({tailscale_status: envelope(status)});
    await routeRow(retryLocal).waitFor({state: 'detached'});
    await routeInput.fill(retryLocal2);
    await button('Add route').click();
    const [heldPut2] = await Promise.all([
      fixture.holdRequest('PUT', '/api/tailscale/config'),
      button('Save routing').click(),
    ]);
    status.advertise_routes = [savedPrefix, retryRemote2];
    updateRouting();
    await releaseResponse(page, heldPut2, 'preferences are busy', 409);
    await routeRow(retryRemote2).getByText('Pending').waitFor();
    await routeRow(retryLocal2).getByText('New').waitFor();
    await button('Save routing').click();
    await said('#tailscale-routing .action-status', 'Tailscale routing saved');
    assert.deepEqual(lastConfig(), {advertise_routes: [savedPrefix, retryRemote2, retryLocal2]});

    status.advertise_routes = [];
    updateRouting();
    fixture.patch({tailscale_status: envelope(status)});
    await routeRow(savedPrefix).waitFor({state: 'detached'});
    await routeInput.fill(savedPrefix);
    await button('Add route').click();
    await routeRow(savedPrefix).getByText('New').waitFor();
    assert.equal(await routing.getAttribute('data-dirty'), 'true');
    status.advertise_routes = [savedPrefix];
    updateRouting();
    status.routing.routes[0].state = 'approved';
    fixture.patch({tailscale_status: envelope(status)});
    await routeRow(savedPrefix).getByText('Approved').waitFor();
    assert.equal(await routing.getAttribute('data-dirty'), 'false');
    assert.equal(await button('Save routing').isDisabled(), true);
    assert.equal(await routing.locator('.tailscale-routing-conflict').isHidden(), true);

    const fullRoutes = Array.from({length: 16}, (_, index) => `10.20.${index}.0/24`);
    await routeInput.fill(localPrefix);
    await button('Add route').click();
    status.advertise_routes = fullRoutes;
    updateRouting();
    fixture.patch({tailscale_status: envelope(status)});
    await said('#tailscale-route-hint', 'Remove subnet routes to stay within the 16-route limit.');
    await routeRow(localPrefix).getByText('New').waitFor();
    assert.equal(await button('Save routing').isDisabled(), true);
    await button(`Remove ${fullRoutes[0]}`).click();
    assert.equal(await button('Save routing').isEnabled(), true);
    await button('Discard routing edits').click();
    status.advertise_routes = earlierRoutes;
    updateRouting();
    fixture.patch({tailscale_status: envelope(status)});
    await routeRow(longPrefix).waitFor();

    // 5g. Tailscale Services (svc:*) panel: merged list, states, hints, picker, CRUD, drain/advertise/clear.
    const services = page.locator('#tailscale-services');
    await services.locator('[data-service="svc:t3code"]').waitFor({state: 'visible'});
    assert.match(await services.locator('[data-service="svc:t3code"]').textContent(), /Active/);
    assert.match(await services.locator('[data-service="svc:mismatch"]').textContent(), /Port mismatch/);
    assert.match(await services.locator('[data-service="svc:mismatch"]').textContent(), /8443/);
    assert.match(await services.locator('[data-service="svc:cli-only"]').textContent(), /Read-only CLI configuration/);
    assert.equal(await services.locator('[data-service="svc:cli-only"]').getByRole('button', {name: 'Edit', exact: true}).count(), 0);
    assert.match(await services.locator('[data-service="svc:assigned-only"]').textContent(), /Unconfigured/);
    const svcAdmin = services.locator('[data-service="svc:t3code"] a', {hasText: 'Tailscale admin'});
    assert.equal(await svcAdmin.getAttribute('href'), 'https://console.tailscale.com/admin/services/svc:t3code');
    assert.equal(await svcAdmin.getAttribute('rel'), 'noopener noreferrer');

    // Editing an existing service transforms its card in-place without spawning a duplicate form below.
    const t3Card = services.locator('[data-service="svc:t3code"]');
    await t3Card.getByRole('button', {name: 'Edit', exact: true}).click();
    assert.equal(await services.locator('[data-service="svc:t3code"]').count(), 1, 'no duplicate card while editing');
    assert.equal(await t3Card.getAttribute('data-editing'), 'true');
    assert.equal(await t3Card.locator('#tailscale-service-editor').count(), 1, 'editor mounts inside the edited card');
    assert.equal(await t3Card.locator('.tailscale-service-rules').count(), 0, 'view rules replaced in-place by editor');
    assert.equal(await t3Card.locator('#tailscale-service-name').isVisible(), false, 'redundant name input hidden in-place');
    // SSE status ticks while typing preserve in-place editor focus and draft text.
    await t3Card.locator('#tailscale-svc-target-0').fill('http://192.168.0.124:3774');
    fixture.patch({tailscale_status: envelope({...status, relay: 'tok'})});
    await said('#tailscale-status .tailscale-facts', 'DERP tok');
    assert.equal(await t3Card.locator('#tailscale-svc-target-0').inputValue(), 'http://192.168.0.124:3774');
    await t3Card.getByRole('button', {name: 'Cancel', exact: true}).click();
    assert.equal(await t3Card.getAttribute('data-editing'), null);
    assert.equal(await t3Card.locator('.tailscale-service-rules').count(), 1);
    assert.equal(await page.locator('#tailscale-service-editor').isHidden(), true);

    // Add a new service with multi-path HTTPS + TCP + dynamic DHCP & missing-subnet hints + device quick-pick.
    await button('Add service').click();
    await page.locator('#tailscale-service-editor').waitFor({state: 'visible'});
    await page.waitForFunction(() => document.querySelector('#tailscale-svc-pick-0')?.options.length >= 3);
    assert.doesNotMatch(await services.textContent(), /aa:bb:cc:dd/i, 'full MAC never leaks into Services picker');
    await page.locator('#tailscale-service-name').fill('my-web');
    await page.locator('#tailscale-svc-pick-0').selectOption('192.168.0.150');
    await page.locator('#tailscale-svc-target-0').fill('http://192.168.0.150:8080');
    // Both non-blocking hints appear for dynamic IP on unapproved/unadvertised subnet (10.99.0.5) & unreserved IP (192.168.0.150).
    await services.locator('[data-kind="dhcp"]').waitFor({state: 'visible'});
    assert.equal(await services.locator('[data-kind="dhcp"] a').getAttribute('href'), '#network/lan');
    await button('+ Add rule').click();
    await page.locator('#tailscale-svc-port-1').fill('443');
    await page.locator('#tailscale-svc-path-1').fill('/api');
    await page.locator('#tailscale-svc-target-1').fill('https+insecure://10.99.0.5:8443');
    await services.locator('[data-kind="subnet"]').waitFor({state: 'visible'});
    assert.match(await services.locator('[data-kind="subnet"]').textContent(), /10\.99\.0\.5/);
    await button('+ Add rule').click();
    await page.locator('#tailscale-svc-proto-2').selectOption('tcp');
    await page.locator('#tailscale-svc-port-2').fill('9001');
    await page.locator('#tailscale-svc-target-2').fill('unix:/tmp/my.sock');
    await button('Save service').click();
    await said('#tailscale-services .action-status', 'svc:my-web saved.');
    await services.locator('[data-service="svc:my-web"]').waitFor({state: 'visible'});
    const lastSvcPut = fixture.requests.filter(r => r.method === 'PUT' && r.url === '/api/tailscale/services/my-web').at(-1);
    assert.equal(lastSvcPut.body.rules.length, 3);

    // Drain, Advertise, and Clear with confirmation dialog.
    const myWebCard = services.locator('[data-service="svc:my-web"]');
    await myWebCard.getByRole('button', {name: 'Drain', exact: true}).click();
    await confirm('Drain service');
    await said('#tailscale-services .action-status', 'svc:my-web drained.');
    assert.match(await myWebCard.textContent(), /Drained/);
    await myWebCard.getByRole('button', {name: 'Advertise', exact: true}).click();
    await confirm('Advertise service');
    await said('#tailscale-services .action-status', 'svc:my-web advertised.');
    await myWebCard.getByRole('button', {name: 'Clear', exact: true}).click();
    assert.match(await text('.confirm-dialog'), /Remove all local serve handlers for svc:my-web/);
    await confirm('Clear svc:my-web');
    await said('#tailscale-services .action-status', 'svc:my-web cleared.');
    assert.equal(await myWebCard.count(), 0);
    assert.equal(await services.locator('[data-service="svc:t3code"]').count(), 1, 'clearing one service preserves others');

    // 6. Responsive & theme checks at 320, 390, 820 and 1440 in light & dark modes.
    for (const width of [320, 390, 820, 1440]) {
      for (const theme of ['light', 'dark']) {
        await page.setViewportSize({width, height: width === 390 ? 844 : 1000});
        await page.evaluate(value => {
          document.documentElement.dataset.theme = value;
        }, theme);
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
        assert.equal(overflow, false, `horizontal overflow at ${width}px (${theme})`);
        if (width === 390) {
          const row = routeRow(longPrefix);
          const prefix = await row.locator('code').boundingBox();
          const remove = await row.getByRole('button').boundingBox();
          assert.ok(remove.y >= prefix.y + prefix.height, 'route actions appear below the prefix');
          assert.ok(remove.width >= 44 && remove.height >= 44, 'route delete supports touch');
        }
      }
    }
    await page.setViewportSize({width: 1440, height: 1200});

    // 7. Disable & Logout surface remote-disconnect confirmation and logout warning.
    await button('Disable Tailscale').click();
    assert.match(await text('.confirm-dialog'), /disconnect immediately/);
    await confirm('Disable Tailscale');
    await said('#tailscale-status .tailscale-state', 'DISABLED');

    await button('Log out & reset').click();
    await confirm('Log out & reset');
    await said('#tailscale-status .tailscale-alerts', 'remove this machine in the admin console');
    assert.equal(fixture.requests.filter(request => request.url.startsWith('/api/tailscale/')).at(-1).url, '/api/tailscale/status');

    // 8. Lock clears drafts & private status, and a delayed status response cannot repopulate after Lock.
    await page.locator('#tailscale-auth-key').fill('tskey-auth-unsaved-secret');
    if (!await page.locator('#tailscale-manual').evaluate(node => node.open)) {
      await page.locator('#tailscale-manual summary').click();
    }
    await page.locator('#tailscale-version').fill('1.90.0');
    await button('+ Add LAN fd00:12::/64').click();
    await routeInput.fill('2001:db8:12::1/64');
    const [lateStatus] = await Promise.all([
      fixture.holdRequest('GET','/api/tailscale/status'),
      button('Read current status').click(),
    ]);
    await page.locator('#signout').click();
    await page.waitForFunction(() => OpenU60Console.locked);
    await releaseResponse(page,lateStatus,{...status, state: 'healthy', backend_state: 'Running', tailscale_ips: ['100.99.99.99'], dns_name: 'leaked.ts.net.'});
    assert.equal(await page.locator('#tailscale-auth-key').inputValue(), '');
    assert.equal(await page.locator('#tailscale-version').inputValue(), '');
    assert.equal(await page.locator('#tailscale-version-select').inputValue(), '');
    assert.equal(await page.locator('#tailscale-manual').evaluate(node => node.open), false);
    assert.equal(await routeInput.inputValue(), '');
    assert.equal(await routing.getAttribute('data-dirty'), 'false');
    assert.equal(await routeRow('fd00:12::/64').count(), 0);
    assert.doesNotMatch(await text('#tailscale-status'), /100\.99\.99\.99|leaked\.ts\.net/);

    // 9. When version lookup fails on unlock, manual entry opens automatically and Refresh versions recovers.
    versionsFail = true;
    await page.locator('#password').fill('fixture-pass');
    await page.locator('#login-form button[type=submit]').click();
    await page.waitForFunction(() => !OpenU60Console.locked);
    await said('#tailscale-version-select-help', 'GitHub and pkgs unavailable');
    assert.equal(await page.locator('#tailscale-manual').evaluate(node => node.open), true);

    versionsFail = false;
    await button('Refresh versions').click();
    await page.waitForFunction(() => document.querySelector('#tailscale-version-select')?.value === '1.104.8');
    await said('#tailscale-update .action-status', 'Loaded 4 official releases');

    // 10. A real stream outage discards staged routes and text.
    await button('+ Add LAN fd00:12::/64').click();
    await routeInput.fill('2001:db8:12::1/64');
    await page.context().setOffline(true);
    await page.clock.fastForward(31000);
    await page.waitForFunction(() => !OpenU60Console.connected);
    assert.equal(await routeInput.inputValue(), '');
    assert.equal(await routing.getAttribute('data-dirty'), 'false');
    assert.equal(await routeRow('fd00:12::/64').count(), 0);

    assert.deepEqual(errors, []);
    console.log('Passed: Tailscale install/upgrade, enrollment and lifecycle, routing validation and approval, split PUT diffs, draft preservation and cleanup, Exit Node confirmation, and responsive layout.');
  } finally {
    await browser.close();
    await fixture.close();
  }
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
