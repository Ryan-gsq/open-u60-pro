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

  const fixture = await start(({method, url, body}, reply, fail) => {
    if (method === 'POST' && url === '/api/auth/login') {
      reply({token: 'fixture-session-2'});
      return true;
    }
    if (method === 'GET' && url === '/api/tailscale/status') {
      reply(status);
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
      reply(status);
      return true;
    }
    if (method === 'PUT' && url === '/api/tailscale/config') {
      if (Object.hasOwn(body, 'hostname')) status.hostname = body.hostname;
      if (Object.hasOwn(body, 'advertise_routes')) status.advertise_routes = body.advertise_routes;
      if (Object.hasOwn(body, 'tailscale_ssh')) status.tailscale_ssh = body.tailscale_ssh;
      if (Object.hasOwn(body, 'hold_wakelock')) {
        status.hold_wakelock = body.hold_wakelock;
        status.wakelock_held = status.enabled && body.hold_wakelock;
      }
      if (status.backend_state === 'Running') {
        status.dns_name = `${status.hostname}.tail1234.ts.net.`;
      }
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
      reply({status: 'logged_out', warning: 'daemon unavailable — remove this machine in the admin console'});
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
  const last = () => fixture.requests.at(-1);

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

    // 5. Preferences validation, dirty-draft preservation across SSE patches, and partial PUT diff.
    await page.locator('#tailscale-routes').fill('192.168.0.0/33');
    await button('Save preferences').click();
    await said('#tailscale-config .action-status', 'Invalid IPv4 CIDR');
    assert.equal(fixture.count('PUT', '/api/tailscale/config'), 0);

    await page.locator('#tailscale-hostname').fill('u60-home');
    await page.locator('#tailscale-routes').fill('192.168.0.0/24, 10.10.0.0/24');
    await page.locator('#tailscale-ssh').check();
    await page.locator('#tailscale-wakelock').uncheck();
    // Live SSE update must preserve unsaved config edits.
    fixture.patch({tailscale_status: envelope({...status, relay: 'sin'})});
    await said('#tailscale-status .tailscale-facts', 'DERP sin');
    assert.equal(await page.locator('#tailscale-hostname').inputValue(), 'u60-home');
    assert.equal(await page.locator('#tailscale-routes').inputValue(), '192.168.0.0/24, 10.10.0.0/24');

    await page.clock.runFor(1200);
    status = {...status, relay: 'fra'};
    await refreshOn(page,fixture,'focus','/api/tailscale/status');
    await said('#tailscale-status .tailscale-facts', 'DERP fra');
    assert.equal(await page.locator('#tailscale-hostname').inputValue(), 'u60-home');
    assert.equal(await page.locator('#tailscale-routes').inputValue(), '192.168.0.0/24, 10.10.0.0/24');

    await button('Save preferences').click();
    assert.match(await text('.confirm-dialog'), /Tailscale SSH will be enabled/);
    await confirm('Save preferences');
    await said('#tailscale-config .action-status', 'Tailscale preferences saved');
    assert.deepEqual(
      fixture.requests.find(item => item.method === 'PUT' && item.url === '/api/tailscale/config').body,
      {hostname: 'u60-home', advertise_routes: ['192.168.0.0/24', '10.10.0.0/24'], tailscale_ssh: true, hold_wakelock: false}
    );
    assert.match(await text('#tailscale-status .tailscale-facts'), /u60-home\.tail1234\.ts\.net/);
    assert.match(await text('#tailscale-status .tailscale-facts'), /192\.168\.0\.0\/24, 10\.10\.0\.0\/24/);
    assert.match(await text('#tailscale-status .tailscale-facts'), /Enabled/);

    // 6. Responsive & theme checks at 320, 390, 820 and 1440 in light & dark modes.
    for (const width of [320, 390, 820, 1440]) {
      for (const theme of ['light', 'dark']) {
        await page.setViewportSize({width, height: 1000});
        await page.evaluate(value => {
          document.documentElement.dataset.theme = value;
        }, theme);
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
        assert.equal(overflow, false, `horizontal overflow at ${width}px (${theme})`);
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
    assert.equal(last().url, '/api/tailscale/status');

    // 8. Lock clears drafts & private status, and a delayed status response cannot repopulate after Lock.
    await page.locator('#tailscale-auth-key').fill('tskey-auth-unsaved-secret');
    if (!await page.locator('#tailscale-manual').evaluate(node => node.open)) {
      await page.locator('#tailscale-manual summary').click();
    }
    await page.locator('#tailscale-version').fill('1.90.0');
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

    assert.deepEqual(errors, []);
    console.log('Passed: Tailscale install/upgrade via SSE, enable, safe HTTPS login URL, auth key enrollment & redaction, preferences diff & draft preservation, responsive light/dark layout, disable/logout warning, and Lock cleanup.');
  } finally {
    await browser.close();
    await fixture.close();
  }
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
