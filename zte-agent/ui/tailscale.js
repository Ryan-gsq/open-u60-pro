'use strict';
(() => {
  const route = 'network/tailscale', UI = OpenU60UI, API = OpenU60Console, M = OpenU60Tailscale;
  const {el, button, request, json, confirm, mutate, say} = UI;

  function field(labelText, input, helpText) {
    const wrapper = el('div', 'form-field'), label = el('label', '', labelText);
    label.htmlFor = input.id;
    wrapper.append(label, input);
    let help = null;
    if (helpText !== undefined) {
      help = el('small', 'field-help', helpText);
      help.id = `${input.id}-help`;
      input.setAttribute('aria-describedby', help.id);
      wrapper.append(help);
    }
    return {wrapper, help};
  }

  function choiceField(id, titleText, detailText) {
    const label = el('label', 'relay-choice tailscale-choice'), input = el('input');
    input.type = 'checkbox';
    input.id = id;
    const copy = el('span', 'tailscale-choice-copy');
    copy.append(el('strong', '', titleText), el('small', '', detailText));
    label.append(input, copy);
    return {label, input};
  }

  // ── Status & Lifecycle ──────────────────────────────────────────────────
  const statusPanel = UI.panel(
    route,
    'tailscale-status',
    'Tailscale',
    'Encrypted mesh access to this router from your Tailscale network. Runs in userspace networking mode without replacing default internet routes.'
  );
  statusPanel.classList.add('tailscale-panel');

  const hero = el('div', 'tailscale-hero');
  const glyph = el('div', 'tailscale-glyph');
  glyph.setAttribute('aria-hidden', 'true');
  const mesh = el('div', 'tailscale-mesh');
  for (let index = 0; index < 9; index++) mesh.append(el('i'));
  glyph.append(mesh);

  const heroCopy = el('div'), title = el('h3', '', 'Checking Tailscale'), detail = el('p', '');
  heroCopy.append(el('span', 'eyebrow', 'TAILSCALE MESH'), title, detail);
  const chip = el('span', 'tailscale-state', 'WAITING');
  hero.append(glyph, heroCopy, chip);

  const facts = el('dl', 'tailscale-facts');
  const alertsBox = el('div', 'relay-problem tailscale-alerts');
  alertsBox.setAttribute('role', 'alert');
  alertsBox.hidden = true;

  const statusActions = el('div', 'form-actions');
  const enableBtn = button('Enable Tailscale', () => toggleService(true), 'primary');
  const disableBtn = button('Disable Tailscale', () => toggleService(false), 'danger');
  const refreshBtn = button('Read current status', () => load(false));
  const logoutBtn = button('Log out & reset', logoutNode, 'danger');
  const adminLink = el('a', 'button', 'Tailscale admin console ↗');
  adminLink.href = M.ADMIN_CONSOLE_URL;
  adminLink.target = '_blank';
  adminLink.rel = 'noopener noreferrer';
  statusActions.append(enableBtn, disableBtn, refreshBtn, logoutBtn, adminLink);
  const statusText = UI.status(statusPanel);
  statusPanel.append(hero, facts, alertsBox, statusActions, statusText);

  // ── Enrollment & Authentication ─────────────────────────────────────────
  const authPanel = UI.panel(
    route,
    'tailscale-auth',
    'Enrollment & authentication',
    'Join this router to your tailnet with an interactive browser login link or a pre-authenticated auth key. An agent password must be configured before remote access can be enabled.'
  );
  const loginRow = el('div', 'form-actions');
  const loginUrlBtn = button('Get login link', requestLoginUrl, 'primary');
  loginUrlBtn.id = 'tailscale-login-url-btn';
  loginRow.append(loginUrlBtn);

  const loginBox = el('div', 'tailscale-login-box');
  loginBox.hidden = true;
  const loginCode = el('code', 'mono tailscale-login-url');
  const loginBoxActions = el('div', 'form-actions');
  const loginOpenLink = el('a', 'button primary', 'Open Tailscale login ↗');
  loginOpenLink.target = '_blank';
  loginOpenLink.rel = 'noopener noreferrer';
  const copyLoginBtn = button('Copy link', copyLoginUrl);
  loginBoxActions.append(loginOpenLink, copyLoginBtn);
  loginBox.append(
    el('span', 'eyebrow', 'BROWSER LOGIN LINK'),
    loginCode,
    loginBoxActions,
    el('small', 'field-help', 'Complete sign-in in the new tab. This page updates automatically once the router joins your tailnet.')
  );

  const authForm = el('form', 'settings-form tailscale-subform');
  authForm.id = 'tailscale-authkey-form';
  authForm.autocomplete = 'off';
  const authFields = el('fieldset', 'form-grid');
  authFields.append(el('legend', 'sr-only', 'Enroll with auth key'));
  const authKeyInput = el('input', 'mono');
  authKeyInput.id = 'tailscale-auth-key';
  authKeyInput.name = 'auth_key';
  authKeyInput.type = 'password';
  authKeyInput.autocomplete = 'off';
  authKeyInput.spellcheck = false;
  authKeyInput.placeholder = 'tskey-auth-…';
  const authKeyField = field(
    'Pre-authenticated auth key',
    authKeyInput,
    'Alternative to browser login. Passed through a temporary 0600 file in tmpfs and deleted immediately; never saved on flash.'
  );
  authKeyField.wrapper.classList.add('tailscale-wide-field');
  authFields.append(authKeyField.wrapper);
  const authFormActions = el('div', 'form-actions');
  const enrollBtn = button('Enroll with auth key', null, 'primary');
  enrollBtn.type = 'submit';
  const clearKeyBtn = button('Clear', () => { authKeyInput.value = ''; drawAuth(); say(authText, ''); });
  authFormActions.append(enrollBtn, clearKeyBtn);
  authForm.append(authFields, authFormActions);

  const authHint = el('p', 'field-help');
  authHint.classList.add('tailscale-auth-hint');
  const authText = UI.status(authPanel);
  authPanel.append(authHint, loginRow, loginBox, authForm, authText);

  // ── Preferences & Routing ───────────────────────────────────────────────
  const configPanel = UI.panel(
    route,
    'tailscale-config',
    'Preferences & routing',
    'Managed node settings re-applied on every daemon start. Advertised subnet routes must also be approved in the Tailscale admin console.'
  );
  const configForm = el('form', 'settings-form');
  configForm.id = 'tailscale-config-form';
  configForm.autocomplete = 'off';
  const configFields = el('fieldset', 'form-grid');
  configFields.id = 'tailscale-config-fields';
  configFields.append(el('legend', 'sr-only', 'Tailscale preferences'));

  const hostnameInput = el('input', 'mono');
  hostnameInput.id = 'tailscale-hostname';
  hostnameInput.name = 'hostname';
  hostnameInput.type = 'text';
  hostnameInput.maxLength = 63;
  hostnameInput.required = true;
  hostnameInput.spellcheck = false;
  hostnameInput.placeholder = 'u60-pro';
  const hostnameField = field(
    'Hostname',
    hostnameInput,
    '1–63 ASCII letters, digits or hyphens. Used for MagicDNS and the console Host allowlist.'
  );

  const routesInput = el('input', 'mono');
  routesInput.id = 'tailscale-routes';
  routesInput.name = 'advertise_routes';
  routesInput.type = 'text';
  routesInput.spellcheck = false;
  routesInput.placeholder = '192.168.0.0/24';
  const routesField = field(
    'Advertise subnet routes',
    routesInput,
    'Comma-separated IPv4 CIDRs (leave blank for none). Approve advertised routes in the Tailscale admin console.'
  );

  const sshChoice = choiceField(
    'tailscale-ssh',
    'Enable Tailscale SSH',
    'Allow SSH access over Tailscale governed by your tailnet ACL policy.'
  );
  const wakelockChoice = choiceField(
    'tailscale-wakelock',
    'Hold device wakelock while enabled',
    'Prevent deep sleep so remote Tailscale access stays reachable. Increases idle battery use.'
  );
  configFields.append(hostnameField.wrapper, routesField.wrapper, sshChoice.label, wakelockChoice.label);

  const configActions = el('div', 'form-actions');
  const saveConfigBtn = button('Save preferences', null, 'primary');
  saveConfigBtn.type = 'submit';
  const discardConfigBtn = button('Discard edits', discardConfig);
  configActions.append(saveConfigBtn, discardConfigBtn);
  configForm.append(configFields, configActions);
  const configText = UI.status(configPanel);
  configPanel.append(configForm, configText);

  // ── Install & Upgrade ───────────────────────────────────────────────────
  const updatePanel = UI.panel(
    route,
    'tailscale-update',
    'Install & upgrade',
    'Download official ARM64 Tailscale binaries from pkgs.tailscale.com, verify SHA-256 and swap atomically with 120-second automatic rollback for enrolled nodes.'
  );
  const updateBanner = el('p', 'tailscale-update-banner');
  updateBanner.hidden = true;

  const updateForm = el('form', 'settings-form');
  updateForm.id = 'tailscale-update-form';
  updateForm.autocomplete = 'off';
  const updateFields = el('fieldset', 'form-grid');
  updateFields.id = 'tailscale-update-fields';
  updateFields.append(el('legend', 'sr-only', 'Install or upgrade Tailscale'));

  const versionInput = el('input', 'mono');
  versionInput.id = 'tailscale-version';
  versionInput.name = 'version';
  versionInput.type = 'text';
  versionInput.spellcheck = false;
  versionInput.required = true;
  versionInput.placeholder = '1.86.2';
  const versionField = field(
    'Tailscale version',
    versionInput,
    'Exact version from pkgs.tailscale.com/stable/#static (without a leading “v”).'
  );

  const sha256Input = el('input', 'mono');
  sha256Input.id = 'tailscale-sha256';
  sha256Input.name = 'sha256';
  sha256Input.type = 'text';
  sha256Input.maxLength = 64;
  sha256Input.spellcheck = false;
  sha256Input.required = true;
  sha256Input.placeholder = '64 hexadecimal characters';
  const sha256Field = field(
    'SHA-256 checksum',
    sha256Input,
    'SHA-256 digest of the arm64 .tgz archive. Verified before extracting or replacing binaries.'
  );
  updateFields.append(versionField.wrapper, sha256Field.wrapper);

  const updateActions = el('div', 'form-actions');
  const installBtn = button('Install Tailscale', null, 'primary');
  installBtn.type = 'submit';
  const clearUpdateBtn = button('Clear', clearUpdateDraft);
  const packagesLink = el('a', 'button', 'Versions & SHA-256 ↗');
  packagesLink.href = M.PACKAGES_URL;
  packagesLink.target = '_blank';
  packagesLink.rel = 'noopener noreferrer';
  updateActions.append(installBtn, clearUpdateBtn, packagesLink);
  updateForm.append(updateFields, updateActions);
  const updateText = UI.status(updatePanel);
  const updateNote = el(
    'p',
    'panel-note',
    'Downloads stream to tmpfs (120 MB cap), verify SHA-256, smoke-test tailscaled --version and swap atomically. If an enrolled node does not return to Running within 120 seconds, the previous binary is restored automatically.'
  );
  updatePanel.append(updateBanner, updateForm, updateText, updateNote);

  // ── State ───────────────────────────────────────────────────────────────
  let status = null, baseline = null, loading = false, attempted = false, busy = false, lastLoad = 0, loadId = 0;
  let pendingLoginUrl = '', loginPending = false, logoutWarning = '';
  const READING_STATUS_MESSAGE = 'Reading Tailscale status…';
  const onRoute = () => OpenU60Navigation.current.key === route;

  function currentConfigDraft() {
    return {
      hostname: hostnameInput.value,
      routesText: routesInput.value,
      tailscale_ssh: sshChoice.input.checked,
      hold_wakelock: wakelockChoice.input.checked
    };
  }
  const configDirty = () => !!baseline && Object.keys(M.configDiff(baseline, currentConfigDraft())).length > 0;
  const authDirty = () => authKeyInput.value.trim().length > 0;
  const updateDirty = () => versionInput.value.trim().length > 0 || sha256Input.value.trim().length > 0;
  const dirty = () => configDirty() || authDirty() || updateDirty();

  function populateConfig(data) {
    baseline = M.configBaseline(data);
    hostnameInput.value = baseline.hostname;
    routesInput.value = baseline.advertise_routes.join(', ');
    sshChoice.input.checked = baseline.tailscale_ssh;
    wakelockChoice.input.checked = baseline.hold_wakelock;
  }

  function discardConfig() {
    if (!baseline) return;
    hostnameInput.value = baseline.hostname;
    routesInput.value = baseline.advertise_routes.join(', ');
    sshChoice.input.checked = baseline.tailscale_ssh;
    wakelockChoice.input.checked = baseline.hold_wakelock;
    drawConfig();
    say(configText, 'Draft discarded.');
  }

  function clearUpdateDraft() {
    versionInput.value = '';
    sha256Input.value = '';
    drawUpdate();
    say(updateText, '');
  }

  function applyStatus(data, {forceConfig = false} = {}) {
    status = data;
    attempted = true;
    const view = M.view(data);
    const daemonUnavailable =
      !view.installed ||
      view.running ||
      view.updating ||
      data?.daemon_running === false ||
      view.state === 'disabled' ||
      view.state === 'respawning' ||
      view.state === 'starting';
    if (daemonUnavailable) {
      pendingLoginUrl = '';
      loginPending = false;
    } else if (view.loginUrl) {
      pendingLoginUrl = '';
      loginPending = false;
    }
    if (view.running || view.enabled) logoutWarning = '';
    if (data && (forceConfig || !baseline || !configDirty())) {
      populateConfig(data);
    }
    draw();
  }

  function drawStatus(view) {
    statusPanel.dataset.state = view.tone;
    glyph.dataset.state = view.tone;
    chip.textContent = view.chip;
    title.textContent = view.title;
    detail.textContent = view.detail;
    facts.replaceChildren(...M.facts(status).map(([label, value, mono]) => {
      const pair = el('div');
      pair.append(el('dt', '', label), el('dd', mono ? 'mono' : '', value));
      return pair;
    }));
    const notes = M.alerts(status);
    if (logoutWarning && !notes.includes(logoutWarning)) notes.unshift(logoutWarning);
    alertsBox.hidden = notes.length === 0;
    alertsBox.replaceChildren(...notes.map(item => el('p', '', item)));

    const inactive = busy || !API.connected || API.locked || !status;
    enableBtn.hidden = !view.canEnable;
    enableBtn.disabled = inactive || loading;
    disableBtn.hidden = !view.canDisable;
    disableBtn.disabled = inactive || loading;
    logoutBtn.hidden = !view.canLogout;
    logoutBtn.disabled = inactive || loading;
    refreshBtn.disabled = loading || busy || !API.connected || API.locked;
  }

  function drawAuth(view = M.view(status)) {
    const inactive = busy || !API.connected || API.locked || !status;
    const effectiveLoginUrl = view.loginUrl || (view.running ? '' : pendingLoginUrl);
    loginUrlBtn.disabled = inactive || !view.canLoginUrl;
    loginUrlBtn.textContent = effectiveLoginUrl ? 'Refresh login link' : 'Get login link';
    loginBox.hidden = !effectiveLoginUrl;
    if (effectiveLoginUrl) {
      loginCode.textContent = effectiveLoginUrl;
      loginOpenLink.href = effectiveLoginUrl;
    } else {
      loginCode.textContent = '';
      loginOpenLink.removeAttribute('href');
    }
    authFields.disabled = inactive || !view.canAuthKey;
    const hasKey = authDirty();
    enrollBtn.disabled = inactive || !view.canAuthKey || !hasKey;
    clearKeyBtn.disabled = inactive || !hasKey;
    authPanel.dataset.dirty = String(hasKey);
    if (loginPending && !effectiveLoginUrl && view.canLoginUrl) {
      authHint.textContent = 'Waiting for Tailscale to generate a login URL… Status updates automatically.';
      authHint.hidden = false;
    } else {
      authHint.textContent = view.authReason;
      authHint.hidden = !view.authReason;
    }
  }

  function drawConfig(view = M.view(status)) {
    const inactive = busy || !API.connected || API.locked || !status;
    const isDirty = configDirty();
    configFields.disabled = inactive || !view.canConfig;
    saveConfigBtn.disabled = inactive || !view.canConfig || !isDirty;
    discardConfigBtn.disabled = inactive || !isDirty;
    configPanel.dataset.dirty = String(isDirty);
  }

  function drawUpdate(view = M.view(status)) {
    const inactive = busy || !API.connected || API.locked || !status;
    const isDirty = updateDirty();
    updateFields.disabled = inactive || !view.canUpdate;
    installBtn.textContent = view.installed ? 'Download & upgrade' : 'Install Tailscale';
    installBtn.disabled = inactive || !view.canUpdate || !versionInput.value.trim() || !sha256Input.value.trim();
    clearUpdateBtn.disabled = inactive || !isDirty;
    updatePanel.dataset.dirty = String(isDirty);

    const previewUrl = M.packageUrl(versionInput.value);
    versionField.help.textContent = previewUrl
      ? `Package URL: ${previewUrl}`
      : 'Exact version from pkgs.tailscale.com/stable/#static (without a leading “v”).';

    if (view.updating) {
      updateBanner.hidden = false;
      updateBanner.dataset.state = 'busy';
      updateBanner.textContent = 'Install or upgrade in progress… Downloading, verifying SHA-256 and swapping binaries in the background. This page updates automatically when finished.';
    } else {
      const summary = M.lastUpdateSummary(status?.last_update);
      if (summary) {
        updateBanner.hidden = false;
        updateBanner.dataset.state = summary.ok ? 'ok' : 'error';
        updateBanner.textContent = summary.text;
      } else {
        updateBanner.hidden = true;
        updateBanner.textContent = '';
      }
    }
  }

  function draw() {
    const view = M.view(status);
    drawStatus(view);
    drawAuth(view);
    drawConfig(view);
    drawUpdate(view);
  }

  async function load(quiet = false) {
    if (loading || API.locked || !API.connected) return;
    const epoch = UI.epoch, id = ++loadId;
    const current = () => UI.current(epoch) && id === loadId;
    loading = true;
    attempted = true;
    lastLoad = Date.now();
    draw();
    if (!quiet) say(statusText, READING_STATUS_MESSAGE);
    let failure = '';
    try {
      const data = await request('/api/tailscale/status', {timeoutMs: 15000});
      if (!current()) return;
      applyStatus(data);
      if (!quiet && statusText.textContent === READING_STATUS_MESSAGE) say(statusText, '');
    } catch (error) {
      if (!current()) return;
      failure = `Tailscale status unavailable. ${error.message}`;
    } finally {
      if (id === loadId) loading = false;
      if (current()) {
        draw();
        if (failure) say(statusText, failure, true);
      }
    }
  }

  async function refreshAfterMutation(live) {
    try {
      const data = await request('/api/tailscale/status', {timeoutMs: 15000});
      if (live()) applyStatus(data);
    } catch {
      /* SSE or manual refresh will follow. */
    }
  }

  async function toggleService(enable) {
    if (!status || busy) return;
    const heading = enable ? 'Enable Tailscale?' : 'Disable Tailscale?';
    const copy = enable
      ? 'Start the supervised tailscaled daemon and reconnect this router to your tailnet. Tailscale requires an agent password to be configured.'
      : 'Stop tailscaled and take this router offline on your tailnet. If you are viewing this console over Tailscale, your session will disconnect immediately.';
    if (!await confirm(heading, copy, {label: enable ? 'Enable Tailscale' : 'Disable Tailscale', destructive: !enable})) return;
    await mutate(statusText, async live => {
      busy = true;
      draw();
      say(statusText, enable ? 'Starting Tailscale…' : 'Stopping Tailscale…');
      try {
        await request(`/api/tailscale/${enable ? 'enable' : 'disable'}`, {...json('POST', {}), timeoutMs: 30000});
        if (!live()) return;
        if (enable) logoutWarning = '';
        else { pendingLoginUrl = ''; loginPending = false; }
        await refreshAfterMutation(live);
        if (!live()) return;
        say(statusText, enable ? 'Tailscale enabled. Status updates automatically as the daemon comes up.' : 'Tailscale disabled.');
      } catch (error) {
        if (live()) say(statusText, error.message, true);
      } finally {
        busy = false;
        if (live()) draw();
      }
    });
  }

  async function logoutNode() {
    if (!status || busy) return;
    const copy = 'Invalidate this router’s Tailscale node key, remove saved identity files and disable Tailscale. If you are viewing this console over Tailscale, your session will disconnect immediately. You will need to re-enroll to use Tailscale again.';
    if (!await confirm('Log out & reset Tailscale?', copy, {label: 'Log out & reset', destructive: true})) return;
    await mutate(statusText, async live => {
      busy = true;
      draw();
      say(statusText, 'Logging out of Tailscale…');
      try {
        const result = await request('/api/tailscale/logout', {...json('POST', {}), timeoutMs: 60000});
        if (!live()) return;
        pendingLoginUrl = '';
        loginPending = false;
        logoutWarning = result?.warning ? String(result.warning) : '';
        await refreshAfterMutation(live);
        if (!live()) return;
        if (logoutWarning) say(statusText, logoutWarning, true);
        else say(statusText, 'Logged out and local Tailscale state removed.');
      } catch (error) {
        if (live()) say(statusText, error.message, true);
      } finally {
        busy = false;
        if (live()) draw();
      }
    });
  }

  async function requestLoginUrl() {
    if (!status || busy) return;
    await mutate(authText, async live => {
      busy = true;
      draw();
      say(authText, 'Requesting browser login link from tailscaled…');
      try {
        const result = await request('/api/tailscale/login-url', {...json('POST', {}), timeoutMs: 45000});
        if (!live()) return;
        const safe = M.safeLoginUrl(result?.login_url);
        if (safe) {
          pendingLoginUrl = safe;
          loginPending = false;
          say(authText, 'Login link ready. Open it in a new tab to approve this router.');
        } else if (result?.pending) {
          pendingLoginUrl = '';
          loginPending = true;
          say(authText, 'Waiting for Tailscale to generate a login link… This page will update automatically.');
        } else {
          pendingLoginUrl = '';
          loginPending = false;
          say(authText, 'The router did not return an HTTPS login URL. Check status and try again.', true);
        }
        await refreshAfterMutation(live);
      } catch (error) {
        if (live()) say(authText, error.message, true);
      } finally {
        busy = false;
        if (live()) draw();
      }
    });
  }

  async function copyLoginUrl() {
    const url = loginCode.textContent.trim();
    if (!url) return;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(url);
        say(authText, 'Login link copied to clipboard.');
        return;
      }
      const helper = el('textarea', 'sr-only');
      helper.value = url;
      helper.setAttribute('readonly', '');
      document.body.append(helper);
      helper.select();
      const copied = document.execCommand('copy');
      helper.remove();
      say(authText, copied ? 'Login link copied to clipboard.' : 'Copy blocked by browser; copy the link shown above.', !copied);
    } catch {
      say(authText, 'Clipboard access is unavailable; copy the link shown above.', true);
    }
  }

  authKeyInput.addEventListener('input', () => {
    drawAuth();
    if (authDirty()) say(authText, 'Auth key stays only in this tab until submitted.');
    else say(authText, '');
  });

  authForm.addEventListener('submit', async event => {
    event.preventDefault();
    if (!status || busy) return;
    const issue = M.authKeyProblem(authKeyInput.value);
    if (issue) { say(authText, issue, true); return; }
    if (!await confirm(
      'Enroll with auth key?',
      'Start tailscaled if needed and join your tailnet using this auth key. The key is written to a 0600 tmpfs file for the enrollment call and deleted immediately afterward.',
      {label: 'Enroll router'}
    )) return;
    const key = authKeyInput.value.trim();
    if (!key) return;
    await mutate(authText, async live => {
      authKeyInput.value = '';
      busy = true;
      draw();
      say(authText, 'Enrolling with Tailscale (this can take up to 90 seconds)…');
      try {
        const data = await request('/api/tailscale/setup', {...json('POST', {auth_key: key}), timeoutMs: 130000});
        if (!live()) return;
        pendingLoginUrl = '';
        loginPending = false;
        logoutWarning = '';
        applyStatus(data);
        say(authText, 'Router enrolled and connected to Tailscale.');
      } catch (error) {
        if (live()) say(authText, error.message, true);
      } finally {
        busy = false;
        if (live()) draw();
      }
    });
  });

  configForm.addEventListener('input', () => {
    drawConfig();
    if (configDirty()) say(configText, 'Unsaved changes · live updates keep your draft.');
    else say(configText, '');
  });
  configForm.addEventListener('change', () => configForm.dispatchEvent(new Event('input')));

  configForm.addEventListener('submit', async event => {
    event.preventDefault();
    if (!status || !baseline || busy) return;
    const draft = currentConfigDraft();
    const issue = M.configProblem(draft);
    if (issue) { say(configText, issue, true); return; }
    const patch = M.configDiff(baseline, draft);
    if (!Object.keys(patch).length) { say(configText, 'No changes to save.'); return; }
    const summary = M.configConfirmation(patch, status.enabled === true);
    if (!await confirm('Save Tailscale preferences?', summary, {label: 'Save preferences'})) return;
    await mutate(configText, async live => {
      busy = true;
      draw();
      say(configText, 'Applying Tailscale preferences…');
      try {
        const data = await request('/api/tailscale/config', {...json('PUT', patch), timeoutMs: 30000});
        if (!live()) return;
        applyStatus(data, {forceConfig: true});
        say(configText, 'Tailscale preferences saved.');
      } catch (error) {
        if (live()) say(configText, error.message, true);
      } finally {
        busy = false;
        if (live()) draw();
      }
    });
  });

  updateForm.addEventListener('input', () => {
    drawUpdate();
    say(updateText, '');
  });

  updateForm.addEventListener('submit', async event => {
    event.preventDefault();
    if (!status || busy) return;
    const draft = {version: versionInput.value, sha256: sha256Input.value};
    const issue = M.updateProblem(draft);
    if (issue) { say(updateText, issue, true); return; }
    const req = M.updateRequest(draft);
    const url = M.packageUrl(req.version);
    const actionLabel = status.installed ? `Upgrade to v${req.version}` : `Install v${req.version}`;
    const copy = `Download ${url} and verify SHA-256 ${req.sha256.slice(0, 12)}…${req.sha256.slice(-8)}. ${status.installed ? 'Tailscale briefly disconnects while swapping binaries, and rolls back automatically if an enrolled node fails to reconnect within 120 seconds.' : 'Binaries are verified and smoke-tested before installation.'}`;
    if (!await confirm(`${actionLabel}?`, copy, {label: actionLabel})) return;
    await mutate(updateText, async live => {
      busy = true;
      draw();
      say(updateText, `Starting download for Tailscale v${req.version}…`);
      try {
        await request('/api/tailscale/update', {...json('POST', req), timeoutMs: 25000});
        if (!live()) return;
        versionInput.value = '';
        sha256Input.value = '';
        await refreshAfterMutation(live);
        if (!live()) return;
        say(updateText, `Background ${status?.installed ? 'upgrade' : 'install'} to v${req.version} started. Status updates automatically when finished.`);
      } catch (error) {
        if (live()) say(updateText, error.message, true);
      } finally {
        busy = false;
        if (live()) draw();
      }
    });
  });

  function refreshVisible() {
    if (document.hidden || loading || busy || API.locked || !API.connected || !onRoute() || Date.now() - lastLoad < 1000) return;
    load(true);
  }
  window.addEventListener('focus', refreshVisible);
  window.addEventListener('pageshow', refreshVisible);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refreshVisible(); });

  UI.track({
    route,
    sync(readings) {
      const sample = readings.tailscale_status;
      if (!onRoute() || API.locked || busy || !sample?.ok) return;
      if (loading) {
        loadId++;
        loading = false;
        if (statusText.textContent === READING_STATUS_MESSAGE) say(statusText, '');
      }
      applyStatus(sample.data);
    },
    get loaded() { return attempted; },
    get dirty() { return dirty(); },
    load: () => load(false),
    refresh: () => load(true),
    clear() {
      loadId++;
      status = null; baseline = null; loading = false; attempted = false; busy = false;
      pendingLoginUrl = ''; loginPending = false; logoutWarning = '';
      authKeyInput.value = '';
      hostnameInput.value = '';
      routesInput.value = '';
      sshChoice.input.checked = false;
      wakelockChoice.input.checked = false;
      versionInput.value = '';
      sha256Input.value = '';
      for (const node of [statusText, authText, configText, updateText]) say(node, '');
      draw();
    }
  });

  draw();
})();
