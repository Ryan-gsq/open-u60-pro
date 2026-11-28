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
    'Encrypted access to this router from your Tailscale network.'
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
  statusActions.append(enableBtn, disableBtn, refreshBtn, logoutBtn);
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

  // ── Preferences ─────────────────────────────────────────────────────────
  const configPanel = UI.panel(
    route,
    'tailscale-config',
    'Preferences',
    'Node settings applied whenever Tailscale starts.'
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
  configFields.append(hostnameField.wrapper, sshChoice.label, wakelockChoice.label);

  const configActions = el('div', 'form-actions');
  const saveConfigBtn = button('Save preferences', null, 'primary');
  saveConfigBtn.type = 'submit';
  const discardConfigBtn = button('Discard edits', discardConfig);
  configActions.append(saveConfigBtn, discardConfigBtn);
  configForm.append(configFields, configActions);
  const configText = UI.status(configPanel);
  configPanel.append(configForm, configText);

  // ── Subnet routes & Exit Node ───────────────────────────────────────────
  const routingPanel = UI.panel(
    route, 'tailscale-routing', 'Subnet routes & Exit Node',
    'Share LAN subnets or this router’s internet connection with your tailnet.'
  );
  statusPanel.after(routingPanel);
  const routingBar = el('div', 'tailscale-routing-bar');
  const tunLabel = el('strong');
  const syncChip = el('span', 'tailscale-routing-chip');
  const adminLink = el('a', 'button', 'Approve in Tailscale admin ↗');
  adminLink.href = M.ADMIN_CONSOLE_URL;
  adminLink.target = '_blank';
  adminLink.rel = 'noopener noreferrer';
  for (const [label, value] of [['TUN mode', tunLabel], ['Config sync', syncChip]]) {
    const fact = el('div', 'tailscale-routing-fact');
    fact.append(el('small', 'field-help', label), value);
    routingBar.append(fact);
  }
  routingBar.append(adminLink);

  const routingForm = el('form', 'settings-form');
  routingForm.autocomplete = 'off';
  const routingFields = el('fieldset', 'tailscale-routing-fields');
  routingFields.append(el('legend', 'sr-only', 'Tailscale routing settings'));
  const routeList = el('ul', 'tailscale-route-list');
  routeList.setAttribute('aria-label', 'Subnet routes');
  const noRoutes = el('p', 'field-help', 'No subnet routes.');
  const routeInput = el('input', 'mono');
  routeInput.id = 'tailscale-route-cidr';
  routeInput.spellcheck = false;
  routeInput.autocapitalize = 'none';
  routeInput.placeholder = '192.168.0.0/24';
  const routeLabel = el('label', '', 'IPv4 or IPv6 CIDR');
  routeLabel.htmlFor = routeInput.id;
  const routeHint = el('small', 'field-help');
  routeHint.id = 'tailscale-route-hint';
  routeHint.setAttribute('aria-live', 'polite');
  routeInput.setAttribute('aria-describedby', routeHint.id);
  const addRouteBtn = button('Add route', () => {
    if (addRoute(routeInput.value)) routeInput.focus();
  });
  const routeEntry = el('div', 'tailscale-route-entry');
  routeEntry.append(routeLabel, routeInput, addRouteBtn, routeHint);
  const lanButtons = el('div', 'tailscale-lan-routes');
  const subnetSection = el('section', 'tailscale-routing-section');
  subnetSection.append(el('h3', '', 'Subnet routes'), routeList, noRoutes, routeEntry, lanButtons);

  const exitChoice = choiceField(
    'tailscale-advertise-exit-node', 'Advertise Exit Node',
    'Let approved tailnet peers use this router for internet access.'
  );
  const mihomoChoice = choiceField(
    'tailscale-exit-via-mihomo', 'Route Exit Node via Mihomo',
    'Use Mihomo for Exit Node traffic when Exit Node is enabled.'
  );
  exitChoice.input.setAttribute('role', 'switch');
  mihomoChoice.input.setAttribute('role', 'switch');
  const approval = el('dl', 'tailscale-exit-approval');
  const exitChips = new Map();
  for (const [key, label] of [['state', 'Overall'], ['state_v4', 'IPv4'], ['state_v6', 'IPv6']]) {
    const entry = el('div');
    const value = el('dd', 'tailscale-routing-chip');
    value.dataset.family = key;
    entry.append(el('dt', 'field-help', label), value);
    approval.append(entry);
    exitChips.set(key, value);
  }
  approval.setAttribute('aria-label', 'Saved Exit Node approval');
  const context = el('p', 'field-help tailscale-exit-context');
  const exitSection = el('section', 'tailscale-routing-section');
  exitSection.append(el('h3', '', 'Exit Node'), exitChoice.label, approval, mihomoChoice.label, context);
  routingFields.append(subnetSection, exitSection);

  const routingConflict = el('p', 'relay-problem tailscale-routing-conflict');
  routingConflict.setAttribute('role', 'status');
  routingConflict.hidden = true;
  const routingActions = el('div', 'form-actions');
  const saveRoutingBtn = button('Save routing', null, 'primary');
  saveRoutingBtn.type = 'submit';
  const discardRoutingBtn = button('Discard routing edits', () => {
    resetRoutingDraft();
    drawRouting();
    say(routingText, 'Routing draft discarded.');
  });
  routingActions.append(saveRoutingBtn, discardRoutingBtn);
  routingForm.append(routingFields, routingConflict, routingActions);
  const routingText = UI.status(routingPanel);
  routingPanel.append(routingBar, routingForm, routingText);

  // ── Tailscale Services (svc:*) ──────────────────────────────────────────
  const servicesPanel = UI.panel(
    route,
    'tailscale-services',
    'Tailscale Services (svc:*)',
    'Publish LAN devices, local router ports, Unix sockets or local files as Tailscale Services with dedicated MagicDNS names, virtual IPs and automatic HTTPS.'
  );
  routingPanel.after(servicesPanel);

  const servicesUnavailable = el('p', 'field-help tailscale-services-unavailable', 'Enable and sign in to Tailscale above to manage Tailscale Services.');
  const servicesBar = el('div', 'tailscale-routing-bar tailscale-services-bar');
  servicesBar.hidden = true;
  const servicesSuffixLabel = el('strong', 'mono', '—');
  const servicesHttpsChip = el('span', 'tailscale-routing-chip', 'Unknown');
  const servicesTagsLabel = el('strong', 'mono', 'None');
  for (const [label, node] of [
    ['MagicDNS suffix', servicesSuffixLabel],
    ['Tailnet HTTPS', servicesHttpsChip],
    ['Node tags', servicesTagsLabel]
  ]) {
    const fact = el('div', 'tailscale-routing-fact');
    fact.append(el('small', 'field-help', label), node);
    servicesBar.append(fact);
  }
  const servicesBarActions = el('div', 'form-actions tailscale-services-bar-actions');
  const addServiceBtn = button('Add service', () => openServiceEditor(null), 'primary');
  addServiceBtn.id = 'tailscale-service-add-btn';
  const refreshServicesBtn = button('Refresh services', () => loadServices({quiet: false}));
  servicesBarActions.append(addServiceBtn, refreshServicesBtn);
  servicesBar.append(servicesBarActions);

  const servicesEnvNotes = el('div', 'relay-problem tailscale-alerts tailscale-services-env-notes');
  servicesEnvNotes.setAttribute('role', 'status');
  servicesEnvNotes.hidden = true;

  const servicesList = el('div', 'tailscale-service-list');
  servicesList.setAttribute('aria-label', 'Tailscale Services');
  const servicesEmpty = el('p', 'field-help tailscale-services-empty', 'No Tailscale Services configured or assigned to this router yet.');
  servicesEmpty.hidden = true;

  // Single-service editor (add / edit / configure)
  const serviceEditor = el('form', 'settings-form tailscale-service-editor');
  serviceEditor.id = 'tailscale-service-editor';
  serviceEditor.autocomplete = 'off';
  serviceEditor.hidden = true;
  const serviceEditorTitle = el('h3', '', 'Add Tailscale Service');
  const serviceEditorFields = el('fieldset', 'tailscale-service-editor-fields');
  serviceEditorFields.append(el('legend', 'sr-only', 'Tailscale Service configuration'));

  const serviceNameInput = el('input', 'mono');
  serviceNameInput.id = 'tailscale-service-name';
  serviceNameInput.name = 'service_name';
  serviceNameInput.type = 'text';
  serviceNameInput.maxLength = 67;
  serviceNameInput.spellcheck = false;
  serviceNameInput.autocapitalize = 'none';
  serviceNameInput.placeholder = 'my-app';
  const serviceNameField = field(
    'Service name (svc:<name>)',
    serviceNameInput,
    '1–63 lowercase ASCII letters, digits or hyphens. Published as <name>.<tailnet>.ts.net.'
  );

  const rulesSection = el('div', 'tailscale-service-rules-editor');
  const rulesHeader = el('div', 'tailscale-service-rules-head');
  const addRuleBtn = button('+ Add rule', () => {
    addEditorRuleRow({protocol: 'https', port: '', path: '/', target: ''});
    editorRowsDirty = true;
    drawServiceEditor();
  });
  rulesHeader.append(el('strong', '', 'Port & route rules'), addRuleBtn);
  const editorRuleRowsEl = el('div', 'tailscale-service-rule-rows');
  rulesSection.append(rulesHeader, editorRuleRowsEl);
  serviceEditorFields.append(serviceNameField.wrapper, rulesSection);

  const serviceEditorHints = el('div', 'tailscale-service-hints');
  serviceEditorHints.setAttribute('aria-live', 'polite');

  const serviceEditorActions = el('div', 'form-actions');
  const saveServiceBtn = button('Save service', null, 'primary');
  saveServiceBtn.id = 'tailscale-service-save-btn';
  saveServiceBtn.type = 'submit';
  const cancelServiceBtn = button('Cancel', () => closeServiceEditor('Service draft discarded.'));
  serviceEditorActions.append(saveServiceBtn, cancelServiceBtn);
  serviceEditor.append(serviceEditorTitle, serviceEditorFields, serviceEditorHints, serviceEditorActions);

  const servicesText = UI.status(servicesPanel);
  servicesPanel.append(
    servicesUnavailable,
    servicesBar,
    servicesEnvNotes,
    servicesList,
    servicesEmpty,
    serviceEditor,
    servicesText
  );

  // ── Install & Upgrade ───────────────────────────────────────────────────
  const updatePanel = UI.panel(
    route,
    'tailscale-update',
    'Install & upgrade',
    'Choose an official ARM64 Tailscale release from pkgs.tailscale.com. The router fetches and verifies the official SHA-256 checksum automatically, then swaps binaries with 120-second rollback for enrolled nodes.'
  );
  const updateBanner = el('p', 'tailscale-update-banner');
  updateBanner.hidden = true;

  const updateForm = el('form', 'settings-form');
  updateForm.id = 'tailscale-update-form';
  updateForm.autocomplete = 'off';
  const updateFields = el('fieldset', 'form-grid');
  updateFields.id = 'tailscale-update-fields';
  updateFields.append(el('legend', 'sr-only', 'Install or upgrade Tailscale'));

  const versionSelect = el('select');
  versionSelect.id = 'tailscale-version-select';
  versionSelect.name = 'version-select';
  const versionSelectField = field(
    'Tailscale version',
    versionSelect,
    'Loading recent stable releases…'
  );
  versionSelectField.wrapper.classList.add('tailscale-wide-field');

  const manualDetails = el('details', 'tailscale-manual');
  manualDetails.id = 'tailscale-manual';
  const manualSummary = el('summary', '', 'Manual version or custom SHA-256');
  const manualGrid = el('div', 'tailscale-manual-grid');

  const versionInput = el('input', 'mono');
  versionInput.id = 'tailscale-version';
  versionInput.name = 'version';
  versionInput.type = 'text';
  versionInput.spellcheck = false;
  versionInput.placeholder = '1.104.7';
  const versionField = field(
    'Custom version (optional)',
    versionInput,
    'Leave blank to install the selected release above, or enter an exact version without a leading “v”.'
  );

  const sha256Input = el('input', 'mono');
  sha256Input.id = 'tailscale-sha256';
  sha256Input.name = 'sha256';
  sha256Input.type = 'text';
  sha256Input.maxLength = 64;
  sha256Input.spellcheck = false;
  sha256Input.placeholder = 'Optional · 64 hexadecimal characters';
  const sha256Field = field(
    'Custom SHA-256 checksum (optional)',
    sha256Input,
    'Leave blank to fetch and verify the official .sha256 digest from pkgs.tailscale.com automatically.'
  );
  manualGrid.append(versionField.wrapper, sha256Field.wrapper);
  manualDetails.append(manualSummary, manualGrid);
  updateFields.append(versionSelectField.wrapper, manualDetails);

  const updateActions = el('div', 'form-actions');
  const installBtn = button('Install Tailscale', null, 'primary');
  installBtn.type = 'submit';
  const refreshVersionsBtn = button('Refresh versions', () => loadVersions({force: true}));
  const clearUpdateBtn = button('Clear manual', clearUpdateDraft);
  const packagesLink = el('a', 'button', 'Official packages ↗');
  packagesLink.href = M.PACKAGES_URL;
  packagesLink.target = '_blank';
  packagesLink.rel = 'noopener noreferrer';
  updateActions.append(installBtn, refreshVersionsBtn, clearUpdateBtn, packagesLink);
  updateForm.append(updateFields, updateActions);
  const updateText = UI.status(updatePanel);
  const updateNote = el(
    'p',
    'panel-note',
    'Downloads stream to tmpfs (120 MB cap), verify the SHA-256 digest, smoke-test tailscaled --version and swap atomically. If an enrolled node does not return to Running within 120 seconds, the previous binary is restored automatically.'
  );
  updatePanel.append(updateBanner, updateForm, updateText, updateNote);

  // ── State ───────────────────────────────────────────────────────────────
  let status = null, baseline = null, loading = false, attempted = false, busy = false, lastLoad = 0, loadId = 0;
  let pendingStatus = null;
  let pendingLoginUrl = '', loginPending = false, logoutWarning = '';
  let versionCatalog = null, selectedVersion = '', versionsLoading = false, versionsAttempted = false, versionsError = '', versionsLoadId = 0;
  let versionSelectSignature = '';
  let routingState = M.rebaseRouting(null), routingSession = 0;
  let mihomoStatus = null, routingContextTimer, routingContextLoad = 0, routingContextLoading = false;
  let routeRows = new Map(), lanSuggestionSignature = '';
  let servicesData = null, servicesLoading = false, servicesAttempted = false, servicesError = '', servicesLoadId = 0;
  let pickerOptions = [], reservationsList = null, pickerLoaded = false, pickerLoadId = 0;
  let editorOpen = false, editorMode = 'new', editorLockedName = '', editorRules = [], editorRowsDirty = true;
  const READING_STATUS_MESSAGE = 'Reading Tailscale status…';
  const onRoute = () => OpenU60Navigation.current.key === route;

  function currentConfigDraft() {
    return {
      hostname: hostnameInput.value,
      tailscale_ssh: sshChoice.input.checked,
      hold_wakelock: wakelockChoice.input.checked
    };
  }
  const configDirty = () => !!baseline && Object.keys(M.configDiff(baseline, currentConfigDraft())).length > 0;
  const routingDirty = () => routingState.dirty || routeInput.value.trim().length > 0;
  const routingEditable = () => routingState.baseline && !busy && API.connected && !API.locked && M.view(status).canConfig;
  const authDirty = () => authKeyInput.value.trim().length > 0;
  const updateDirty = () => versionInput.value.trim().length > 0 || sha256Input.value.trim().length > 0;
  const serviceEditorDirty = () => editorOpen;
  const dirty = () => configDirty() || routingDirty() || authDirty() || updateDirty() || serviceEditorDirty();
  const effectiveUpdateVersion = () => versionInput.value.trim() || selectedVersion;

  function populateConfig(data) {
    baseline = M.configBaseline(data);
    hostnameInput.value = baseline.hostname;
    sshChoice.input.checked = baseline.tailscale_ssh;
    wakelockChoice.input.checked = baseline.hold_wakelock;
  }

  function discardConfig() {
    if (!baseline) return;
    hostnameInput.value = baseline.hostname;
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

  function resetRoutingDraft(baseline = routingState.baseline) {
    routingState = M.rebaseRouting(baseline);
    routeInput.value = '';
    say(routingText, '');
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
    if (data) {
      const next = M.rebaseRouting(M.routingBaseline(data), routingState);
      if (routingState.dirty && !next.dirty) say(routingText, '');
      routingState = next;
    }
    if (view.running) {
      if (!servicesAttempted && !servicesLoading) loadServices({quiet: true});
    } else {
      servicesLoadId++;
      servicesLoading = false;
      servicesAttempted = false;
      servicesError = '';
      servicesData = null;
      if (editorOpen) closeServiceEditor('');
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

  function setRoutingChip(chip, state, label) {
    chip.dataset.state = state;
    if (chip.textContent !== label) chip.textContent = label;
  }

  function reviewRoutingChanges(before, after) {
    const added = after.advertise_routes.filter(prefix => !before.advertise_routes.includes(prefix)).length;
    const removed = before.advertise_routes.filter(prefix => !after.advertise_routes.includes(prefix)).length;
    const changes = [];
    if (added) changes.push(`${added} saved subnet ${added === 1 ? 'route was' : 'routes were'} added.`);
    if (removed) changes.push(`${removed} saved subnet ${removed === 1 ? 'route was' : 'routes were'} removed.`);
    if (before.advertise_exit_node !== after.advertise_exit_node) {
      changes.push(`Exit Node advertising was turned ${after.advertise_exit_node ? 'on' : 'off'}.`);
    }
    if (before.exit_via_mihomo !== after.exit_via_mihomo) {
      changes.push(`The Mihomo preference was turned ${after.exit_via_mihomo ? 'on' : 'off'}.`);
    }
    return `Saved routing settings changed elsewhere. ${changes.join(' ')} Review your draft before saving, or discard your edits.`;
  }

  function drawRouting() {
    const editable = routingEditable();
    const {baseline, draft, dirty, reviewBaseline, overLimit} = routingState;
    const savedRoutes = baseline?.advertise_routes ?? [], routes = draft.advertise_routes;
    const live = API.connected ? status?.routing : null;
    const routing = M.routingStatus(live);
    tunLabel.textContent = routing.modeLabel;
    setRoutingChip(syncChip, routing.sync, routing.syncLabel);
    routingFields.disabled = !editable;

    const renderedRoutes = [...routeRows.keys()];
    if (routes.length !== renderedRoutes.length || routes.some((prefix, index) => prefix !== renderedRoutes[index])) {
      const nextRows = new Map();
      for (const prefix of routes) {
        let row = routeRows.get(prefix);
        if (!row) {
          const item = el('li', 'tailscale-route-row');
          const state = el('span', 'tailscale-routing-chip');
          const remove = button('Remove', () => {
            if (!routingEditable()) return;
            editRoute(prefix, false);
            (routeRows.values().next().value?.item.querySelector('button') ?? routeInput).focus();
          });
          remove.setAttribute('aria-label', `Remove ${prefix}`);
          item.append(el('code', 'mono', prefix), state, remove);
          row = {item, state};
        }
        nextRows.set(prefix, row);
      }
      routeRows = nextRows;
      routeList.replaceChildren(...Array.from(routeRows.values(), row => row.item));
    }
    noRoutes.hidden = routes.length > 0;
    routeList.hidden = routes.length === 0;
    for (const [prefix, row] of routeRows) {
      const state = M.routeState(prefix, savedRoutes, live?.routes);
      setRoutingChip(row.state, state, M.ROUTE_STATES[state]);
    }

    const input = routeInput.value.trim();
    const candidate = input ? M.routeCandidate(input, routes) : null;
    const hint = (overLimit ? `Remove subnet routes to stay within the ${M.MAX_ADVERTISE_ROUTES}-route limit.` : candidate?.error) ||
      (candidate?.hasHostBits ? `Will normalize to ${candidate.prefix}` : '') ||
      `${routes.length} of ${M.MAX_ADVERTISE_ROUTES} routes`;
    if (hint !== routeHint.textContent) routeHint.textContent = hint;
    routeHint.dataset.error = String(overLimit || !!candidate?.error);
    routeInput.setAttribute('aria-invalid', String(!!candidate?.error));
    addRouteBtn.disabled = !editable || !candidate?.prefix;
    const suggestions = M.lanRouteSuggestions(live?.lan_subnets, routes);
    const signature = `${routes.length >= M.MAX_ADVERTISE_ROUTES}|${suggestions.join(',')}`;
    if (signature !== lanSuggestionSignature) {
      lanSuggestionSignature = signature;
      lanButtons.replaceChildren(...suggestions.map(prefix => {
        const add = button(`+ Add LAN ${prefix}`, () => {
          if (addRoute(prefix)) routeInput.focus();
        }, 'mono');
        add.disabled = routes.length >= M.MAX_ADVERTISE_ROUTES;
        return add;
      }));
    }

    exitChoice.input.checked = draft.advertise_exit_node;
    mihomoChoice.input.checked = draft.exit_via_mihomo;
    mihomoChoice.input.disabled = !draft.advertise_exit_node;
    for (const [key, chip] of exitChips) {
      const approval = M.exitApproval(live?.exit?.[key]);
      setRoutingChip(chip, approval.state, approval.label);
    }
    const exitContext = M.exitContext(mihomoStatus, live);
    context.textContent = `Mihomo · ${exitContext.mihomoLabel}   |   Exit Node Clean DNS · ${exitContext.dnsLabel}`;
    const notice = reviewBaseline ? reviewRoutingChanges(reviewBaseline, baseline) : '';
    if (routingConflict.textContent !== notice) routingConflict.textContent = notice;
    routingConflict.hidden = !notice;
    saveRoutingBtn.disabled = !editable || !!input || !dirty || overLimit;
    discardRoutingBtn.disabled = !editable || (!dirty && !input);
    routingPanel.dataset.dirty = String(dirty);
  }

  function editRouting(edits) {
    routingState = M.rebaseRouting(routingState.baseline, {
      ...routingState,
      edits: {...routingState.edits, ...edits}
    });
    say(routingText, '');
    drawRouting();
  }

  function editRoute(prefix, adding) {
    const {addedRoutes, removedRoutes} = routingState.edits;
    editRouting({
      addedRoutes: adding ? [...addedRoutes, prefix] : addedRoutes.filter(route => route !== prefix),
      removedRoutes: adding ? removedRoutes.filter(route => route !== prefix) : [...removedRoutes, prefix]
    });
  }

  function addRoute(raw) {
    if (!routingEditable()) return false;
    const candidate = M.routeCandidate(raw, routingState.draft.advertise_routes);
    if (!candidate.prefix) return false;
    if (raw === routeInput.value) routeInput.value = '';
    editRoute(candidate.prefix, true);
    return true;
  }

  function drawUpdate(view = M.view(status)) {
    const inactive = busy || !API.connected || API.locked || !status;
    const isDirty = updateDirty();
    const installed = M.installedVersion(status);
    const entries = versionCatalog?.versions || [];
    const selectState = entries.length
      ? `list:${versionCatalog.latest}:${installed}:${entries.map(item => `${item.version}@${item.published_at}`).join(',')}`
      : versionsLoading
        ? 'loading'
        : versionsError
          ? 'error'
          : 'idle';
    if (selectState !== versionSelectSignature) {
      versionSelectSignature = selectState;
      if (entries.length) {
        if (!selectedVersion || !entries.some(item => item.version === selectedVersion)) {
          selectedVersion = versionCatalog.latest || entries[0].version;
        }
        versionSelect.replaceChildren(...entries.map(entry =>
          new Option(M.versionOptionLabel(entry, {latest: versionCatalog.latest, installed}), entry.version)
        ));
        versionSelect.value = selectedVersion;
      } else {
        selectedVersion = '';
        const placeholder = versionsLoading
          ? 'Loading recent stable releases…'
          : versionsError
            ? 'Version list unavailable — use manual entry below'
            : 'Connect and unlock to load versions';
        const opt = new Option(placeholder, '');
        opt.disabled = true;
        versionSelect.replaceChildren(opt);
        versionSelect.value = '';
      }
    }

    const manualVersion = versionInput.value.trim();
    const targetVersion = effectiveUpdateVersion();
    const validTarget = M.validVersion(targetVersion);
    const intent = validTarget ? M.updateIntent(targetVersion, status) : (view.installed ? 'upgrade' : 'install');
    const actionLabels = {
      install: validTarget ? `Install v${targetVersion}` : 'Install Tailscale',
      upgrade: validTarget ? `Upgrade to v${targetVersion}` : 'Download & upgrade',
      downgrade: validTarget ? `Downgrade to v${targetVersion}` : 'Download & install',
      reinstall: validTarget ? `Reinstall v${targetVersion}` : 'Reinstall Tailscale'
    };
    updateFields.disabled = inactive || !view.canUpdate;
    versionSelect.disabled = inactive || !view.canUpdate || !entries.length;
    installBtn.textContent = actionLabels[intent];
    installBtn.disabled = inactive || !view.canUpdate || !targetVersion;
    refreshVersionsBtn.disabled = versionsLoading || busy || !API.connected || API.locked;
    refreshVersionsBtn.textContent = versionsLoading ? 'Refreshing…' : 'Refresh versions';
    clearUpdateBtn.disabled = inactive || !isDirty;
    updatePanel.dataset.dirty = String(isDirty);

    if (manualVersion) {
      versionSelectField.help.textContent = `Using custom version override (${manualVersion}) below. Clear manual inputs to use the dropdown selection.`;
    } else if (versionsLoading && !entries.length) {
      versionSelectField.help.textContent = 'Fetching recent stable releases from pkgs.tailscale.com and GitHub…';
    } else if (entries.length) {
      const parts = [];
      if (installed && selectedVersion === installed) {
        parts.push(`v${selectedVersion} is currently installed. Official .sha256 checksum is fetched and verified automatically.`);
      } else if (selectedVersion) {
        parts.push(`Official ARM64 package tailscale_${selectedVersion}_arm64.tgz · SHA-256 fetched and verified automatically.`);
      }
      if (versionCatalog.warning) parts.push(versionCatalog.warning);
      if (versionsError) parts.push(`Last refresh failed: ${versionsError}.`);
      versionSelectField.help.textContent = parts.join(' ');
    } else if (versionsError) {
      versionSelectField.help.textContent = `Could not load release list: ${versionsError}. Retry with “Refresh versions” or enter a version manually below.`;
    } else {
      versionSelectField.help.textContent = 'Connect and unlock the console to load official Tailscale releases.';
    }

    const previewUrl = M.packageUrl(versionInput.value);
    versionField.help.textContent = previewUrl
      ? `Package URL: ${previewUrl}`
      : 'Leave blank to install the selected release above, or enter an exact version without a leading “v”.';

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

  async function copyText(text, targetStatus, label) {
    const clean = String(text || '').trim();
    if (!clean) return;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(clean);
        say(targetStatus, `${label} copied to clipboard.`);
        return;
      }
      const helper = el('textarea', 'sr-only');
      helper.value = clean;
      helper.setAttribute('readonly', '');
      document.body.append(helper);
      helper.select();
      const copied = document.execCommand('copy');
      helper.remove();
      say(targetStatus, copied ? `${label} copied to clipboard.` : `Copy blocked by browser; copy ${clean} manually.`, !copied);
    } catch {
      say(targetStatus, `Clipboard access is unavailable; copy ${clean} manually.`, true);
    }
  }

  function addEditorRuleRow(rule) {
    editorRules.push({
      protocol: rule?.protocol === 'tcp' ? 'tcp' : 'https',
      port: rule?.port !== undefined && rule?.port !== null ? String(rule.port) : '',
      path: rule?.path ?? '/',
      target: String(rule?.target || '')
    });
  }

  function openServiceEditor(svc) {
    editorOpen = true;
    editorRules = [];
    editorRowsDirty = true;
    if (!svc) {
      editorMode = 'new';
      editorLockedName = '';
      serviceNameInput.value = '';
      serviceNameInput.readOnly = false;
      addEditorRuleRow({protocol: 'https', port: '443', path: '/', target: ''});
    } else {
      editorMode = svc.configured ? 'edit' : 'configure';
      editorLockedName = svc.name;
      serviceNameInput.value = svc.name;
      serviceNameInput.readOnly = true;
      if (Array.isArray(svc.rules) && svc.rules.length) {
        for (const r of svc.rules) addEditorRuleRow(r);
      } else {
        const firstPort = Array.isArray(svc.tailnet_ports)
          ? (svc.tailnet_ports[0]?.match(/(\d+)/)?.[1] || '443')
          : '443';
        addEditorRuleRow({protocol: firstPort === '443' ? 'https' : 'tcp', port: firstPort, path: '/', target: ''});
      }
    }
    say(servicesText, '');
    loadPickerSources();
    drawServices();
    (editorLockedName ? editorRuleRowsEl.querySelector('input, select') : serviceNameInput)?.focus();
  }

  function parkServiceEditor() {
    if (serviceEditor.parentNode !== servicesPanel) {
      servicesPanel.insertBefore(serviceEditor, servicesText);
    }
    serviceEditor.hidden = true;
    serviceEditor.dataset.inline = 'false';
  }

  function closeServiceEditor(message = '') {
    editorOpen = false;
    editorMode = 'new';
    editorLockedName = '';
    editorRules = [];
    editorRowsDirty = true;
    serviceNameInput.value = '';
    serviceNameInput.readOnly = false;
    parkServiceEditor();
    editorRuleRowsEl.replaceChildren();
    serviceEditorHints.replaceChildren();
    if (message !== undefined) say(servicesText, message);
    drawServices();
  }

  function refreshPickerSelects() {
    for (const select of editorRuleRowsEl.querySelectorAll('select[id^="tailscale-svc-pick-"]')) {
      const promptOpt = new Option(
        pickerOptions.length ? 'Pick LAN device / static IP…' : (pickerLoaded ? 'No LAN devices reported' : 'Loading LAN devices…'),
        ''
      );
      select.replaceChildren(promptOpt, ...pickerOptions.map(opt => new Option(opt.label, opt.ip)));
      select.value = '';
    }
  }

  async function loadPickerSources() {
    if (API.locked || !API.connected) return;
    const epoch = UI.epoch, id = ++pickerLoadId;
    const [clients, reservations] = await Promise.all([
      request('/api/network/clients', {timeoutMs: 10000}).catch(() => null),
      request('/api/router/reservations', {timeoutMs: 10000}).catch(() => null)
    ]);
    if (!UI.current(epoch) || id !== pickerLoadId) return;
    reservationsList = Array.isArray(reservations?.entries) ? reservations.entries : null;
    pickerOptions = M.buildTargetPickerOptions(clients, reservations);
    pickerLoaded = true;
    if (editorOpen) {
      refreshPickerSelects();
      drawServiceEditorHints();
    }
  }

  function drawServiceEditorHints() {
    const nodes = [];
    const nameText = serviceNameInput.value.trim();
    if (editorMode === 'new' && nameText) {
      const nameErr = M.serviceNameProblem(nameText);
      if (nameErr) {
        const errEl = el('p', 'relay-problem tailscale-service-hint', nameErr);
        errEl.dataset.kind = 'error';
        nodes.push(errEl);
      }
    }
    const hints = M.serviceTargetHints(editorRules, {
      reservations: reservationsList,
      advertisedRoutes: servicesData?.advertised_routes || status?.advertise_routes || [],
      approvedRoutes: servicesData?.approved_routes || (status?.routing?.routes || []).filter(r => r.state === 'approved').map(r => r.prefix),
      routerIps: servicesData?.router_ips || [],
      httpsEnabled: servicesData?.https_enabled !== false
    });
    if (hints.httpsDisabledWarning) {
      const box = el('p', 'relay-problem tailscale-service-hint', 'HTTPS certificates are not enabled on your tailnet yet. Enable MagicDNS and HTTPS Certificates in the Tailscale admin console for HTTPS services to issue certificates.');
      box.dataset.kind = 'https';
      nodes.push(box);
    }
    if (hints.unadvertisedSubnetIps.length || hints.pendingSubnetIps.length) {
      const box = el('div', 'tailscale-service-hint-note');
      box.dataset.kind = 'subnet';
      const parts = [];
      if (hints.unadvertisedSubnetIps.length) {
        parts.push(`Subnet route is not enabled for ${hints.unadvertisedSubnetIps.join(', ')}.`);
      }
      if (hints.pendingSubnetIps.length) {
        parts.push(`Subnet route for ${hints.pendingSubnetIps.join(', ')} is still pending approval.`);
      }
      const copy = el('p', 'field-help', `${parts.join(' ')} Tailscale Services proxy still reaches these targets directly through this router; enable and approve the matching Subnet Route above if tailnet peers also need direct LAN IP access.`);
      const jump = button('Go to Subnet routes ↑', () => {
        routingPanel.scrollIntoView?.({behavior: 'smooth', block: 'start'});
        routeInput.focus();
      });
      box.append(copy, jump);
      nodes.push(box);
    }
    if (hints.unreservedIps.length) {
      const box = el('div', 'tailscale-service-hint-note');
      box.dataset.kind = 'dhcp';
      const copy = el('p', 'field-help', `${hints.unreservedIps.join(', ')} ${hints.unreservedIps.length === 1 ? 'is' : 'are'} not pinned as a static DHCP reservation. Assign a static lease so the target device keeps the same LAN IP.`);
      const link = el('a', 'button', 'Open LAN & DHCP →');
      link.href = '#network/lan';
      box.append(copy, link);
      nodes.push(box);
    }
    serviceEditorHints.replaceChildren(...nodes);
  }

  function renderEditorRuleRows(disabled) {
    const rows = editorRules.map((rule, index) => {
      const row = el('div', 'tailscale-service-rule-row');
      row.dataset.index = String(index);

      const protoSelect = el('select');
      protoSelect.id = `tailscale-svc-proto-${index}`;
      protoSelect.setAttribute('aria-label', `Rule ${index + 1} protocol`);
      protoSelect.add(new Option('HTTPS', 'https'));
      protoSelect.add(new Option('TCP', 'tcp'));
      protoSelect.value = rule.protocol;
      protoSelect.addEventListener('change', () => {
        rule.protocol = protoSelect.value;
        if (rule.protocol === 'https' && !rule.port) rule.port = '443';
        if (rule.protocol === 'https' && !rule.path) rule.path = '/';
        renderEditorRuleRows(serviceEditorFields.disabled);
        drawServiceEditorHints();
        updateServiceEditorButtons();
      });

      const portInput = el('input', 'mono');
      portInput.id = `tailscale-svc-port-${index}`;
      portInput.type = 'number';
      portInput.min = '1';
      portInput.max = '65535';
      portInput.inputMode = 'numeric';
      portInput.placeholder = rule.protocol === 'https' ? '443' : '3773';
      portInput.value = rule.port;
      portInput.addEventListener('input', () => {
        rule.port = portInput.value;
        updateServiceEditorButtons();
      });

      const pathInput = el('input', 'mono');
      pathInput.id = `tailscale-svc-path-${index}`;
      pathInput.type = 'text';
      pathInput.spellcheck = false;
      pathInput.placeholder = '/ or /api';
      pathInput.value = rule.protocol === 'https' ? (rule.path ?? '/') : '';
      pathInput.disabled = disabled || rule.protocol !== 'https';
      pathInput.addEventListener('input', () => {
        rule.path = pathInput.value;
        updateServiceEditorButtons();
      });

      const pickerSelect = el('select');
      pickerSelect.id = `tailscale-svc-pick-${index}`;
      pickerSelect.setAttribute('aria-label', `Rule ${index + 1} LAN device quick pick`);
      const promptOpt = new Option(
        pickerOptions.length ? 'Pick LAN device / static IP…' : (pickerLoaded ? 'No LAN devices reported' : 'Loading LAN devices…'),
        ''
      );
      pickerSelect.add(promptOpt);
      for (const opt of pickerOptions) {
        pickerSelect.add(new Option(opt.label, opt.ip));
      }
      pickerSelect.addEventListener('change', () => {
        if (!pickerSelect.value) return;
        rule.target = M.applyPickedIpToTarget(rule.protocol, rule.target, pickerSelect.value);
        targetInput.value = rule.target;
        pickerSelect.value = '';
        drawServiceEditorHints();
        updateServiceEditorButtons();
        targetInput.focus();
      });

      const targetInput = el('input', 'mono');
      targetInput.id = `tailscale-svc-target-${index}`;
      targetInput.type = 'text';
      targetInput.spellcheck = false;
      targetInput.placeholder = rule.protocol === 'https'
        ? 'http://192.168.0.124:3773, https+insecure://…, unix:/…, file:///…'
        : '192.168.0.124:3773 or unix:/…';
      targetInput.value = rule.target;
      targetInput.addEventListener('input', () => {
        rule.target = targetInput.value;
        drawServiceEditorHints();
        updateServiceEditorButtons();
      });

      const protoWrap = field('Protocol', protoSelect).wrapper;
      const portWrap = field('External port', portInput).wrapper;
      const pathWrap = field('URL path', pathInput).wrapper;
      pathWrap.hidden = rule.protocol !== 'https';
      const pickWrap = field('Quick pick device', pickerSelect).wrapper;
      const targetWrap = field('Backend target', targetInput).wrapper;
      targetWrap.classList.add('tailscale-service-target-field');

      const removeBtn = button('Remove', () => {
        if (editorRules.length <= 1) return;
        editorRules.splice(index, 1);
        editorRowsDirty = true;
        drawServiceEditor();
      });
      removeBtn.setAttribute('aria-label', `Remove rule ${index + 1}`);
      removeBtn.disabled = disabled || editorRules.length <= 1;

      row.append(protoWrap, portWrap, pathWrap, pickWrap, targetWrap, removeBtn);
      return row;
    });
    editorRuleRowsEl.replaceChildren(...rows);
    editorRowsDirty = false;
  }

  function updateServiceEditorButtons() {
    const view = M.view(status);
    const editable = !busy && API.connected && !API.locked && view.running && servicesData?.available === true;
    const nameOk = !M.serviceNameProblem(serviceNameInput.value);
    const rulesCheck = M.validateServiceRules(editorRules);
    saveServiceBtn.disabled = !editable || !nameOk || !!rulesCheck.error;
    addRuleBtn.disabled = !editable || editorRules.length >= M.MAX_SERVICE_RULES;
    cancelServiceBtn.disabled = busy;
  }

  function drawServiceEditor() {
    servicesPanel.dataset.dirty = String(editorOpen);
    if (!editorOpen) {
      parkServiceEditor();
      return;
    }
    const inline = editorMode !== 'new';
    const view = M.view(status);
    const editable = !busy && API.connected && !API.locked && view.running && servicesData?.available === true;
    serviceEditor.hidden = false;
    serviceEditor.dataset.inline = String(inline);
    serviceEditorTitle.hidden = inline;
    serviceNameField.wrapper.hidden = inline;
    if (!inline) {
      serviceEditorTitle.textContent = 'Add Tailscale Service';
      if (serviceEditor.parentNode !== servicesPanel) {
        servicesPanel.insertBefore(serviceEditor, servicesText);
      }
    }
    serviceEditorFields.disabled = !editable;
    if (editorRowsDirty) {
      renderEditorRuleRows(!editable);
    } else {
      for (const [index, row] of [...editorRuleRowsEl.children].entries()) {
        const pathInput = row.querySelector(`#tailscale-svc-path-${index}`);
        if (pathInput) pathInput.disabled = !editable || editorRules[index]?.protocol !== 'https';
        const rmBtn = row.querySelector('button');
        if (rmBtn) rmBtn.disabled = !editable || editorRules.length <= 1;
      }
    }
    drawServiceEditorHints();
    updateServiceEditorButtons();
  }

  function drawServices(view = M.view(status)) {
    const connected = API.connected && !API.locked;
    const ready = connected && view.running && servicesData?.available === true;
    const inactive = busy || !connected;

    if (!connected || !view.running || (servicesData && !servicesData.available)) {
      servicesUnavailable.hidden = false;
      servicesUnavailable.textContent = !connected
        ? 'Connect and unlock the console to manage Tailscale Services.'
        : !view.installed
          ? 'Install and sign in to Tailscale before managing Tailscale Services.'
          : servicesData?.reason || 'Enable and sign in to Tailscale above to manage Tailscale Services.';
      servicesBar.hidden = true;
      servicesEnvNotes.hidden = true;
      parkServiceEditor();
      servicesList.replaceChildren();
      servicesEmpty.hidden = true;
      servicesPanel.dataset.dirty = 'false';
      return;
    }

    if (!servicesData) {
      servicesUnavailable.hidden = false;
      servicesUnavailable.textContent = servicesLoading
        ? 'Loading Tailscale Services…'
        : servicesError
          ? `Tailscale Services unavailable: ${servicesError}`
          : 'Waiting for Tailscale Services…';
      servicesBar.hidden = false;
      servicesSuffixLabel.textContent = '—';
      setRoutingChip(servicesHttpsChip, 'unknown', 'Unknown');
      servicesTagsLabel.textContent = '—';
      addServiceBtn.disabled = true;
      refreshServicesBtn.disabled = servicesLoading || inactive;
      servicesEnvNotes.hidden = true;
      parkServiceEditor();
      servicesList.replaceChildren();
      servicesEmpty.hidden = true;
      servicesPanel.dataset.dirty = 'false';
      return;
    }

    servicesUnavailable.hidden = true;
    servicesBar.hidden = false;
    servicesSuffixLabel.textContent = servicesData.magic_dns_suffix || 'Unavailable';
    setRoutingChip(
      servicesHttpsChip,
      servicesData.https_enabled ? 'approved' : 'pending',
      servicesData.https_enabled ? 'Enabled' : 'Disabled'
    );
    const tags = Array.isArray(servicesData.tags) ? servicesData.tags : [];
    servicesTagsLabel.textContent = tags.length ? tags.join(', ') : 'None';
    addServiceBtn.disabled = inactive || !ready;
    refreshServicesBtn.disabled = servicesLoading || inactive;
    refreshServicesBtn.textContent = servicesLoading ? 'Refreshing…' : 'Refresh services';

    const envNotes = [];
    if (!servicesData.https_enabled) {
      envNotes.push('HTTPS certificates are not reported on this tailnet. Enable MagicDNS and HTTPS Certificates in Tailscale Admin to serve HTTPS endpoints.');
    }
    if (!tags.length) {
      envNotes.push('This router has no Tailscale node tags. Tailscale Services typically require a node tag or ACL service-host grant.');
    }
    servicesEnvNotes.hidden = envNotes.length === 0;
    servicesEnvNotes.replaceChildren(...envNotes.map(note => el('p', '', note)));

    const list = Array.isArray(servicesData.services) ? servicesData.services : [];
    servicesEmpty.hidden = list.length > 0;

    const editingInlineTarget = editorOpen && editorMode !== 'new' ? `svc:${editorLockedName}` : '';
    const existingEditingCard = editingInlineTarget
      ? servicesList.querySelector('article.tailscale-service-card[data-editing="true"]')
      : null;
    const reuseEditingCard = existingEditingCard && existingEditingCard.dataset.service === editingInlineTarget
      ? existingEditingCard
      : null;
    if (!reuseEditingCard && serviceEditor.parentNode !== servicesPanel) {
      servicesPanel.insertBefore(serviceEditor, servicesText);
    }

    const nextCards = list.map(svc => {
      const meta = M.serviceStateMeta(svc.state);
      const isEditing = editingInlineTarget && svc.service === editingInlineTarget;
      if (isEditing && reuseEditingCard) {
        reuseEditingCard.dataset.state = meta.state;
        const badgeEl = reuseEditingCard.querySelector('.tailscale-service-state');
        if (badgeEl) {
          badgeEl.dataset.state = meta.chipState;
          if (badgeEl.textContent !== meta.label) badgeEl.textContent = meta.label;
        }
        return reuseEditingCard;
      }

      const card = el('article', 'tailscale-service-card');
      card.dataset.service = svc.service;
      card.dataset.state = meta.state;

      const head = el('div', 'tailscale-service-head');
      const headCopy = el('div', 'tailscale-service-title');
      headCopy.append(el('h3', 'mono', svc.service));
      if (svc.fqdn) headCopy.append(el('p', 'mono field-help', svc.fqdn));
      if (Array.isArray(svc.vips) && svc.vips.length) {
        headCopy.append(el('small', 'mono field-help', `VIP: ${svc.vips.join(' · ')}`));
      }
      const badge = el('span', 'tailscale-routing-chip tailscale-service-state', meta.label);
      badge.dataset.state = meta.chipState;
      head.append(headCopy, badge);
      card.append(head);

      const mismatchMsg = M.formatServicePortDiff(svc);
      if (isEditing) {
        card.dataset.editing = 'true';
        if (mismatchMsg) {
          const warn = el('div', 'relay-problem tailscale-service-alert');
          warn.append(el('p', '', mismatchMsg));
          card.append(warn);
        }
        card.append(serviceEditor);
        return card;
      }

      if (svc.editable === false) {
        const ro = el('div', 'relay-problem tailscale-service-alert');
        const reasons = Array.isArray(svc.unsupported_reasons) && svc.unsupported_reasons.length
          ? svc.unsupported_reasons.join('; ')
          : 'contains CLI-only advanced handlers';
        ro.append(el('p', '', `Read-only CLI configuration: ${reasons}. Editing is locked to prevent accidental overwrite; you can still drain, advertise, or clear it.`));
        card.append(ro);
      }

      if (mismatchMsg) {
        const warn = el('div', 'relay-problem tailscale-service-alert');
        warn.append(el('p', '', mismatchMsg));
        card.append(warn);
      } else if (meta.state === 'pending') {
        card.append(el('p', 'field-help', M.servicePendingNotice(svc)));
      } else if (meta.state === 'unconfigured') {
        card.append(el('p', 'field-help', 'Assigned to this router in Tailscale admin, but no local backend rules are configured yet.'));
      }

      const rules = Array.isArray(svc.rules) ? svc.rules : [];
      if (rules.length) {
        const ul = el('ul', 'tailscale-service-rules');
        for (const r of rules) {
          const li = el('li', 'tailscale-service-rule-item');
          const protoBadge = el(
            'span',
            'tag mono',
            r.protocol === 'https'
              ? `HTTPS :${r.port}${r.path && r.path !== '/' ? ` ${r.path}` : ' /'}`
              : `TCP :${r.port}`
          );
          const targetCode = el('code', 'mono', `→ ${r.target}`);
          const detailWrap = el('div', 'tailscale-service-rule-meta');
          detailWrap.append(protoBadge, targetCode);
          if (r.port_allowed === false) {
            const pChip = el('span', 'tailscale-routing-chip', 'Port not allowed');
            pChip.dataset.state = 'pending';
            detailWrap.append(pChip);
          }
          if (r.subnet_route_state === 'not_advertised' || r.subnet_route_state === 'pending') {
            const sChip = el(
              'span',
              'tailscale-routing-chip',
              r.subnet_route_state === 'pending' ? 'Subnet pending' : 'No subnet route'
            );
            sChip.dataset.state = 'standby';
            detailWrap.append(sChip);
          }
          li.append(detailWrap);
          if (r.access_url) {
            const urlRow = el('div', 'tailscale-service-url-row');
            urlRow.append(el('code', 'mono tailscale-service-url', r.access_url));
            const cp = button('Copy', () => copyText(r.access_url, servicesText, r.access_url));
            cp.setAttribute('aria-label', `Copy ${r.access_url}`);
            urlRow.append(cp);
            li.append(urlRow);
          }
          ul.append(li);
        }
        card.append(ul);
      }

      const actions = el('div', 'form-actions');
      const primaryUrl = Array.isArray(svc.access_urls) ? svc.access_urls[0] : '';
      if (primaryUrl) {
        const copyPrimary = button('Copy address', () => copyText(primaryUrl, servicesText, primaryUrl));
        actions.append(copyPrimary);
      }
      const isDefined = svc.defined_in_tailnet === true || (Array.isArray(svc.vips) && svc.vips.length > 0);
      const adminHref = svc.admin_url || M.serviceAdminUrl(svc.name, isDefined);
      if (adminHref) {
        const link = el('a', 'button', isDefined ? 'Tailscale admin ↗' : 'Define in Tailscale admin ↗');
        link.href = adminHref;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        actions.append(link);
      }
      if (!svc.configured) {
        const cfgBtn = button('Configure', () => openServiceEditor(svc), 'primary');
        cfgBtn.disabled = inactive;
        actions.append(cfgBtn);
      } else if (svc.editable !== false) {
        const editBtn = button('Edit', () => openServiceEditor(svc));
        editBtn.disabled = inactive;
        actions.append(editBtn);
      }
      if (svc.configured) {
        if (svc.drained) {
          const advBtn = button('Advertise', () => toggleServiceDrain(svc, false), 'primary');
          advBtn.disabled = inactive;
          actions.append(advBtn);
        } else {
          if (meta.state === 'pending') {
            const readvBtn = button('Re-advertise', () => toggleServiceDrain(svc, false, {readvertise: true}), 'primary');
            readvBtn.disabled = inactive;
            actions.append(readvBtn);
          }
          const drainBtn = button('Drain', () => toggleServiceDrain(svc, true));
          drainBtn.disabled = inactive;
          actions.append(drainBtn);
        }
        const clearBtn = button('Clear', () => clearService(svc), 'danger');
        clearBtn.disabled = inactive;
        actions.append(clearBtn);
      }
      card.append(actions);
      return card;
    });

    if (editingInlineTarget && !nextCards.some(card => card.dataset.editing === 'true')) {
      editorOpen = false;
      editorMode = 'new';
      editorLockedName = '';
      editorRules = [];
      editorRowsDirty = true;
    }

    const wanted = new Set(nextCards);
    for (const child of [...servicesList.children]) {
      if (!wanted.has(child)) child.remove();
    }
    nextCards.forEach((card, index) => {
      if (servicesList.children[index] !== card) {
        servicesList.insertBefore(card, servicesList.children[index] || null);
      }
    });

    drawServiceEditor();
  }

  function draw() {
    const view = M.view(status);
    drawStatus(view);
    drawAuth(view);
    drawConfig(view);
    drawRouting();
    drawServices(view);
    drawUpdate(view);
  }

  function stopRoutingContext() {
    clearTimeout(routingContextTimer);
    routingContextTimer = undefined;
    routingContextLoad++;
    routingContextLoading = false;
    mihomoStatus = null;
  }

  async function loadRoutingContext() {
    if (routingContextLoading || document.hidden || !onRoute() || !API.connected) return;
    const id = ++routingContextLoad;
    routingContextLoading = true;
    const mihomo = await request('/api/mihomo/status').catch(() => null);
    if (id !== routingContextLoad) return;
    routingContextLoading = false;
    if (document.hidden || !onRoute() || !API.connected) return;
    mihomoStatus = mihomo;
    drawRouting();
    routingContextTimer = setTimeout(() => {
      routingContextTimer = undefined;
      loadRoutingContext();
    }, 5000);
  }

  async function load(quiet = false) {
    if (loading || API.locked || !API.connected) return;
    const epoch = UI.epoch, id = ++loadId;
    const current = () => UI.current(epoch) && id === loadId;
    loading = true;
    attempted = true;
    lastLoad = Date.now();
    if (!routingContextTimer) loadRoutingContext();
    if (!versionsAttempted && !versionsLoading) loadVersions({force: false});
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
      if (!live()) return false;
      pendingStatus = null;
      applyStatus(data);
      return true;
    } catch {
      /* SSE or manual refresh will follow. */
      return false;
    }
  }

  function flushPendingStatus(live) {
    const queued = pendingStatus;
    pendingStatus = null;
    if (!live() || !queued) return false;
    applyStatus(queued);
    return true;
  }

  function finishBusy(live) {
    busy = false;
    if (!flushPendingStatus(live) && live()) draw();
  }

  async function loadVersions({force = false} = {}) {
    if (versionsLoading || API.locked || !API.connected) return;
    const epoch = UI.epoch, id = ++versionsLoadId;
    const current = () => UI.current(epoch) && id === versionsLoadId;
    versionsLoading = true;
    versionsAttempted = true;
    versionsError = '';
    drawUpdate();
    try {
      const data = force
        ? await request('/api/tailscale/versions/refresh', {...json('POST', {}), timeoutMs: 25000})
        : await request('/api/tailscale/versions', {timeoutMs: 25000});
      if (!current()) return;
      const normalized = M.normalizeVersions(data);
      if (!normalized.versions.length) {
        throw new Error('The router returned no stable Tailscale releases');
      }
      versionCatalog = normalized;
      if (!selectedVersion || !normalized.versions.some(item => item.version === selectedVersion)) {
        selectedVersion = normalized.latest || normalized.versions[0].version;
      }
      versionsError = '';
      if (force) {
        say(updateText, `Loaded ${normalized.versions.length} official release${normalized.versions.length === 1 ? '' : 's'} (latest v${normalized.latest}).`);
      }
    } catch (error) {
      if (!current()) return;
      versionsError = error.message || 'Release lookup failed';
      if (!versionCatalog?.versions?.length) manualDetails.open = true;
      if (force) say(updateText, `Could not refresh Tailscale versions: ${versionsError}`, true);
    } finally {
      if (id === versionsLoadId) versionsLoading = false;
      if (current()) drawUpdate();
    }
  }

  async function loadServices({quiet = false} = {}) {
    if (servicesLoading || API.locked || !API.connected) return;
    if (status?.backend_state !== 'Running') return;
    const epoch = UI.epoch, id = ++servicesLoadId;
    const current = () => UI.current(epoch) && id === servicesLoadId;
    servicesLoading = true;
    servicesAttempted = true;
    servicesError = '';
    drawServices();
    if (!quiet) say(servicesText, 'Loading Tailscale Services…');
    try {
      const data = await request('/api/tailscale/services', {timeoutMs: 20000});
      if (!current()) return;
      servicesData = data;
      servicesError = '';
      if (!quiet) say(servicesText, '');
    } catch (error) {
      if (!current()) return;
      servicesError = error.message || 'Services unavailable';
      if (!quiet) say(servicesText, `Could not load Tailscale Services: ${servicesError}`, true);
    } finally {
      if (id === servicesLoadId) servicesLoading = false;
      if (current()) drawServices();
    }
  }

  async function toggleServiceDrain(svc, drain, {readvertise = false} = {}) {
    if (!svc || busy) return;
    const titleText = drain
      ? `Drain ${svc.service}?`
      : readvertise
        ? `Re-advertise ${svc.service}?`
        : `Advertise ${svc.service}?`;
    const bodyText = drain
      ? `Stop accepting new connections for ${svc.service} on this router. Existing connections stay open and rules remain saved so you can re-advertise later.`
      : readvertise
        ? `Drain and re-advertise ${svc.service} so the Tailscale control plane registers this router as a host (useful if you defined the service in Tailscale Admin after configuring it here).`
        : `Resume advertising ${svc.service} from this router to your tailnet.`;
    const confirmLabel = drain ? 'Drain service' : readvertise ? 'Re-advertise service' : 'Advertise service';
    if (!await confirm(titleText, bodyText, {label: confirmLabel})) return;
    await mutate(servicesText, async live => {
      busy = true;
      draw();
      say(servicesText, drain ? `Draining ${svc.service}…` : readvertise ? `Re-advertising ${svc.service}…` : `Advertising ${svc.service}…`);
      try {
        const action = drain ? 'drain' : 'advertise';
        const data = await request(
          `/api/tailscale/services/${encodeURIComponent(svc.name)}/${action}`,
          {...json('POST', {}), timeoutMs: 30000}
        );
        if (!live()) return;
        servicesData = data;
        say(servicesText, drain ? `${svc.service} drained.` : readvertise ? `${svc.service} re-advertised.` : `${svc.service} advertised.`);
      } catch (error) {
        if (live()) say(servicesText, error.message, true);
      } finally {
        finishBusy(live);
      }
    });
  }

  async function clearService(svc) {
    if (!svc || busy) return;
    const copy = `Remove all local serve handlers for ${svc.service} and stop advertising it from this router. Other Tailscale Services are not affected.`;
    if (!await confirm(`Clear ${svc.service}?`, copy, {label: `Clear ${svc.service}`, destructive: true})) return;
    await mutate(servicesText, async live => {
      busy = true;
      draw();
      say(servicesText, `Clearing ${svc.service}…`);
      try {
        const data = await request(
          `/api/tailscale/services/${encodeURIComponent(svc.name)}`,
          {method: 'DELETE', timeoutMs: 30000}
        );
        if (!live()) return;
        servicesData = data;
        if (editorOpen && editorLockedName === svc.name) closeServiceEditor('');
        say(servicesText, `${svc.service} cleared.`);
      } catch (error) {
        if (live()) say(servicesText, error.message, true);
      } finally {
        finishBusy(live);
      }
    });
  }

  serviceNameInput.addEventListener('input', () => {
    drawServiceEditorHints();
    updateServiceEditorButtons();
  });

  serviceEditor.addEventListener('submit', async event => {
    event.preventDefault();
    if (!editorOpen || busy) return;
    const parsedName = M.normalizeServiceName(serviceNameInput.value);
    if (parsedName.error) { say(servicesText, parsedName.error, true); return; }
    const validated = M.validateServiceRules(editorRules);
    if (validated.error) { say(servicesText, validated.error, true); return; }
    await mutate(servicesText, async live => {
      busy = true;
      draw();
      say(servicesText, `Saving ${parsedName.service}…`);
      try {
        const data = await request(
          `/api/tailscale/services/${encodeURIComponent(parsedName.name)}`,
          {...json('PUT', {rules: validated.rules}), timeoutMs: 30000}
        );
        if (!live()) return;
        servicesData = data;
        closeServiceEditor(`${parsedName.service} saved.`);
      } catch (error) {
        if (live()) say(servicesText, error.message, true);
      } finally {
        finishBusy(live);
      }
    });
  });

  async function toggleService(enable) {
    if (!status || busy) return;
    const heading = enable ? 'Enable Tailscale?' : 'Disable Tailscale?';
    const copy = enable
      ? 'Start the supervised tailscaled daemon and reconnect this router to your tailnet. Tailscale requires an agent password to be configured.'
      : 'Stop tailscaled and take this router offline on your tailnet. If you are viewing this console over Tailscale, your session will disconnect immediately.';
    if (!await confirm(heading, copy, {label: enable ? 'Enable Tailscale' : 'Disable Tailscale', destructive: !enable})) return;
    await mutate(statusText, async live => {
      busy = true;
      pendingStatus = null;
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
        finishBusy(live);
      }
    });
  }

  async function logoutNode() {
    if (!status || busy) return;
    const copy = 'Invalidate this router’s Tailscale node key, remove saved identity files and disable Tailscale. If you are viewing this console over Tailscale, your session will disconnect immediately. You will need to re-enroll to use Tailscale again.';
    if (!await confirm('Log out & reset Tailscale?', copy, {label: 'Log out & reset', destructive: true})) return;
    await mutate(statusText, async live => {
      busy = true;
      pendingStatus = null;
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
        finishBusy(live);
      }
    });
  }

  async function requestLoginUrl() {
    if (!status || busy) return;
    await mutate(authText, async live => {
      busy = true;
      pendingStatus = null;
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
        finishBusy(live);
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
      pendingStatus = null;
      draw();
      say(authText, 'Enrolling with Tailscale (this can take up to 90 seconds)…');
      try {
        const data = await request('/api/tailscale/setup', {...json('POST', {auth_key: key}), timeoutMs: 130000});
        if (!live()) return;
        pendingLoginUrl = '';
        loginPending = false;
        logoutWarning = '';
        pendingStatus = null;
        applyStatus(data);
        say(authText, 'Router enrolled and connected to Tailscale.');
      } catch (error) {
        if (live()) say(authText, error.message, true);
      } finally {
        finishBusy(live);
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
    const issue = M.hostnameProblem(draft.hostname);
    if (issue) { say(configText, issue, true); return; }
    const patch = M.configDiff(baseline, draft);
    if (!Object.keys(patch).length) { say(configText, 'No changes to save.'); return; }
    const summary = M.configConfirmation(patch, status.enabled === true);
    if (!await confirm('Save Tailscale preferences?', summary, {label: 'Save preferences'})) return;
    await mutate(configText, async live => {
      busy = true;
      pendingStatus = null;
      draw();
      say(configText, 'Applying Tailscale preferences…');
      try {
        const data = await request('/api/tailscale/config', {...json('PUT', patch), timeoutMs: 30000});
        if (!live()) return;
        pendingStatus = null;
        applyStatus(data, {forceConfig: true});
        say(configText, 'Tailscale preferences saved.');
      } catch (error) {
        if (live()) say(configText, error.message, true);
      } finally {
        finishBusy(live);
      }
    });
  });

  routeInput.addEventListener('input', () => {
    say(routingText, '');
    drawRouting();
  });
  routeInput.addEventListener('keydown', event => {
    if (event.key !== 'Enter' || event.isComposing) return;
    event.preventDefault();
    if (addRoute(routeInput.value)) routeInput.focus();
  });
  exitChoice.input.addEventListener('change', async () => {
    if (!routingEditable()) return;
    const next = exitChoice.input.checked;
    const confirmation = M.exitEnableConfirmation(routingState.baseline.advertise_exit_node, next);
    if (confirmation) {
      const session = routingSession;
      drawRouting();
      if (!await confirm('Advertise Exit Node?', confirmation, {label: 'Advertise Exit Node'})) return;
      if (session !== routingSession || !routingEditable()) return;
    }
    editRouting({advertiseExitNode: next});
  });
  mihomoChoice.input.addEventListener('change', () => {
    if (routingEditable() && routingState.draft.advertise_exit_node) {
      editRouting({exitViaMihomo: mihomoChoice.input.checked});
    }
  });
  routingForm.addEventListener('submit', async event => {
    event.preventDefault();
    if (!routingEditable() || !routingState.dirty || routeInput.value.trim()) return;
    const {baseline, draft, overLimit} = routingState;
    if (overLimit) {
      say(routingText, `Remove subnet routes to stay within the ${M.MAX_ADVERTISE_ROUTES}-route limit.`, true);
      return;
    }
    const patch = M.routingDiff(baseline, draft);
    const session = routingSession;
    await mutate(routingText, async live => {
      const current = () => live() && session === routingSession;
      busy = true;
      pendingStatus = null;
      loadId++;
      loading = false;
      if (statusText.textContent === READING_STATUS_MESSAGE) say(statusText, '');
      draw();
      say(routingText, 'Saving Tailscale routing…');
      try {
        const data = await request('/api/tailscale/config', {...json('PUT', patch), timeoutMs: 30000});
        if (!current()) return;
        pendingStatus = null;
        resetRoutingDraft();
        applyStatus(data);
        say(routingText, 'Tailscale routing saved.');
      } catch (error) {
        if (!current()) return;
        flushPendingStatus(current);
        await refreshAfterMutation(current);
        if (!current()) return;
        flushPendingStatus(current);
        if (routingState.dirty) {
          say(routingText, `Could not save routing. Your draft is kept. ${error.message}`, true);
        } else {
          say(routingText, 'Saved routing already matches your changes.');
        }
      } finally {
        finishBusy(live);
      }
    });
  });

  updateForm.addEventListener('input', () => {
    drawUpdate();
    say(updateText, '');
  });

  versionSelect.addEventListener('change', () => {
    selectedVersion = versionSelect.value;
    drawUpdate();
    say(updateText, '');
  });

  updateForm.addEventListener('submit', async event => {
    event.preventDefault();
    if (!status || busy) return;
    const draft = {version: effectiveUpdateVersion(), sha256: sha256Input.value};
    const issue = M.updateProblem(draft);
    if (issue) { say(updateText, issue, true); return; }
    const req = M.updateRequest(draft);
    const url = M.packageUrl(req.version);
    const intent = M.updateIntent(req.version, status);
    const installed = M.installedVersion(status);
    const actionLabels = {
      install: `Install v${req.version}`,
      upgrade: `Upgrade to v${req.version}`,
      downgrade: `Downgrade to v${req.version}`,
      reinstall: `Reinstall v${req.version}`
    };
    const actionLabel = actionLabels[intent];
    const downgradeLead = intent === 'downgrade' && installed
      ? `You are switching from v${installed} to an older release (v${req.version}). `
      : '';
    const checksumCopy = req.sha256
      ? `verify custom SHA-256 ${req.sha256.slice(0, 12)}…${req.sha256.slice(-8)}`
      : 'verify against the official .sha256 checksum from pkgs.tailscale.com';
    const swapCopy = status.installed
      ? 'Tailscale briefly disconnects while swapping binaries, and rolls back automatically if an enrolled node fails to reconnect within 120 seconds.'
      : 'Binaries are verified and smoke-tested before installation.';
    const copy = `${downgradeLead}Download ${url} and ${checksumCopy}. ${swapCopy}`;
    if (!await confirm(`${actionLabel}?`, copy, {label: actionLabel})) return;
    await mutate(updateText, async live => {
      busy = true;
      pendingStatus = null;
      draw();
      say(updateText, `Starting download for Tailscale v${req.version}…`);
      try {
        await request('/api/tailscale/update', {...json('POST', req), timeoutMs: 25000});
        if (!live()) return;
        versionInput.value = '';
        sha256Input.value = '';
        await refreshAfterMutation(live);
        if (!live()) return;
        const verb = intent === 'install' ? 'install' : intent === 'downgrade' ? 'downgrade' : intent === 'reinstall' ? 'reinstall' : 'upgrade';
        say(updateText, `Background ${verb} to v${req.version} started. Status updates automatically when finished.`);
      } catch (error) {
        if (live()) say(updateText, error.message, true);
      } finally {
        finishBusy(live);
      }
    });
  });

  function refreshVisible() {
    if (document.hidden || API.locked || !API.connected || !onRoute()) return;
    if (!routingContextTimer) loadRoutingContext();
    if (loading || busy || Date.now() - lastLoad < 1000) return;
    load(true);
  }
  UI.listenForVisibility(refreshVisible);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) stopRoutingContext();
  });
  window.addEventListener('dashboard:navigate', () => {
    if (!onRoute()) stopRoutingContext();
  });
  window.addEventListener('dashboard:connection', event => {
    if (event.detail.state !== 'retrying' || API.connected) return;
    routingSession++;
    loadId++;
    loading = false;
    pendingStatus = null;
    if (statusText.textContent === READING_STATUS_MESSAGE) say(statusText, '');
    stopRoutingContext();
    resetRoutingDraft();
    drawRouting();
  });

  UI.track({
    route,
    sync(readings) {
      const sample = readings.tailscale_status;
      if (!onRoute() || API.locked || !sample?.ok) return;
      if (busy) {
        pendingStatus = sample.data;
        return;
      }
      pendingStatus = null;
      if (loading) {
        loadId++;
        loading = false;
        if (statusText.textContent === READING_STATUS_MESSAGE) say(statusText, '');
      }
      applyStatus(sample.data);
      if (!versionsAttempted && !versionsLoading) loadVersions({force: false});
    },
    get loaded() { return attempted; },
    get dirty() { return dirty(); },
    load: () => load(false),
    refresh: () => load(true),
    clear() {
      loadId++;
      versionsLoadId++;
      servicesLoadId++;
      pickerLoadId++;
      routingSession++;
      stopRoutingContext();
      resetRoutingDraft(null);
      status = null; baseline = null; loading = false; attempted = false; busy = false; pendingStatus = null;
      pendingLoginUrl = ''; loginPending = false; logoutWarning = '';
      versionCatalog = null; selectedVersion = ''; versionsLoading = false; versionsAttempted = false; versionsError = ''; versionSelectSignature = '';
      servicesData = null; servicesLoading = false; servicesAttempted = false; servicesError = '';
      pickerOptions = []; reservationsList = null; pickerLoaded = false;
      editorOpen = false; editorMode = 'new'; editorLockedName = ''; editorRules = []; editorRowsDirty = true;
      serviceNameInput.value = ''; serviceNameInput.readOnly = false;
      parkServiceEditor();
      editorRuleRowsEl.replaceChildren(); serviceEditorHints.replaceChildren();
      manualDetails.open = false;
      authKeyInput.value = '';
      hostnameInput.value = '';
      sshChoice.input.checked = false;
      wakelockChoice.input.checked = false;
      versionInput.value = '';
      sha256Input.value = '';
      for (const node of [statusText, authText, configText, servicesText, updateText]) say(node, '');
      draw();
    }
  });

  draw();
})();
