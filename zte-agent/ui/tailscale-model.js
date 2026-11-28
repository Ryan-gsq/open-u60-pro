'use strict';
((globalThis) => {
  const ADMIN_CONSOLE_URL = 'https://login.tailscale.com/admin/machines';
  const ADMIN_SERVICES_URL = 'https://console.tailscale.com/admin/services';
  const ADMIN_SERVICES_BASE_URL = 'https://console.tailscale.com/admin/services/';
  const PACKAGES_URL = 'https://pkgs.tailscale.com/stable/#static';
  const HOSTNAME_RE = /^[A-Za-z0-9-]+$/;
  const SERVICE_NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  const VERSION_RE = /^\d+(?:\.\d+)*$/;
  const HEX64_RE = /^[0-9a-fA-F]{64}$/;
  const MAX_ADVERTISE_ROUTES = 16;
  const MAX_SERVICE_RULES = 32;
  const MAX_SERVICE_PATH_LEN = 256;
  const ROUTE_STATES = Object.freeze({
    approved: 'Approved', standby: 'Standby', pending: 'Pending', new: 'New', unknown: 'Unknown'
  });
  const SYNC_STATES = Object.freeze({
    applied: 'Applied', pending_daemon: 'Pending daemon', drift: 'Drift', unknown: 'Unknown'
  });
  const SERVICE_STATES = Object.freeze({
    active: 'Active',
    pending: 'Pending approval',
    drained: 'Drained',
    port_mismatch: 'Port mismatch',
    unconfigured: 'Unconfigured'
  });

  function cleanDnsName(raw) {
    return String(raw || '').trim().replace(/\.+$/, '');
  }

  function safeLoginUrl(raw) {
    const text = String(raw || '').trim();
    if (!text) return '';
    let url;
    try { url = new URL(text); } catch { return ''; }
    if (url.protocol !== 'https:' || !url.hostname) return '';
    return url.href;
  }

  function validVersion(raw) {
    const text = String(raw || '').trim();
    return text.length > 0 && VERSION_RE.test(text);
  }

  function cleanVersion(raw) {
    const text = String(raw || '').trim().replace(/^[vV]/, '').split(/[-+]/)[0];
    return validVersion(text) ? text : '';
  }

  function installedVersion(status) {
    if (!status || status.installed !== true) return '';
    return cleanVersion(status.client_version) || cleanVersion(status.pinned_version);
  }

  function compareVersions(left, right) {
    const leftClean = cleanVersion(left), rightClean = cleanVersion(right);
    if (!leftClean || !rightClean) return null;
    const leftParts = leftClean.split('.').map(Number);
    const rightParts = rightClean.split('.').map(Number);
    const count = Math.max(leftParts.length, rightParts.length);
    for (let index = 0; index < count; index++) {
      const leftNum = leftParts[index] || 0;
      const rightNum = rightParts[index] || 0;
      if (leftNum !== rightNum) return leftNum > rightNum ? 1 : -1;
    }
    return 0;
  }

  function formatReleaseDate(raw) {
    const text = String(raw || '').trim();
    if (!text) return '';
    const parsed = Date.parse(text);
    if (!Number.isFinite(parsed)) return '';
    return new Date(parsed).toISOString().slice(0, 10);
  }

  function normalizeVersions(payload) {
    const data = payload && typeof payload === 'object' ? payload : {};
    const seen = new Set(), versions = [];
    for (const item of Array.isArray(data.versions) ? data.versions : []) {
      const version = validVersion(item?.version) ? String(item.version).trim() : '';
      if (!version || seen.has(version)) continue;
      seen.add(version);
      versions.push({
        version,
        published_at: typeof item?.published_at === 'string' ? item.published_at.trim() : ''
      });
    }
    const rawLatest = validVersion(data.latest) ? String(data.latest).trim() : '';
    const latest = rawLatest || (versions[0]?.version || '');
    if (latest && !seen.has(latest)) {
      versions.unshift({version: latest, published_at: ''});
    }
    return {
      latest,
      versions,
      source: typeof data.source === 'string' ? data.source.trim() : '',
      warning: typeof data.warning === 'string' ? data.warning.trim() : '',
      fetchedAt: Number.isFinite(Number(data.fetched_at)) ? Number(data.fetched_at) : 0
    };
  }

  function versionOptionLabel(entry, {latest = '', installed = ''} = {}) {
    const version = String(entry?.version || '').trim();
    if (!version) return '';
    const tags = [];
    if (latest && version === latest) tags.push('Latest');
    if (installed && version === installed) tags.push('Installed');
    const releaseDate = formatReleaseDate(entry?.published_at);
    if (releaseDate) tags.push(releaseDate);
    return tags.length ? `v${version} — ${tags.join(' · ')}` : `v${version}`;
  }

  function updateIntent(targetVersion, status) {
    if (!status || status.installed !== true) return 'install';
    const installed = installedVersion(status);
    const cmp = compareVersions(targetVersion, installed);
    if (cmp === 0) return 'reinstall';
    if (cmp !== null && cmp < 0) return 'downgrade';
    return 'upgrade';
  }

  function packageUrl(version) {
    const text = String(version || '').trim();
    return validVersion(text) ? `https://pkgs.tailscale.com/stable/tailscale_${text}_arm64.tgz` : '';
  }

  function ipv4Octets(address) {
    const octets = address.split('.');
    if (octets.length !== 4 || !octets.every(octet => /^(?:0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255)) {
      return null;
    }
    return octets.map(Number);
  }

  function ipv6Words(address) {
    if (!/^[0-9a-f:.]+$/i.test(address)) return null;
    let canonical;
    try { canonical = new URL(`http://[${address}]/`).hostname.slice(1, -1); }
    catch { return null; }
    const [start, end] = canonical.split('::');
    const parse = side => side ? side.split(':').map(word => parseInt(word, 16)) : [];
    const left = parse(start);
    if (end === undefined) return left;
    const right = parse(end);
    return [...left, ...Array(8 - left.length - right.length).fill(0), ...right];
  }

  function formatIpv6(words) {
    if (words.slice(0, 5).every(word => word === 0) && words[5] === 0xffff) {
      return `::ffff:${[words[6] >> 8, words[6] & 255, words[7] >> 8, words[7] & 255].join('.')}`;
    }
    const address = words.map(word => word.toString(16)).join(':');
    return new URL(`http://[${address}]/`).hostname.slice(1, -1);
  }

  function parsePrefix(raw) {
    const parts = String(raw ?? '').trim().split('/');
    if (parts.length !== 2 || /\s/.test(parts[0]) || !/^\+?\d+$/.test(parts[1])) return null;
    const [address, lengthText] = parts, length = Number(lengthText);
    const bits = address.includes(':') ? 16 : 8;
    if (length > (bits === 16 ? 128 : 32)) return null;
    const words = bits === 16 ? ipv6Words(address) : ipv4Octets(address);
    if (!words) return null;
    const network = maskAddress(words, bits, length);
    return {
      bits, length, network,
      prefix: `${bits === 16 ? formatIpv6(network) : network.join('.')}/${length}`,
      hasHostBits: !sameList(words, network)
    };
  }

  function maskAddress(words, bits, length) {
    return words.map((word, index) => {
      const keep = Math.min(bits, Math.max(0, length - index * bits));
      return (word >> (bits - keep)) << (bits - keep);
    });
  }

  const RESERVED_ROUTES = [
    '100.64.0.0/10', 'fd7a:115c:a1e0::/48', '0.0.0.0/32', '127.0.0.0/8',
    '224.0.0.0/4', '::/128', '::1/128', 'ff00::/8'
  ].map(parsePrefix);

  function normalizeRoute(raw) {
    const route = parsePrefix(raw);
    if (!route) return {error: 'Enter a valid IPv4 or IPv6 CIDR, such as 192.168.0.0/24 or fd00::/64.'};
    if (route.length === 0) return {error: 'Use the Advertise Exit Node switch for default routes (/0).'};
    for (const reserved of RESERVED_ROUTES) {
      if (route.bits !== reserved.bits) continue;
      const shared = Math.min(route.length, reserved.length);
      if (sameList(maskAddress(route.network, route.bits, shared), maskAddress(reserved.network, route.bits, shared))) {
        return {error: `This route overlaps the reserved range ${reserved.prefix}.`};
      }
    }
    return {prefix: route.prefix, hasHostBits: route.hasHostBits};
  }

  function routeCandidate(raw, routes) {
    const route = normalizeRoute(raw);
    if (route.error) return route;
    if (routes.includes(route.prefix)) return {error: `${route.prefix} is already in the list.`};
    if (routes.length >= MAX_ADVERTISE_ROUTES) return {error: `You can advertise up to ${MAX_ADVERTISE_ROUTES} subnet routes.`};
    return route;
  }

  function hostnameProblem(raw) {
    const value = String(raw || '').trim();
    if (!value || value.length > 63 || !HOSTNAME_RE.test(value)) {
      return 'Hostname must be 1–63 ASCII letters, digits or hyphens.';
    }
    return '';
  }

  function configBaseline(status) {
    const data = status || {};
    return {
      hostname: typeof data.hostname === 'string' && data.hostname.trim() ? data.hostname.trim() : 'u60-pro',
      tailscale_ssh: data.tailscale_ssh === true,
      hold_wakelock: data.hold_wakelock !== false
    };
  }

  function sameList(left, right) {
    return left.length === right.length && left.every((item, index) => item === right[index]);
  }

  function configDiff(baseline, draft) {
    const patch = {};
    const hostname = String(draft.hostname || '').trim();
    const ssh = draft.tailscale_ssh === true;
    const wakelock = draft.hold_wakelock === true;
    if (hostname !== baseline.hostname) patch.hostname = hostname;
    if (ssh !== baseline.tailscale_ssh) patch.tailscale_ssh = ssh;
    if (wakelock !== baseline.hold_wakelock) patch.hold_wakelock = wakelock;
    return patch;
  }

  function routingBaseline(status) {
    return {
      advertise_routes: Array.isArray(status?.advertise_routes) ? [...new Set(status.advertise_routes)] : [],
      advertise_exit_node: status?.advertise_exit_node === true,
      exit_via_mihomo: status?.exit_via_mihomo === true
    };
  }

  function routingDiff(baseline, draft) {
    const patch = {};
    if (baseline.advertise_routes.length !== draft.advertise_routes.length ||
        baseline.advertise_routes.some(prefix => !draft.advertise_routes.includes(prefix))) {
      patch.advertise_routes = draft.advertise_routes;
    }
    if (baseline.advertise_exit_node !== draft.advertise_exit_node) patch.advertise_exit_node = draft.advertise_exit_node;
    if (baseline.exit_via_mihomo !== draft.exit_via_mihomo) patch.exit_via_mihomo = draft.exit_via_mihomo;
    return patch;
  }

  const routingBaselineChanged = (before, after) => Object.keys(routingDiff(before, after)).length > 0;

  function rebaseRouting(baseline, previous = {}) {
    const saved = baseline ?? routingBaseline();
    const edits = {
      addedRoutes: [...new Set(previous.edits?.addedRoutes)].filter(prefix => !saved.advertise_routes.includes(prefix)),
      removedRoutes: [...new Set(previous.edits?.removedRoutes)].filter(prefix => saved.advertise_routes.includes(prefix)),
      advertiseExitNode: previous.edits?.advertiseExitNode ?? null,
      exitViaMihomo: previous.edits?.exitViaMihomo ?? null
    };
    if (edits.advertiseExitNode === saved.advertise_exit_node) edits.advertiseExitNode = null;
    if (edits.exitViaMihomo === saved.exit_via_mihomo) edits.exitViaMihomo = null;
    const dirty = edits.addedRoutes.length > 0 || edits.removedRoutes.length > 0 ||
      edits.advertiseExitNode !== null || edits.exitViaMihomo !== null;
    const draft = {
      advertise_routes: [
        ...saved.advertise_routes.filter(prefix => !edits.removedRoutes.includes(prefix)),
        ...edits.addedRoutes
      ],
      advertise_exit_node: edits.advertiseExitNode ?? saved.advertise_exit_node,
      exit_via_mihomo: edits.exitViaMihomo ?? saved.exit_via_mihomo
    };
    let reviewBaseline = null;
    if (dirty && previous.baseline) {
      reviewBaseline = routingBaselineChanged(previous.baseline, saved) ? previous.baseline : previous.reviewBaseline;
    }
    const overLimit = draft.advertise_routes.length > MAX_ADVERTISE_ROUTES;
    return {baseline, edits, draft, dirty, reviewBaseline: reviewBaseline ?? null, overLimit};
  }

  function routeState(prefix, savedRoutes, liveRoutes) {
    if (!savedRoutes.includes(prefix)) return 'new';
    const state = liveRoutes?.find(route => route.prefix === prefix)?.state;
    return ['approved', 'standby', 'pending'].includes(state) ? state : 'unknown';
  }

  function lanRouteSuggestions(lanSubnets, draftRoutes) {
    if (!Array.isArray(lanSubnets)) return [];
    const routes = lanSubnets.map(normalizeRoute).filter(route => route.prefix).map(route => route.prefix);
    return [...new Set(routes)].filter(prefix => !draftRoutes.includes(prefix));
  }

  function routingStatus(raw) {
    const mode = raw?.tun?.mode;
    const modeLabel = mode === 'kernel' ? 'Kernel TUN' : mode === 'userspace' ? 'Userspace networking' : 'Unknown';
    const sync = Object.hasOwn(SYNC_STATES, raw?.sync) ? raw.sync : 'unknown';
    return {modeLabel, sync, syncLabel: SYNC_STATES[sync]};
  }

  function exitApproval(state) {
    if (state === 'off') return {state, label: 'Off'};
    if (state === 'approved' || state === 'pending') return {state, label: ROUTE_STATES[state]};
    return {state: 'unknown', label: ROUTE_STATES.unknown};
  }

  function exitEnableConfirmation(saved, next) {
    if (saved || !next) return '';
    return 'Tailnet peers can send their internet traffic through this router once the exit node is approved. Peer traffic may consume your router’s cellular data.';
  }

  function cleanDnsLabel(dns) {
    switch (dns?.state ?? dns?.status ?? dns) {
      case 'active': case 'running': return 'Active';
      case 'disabled': case 'off': return 'Off';
      case 'inactive': case 'stopped': return 'Inactive';
      case 'degraded': case 'error': return 'Degraded';
    }
    if (dns?.enabled === false) return 'Off';
    if (dns?.degraded === true || dns?.error) return 'Degraded';
    const active = dns?.active ?? dns?.running;
    if (active === true) return 'Active';
    if (active === false) return 'Inactive';
    return 'Unknown';
  }

  function exitContext(mihomo, routing) {
    const mihomoLabel = mihomo?.running === true ? 'Running' : mihomo?.running === false ? 'Stopped' : 'Unknown';
    return {mihomoLabel, dnsLabel: cleanDnsLabel(routing?.clean_dns ?? routing?.exit?.clean_dns)};
  }

  function authKeyProblem(raw) {
    const value = String(raw || '').trim();
    if (!value) return 'Enter a Tailscale auth key (for example tskey-auth-…).';
    if (/\s/.test(value)) return 'Auth keys cannot contain spaces or line breaks.';
    return '';
  }

  function versionProblem(raw) {
    const value = String(raw || '').trim();
    if (!value) return 'Enter a Tailscale version number (for example 1.86.2).';
    if (/^[vV]\d/.test(value)) return 'Enter the version without a leading “v” (for example 1.86.2).';
    if (!VERSION_RE.test(value)) return 'Version may contain only digits and dots (for example 1.86.2).';
    return '';
  }

  function sha256Problem(raw) {
    const value = String(raw || '').trim();
    if (!value) return '';
    if (!HEX64_RE.test(value)) return 'SHA-256 checksum must be exactly 64 hexadecimal characters.';
    return '';
  }

  function updateProblem({version, sha256}) {
    return versionProblem(version) || sha256Problem(sha256);
  }

  function updateRequest({version, sha256}) {
    const req = {version: String(version || '').trim()};
    const digest = String(sha256 || '').trim().toLowerCase();
    if (digest) req.sha256 = digest;
    return req;
  }

  function formatExpiry(raw, expired, nowMs = Date.now()) {
    if (expired === true) return 'Expired';
    const text = String(raw || '').trim();
    if (!text) return '—';
    if (text.startsWith('0001-')) return 'Never expires';
    const parsed = Date.parse(text);
    if (!Number.isFinite(parsed)) return text;
    if (parsed <= nowMs) return 'Expired';
    return new Date(parsed).toISOString().slice(0, 10);
  }

  function ageLabel(unixSeconds, nowSeconds = Date.now() / 1000) {
    const at = Number(unixSeconds);
    if (!Number.isFinite(at) || at <= 0 || at > 253402300800) return '';
    const age = Math.max(0, nowSeconds - at);
    if (age < 60) return 'just now';
    if (age < 3600) return `${Math.floor(age / 60)} min ago`;
    if (age < 86400) return `${Math.floor(age / 3600)} h ago`;
    return `${Math.floor(age / 86400)} d ago`;
  }

  function lastUpdateSummary(lastUpdate, nowSeconds = Date.now() / 1000) {
    if (!lastUpdate || typeof lastUpdate !== 'object') return null;
    const version = String(lastUpdate.version || '').trim() || 'unknown';
    const when = ageLabel(lastUpdate.finished_at, nowSeconds);
    const suffix = when ? ` · ${when}` : '';
    if (lastUpdate.ok === true) {
      return {ok: true, text: `Installed v${version}${suffix}.`};
    }
    const error = String(lastUpdate.error || 'update failed').trim();
    return {ok: false, text: `Update to v${version} failed${suffix}: ${error}`};
  }

  function view(status) {
    if (!status || typeof status !== 'object') {
      return {
        state: 'unknown', tone: 'off', chip: 'WAITING',
        title: 'Checking Tailscale',
        detail: 'Connect and unlock the console to read Tailscale status.',
        installed: false, enabled: false, enrolled: false, updating: false, running: false,
        loginUrl: '', canEnable: false, canDisable: false, canLogout: false,
        canLoginUrl: false, canAuthKey: false, canConfig: false, canUpdate: false,
        authReason: 'Waiting for Tailscale status.'
      };
    }
    const installed = status.installed === true;
    const enabled = status.enabled === true;
    const enrolled = status.enrolled === true;
    const daemonRunning = status.daemon_running === true;
    const updating = status.updating === true || status.state === 'updating';
    const running = status.backend_state === 'Running';
    const state = String(status.state || 'unknown');
    const dnsName = cleanDnsName(status.dns_name);
    const loginUrl = safeLoginUrl(status.login_url);
    const meta = {
      not_installed: ['off', 'NOT INSTALLED', 'Tailscale is not installed', 'Install the official ARM64 Tailscale binaries below to enable encrypted remote access.'],
      updating: ['busy', 'UPDATING', 'Installing or upgrading Tailscale', 'Downloading, verifying SHA-256 and swapping binaries in the background. On cellular this can take several minutes.'],
      disabled: enrolled
        ? ['off', 'DISABLED', 'Tailscale is off', 'Your node identity is saved. Enable Tailscale to reconnect to your tailnet.']
        : ['off', 'NOT ENROLLED', 'Tailscale is ready to set up', 'Use a browser login link or an auth key below to enroll this router into your tailnet.'],
      respawning: ['busy', 'STARTING', 'Starting Tailscale daemon', 'Waiting for the supervised tailscaled process to come up.'],
      starting: ['busy', 'STARTING', 'Waiting for Tailscale daemon', 'tailscaled is starting up and opening its local control socket.'],
      connecting: ['busy', 'CONNECTING', 'Connecting to Tailscale', 'Negotiating with the Tailscale control plane and relay network.'],
      awaiting_setup: ['warn', 'AWAITING SETUP', 'Sign in to join your tailnet', 'Open a browser login link or submit a pre-authenticated auth key below.'],
      needs_login: ['warn', 'NEEDS LOGIN', 'Re-authentication required', 'This enrolled node needs to sign in again. Its node key may have expired or been revoked.'],
      pending_approval: ['warn', 'PENDING APPROVAL', 'Waiting for admin approval', 'Approve this machine in the Tailscale admin console to bring it online.'],
      paused: ['off', 'PAUSED', 'Tailscale backend is stopped', 'Enable Tailscale or wait for the supervisor to bring the backend up.'],
      healthy: ['active', 'CONNECTED', dnsName || status.hostname || 'Tailscale connected', 'Connected to your tailnet. Console and API traffic over Tailscale are accepted.'],
      degraded: ['warn', 'OFFLINE', 'Tailscale is offline', 'The daemon is running, but this node is currently offline on the tailnet. Check your internet uplink.']
    }[state] || ['off', 'UNKNOWN', 'Tailscale status unknown', 'The router reported an unrecognized Tailscale state.'];

    const [tone, chip, title, detail] = meta;
    const canEnable = installed && !updating && !enabled;
    const canDisable = installed && !updating && (enabled || daemonRunning);
    const canLogout = installed && !updating && (
      enrolled || daemonRunning || ['healthy', 'degraded', 'needs_login', 'pending_approval', 'paused', 'awaiting_setup'].includes(state)
    );
    const canLoginUrl = installed && !updating && !running && !(enrolled && !enabled);
    const canAuthKey = installed && !updating && !running;
    let authReason = '';
    if (!installed) authReason = 'Install Tailscale below before enrolling this router.';
    else if (updating) authReason = 'Wait for the current install or upgrade to finish.';
    else if (running) authReason = 'Already enrolled and connected. Log out first to switch accounts or re-enroll with a new key.';
    else if (enrolled && !enabled) authReason = 'Enable Tailscale above before requesting a browser login link, or re-enroll with an auth key.';

    return {
      state, tone, chip, title, detail,
      installed, enabled, enrolled, updating, running, loginUrl,
      canEnable, canDisable, canLogout, canLoginUrl, canAuthKey,
      canConfig: !updating, canUpdate: !updating, authReason
    };
  }

  function connectionLabel(status) {
    if (!status || status.backend_state !== 'Running') return '—';
    const relay = String(status.relay || '').trim();
    if (status.direct === true) return relay ? `Direct · DERP ${relay}` : 'Direct';
    return relay ? `Relayed · DERP ${relay}` : 'Relayed';
  }

  function facts(status, nowMs = Date.now()) {
    const data = status || {};
    const ips = Array.isArray(data.tailscale_ips) ? data.tailscale_ips.filter(Boolean) : [];
    const dnsName = cleanDnsName(data.dns_name);
    const routes = Array.isArray(data.advertise_routes) ? data.advertise_routes.filter(Boolean) : [];
    const version = data.client_version
      ? String(data.client_version)
      : data.pinned_version
        ? `${data.pinned_version} (pinned)`
        : data.installed === true
          ? 'Installed'
          : 'Not installed';
    const wakelock = data.wakelock_held === true
      ? 'Held'
      : data.hold_wakelock === false
        ? 'Disabled'
        : 'Standby';
    return [
      ['Tailscale IP', ips.length ? ips.join(' · ') : '—', true],
      ['MagicDNS', dnsName || '—', true],
      ['Connection', connectionLabel(data), false],
      ['Version', version, true],
      ['Key expiry', formatExpiry(data.key_expiry, data.expired, nowMs), false],
      ['Wakelock', wakelock, false],
      ['Advertised routes', routes.length ? routes.join(', ') : 'None', true],
      ['Tailscale SSH', data.tailscale_ssh === true ? 'Enabled' : 'Disabled', false]
    ];
  }

  function alerts(status) {
    if (!status || typeof status !== 'object') return [];
    const list = [], push = text => {
      const clean = String(text || '').trim();
      if (clean && !list.includes(clean)) list.push(clean);
    };
    if (status.error) push(status.error);
    if (status.expired === true) {
      push('Node key has expired. Re-authenticate below or disable key expiry in the Tailscale admin console.');
    }
    if (status.state === 'pending_approval') {
      push('Approve this machine in the Tailscale admin console to bring it online.');
    }
    if (Array.isArray(status.health)) {
      for (const item of status.health) push(item);
    }
    return list;
  }

  function configConfirmation(patch, enabled) {
    const lines = [];
    if (Object.hasOwn(patch, 'hostname')) {
      lines.push(`Hostname becomes “${patch.hostname}”.${enabled ? ' If you open this console by MagicDNS name, you may need the new name afterward.' : ''}`);
    }
    if (Object.hasOwn(patch, 'tailscale_ssh')) {
      lines.push(patch.tailscale_ssh
        ? 'Tailscale SSH will be enabled for tailnet peers allowed by your ACLs.'
        : 'Tailscale SSH will be disabled.');
    }
    if (Object.hasOwn(patch, 'hold_wakelock')) {
      lines.push(patch.hold_wakelock
        ? 'The router will hold a wakelock while Tailscale is enabled.'
        : 'The wakelock will be released; the router may sleep and interrupt remote reachability.');
    }
    return lines.join(' ');
  }

  // ── Tailscale Services (svc:*) model ────────────────────────────────────
  function hasControlChars(text) {
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i);
      if (code < 0x20 || code === 0x7f) return true;
    }
    return false;
  }

  function normalizeServiceName(raw) {
    const text = String(raw ?? '').trim();
    const short = text.startsWith('svc:') ? text.slice(4) : text;
    if (!short || short.length > 63 || !SERVICE_NAME_RE.test(short)) {
      return {error: 'Service name must be 1–63 lowercase letters, digits or hyphens, starting and ending with a letter or digit.'};
    }
    return {name: short, service: `svc:${short}`};
  }

  function serviceNameProblem(raw) {
    return normalizeServiceName(raw).error || '';
  }

  function serviceAdminUrl(raw, defined = true) {
    if (!defined) return ADMIN_SERVICES_URL;
    const parsed = normalizeServiceName(raw);
    return parsed.service ? `${ADMIN_SERVICES_BASE_URL}${parsed.service}` : '';
  }

  function servicePendingNotice(svc) {
    const defined = svc?.defined_in_tailnet === true || (Array.isArray(svc?.vips) && svc.vips.length > 0);
    if (defined) {
      return `Defined in Tailscale Admin, waiting for host approval. Approve this router under ${svc.service || 'this service'}, or click Re-advertise if Tailscale Admin still shows no hosts.`;
    }
    const ports = Array.isArray(svc?.configured_ports) && svc.configured_ports.length
      ? `, ports: ${svc.configured_ports.map(p => `tcp:${p}`).join(', ')}`
      : '';
    return `Not defined in Tailscale Admin yet. Click “Define Service” in Tailscale Admin (name: ${svc?.name || ''}${ports}), then click Re-advertise if Tailscale Admin does not list this router.`;
  }

  function isValidHostName(host) {
    if (!host || host.length > 253) return false;
    const clean = host.endsWith('.') ? host.slice(0, -1) : host;
    if (!clean) return false;
    return clean.split('.').every(label =>
      label.length > 0 && label.length <= 63 && HOSTNAME_RE.test(label) && !label.startsWith('-') && !label.endsWith('-')
    );
  }

  function parseAuthority(authority, requirePort) {
    if (!authority || hasControlChars(authority) || /\s/.test(authority) || /[@/?#]/.test(authority)) {
      return {error: 'Invalid backend host or port.'};
    }
    let hostPart = '', portStr = null;
    if (authority.startsWith('[')) {
      const close = authority.indexOf(']');
      if (close < 0) return {error: 'Unclosed IPv6 bracket in backend target.'};
      const addr = authority.slice(1, close);
      const words = ipv6Words(addr);
      if (!words) return {error: 'Invalid IPv6 address in backend target.'};
      const after = authority.slice(close + 1);
      if (after && !after.startsWith(':')) return {error: 'Invalid port syntax after IPv6 address.'};
      hostPart = `[${formatIpv6(words)}]`;
      portStr = after ? after.slice(1) : null;
    } else {
      const colon = authority.lastIndexOf(':');
      if (colon >= 0) {
        const left = authority.slice(0, colon);
        if (left.includes(':')) return {error: 'Wrap IPv6 addresses in brackets, e.g. [::1]:8080.'};
        hostPart = left.toLowerCase();
        portStr = authority.slice(colon + 1);
      } else {
        hostPart = authority.toLowerCase();
      }
      if (!ipv4Octets(hostPart) && !isValidHostName(hostPart)) {
        return {error: `Invalid backend host “${hostPart}”.`};
      }
    }

    let port = null;
    if (portStr !== null) {
      if (!/^\d+$/.test(portStr)) return {error: 'Backend port must be a whole number from 1 to 65535.'};
      port = Number(portStr);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        return {error: 'Backend port must be between 1 and 65535.'};
      }
    }
    if (requirePort && port === null) {
      return {error: 'TCP backend target must include a port (for example 192.168.0.10:22).'};
    }
    return {host: hostPart, port};
  }

  function normalizeUnixTarget(raw) {
    const rest = raw.startsWith('unix://') ? raw.slice(7) : raw.startsWith('unix:') ? raw.slice(5) : '';
    if (!rest.startsWith('/') || rest.length < 2 || hasControlChars(rest) || /\s/.test(rest)) {
      return {error: 'Unix socket target must be an absolute path (for example unix:/tmp/app.sock).'};
    }
    return {target: `unix:${rest}`};
  }

  function normalizeServicePath(raw, isFile = false) {
    const text = String(raw ?? '').trim();
    const path = text || '/';
    if (!path.startsWith('/')) return {error: 'HTTPS URL path must start with “/”.'};
    if (path.length > MAX_SERVICE_PATH_LEN) return {error: `HTTPS URL path must be at most ${MAX_SERVICE_PATH_LEN} characters.`};
    if (hasControlChars(path) || /\s/.test(path) || path.includes('?') || path.includes('#') || path.includes('//')) {
      return {error: 'HTTPS URL path must not contain spaces, query strings, fragments or “//”.'};
    }
    const normalized = path === '/' ? '/' : (isFile ? path : path.replace(/\/+$/, '') || '/');
    const dedupKey = normalized === '/' ? '/' : normalized.replace(/\/+$/, '') || '/';
    return {path: normalized, dedupKey};
  }

  function validateHttpsTarget(raw) {
    const text = String(raw ?? '').trim();
    if (!text) return {error: 'Enter a backend target.'};
    if (hasControlChars(text)) return {error: 'Backend target must not contain control characters.'};
    if (text.startsWith('file://') || text.startsWith('/')) {
      const fsPath = text.startsWith('file://') ? text.slice(7) : text;
      if (!fsPath.startsWith('/')) return {error: 'File target must use an absolute path (for example file:///data/share).'};
      return {target: `file://${fsPath}`, isFile: true};
    }
    if (/^unix:/i.test(text)) {
      const unix = normalizeUnixTarget(`unix:${text.slice(5)}`);
      return unix.error ? unix : {target: unix.target, isFile: false};
    }
    const sep = text.indexOf('://');
    if (sep < 0) {
      return {error: 'HTTPS backend target must start with http://, https://, https+insecure://, unix:, or file://.'};
    }
    const scheme = text.slice(0, sep).toLowerCase();
    const rest = text.slice(sep + 3);
    if (!['http', 'https', 'https+insecure'].includes(scheme)) {
      return {error: `Unsupported HTTPS backend scheme “${scheme}://”.`};
    }
    if (/\s/.test(rest) || rest.includes('?') || rest.includes('#')) {
      return {error: 'HTTPS backend URL must not contain spaces, query strings or fragments.'};
    }
    const slash = rest.indexOf('/');
    const authority = slash >= 0 ? rest.slice(0, slash) : rest;
    const suffix = slash >= 0 ? rest.slice(slash) : '';
    const parsed = parseAuthority(authority, false);
    if (parsed.error) return parsed;
    const target = `${scheme}://${parsed.host}${parsed.port !== null ? `:${parsed.port}` : ''}${suffix}`;
    return {target, isFile: false};
  }

  function validateTcpTarget(raw) {
    const text = String(raw ?? '').trim();
    if (!text) return {error: 'Enter a TCP backend target.'};
    if (hasControlChars(text) || /\s/.test(text)) return {error: 'TCP backend target must not contain spaces or control characters.'};
    if (/^unix:/i.test(text)) return normalizeUnixTarget(`unix:${text.slice(5)}`);
    if (text.startsWith('/') || /^file:\/\//i.test(text)) {
      return {error: 'file:// targets are only supported for HTTPS rules, not raw TCP.'};
    }
    let authority = text;
    const sep = text.indexOf('://');
    if (sep >= 0) {
      const scheme = text.slice(0, sep).toLowerCase();
      if (scheme !== 'tcp') {
        return {error: `TCP backend target does not accept “${scheme}://” (use host:port, tcp://host:port, or unix:/path).`};
      }
      authority = text.slice(sep + 3);
    }
    const parsed = parseAuthority(authority, true);
    if (parsed.error) return parsed;
    return {target: `${parsed.host}:${parsed.port}`};
  }

  function validateServiceRules(rawRules) {
    if (!Array.isArray(rawRules) || rawRules.length === 0) {
      return {error: 'Add at least one port rule, or clear the service to remove it.'};
    }
    if (rawRules.length > MAX_SERVICE_RULES) {
      return {error: `A service may configure at most ${MAX_SERVICE_RULES} rules.`};
    }
    const portProtocols = new Map(), tcpPorts = new Set(), httpsPaths = new Set(), out = [];
    for (const [index, item] of rawRules.entries()) {
      const rowLabel = `Rule ${index + 1}`;
      const protocol = String(item?.protocol || '').toLowerCase();
      if (protocol !== 'https' && protocol !== 'tcp') {
        return {error: `${rowLabel}: protocol must be HTTPS or TCP.`};
      }
      const portText = String(item?.port ?? '').trim();
      if (!/^\d+$/.test(portText)) return {error: `${rowLabel}: enter an external port between 1 and 65535.`};
      const port = Number(portText);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        return {error: `${rowLabel}: external port must be between 1 and 65535.`};
      }
      const prevProto = portProtocols.get(port);
      if (prevProto && prevProto !== protocol) {
        return {error: `Port ${port} cannot be used by both HTTPS and TCP rules.`};
      }
      portProtocols.set(port, protocol);
      if (protocol === 'https') {
        const target = validateHttpsTarget(item?.target);
        if (target.error) return {error: `${rowLabel}: ${target.error}`};
        const path = normalizeServicePath(item?.path, target.isFile);
        if (path.error) return {error: `${rowLabel}: ${path.error}`};
        const key = `${port}|${path.dedupKey}`;
        if (httpsPaths.has(key)) return {error: `Duplicate HTTPS path “${path.path}” on port ${port}.`};
        httpsPaths.add(key);
        out.push({protocol: 'https', port, path: path.path, target: target.target});
      } else {
        if (tcpPorts.has(port)) return {error: `Duplicate TCP rule on port ${port}.`};
        tcpPorts.add(port);
        const target = validateTcpTarget(item?.target);
        if (target.error) return {error: `${rowLabel}: ${target.error}`};
        out.push({protocol: 'tcp', port, target: target.target});
      }
    }
    return {rules: out};
  }

  function extractTargetIp(target) {
    const text = String(target || '').trim();
    if (!text || /^unix:/i.test(text) || /^file:\/\//i.test(text) || text.startsWith('/')) return '';
    const sep = text.indexOf('://');
    const rest = sep >= 0 ? text.slice(sep + 3) : text;
    const slash = rest.indexOf('/');
    const authority = slash >= 0 ? rest.slice(0, slash) : rest;
    if (authority.startsWith('[')) {
      const close = authority.indexOf(']');
      if (close < 0) return '';
      const words = ipv6Words(authority.slice(1, close));
      return words ? formatIpv6(words) : '';
    }
    const colon = authority.lastIndexOf(':');
    const host = colon >= 0 && !authority.slice(0, colon).includes(':') ? authority.slice(0, colon) : authority;
    const octets = ipv4Octets(host);
    return octets ? octets.join('.') : '';
  }

  function parseIpWords(ip) {
    const text = String(ip || '').trim();
    if (!text) return null;
    if (text.includes(':')) {
      const words = ipv6Words(text);
      return words ? {bits: 16, words, canonical: formatIpv6(words)} : null;
    }
    const octets = ipv4Octets(text);
    return octets ? {bits: 8, words: octets, canonical: octets.join('.')} : null;
  }

  function ipInPrefix(ip, cidr) {
    const parsedIp = parseIpWords(ip);
    const prefix = parsePrefix(cidr);
    if (!parsedIp || !prefix || parsedIp.bits !== prefix.bits) return false;
    return sameList(maskAddress(parsedIp.words, parsedIp.bits, prefix.length), prefix.network);
  }

  const TAILNET_V6_PREFIX = parsePrefix('fd7a:115c:a1e0::/48');

  function isPrivateLanIp(ip) {
    const parsed = parseIpWords(ip);
    if (!parsed) return false;
    if (parsed.bits === 8) {
      const [a, b] = parsed.words;
      return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
    }
    if ((parsed.words[0] & 0xfe00) !== 0xfc00) return false;
    return !sameList(maskAddress(parsed.words, 16, TAILNET_V6_PREFIX.length), TAILNET_V6_PREFIX.network);
  }

  function maskMac(raw) {
    const clean = String(raw || '').trim().toLowerCase();
    if (!/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(clean)) return '';
    const octets = clean.split(':');
    return `••:••:••:••:${octets[4]}:${octets[5]}`;
  }

  function buildTargetPickerOptions(clientsData, reservationsData) {
    const byIp = new Map();
    const record = (ip, name, mac, isStatic) => {
      const parsed = parseIpWords(ip);
      if (!parsed) return;
      const key = parsed.canonical;
      const cleanName = String(name || '').trim();
      const masked = maskMac(mac);
      const existing = byIp.get(key);
      if (!existing) {
        byIp.set(key, {ip: key, name: cleanName, macMasked: masked, isStatic: !!isStatic});
      } else {
        if (isStatic) existing.isStatic = true;
        if (!existing.name && cleanName) existing.name = cleanName;
        if (!existing.macMasked && masked) existing.macMasked = masked;
      }
    };

    for (const entry of Array.isArray(reservationsData?.entries) ? reservationsData.entries : []) {
      record(entry?.ip, entry?.name, entry?.mac, true);
    }
    for (const [macAddr, host] of Object.entries(clientsData?.hosts || {})) {
      if (!host || typeof host !== 'object') continue;
      for (const ip of [...(Array.isArray(host.ipaddrs) ? host.ipaddrs : []), ...(Array.isArray(host.ip6addrs) ? host.ip6addrs : [])]) {
        if (!String(ip).toLowerCase().startsWith('fe80:')) record(ip, host.name, macAddr, false);
      }
    }
    for (const lease of Array.isArray(clientsData?.dhcp_leases) ? clientsData.dhcp_leases : []) {
      record(lease?.ipaddr, lease?.hostname, lease?.macaddr, false);
    }

    return [...byIp.values()]
      .sort((a, b) => Number(b.isStatic) - Number(a.isStatic) || a.ip.localeCompare(b.ip))
      .map(item => {
        const tag = item.isStatic ? 'Static DHCP' : 'LAN device';
        const title = item.name || item.macMasked || 'Device';
        return {
          ...item,
          label: `${item.ip} — ${title} (${tag})`
        };
      });
  }

  function applyPickedIpToTarget(protocol, currentTarget, ip) {
    const parsed = parseIpWords(ip);
    if (!parsed) return currentTarget;
    const host = parsed.bits === 16 ? `[${parsed.canonical}]` : parsed.canonical;
    const raw = String(currentTarget || '').trim();
    if (protocol === 'tcp') {
      const existingPort = raw.match(/:(\d+)$/)?.[1] || '';
      return existingPort ? `${host}:${existingPort}` : `${host}:`;
    }
    const schemeMatch = raw.match(/^(https\+insecure|https|http):\/\//i);
    const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : 'http';
    const rest = schemeMatch ? raw.slice(schemeMatch[0].length) : '';
    const slash = rest.indexOf('/');
    const authority = slash >= 0 ? rest.slice(0, slash) : rest;
    const suffix = slash >= 0 ? rest.slice(slash) : '';
    const existingPort = authority.match(/:(\d+)$/)?.[1] || '';
    return `${scheme}://${host}${existingPort ? `:${existingPort}` : ''}${suffix}`;
  }

  function serviceTargetHints(rules, {
    reservations = null,
    advertisedRoutes = [],
    approvedRoutes = [],
    routerIps = [],
    httpsEnabled = true
  } = {}) {
    const routerSet = new Set(routerIps.map(ip => parseIpWords(ip)?.canonical).filter(Boolean));
    const reservedSet = Array.isArray(reservations)
      ? new Set(reservations.map(entry => parseIpWords(entry?.ip ?? entry)?.canonical).filter(Boolean))
      : null;

    const unreservedIps = [], unadvertisedSubnetIps = [], pendingSubnetIps = [];
    let usesHttps = false;
    const pushUnique = (list, value) => { if (value && !list.includes(value)) list.push(value); };

    for (const rule of Array.isArray(rules) ? rules : []) {
      if (String(rule?.protocol || '').toLowerCase() === 'https') usesHttps = true;
      const ip = extractTargetIp(rule?.target);
      if (!ip || routerSet.has(ip) || !isPrivateLanIp(ip)) continue;
      const parsed = parseIpWords(ip);
      if (reservedSet && parsed?.bits === 8 && !reservedSet.has(ip)) {
        pushUnique(unreservedIps, ip);
      }
      const isApproved = approvedRoutes.some(cidr => ipInPrefix(ip, cidr));
      if (!isApproved) {
        const isAdvertised = advertisedRoutes.some(cidr => ipInPrefix(ip, cidr));
        if (isAdvertised) pushUnique(pendingSubnetIps, ip);
        else pushUnique(unadvertisedSubnetIps, ip);
      }
    }

    return {
      unreservedIps,
      unadvertisedSubnetIps,
      pendingSubnetIps,
      httpsDisabledWarning: usesHttps && httpsEnabled === false
    };
  }

  function serviceStateMeta(rawState) {
    const state = Object.hasOwn(SERVICE_STATES, rawState) ? rawState : 'pending';
    const chipState = state === 'active'
      ? 'approved'
      : state === 'pending' || state === 'port_mismatch'
        ? 'pending'
        : 'unknown';
    return {state, label: SERVICE_STATES[state], chipState};
  }

  function formatServicePortDiff(service) {
    const unallowed = Array.isArray(service?.unallowed_ports) ? service.unallowed_ports : [];
    if (!unallowed.length) return '';
    const allowed = Array.isArray(service?.tailnet_ports) && service.tailnet_ports.length
      ? service.tailnet_ports.join(', ')
      : 'none';
    return `Ports not allowed in Tailscale admin: ${unallowed.join(', ')} (admin allows: ${allowed}).`;
  }

  const api = {
    ADMIN_CONSOLE_URL,
    ADMIN_SERVICES_URL,
    ADMIN_SERVICES_BASE_URL,
    PACKAGES_URL,
    MAX_ADVERTISE_ROUTES,
    MAX_SERVICE_RULES,
    ROUTE_STATES,
    SERVICE_STATES,
    cleanDnsName,
    safeLoginUrl,
    validVersion,
    cleanVersion,
    installedVersion,
    compareVersions,
    formatReleaseDate,
    normalizeVersions,
    versionOptionLabel,
    updateIntent,
    packageUrl,
    normalizeRoute,
    routeCandidate,
    routingBaseline,
    routingDiff,
    routingBaselineChanged,
    rebaseRouting,
    routeState,
    lanRouteSuggestions,
    routingStatus,
    exitApproval,
    exitEnableConfirmation,
    exitContext,
    hostnameProblem,
    configBaseline,
    configDiff,
    authKeyProblem,
    versionProblem,
    sha256Problem,
    updateProblem,
    updateRequest,
    formatExpiry,
    ageLabel,
    lastUpdateSummary,
    view,
    facts,
    alerts,
    configConfirmation,
    normalizeServiceName,
    serviceNameProblem,
    serviceAdminUrl,
    servicePendingNotice,
    normalizeServicePath,
    validateServiceRules,
    extractTargetIp,
    ipInPrefix,
    isPrivateLanIp,
    maskMac,
    buildTargetPickerOptions,
    applyPickedIpToTarget,
    serviceTargetHints,
    serviceStateMeta,
    formatServicePortDiff
  };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else globalThis.OpenU60Tailscale = api;
})(globalThis);
